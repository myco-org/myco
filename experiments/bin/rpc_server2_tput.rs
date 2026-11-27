use myco::constants::{MAX_READ_INDICES_PER_CHUNK, NUM_BUCKETS_PER_BATCH_WRITE_CHUNK, NUM_BUCKETS_PER_GRPC_MESSAGE, NUM_BUCKETS_PER_NOTIFICATION_CHUNK, NUM_CLIENTS, NUM_CLIENT_WRITES_PER_CHUNK, S1_S2_CONNECTION_COUNT, THROUGHPUT_ITERATIONS};
use myco::dtypes::{self, Key};
use myco::dtypes::TreeMycoKey;
use myco::logging;
use myco::megaclient::MegaClient;
use myco::proto::myco::read_notifs_response::Buckets;
use myco::proto::myco::server2_service_server::{Server2Service, Server2ServiceServer};
use myco::proto::myco::{ChunkProcessNotifIndicesResponse, ChunkProcessReadIndicesResponse, ChunkProcessReadResponse, ChunkWriteRequest, ChunkWriteResponse, GetPrfKeysRequest, GetPrfKeysResponse, ReadNotifsRequest, ReadNotifsResponse, ReadRequest, ReadResponse, WriteRequest, WriteResponse};
use myco::{
    constants::WARMUP_COUNT,
    utils::generate_test_certificates,
    dtypes::Path,
    server2::Server2,
    tree::SparseBinaryTree,
};
use tokio::sync::{RwLock, Mutex};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tonic::Streaming;
use tracing::debug;
use std::cmp::min;
use std::env;
use std::sync::Arc;
use tonic::{
    transport::{Server, ServerTlsConfig, Identity},
    Request, Response, Status,
};
use tokio_stream::wrappers::ReceiverStream;
use std::collections::HashMap;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static ALLOCATOR: Jemalloc = Jemalloc;

#[derive(Clone)]
pub struct MyServer2Service {
    pub server2: Arc<RwLock<Server2>>,
    pub write_count: Arc<Mutex<usize>>,
    pub mega_client: Arc<Mutex<MegaClient>>,
    pub warm_up_remaining: Arc<Mutex<usize>>,
    pub cached_writes: Arc<RwLock<Option<(Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Key<TreeMycoKey>>, Vec<Vec<u8>>)>>>,
    pub total_iterations: Arc<Mutex<usize>>,
}

impl MyServer2Service {
    pub fn new() -> Self {        
        println!("Initializing Server2 Tput Service with {} warmup + {} measurement iterations",
                 WARMUP_COUNT, THROUGHPUT_ITERATIONS);
        
        let server2 = if cfg!(feature = "prefill") { Server2::new_prefilled(NUM_CLIENTS) } else { Server2::new(NUM_CLIENTS) };
        let server2 = Arc::new(RwLock::new(server2));
        
        let mega_client = MegaClient::new();
        
        Self {
            server2,
            write_count: Arc::new(Mutex::new(0)),
            mega_client: Arc::new(Mutex::new(mega_client)),
            warm_up_remaining: Arc::new(Mutex::new(WARMUP_COUNT)),
            cached_writes: Arc::new(RwLock::new(None)),
            total_iterations: Arc::new(Mutex::new(0)),
        }
    }
    
    pub async fn pre_generate_test_data(&self) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Key<TreeMycoKey>>, Vec<Vec<u8>>) {
        let mut cache = self.cached_writes.write().await;
        if cache.is_none() {
            let generated = self.mega_client.lock().await.generate_writes();
            *cache = Some(generated.clone());
            generated
        } else {
            cache.as_ref().unwrap().clone()
        }
    }
}


#[tonic::async_trait]
impl Server2Service for MyServer2Service {
    type StreamProcessReadIndicesStream = ReceiverStream<Result<myco::proto::myco::ChunkProcessReadIndicesResponse, Status>>;
    type StreamProcessNotifIndicesStream = ReceiverStream<Result<myco::proto::myco::ChunkProcessNotifIndicesResponse, Status>>;
    type GetMegaClientWritesStream = ReceiverStream<Result<myco::proto::myco::GetMegaClientWritesResponse, Status>>;
    
    async fn read(
        &self,
        request: Request<ReadRequest>,
    ) -> Result<Response<ReadResponse>, Status> {

        let index = request.into_inner().index;
        let buckets = self.server2
            .read()
            .await
            .read(index)
            .map_err(|e| Status::internal(e.to_string()))?;
        
        Ok(Response::new(ReadResponse { 
            buckets: buckets.into_iter().map(|b| b.into()).collect() 
        }))
    }

    async fn chunk_write(
        &self,
        request: Request<Streaming<ChunkWriteRequest>>,
    ) -> Result<Response<ChunkWriteResponse>, Status> {
        let mut stream = request.into_inner();
        
        while let Some(chunk) = stream.message().await? {
            let indices = chunk.pathset_indices.into_iter().map(|x| x as usize).collect::<Vec<_>>();
            // Kept apart from the tree, under the shared lock, until the epoch is finalized:
            // clients can keep reading the previous epoch, and no writer waits for another.
            self.server2.read().await.stage_wire_chunk(chunk.buckets, indices);
        }

        Ok(Response::new(ChunkWriteResponse { success: true }))
    }

    async fn get_prf_keys(
        &self,
        request: Request<GetPrfKeysRequest>,
    ) -> Result<Response<GetPrfKeysResponse>, Status> {
        let req = request.into_inner();
        let num_clients = if req.num_clients > 0 { req.num_clients as usize } else { 1 };

        let base_keys = self.server2
            .read()
            .await
            .get_prf_keys()
            .map_err(|e| Status::internal(e.to_string()))?;

        if num_clients == 1 {
            // One client's request, as a client sends it.
            return Ok(Response::new(GetPrfKeysResponse {
                keys: base_keys.into_iter().map(|k| k.into()).collect(),
                packed_keys: Vec::new(),
            }));
        }

        // The benchmark's batched clients: every client's keys, one after the other, as bytes.
        let one_client: Vec<u8> = base_keys.iter().flat_map(|k| k.bytes.iter().copied()).collect();
        let mut packed_keys = Vec::with_capacity(one_client.len() * num_clients);
        for _ in 0..num_clients {
            packed_keys.extend_from_slice(&one_client);
        }
        debug!("Serving the PRF keys of {} clients ({} bytes)", num_clients, packed_keys.len());

        Ok(Response::new(GetPrfKeysResponse { keys: Vec::new(), packed_keys }))
    }

    async fn get_mega_client_writes(
        &self,
        request: Request<myco::proto::myco::GetMegaClientWritesRequest>,
    ) -> Result<Response<Self::GetMegaClientWritesStream>, Status> {
        let req = request.into_inner();
        let chunk_size = if req.chunk_size > 0 { 
            req.chunk_size as usize 
        } else { 
            NUM_CLIENT_WRITES_PER_CHUNK 
        };
        let chunk_index = req.chunk_index as usize;
        
        let cache_ref = self.cached_writes.read().await;
        let (cts, ct_ntfs, fs, f_ntfs, k_renc_ts, c_ss) = cache_ref.as_ref().unwrap();
        
        let total_clients = cts.len();
        
        let start_client = chunk_index * chunk_size;
        
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let output_stream = ReceiverStream::new(rx);
        
        if start_client >= total_clients {
            tokio::spawn(async move {
                let response = myco::proto::myco::GetMegaClientWritesResponse {
                    cts: Vec::new(),
                    ct_ntfs: Vec::new(),
                    fs: Vec::new(),
                    f_ntfs: Vec::new(),
                    k_renc_ts: Vec::new(),
                    c_ss: Vec::new(),
                    is_last_chunk: true,
                };
                let _ = tx.send(Ok(response)).await;
            });
            
            return Ok(Response::new(output_stream));
        }
        
        let end_client = std::cmp::min(start_client + chunk_size, total_clients);
        
        let chunk_cts = cts[start_client..end_client].to_vec();
        let chunk_ct_ntfs = ct_ntfs[start_client..end_client].to_vec();
        let chunk_fs = fs[start_client..end_client].to_vec();
        let chunk_f_ntfs = f_ntfs[start_client..end_client].to_vec();
        let chunk_k_renc_ts: Vec<myco::proto::myco::Key> = k_renc_ts[start_client..end_client].iter()
            .map(|k| k.clone().into())
            .collect();
        let chunk_c_ss = c_ss[start_client..end_client].to_vec();
        
        let is_last_chunk = end_client >= total_clients;
        
        drop(cache_ref);
        
        tokio::spawn(async move {
            let response = myco::proto::myco::GetMegaClientWritesResponse {
                cts: chunk_cts,
                ct_ntfs: chunk_ct_ntfs,
                fs: chunk_fs,
                f_ntfs: chunk_f_ntfs,
                k_renc_ts: chunk_k_renc_ts,
                c_ss: chunk_c_ss,
                is_last_chunk,
            };
            
            if tx.send(Ok(response)).await.is_err() {
                println!("Client disconnected while streaming chunk {}", chunk_index);
            }
        });
        
        Ok(Response::new(output_stream))
    }

    async fn write(
        &self,
        request: Request<tonic::Streaming<WriteRequest>>,
    ) -> Result<Response<WriteResponse>, Status> {
        let mut stream = request.into_inner();
        let mut pathset = SparseBinaryTree::new();
        
        while let Some(chunk) = stream.message().await? {
            for (i, bucket) in chunk.pathset.into_iter().enumerate() {
                pathset.write(bucket.into(), Path::from(i));
            }
            if let Some(prf_key) = chunk.prf_key {
                self.server2.write().await.add_prf_key(&prf_key.into());
            }
        }
        
        self.server2.write().await.write(pathset);

        let is_warmup = {
            let mut warm_up_remaining = self.warm_up_remaining.lock().await;
            println!("Server2 Tput Debug: Warmup remaining: {}", *warm_up_remaining);
            if *warm_up_remaining > 0 {
                *warm_up_remaining -= 1;
                true
            } else {
                false
            }
        };

        let mut total_iter = self.total_iterations.lock().await;
        *total_iter += 1;
        let current_iter = *total_iter;
        println!("Server2 Tput Debug: Current iteration: {}, Total expected: {}", 
                 current_iter, WARMUP_COUNT + THROUGHPUT_ITERATIONS);

        if !is_warmup {
            let mut write_count = self.write_count.lock().await;
            *write_count += 1;
            println!("Server2 Tput Debug: Non-warmup write count: {}", *write_count);
        }

        if current_iter == WARMUP_COUNT + THROUGHPUT_ITERATIONS {
            println!("\nServer2 Tput: All iterations complete ({} warmup + {} measurement = {})", 
                     WARMUP_COUNT, THROUGHPUT_ITERATIONS, WARMUP_COUNT + THROUGHPUT_ITERATIONS);
            println!("Server2 Tput: Logging final averages to CSV files...");
            logging::calculate_and_append_averages("server2_tput_latency.csv", "server2_tput_bytes.csv");
            println!("Server2 Tput: Logging complete");
            
            *total_iter = 0;
            let mut write_count = self.write_count.lock().await;
            *write_count = 0;
        }

        let prf_key = Key::random(&mut ChaCha20Rng::from_entropy());
        {
            let mut server = self.server2.write().await;
            server.finalize_epoch(&prf_key.into());
        }
        
        Ok(Response::new(WriteResponse { success: true }))
    }

    async fn read_notifs(
        &self,  
        request: Request<ReadNotifsRequest>,
    ) -> Result<Response<ReadNotifsResponse>, Status> {
        let notifications = request.into_inner().notifications;
        let ls = notifications.into_iter()
            .map(|(epoch, indices)| {
                (epoch, indices.index.into_iter().map(|i| i.to_vec()).collect())
            })
            .collect();

        let epoch_buckets = self.server2
            .read()
            .await
            .read_notifs(ls)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(ReadNotifsResponse {
            epoch_buckets: epoch_buckets.into_iter()
                .map(|(epoch, buckets)| (epoch, Buckets {
                    bucket: buckets.into_iter().map(|b| b.into()).collect()
                }))
                .collect()
        }))
    }

    async fn notif_chunk_stream(
        &self,
        request: Request<tonic::Streaming<myco::proto::myco::NotifChunkRequest>>,
    ) -> Result<Response<myco::proto::myco::NotifChunkResponse>, Status> {
        let mut stream = request.into_inner();
        
        while let Some(chunk) = stream.message().await? {
            self.server2.read().await.stage_notifs_chunk(chunk.start_index as usize, &chunk.raw_notification_data);
        }

        Ok(Response::new(myco::proto::myco::NotifChunkResponse { success: true }))
    }

    async fn add_prf_key(
        &self,
        request: Request<myco::proto::myco::AddPrfKeyRequest>,
    ) -> Result<Response<myco::proto::myco::AddPrfKeyResponse>, Status> {
        let req = request.into_inner();
        let prf_key = req.prf_key.ok_or_else(|| Status::invalid_argument("Missing prf_key"))?;
        
        let mut server = self.server2.write().await;
        if req.expected_buckets > 0 {
            server
                .finalize_epoch_checked(&prf_key.into(), req.expected_buckets as usize)
                .map_err(|e| Status::failed_precondition(format!("{:?}", e)))?;
        } else {
            server.finalize_epoch(&prf_key.into());
        }

        Ok(Response::new(myco::proto::myco::AddPrfKeyResponse { success: true }))
    }

    async fn chunk_process_read(
        &self,
        request: Request<myco::proto::myco::ChunkProcessReadRequest>,
    ) -> Result<Response<myco::proto::myco::ChunkProcessReadResponse>, Status> {
        let start_time = std::time::Instant::now();
        let req = request.into_inner();
        
        let max_read_indices = min(
            req.read_indices.len(),
            MAX_READ_INDICES_PER_CHUNK
        );
        
        let mut read_buckets = Vec::new();
        if !req.read_indices.is_empty() {
            let read_indices_to_process = &req.read_indices[0..max_read_indices];
            
            match self.server2.read().await.parallel_read(read_indices_to_process.to_vec()) {
                Ok(results) => {
                    for buckets in results {
                        read_buckets.extend(buckets);
                        if read_buckets.len() >= NUM_BUCKETS_PER_BATCH_WRITE_CHUNK {
                            break;
                        }
                    }
                },
                Err(e) => {
                    println!("Error processing read indices: {}", e);
                }
            }
        }
        
        let mut notification_buckets = Vec::new();
        
        if !req.notification_indices.is_empty() {
            let max_notif_indices = min(
                req.notification_indices.len(),
                NUM_BUCKETS_PER_NOTIFICATION_CHUNK
            );
            
            let notification_indices = &req.notification_indices[0..max_notif_indices];
            
            let mut notif_map = std::collections::HashMap::new();
            notif_map.insert(1, notification_indices.to_vec());
            
            match self.server2.read().await.read_notifs(notif_map) {
                Ok(results) => {
                    for buckets in results.values() {
                        notification_buckets.extend(buckets.clone());
                        if notification_buckets.len() >= NUM_BUCKETS_PER_NOTIFICATION_CHUNK {
                            break;
                        }
                    }
                },
                Err(e) => {
                    println!("Error processing notification indices: {}", e);
                }
            }
        }
        
        let processing_time = start_time.elapsed().as_millis() as u32;
        println!("chunk_process_read completed in {}ms", processing_time);
        
        Ok(Response::new(ChunkProcessReadResponse {
            read_buckets: read_buckets.into_iter().map(|b| b.into()).collect(),
            notification_buckets: notification_buckets.into_iter().map(|b| b.into()).collect(),
            processing_time_ms: processing_time,
        }))
    }

    async fn chunk_process_read_indices(
        &self,
        request: Request<myco::proto::myco::ChunkProcessReadIndicesRequest>,
    ) -> Result<Response<myco::proto::myco::ChunkProcessReadIndicesResponse>, Status> {
        let req = request.into_inner();
        let start_time = std::time::Instant::now();
        
        let mut read_buckets = Vec::new();
        if !req.read_indices.is_empty() {
            let server2 = self.server2.read().await;
            for (i, index) in req.read_indices.iter().enumerate() {
                match server2.read(index.clone()) {
                    Ok(buckets) => {
                        read_buckets.extend(buckets);
                    },
                    Err(e) => {
                        println!("Error processing read index #{}: {}", i+1, e);
                    }
                }
            }
        }
        
        let processing_time = start_time.elapsed().as_millis() as u32;
        
        Ok(Response::new(ChunkProcessReadIndicesResponse {
            read_buckets: read_buckets.into_iter().map(|b| b.into()).collect(),
            processing_time_ms: processing_time,
            is_last_chunk: true,
        }))
    }
    
    async fn chunk_process_notif_indices(
        &self,
        request: Request<myco::proto::myco::ChunkProcessNotifIndicesRequest>,
    ) -> Result<Response<myco::proto::myco::ChunkProcessNotifIndicesResponse>, Status> {
        let req = request.into_inner();
        let start_time = std::time::Instant::now();
        
        let mut notification_buckets = Vec::new();
        
        if !req.notification_indices.is_empty() {
            let max_notif_indices = min(
                req.notification_indices.len(),
                NUM_BUCKETS_PER_NOTIFICATION_CHUNK
            );
            
            let notification_indices = &req.notification_indices[0..max_notif_indices];
            
            let mut notif_map = std::collections::HashMap::new();
            notif_map.insert(1, notification_indices.to_vec());
            
            match self.server2.read().await.read_notifs(notif_map) {
                Ok(results) => {
                    for buckets in results.values() {
                        notification_buckets.extend(buckets.clone());
                        if notification_buckets.len() >= NUM_BUCKETS_PER_NOTIFICATION_CHUNK {
                            break;
                        }
                    }
                },
                Err(e) => {
                    println!("Error processing notification indices: {}", e);
                }
            }
        }
        
        let processing_time = start_time.elapsed().as_millis() as u32;
        
        let num_buckets = notification_buckets.len() as u32;
        Ok(Response::new(ChunkProcessNotifIndicesResponse {
            raw_bucket_data: {
                let mut raw_data = Vec::with_capacity(notification_buckets.len() * myco::constants::LAMBDA_BYTES * myco::constants::Z_M);
                for bucket in notification_buckets {
                    for block in &bucket.0 {
                        raw_data.extend_from_slice(&block.0);
                    }
                }
                raw_data
            },
            num_buckets,
            processing_time_ms: processing_time,
            is_last_chunk: true,
        }))
    }

    async fn get_all_client_prf_keys(
        &self,
        request: Request<myco::proto::myco::GetAllClientPrfKeysRequest>,
    ) -> Result<Response<myco::proto::myco::GetAllClientPrfKeysResponse>, Status> {
        let req = request.into_inner();
        let num_clients = req.num_clients as usize;
        
        let keys = match self.server2.read().await.get_prf_keys() {
            Ok(keys) => keys,
            Err(e) => {
                println!("Error getting PRF keys: {}", e);
                return Err(Status::internal(e.to_string()));
            }
        };
        
        let proto_keys: Vec<myco::proto::myco::Key> = keys.into_iter()
            .map(|k| k.into())
            .collect();
        
        let clients_in_this_chunk = std::cmp::min(num_clients, myco::constants::MAX_CLIENTS_PER_PRF_KEY_CHUNK);
        let remaining_clients = num_clients - clients_in_this_chunk;
        
        let mut client_keys = Vec::new();
        for _ in 0..clients_in_this_chunk {
            client_keys.extend_from_slice(&proto_keys);
        }
        
        let total_key_bytes = client_keys.iter()
            .map(|k| k.data.len())
            .sum::<usize>() as u32;
        
        Ok(Response::new(myco::proto::myco::GetAllClientPrfKeysResponse {
            client_keys,
            total_key_bytes,
            remaining_clients: remaining_clients as u32,
        }))
    }

    async fn pre_generate_test_data(
        &self,
        _request: Request<myco::proto::myco::PreGenerateTestDataRequest>,
    ) -> Result<Response<myco::proto::myco::PreGenerateTestDataResponse>, Status> {
        {
            let mut cache = self.cached_writes.write().await;
            *cache = None;
            drop(cache);
        }
        
        let _ = self.pre_generate_test_data().await;
                
        Ok(Response::new(myco::proto::myco::PreGenerateTestDataResponse {
            success: true
        }))
    }

    async fn stream_process_read_indices(
        &self,
        request: Request<Streaming<myco::proto::myco::ChunkProcessReadIndicesRequest>>,
    ) -> Result<Response<Self::StreamProcessReadIndicesStream>, Status> {
        let mut stream = request.into_inner();
        let start_time = std::time::Instant::now();
        
        let mut all_read_buckets = Vec::new();
        
        while let Some(chunk) = stream.message().await? {
            let read_indices = chunk.read_indices;
            
            let server2 = self.server2.read().await;
            let buckets = server2.parallel_read(read_indices).unwrap();
            all_read_buckets.extend(buckets);
        }
        
        let processing_time = start_time.elapsed().as_millis() as u32;
        
        let flattened_buckets: Vec<crate::dtypes::Bucket> = all_read_buckets
            .into_iter()
            .flatten()
            .collect();

        let chunks: Vec<Vec<crate::dtypes::Bucket>> = flattened_buckets
            .chunks(NUM_BUCKETS_PER_GRPC_MESSAGE)
            .map(|chunk| chunk.to_vec())
            .collect();

        let total_chunks = chunks.len();
        let total_buckets = flattened_buckets.len();
        
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let output_stream = ReceiverStream::new(rx);
        
        tokio::spawn(async move {
            for (i, chunk) in chunks.into_iter().enumerate() {
                let is_last = i == total_chunks - 1;
                let response = myco::proto::myco::ChunkProcessReadIndicesResponse {
                    read_buckets: chunk.into_iter().map(|b| b.into()).collect(),
                    processing_time_ms: processing_time,
                    is_last_chunk: is_last,
                };
                
                if let Err(_) = tx.send(Ok(response)).await {
                    break;
                }
            }
            
            println!("Processed {} read buckets in {}ms", total_buckets, processing_time);
        });
        
        Ok(Response::new(output_stream))
    }
    
    async fn stream_process_notif_indices(
        &self,
        request: Request<Streaming<myco::proto::myco::ChunkProcessNotifIndicesRequest>>,
    ) -> Result<Response<Self::StreamProcessNotifIndicesStream>, Status> {
        let mut stream = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        
        let server2 = self.server2.clone();
        tokio::spawn(async move {            
            let mut raw_bucket_data = Vec::with_capacity(NUM_BUCKETS_PER_NOTIFICATION_CHUNK * myco::constants::LAMBDA_BYTES * myco::constants::Z_M);
        
            let first_message_result = stream.message().await;
            
            match first_message_result {
                Ok(Some(chunk)) => {                                        
                    if chunk.notification_indices.is_empty() {
                    } else {
                        let start_time = std::time::Instant::now();
                        let server = server2.read().await;
                        
                        let mut notif_map = HashMap::with_capacity(1);
                        notif_map.insert(1, chunk.notification_indices);
                        
                        match server.read_notifs_refs(notif_map) {
                            Ok(results) => {                                
                                for (_, buckets) in results.iter() {                                    
                                    for bucket_chunk in buckets.chunks(NUM_BUCKETS_PER_NOTIFICATION_CHUNK) {
                                        let chunk_size = bucket_chunk.len();
                                        
                                        raw_bucket_data.clear();
                                        
                                        for &bucket in bucket_chunk {
                                            raw_bucket_data.extend_from_slice(bucket);
                                        }
                                                                                
                                        let response = ChunkProcessNotifIndicesResponse {
                                            raw_bucket_data: raw_bucket_data.clone(),
                                            num_buckets: chunk_size as u32,
                                            processing_time_ms: start_time.elapsed().as_millis() as u32,
                                            is_last_chunk: false,
                                        };
                                        
                                        match tx.send(Ok(response)).await {
                                            Ok(_) => {
                                            },
                                            Err(_) => {
                                                return;
                                            }
                                        }
                                    }
                                }
                            },
                            Err(e) => {
                                println!("SERVER ERROR: read_notifs_refs failed: {:?}", e);
                            }
                        }
                        drop(server);
                    }
                    
                    while let Ok(Some(chunk)) = stream.message().await {
                        if chunk.notification_indices.is_empty() {
                            continue;
                        }
                        
                        let start_time = std::time::Instant::now();
                        
                        let mut notif_map = HashMap::with_capacity(1);
                        notif_map.insert(1, chunk.notification_indices);
                        
                        let server = server2.read().await;
                        match server.read_notifs_refs(notif_map) {
                            Ok(results) => {                                
                                for (_, buckets) in results.iter() {
                                    
                                    for bucket_chunk in buckets.chunks(NUM_BUCKETS_PER_NOTIFICATION_CHUNK) {
                                        let chunk_size = bucket_chunk.len();
                                        
                                        raw_bucket_data.clear();
                                        
                                        for &bucket in bucket_chunk {
                                            raw_bucket_data.extend_from_slice(bucket);
                                        }
                                        
                                        let response = ChunkProcessNotifIndicesResponse {
                                            raw_bucket_data: raw_bucket_data.clone(),
                                            num_buckets: chunk_size as u32,
                                            processing_time_ms: start_time.elapsed().as_millis() as u32,
                                            is_last_chunk: false,
                                        };
                                        
                                        if tx.send(Ok(response)).await.is_err() {
                                            return;
                                        }
                                    }
                                }
                            },
                            Err(e) => {
                                println!("SERVER ERROR: read_notifs_refs failed: {:?}", e);
                            }
                        }
                        drop(server);
                    }
                },
                Ok(None) => {
                },
                Err(_) => {
                }
            }
        
            match tx.send(Ok(ChunkProcessNotifIndicesResponse {
                raw_bucket_data: Vec::new(),
                num_buckets: 0,
                processing_time_ms: 0,
                is_last_chunk: true,
            })).await {
                Ok(_) => (),
                Err(e) => println!("SERVER ERROR: Failed to send final chunk: {}", e),
            }
        });
        
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env::set_var("RUST_LOG", "info");
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let addr = args.get(1).unwrap_or(&"0.0.0.0:3004".to_string()).parse()?;
    let server2_service = MyServer2Service::new();
    
    if tokio::fs::metadata("certs/server-cert.pem").await.is_err() 
        || tokio::fs::metadata("certs/server-key.pem").await.is_err() 
    {
        tokio::task::spawn_blocking(|| {
            generate_test_certificates().map_err(|e| format!("Failed generating test certificates: {}", e))
        }).await??;
    }

    let cert = tokio::fs::read("certs/server-cert.pem").await?;
    let key = tokio::fs::read("certs/server-key.pem").await?;
    let identity = Identity::from_pem(cert, key);
    
    println!("Starting Server2 with support for multiple connections and increased message size limits");
    let mut builder = Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity))?
        .http2_keepalive_interval(Some(std::time::Duration::from_secs(30)))
        .http2_keepalive_timeout(Some(std::time::Duration::from_secs(10)));
    builder = builder
        .initial_stream_window_size(Some(myco::network::server2::HTTP2_STREAM_WINDOW))
        .initial_connection_window_size(Some(myco::network::server2::HTTP2_CONNECTION_WINDOW))
        .max_frame_size(Some(myco::network::server2::HTTP2_MAX_FRAME_SIZE));
    builder
        .tcp_keepalive(Some(std::time::Duration::from_secs(60)))
        .tcp_nodelay(true)
        .concurrency_limit_per_connection(S1_S2_CONNECTION_COUNT * 4)
        .add_service(
            Server2ServiceServer::new(server2_service)
                .max_decoding_message_size(16 * 1024 * 1024)
                .max_encoding_message_size(16 * 1024 * 1024)
        )
        .serve(addr)
        .await?;

    Ok(())
}
