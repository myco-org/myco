use myco::{
    constants::{LATENCY_BENCH_COUNT, NUM_BUCKETS_PER_NOTIFICATION_CHUNK, NUM_CLIENTS, S1_S2_CONNECTION_COUNT, WARMUP_COUNT}, dtypes::Path, proto::myco::{
        read_notifs_response::Buckets, server2_service_server::{Server2Service, Server2ServiceServer}, ChunkProcessNotifIndicesResponse, ChunkProcessReadIndicesResponse, ChunkWriteRequest, ChunkWriteResponse, GetPrfKeysRequest, GetPrfKeysResponse, ReadNotifsRequest, ReadNotifsResponse, ReadRequest, ReadResponse, WriteRequest, WriteResponse
    }, server2::Server2, tree::SparseBinaryTree
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};
use tonic::transport::{Server, ServerTlsConfig, Identity};
use tonic::codec::Streaming;
use myco::logging;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::atomic::AtomicBool;
use tokio_stream::wrappers::ReceiverStream;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static ALLOCATOR: Jemalloc = Jemalloc;

pub struct MyServer2Service {
    server2: Arc<RwLock<Server2>>,
    read_count: Arc<AtomicUsize>,
    warm_up_complete: Arc<AtomicBool>,
}

impl Default for MyServer2Service {
    fn default() -> Self {
        Self {
            server2: Arc::new(RwLock::new(if cfg!(feature = "prefill") { Server2::new_prefilled(NUM_CLIENTS) } else { Server2::new(NUM_CLIENTS) })),
            read_count: Arc::new(AtomicUsize::new(0)),
            warm_up_complete: Arc::new(AtomicBool::new(false)),
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

        let count = self.read_count.fetch_add(1, Ordering::SeqCst) + 1;
        
        println!("Read count: {}, Warmup complete: {}, WARMUP_COUNT: {}, LATENCY_BENCH_COUNT: {}", 
                 count, 
                 self.warm_up_complete.load(Ordering::SeqCst),
                 WARMUP_COUNT,
                 LATENCY_BENCH_COUNT);
        
        if !self.warm_up_complete.load(Ordering::SeqCst) && count >= WARMUP_COUNT {
            println!("Warm-up phase complete, starting measurements");
            self.warm_up_complete.store(true, Ordering::SeqCst);
            self.read_count.store(0, Ordering::SeqCst);
        } else if self.warm_up_complete.load(Ordering::SeqCst) && count >= LATENCY_BENCH_COUNT {
            println!("Measurement phase complete - logging results");
            self.read_count.store(0, Ordering::SeqCst);
            logging::calculate_and_append_averages("server2_latency.csv", "server2_bytes.csv");
        }
        
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
            // Kept apart from the tree, under the shared lock, until the epoch is finalized.
            self.server2.read().await.stage_wire_chunk(chunk.buckets, indices);
        }

        Ok(Response::new(ChunkWriteResponse { success: true }))
    }

    async fn get_prf_keys(
        &self,
        _request: Request<GetPrfKeysRequest>,
    ) -> Result<Response<GetPrfKeysResponse>, Status> {
        let keys = self.server2
            .read()
            .await
            .get_prf_keys()
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(GetPrfKeysResponse {
            keys: keys.into_iter().map(|k| k.into()).collect(),
            packed_keys: Vec::new(),
        }))
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

    async fn get_mega_client_writes(
        &self,
        _request: Request<myco::proto::myco::GetMegaClientWritesRequest>,
    ) -> Result<Response<Self::GetMegaClientWritesStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let output_stream = ReceiverStream::new(rx);
        
        tokio::spawn(async move {
            let response = myco::proto::myco::GetMegaClientWritesResponse {
                cts: vec![],
                ct_ntfs: vec![],
                fs: vec![],
                f_ntfs: vec![],
                k_renc_ts: vec![],
                c_ss: vec![],
                is_last_chunk: true,
            };
            let _ = tx.send(Ok(response)).await;
        });
        
        Ok(Response::new(output_stream))
    }

    async fn chunk_process_read(
        &self,
        _request: Request<myco::proto::myco::ChunkProcessReadRequest>,
    ) -> Result<Response<myco::proto::myco::ChunkProcessReadResponse>, Status> {
        unimplemented!()
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
        _request: Request<myco::proto::myco::ChunkProcessNotifIndicesRequest>,
    ) -> Result<Response<myco::proto::myco::ChunkProcessNotifIndicesResponse>, Status> {
        unimplemented!()
    }

    async fn get_all_client_prf_keys(
        &self,
        _request: Request<myco::proto::myco::GetAllClientPrfKeysRequest>,
    ) -> Result<Response<myco::proto::myco::GetAllClientPrfKeysResponse>, Status> {
        unimplemented!()    
    }

    async fn pre_generate_test_data(
        &self,
        _request: Request<myco::proto::myco::PreGenerateTestDataRequest>,
    ) -> Result<Response<myco::proto::myco::PreGenerateTestDataResponse>, Status> {
        unimplemented!()
    }

    async fn stream_process_read_indices(
        &self,
        _request: Request<Streaming<myco::proto::myco::ChunkProcessReadIndicesRequest>>,
    ) -> Result<Response<Self::StreamProcessReadIndicesStream>, Status> {
        unimplemented!()
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
            
            while let Ok(Some(chunk)) = stream.message().await {
                if chunk.notification_indices.is_empty() {
                    continue;
                }
                
                let start_time = std::time::Instant::now();
                
                let mut notif_map = HashMap::with_capacity(1);
                notif_map.insert(1, chunk.notification_indices);
                
                let server = server2.read().await;
                if let Ok(results) = server.read_notifs(notif_map) {
                    for buckets in results.values() {
                        for bucket_chunk in buckets.chunks(NUM_BUCKETS_PER_NOTIFICATION_CHUNK) {
                            raw_bucket_data.clear();
                            
                            for bucket in bucket_chunk {
                                for block in &bucket.0 {
                                    raw_bucket_data.extend_from_slice(&block.0);
                                }
                            }
                            
                            let response = ChunkProcessNotifIndicesResponse {
                                raw_bucket_data: raw_bucket_data.clone(),
                                num_buckets: bucket_chunk.len() as u32,
                                processing_time_ms: start_time.elapsed().as_millis() as u32,
                                is_last_chunk: false,
                            };
                            
                            if tx.send(Ok(response)).await.is_err() {
                                return;
                            }
                        }
                    }
                }
                drop(server);
            }
            
            let _ = tx.send(Ok(ChunkProcessNotifIndicesResponse {
                raw_bucket_data: Vec::new(),
                num_buckets: 0,
                processing_time_ms: 0,
                is_last_chunk: true,
            })).await;
                        
        });
        
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}   

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use myco::utils::generate_test_certificates;
    let args: Vec<String> = std::env::args().collect();
    let addr = args.get(1).unwrap_or(&"0.0.0.0:3004".to_string()).parse()?;
    let server2_service = MyServer2Service::default();
    println!("Server2 listening on {}", addr);
    println!("Configured to handle up to {} concurrent connections", S1_S2_CONNECTION_COUNT);

    if tokio::fs::metadata("certs/server-cert.pem").await.is_err() 
        || tokio::fs::metadata("certs/server-key.pem").await.is_err() 
    {
        println!("Certificate or key not found in 'certs/' folder. Generating test certificates...");
        tokio::task::spawn_blocking(|| {
            generate_test_certificates().map_err(|e| format!("Failed generating test certificates: {}", e))
        }).await??;
    }

    let cert = tokio::fs::read("certs/server-cert.pem").await?;
    let key = tokio::fs::read("certs/server-key.pem").await?;
    let identity = Identity::from_pem(cert, key);

    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity))?
        .initial_stream_window_size(Some(myco::network::server2::HTTP2_STREAM_WINDOW))
        .initial_connection_window_size(Some(myco::network::server2::HTTP2_CONNECTION_WINDOW))
        .max_frame_size(Some(myco::network::server2::HTTP2_MAX_FRAME_SIZE))
        .tcp_keepalive(Some(std::time::Duration::from_secs(60)))
        .tcp_nodelay(true)
        .concurrency_limit_per_connection(S1_S2_CONNECTION_COUNT * 4)
        .add_service(Server2ServiceServer::new(server2_service))
        .serve(addr)
        .await?;

    Ok(())
}
