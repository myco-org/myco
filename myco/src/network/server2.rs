//! # Myco Server2 Network Module
//!
//! This module contains the network communication code for interacting with Server2.

use crate::constants::{
    BUCKET_SIZE_BYTES, D, DELTA, LAMBDA_BYTES, MAX_CLIENTS_PER_PRF_KEY_CHUNK, MAX_REQUEST_SIZE, NOTIF_LOC_BYTES, NUM_BUCKETS_PER_BATCH_WRITE_CHUNK, NUM_BUCKETS_PER_NOTIFICATION_CHUNK, NUM_CLIENTS, NUM_CLIENT_WRITES_PER_CHUNK, S1_S2_CONNECTION_COUNT, Z_M
};
use crate::dtypes::{Bucket, Key, TreeMycoKey};
use crate::proto::myco::{self, ChunkProcessNotifIndicesRequest, ChunkProcessReadIndicesRequest, ChunkProcessReadRequest, GetAllClientPrfKeysRequest, GetMegaClientWritesRequest, PreGenerateTestDataRequest};
use crate::proto::myco::{
    server2_service_client::Server2ServiceClient,
    ChunkWriteRequest, GetPrfKeysRequest, AddPrfKeyRequest, NotifChunkRequest, ReadNotifsRequest, ReadRequest,
};
use crate::tree::SparseBinaryTree;
use crate::utils::Index;
use crate::server1::EpochWrite;
use crate::server2::Server2;
use crate::error::MycoError;
use crate::network::common::Result;
use rayon::prelude::*;
use tokio::sync::mpsc::Sender;
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration; 
use tonic::{transport::Channel, Request};
use std::fs;
use tonic::transport::{Certificate, ClientTlsConfig};
use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "bandwidth")]
use crate::logging::BytesMetric;
#[cfg(feature = "bandwidth")]
use prost::Message;

pub trait BandwidthMetric {
    fn metric_name() -> &'static str;
}

impl BandwidthMetric for NotifChunkRequest {
    fn metric_name() -> &'static str {
        "server2_notif_write_bandwidth"
    }
}

impl BandwidthMetric for ChunkWriteRequest {
    fn metric_name() -> &'static str {
        "server2_chunk_write_bandwidth"
    }
} 


/// A trait for remote communication with Server2
#[async_trait]
pub trait Server2Access: Send + Sync {
    /// Write to Server2
    async fn write(
        &self,
        pathset: &SparseBinaryTree<crate::dtypes::Bucket>,
        notif_table: &Vec<crate::dtypes::Bucket>,
        prf_key: &crate::dtypes::Key<TreeMycoKey>,
    ) -> Result<()>;
    /// Write one epoch to Server2, building its chunks as they are sent
    async fn write_epoch(
        &self,
        epoch_write: Arc<EpochWrite>,
        prf_key: &crate::dtypes::Key<TreeMycoKey>,
    ) -> Result<()>;
    /// Send one epoch's buckets and notification table to Server2 without ending the epoch:
    /// Server2 keeps serving the previous epoch until [`Server2Access::finalize_epoch`].
    async fn stream_epoch(&self, _epoch_write: Arc<EpochWrite>) -> Result<()> {
        Err(MycoError::NetworkError("stream_epoch is not supported by this kind of access".to_string()))
    }
    /// End the epoch sent with [`Server2Access::stream_epoch`] and publish its PRF key. Server2
    /// applies the epoch only if it received exactly `expected_buckets` tree buckets and the whole
    /// notification table.
    async fn finalize_epoch(&self, _prf_key: &crate::dtypes::Key<TreeMycoKey>, _expected_buckets: usize) -> Result<()> {
        Err(MycoError::NetworkError("finalize_epoch is not supported by this kind of access".to_string()))
    }
    /// Get PRF keys from Server2
    async fn get_prf_keys(&self) -> Result<Vec<crate::dtypes::Key<TreeMycoKey>>>;
    /// Read notifications from Server2
    async fn read_notifs(
        &self,
        ls: HashMap<u64, Vec<Index>>,
    ) -> Result<HashMap<u64, Vec<crate::dtypes::Bucket>>>;
    async fn read(&self, l: Vec<u8>) -> Result<Vec<crate::dtypes::Bucket>>;
    /// Get MegaClient writes from Server2
    async fn get_mega_client_writes(&self) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<crate::dtypes::Key<TreeMycoKey>>, Vec<Vec<u8>>)>;
    /// Process chunks of indices and return corresponding buckets
    async fn chunk_process_read(&self, notification_indices: Vec<Vec<u8>>, read_indices: Vec<Vec<u8>>) 
        -> Result<(Vec<crate::dtypes::Bucket>, Vec<crate::dtypes::Bucket>, u32)>;
    // Separate methods for processing notifications and reads
    async fn process_read_indices(&self, read_indices: Vec<Vec<u8>>) 
        -> Result<()>;
    
    async fn process_notification_indices(&self, notification_indices: Vec<Vec<u8>>) 
        -> Result<()>;

    /// Get PRF keys for all clients
    async fn get_all_client_prf_keys(&self, num_clients: usize) 
        -> Result<()>;

    /// Pre-generate test data
    async fn pre_generate_test_data(&self) -> Result<bool>;
}

/// Local access - direct memory access
#[derive(Clone)]
pub struct LocalServer2Access {
    /// The server instance
    pub server: Arc<RwLock<Server2>>,
}

impl LocalServer2Access {
    /// Create a new LocalServer2Access instance
    pub fn new(server: Arc<RwLock<Server2>>) -> Self {
        Self { server }
    }
}

#[async_trait]
impl Server2Access for LocalServer2Access {
    async fn write(
        &self,
        pathset: &SparseBinaryTree<crate::dtypes::Bucket>,
        notif_table: &Vec<crate::dtypes::Bucket>,
        prf_key: &crate::dtypes::Key<TreeMycoKey>,
    ) -> Result<()> {
        let mut server = self.server.write().await;
        server.write(pathset.clone());
        server.write_notifs(notif_table.clone());
        server.add_prf_key(prf_key);
        Ok(())
    }

    async fn write_epoch(
        &self,
        epoch_write: Arc<EpochWrite>,
        prf_key: &crate::dtypes::Key<TreeMycoKey>,
    ) -> Result<()> {
        let mut server = self.server.write().await;
        // Build a few chunks at a time in parallel, then store them.
        let batch = rayon::current_num_threads().max(1);
        let notif_chunks: Vec<usize> = (0..epoch_write.notif_chunks()).collect();
        for chunks in notif_chunks.chunks(batch) {
            let requests: Vec<NotifChunkRequest> = chunks.par_iter().map(|&chunk| epoch_write.notif_chunk(chunk)).collect();
            for request in requests {
                server.write_notifs_chunk(request.start_index as usize, &request.raw_notification_data);
            }
        }
        let bucket_chunks: Vec<usize> = (0..epoch_write.bucket_chunks()).collect();
        for chunks in bucket_chunks.chunks(batch) {
            let requests: Vec<ChunkWriteRequest> = chunks.par_iter().map(|&chunk| epoch_write.bucket_chunk(chunk)).collect();
            for request in requests {
                // Local clients read buckets straight from the tree, so store them split into blocks.
                let buckets = request.buckets.into_iter().map(Bucket::from).collect();
                let indices = request.pathset_indices.into_iter().map(|index| index as usize).collect();
                server.chunk_write(buckets, indices);
            }
        }
        server.finalize_epoch(prf_key);
        Ok(())
    }

    async fn get_prf_keys(&self) -> Result<Vec<crate::dtypes::Key<TreeMycoKey>>> {
        let server = self.server.read().await;
        server.get_prf_keys()
    }

    async fn read_notifs(
        &self,
        ls: HashMap<u64, Vec<Index>>,
    ) -> Result<HashMap<u64, Vec<crate::dtypes::Bucket>>> {
        let server = self.server.read().await;
        server.read_notifs(ls)
    }

    async fn read(&self, l: Vec<u8>) -> Result<Vec<crate::dtypes::Bucket>> {
        // Run the read synchronously in an async context.
        let result = {
            let server = self.server.read().await;
            server.read(l)
        };
        result
    }

    async fn get_mega_client_writes(&self) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<crate::dtypes::Key<TreeMycoKey>>, Vec<Vec<u8>>)> {
        // let mut server = self.server.write().unwrap();
        // This would need to be implemented in Server2
        Err(MycoError::NetworkError("Not implemented for local access".to_string()))
    }

    async fn chunk_process_read(&self, _notification_indices: Vec<Vec<u8>>, _read_indices: Vec<Vec<u8>>) 
        -> Result<(Vec<crate::dtypes::Bucket>, Vec<crate::dtypes::Bucket>, u32)> {
        unimplemented!("chunk_process_read is not implemented for local access")
    }

    async fn process_read_indices(&self, _read_indices: Vec<Vec<u8>>) 
        -> Result<()> {
        unimplemented!("process_read_indices is not implemented for local access")
    }

    async fn process_notification_indices(&self, _notification_indices: Vec<Vec<u8>>) 
        -> Result<()> {
        unimplemented!("process_notification_indices is not implemented for local access")
    }

    async fn get_all_client_prf_keys(&self, _num_clients: usize) 
        -> Result<()> {
        unimplemented!("get_all_client_prf_keys is not implemented for local access")
    }

    async fn pre_generate_test_data(&self) -> Result<bool> {
        Ok(true)
    }
}


/// Number of built chunks that may wait to be sent, per connection. Producers pause when the
/// queue is full, so chunks are built only as fast as they can be sent.
const CHUNKS_QUEUED_PER_CONNECTION: usize = 2;

/// HTTP/2 flow-control windows for connections that carry bulk data. The library defaults
/// (64 KB growing adaptively on the server, 2 MB per stream on the client) make a 4 MB message
/// wait for many window updates.
pub const HTTP2_STREAM_WINDOW: u32 = 32 * 1024 * 1024;
/// See [`HTTP2_STREAM_WINDOW`].
pub const HTTP2_CONNECTION_WINDOW: u32 = 128 * 1024 * 1024;
/// Largest HTTP/2 frame Server2 accepts. The default of 16 KB splits a 4 MB chunk into 256 frames.
pub const HTTP2_MAX_FRAME_SIZE: u32 = 1024 * 1024;

/// Lowers the calling thread's scheduling priority a little. The producers that build chunks
/// can keep every core busy; the threads that encrypt and send what they built must not wait
/// behind them for a core.
fn yield_to_network_threads() {
    #[cfg(target_os = "linux")]
    // SAFETY: a plain system call. On Linux, "process 0" here means the calling thread only.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 5);
    }
}

/// Returns a stream of requests for one connection, fed from a queue that all connections
/// share: each connection gets the next request as soon as it has taken its previous one, so
/// a connection that is momentarily slow does not hold back the others.
///
/// A task of its own moves requests from the shared queue to the connection. The connection's
/// stream must not take them from the shared queue itself: the transport polls a request
/// stream only while the connection can send, so a stalled connection that had been handed the
/// queue's lock would keep every other connection waiting.
fn shared_requests<T: Send + 'static>(
    receiver: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<T>>>,
) -> tokio_stream::wrappers::ReceiverStream<T> {
    let (to_connection, for_connection) = tokio::sync::mpsc::channel::<T>(1);
    tokio::spawn(async move {
        // Wait until the connection has taken its previous request, then fetch the next one.
        while let Ok(permit) = to_connection.reserve().await {
            let request = receiver.lock().await.recv().await;
            match request {
                Some(request) => permit.send(request),
                None => break,
            }
        }
    });
    tokio_stream::wrappers::ReceiverStream::new(for_connection)
}

/// Sends one epoch's buckets and notification table to Server2 over `clients`.
///
/// Chunks are built on producer threads while earlier chunks are in flight, so the per-bucket
/// cryptography overlaps with the transfer. Each connection carries one stream of bucket chunks
/// and one stream of notification chunks, in the same wire format as [`Server2Access::write`].
async fn stream_epoch(
    clients: &[Server2ServiceClient<Channel>],
    epoch_write: Arc<EpochWrite>,
    bucket_metric: &'static str,
    notif_metric: &'static str,
) -> Result<()> {
    let connections = clients.len();
    if connections == 0 {
        return Err(MycoError::NetworkError("No available connections".to_string()));
    }

    let (bucket_sender, bucket_receiver) = tokio::sync::mpsc::channel::<ChunkWriteRequest>(CHUNKS_QUEUED_PER_CONNECTION * connections);
    let (notif_sender, notif_receiver) = tokio::sync::mpsc::channel::<NotifChunkRequest>(8 * CHUNKS_QUEUED_PER_CONNECTION * connections);
    let bucket_receiver = Arc::new(tokio::sync::Mutex::new(bucket_receiver));
    let notif_receiver = Arc::new(tokio::sync::Mutex::new(notif_receiver));
    let mut streams = Vec::with_capacity(2 * connections);
    for client in clients {
        let mut bucket_client = client.clone();
        let mut notif_client = client.clone();
        let bucket_requests = shared_requests(bucket_receiver.clone());
        let notif_requests = shared_requests(notif_receiver.clone());
        streams.push(tokio::spawn(async move {
            bucket_client.chunk_write(Request::new(bucket_requests)).await.map(|_| ())
        }));
        streams.push(tokio::spawn(async move {
            notif_client.notif_chunk_stream(Request::new(notif_requests)).await.map(|_| ())
        }));
    }
    drop(bucket_receiver);
    drop(notif_receiver);

    let next_bucket_chunk = Arc::new(AtomicUsize::new(0));
    let next_notif_chunk = Arc::new(AtomicUsize::new(0));
    let bucket_bytes = Arc::new(AtomicUsize::new(0));
    let notif_bytes = Arc::new(AtomicUsize::new(0));
    // One producer per CPU.
    let producers = std::thread::available_parallelism().map_or(1, |n| n.get());
    // Notification chunks are cheap to build. A few producers start with them so that the link
    // is busy from the first moment; every producer then builds bucket chunks.
    let notif_first = (producers / 16).max(1);

    let handles: Vec<std::thread::JoinHandle<()>> = (0..producers)
        .map(|producer| {
            let epoch_write = epoch_write.clone();
            let bucket_sender = bucket_sender.clone();
            let notif_sender = notif_sender.clone();
            let next_bucket_chunk = next_bucket_chunk.clone();
            let next_notif_chunk = next_notif_chunk.clone();
            let bucket_bytes = bucket_bytes.clone();
            let notif_bytes = notif_bytes.clone();
            std::thread::spawn(move || {
                yield_to_network_threads();
                let send_notif_chunks = || loop {
                    let chunk = next_notif_chunk.fetch_add(1, Ordering::Relaxed);
                    if chunk >= epoch_write.notif_chunks() {
                        return true;
                    }
                    let request = epoch_write.notif_chunk(chunk);
                    if cfg!(feature = "bandwidth") {
                        notif_bytes.fetch_add(request.raw_notification_data.len(), Ordering::Relaxed);
                    }
                    if notif_sender.blocking_send(request).is_err() {
                        return false;
                    }
                };
                if producer < notif_first && !send_notif_chunks() {
                    return;
                }
                loop {
                    let chunk = next_bucket_chunk.fetch_add(1, Ordering::Relaxed);
                    if chunk >= epoch_write.bucket_chunks() {
                        break;
                    }
                    let request = epoch_write.bucket_chunk(chunk);
                    if cfg!(feature = "bandwidth") {
                        bucket_bytes.fetch_add(prost::Message::encoded_len(&request), Ordering::Relaxed);
                    }
                    if bucket_sender.blocking_send(request).is_err() {
                        return;
                    }
                }
                send_notif_chunks();
            })
        })
        .collect();
    // The producers hold the only senders now: the streams end when the last producer is done.
    drop(bucket_sender);
    drop(notif_sender);

    // A producer only panics when Server1 must abort the epoch: a bucket holds more than its
    // capacity, or a message would be stored above the first level readers download. Raise
    // that panic here, so that the batch write stops before Server2 is told to switch epochs.
    let aborted = tokio::task::spawn_blocking(move || handles.into_iter().filter_map(|handle| handle.join().err()).next())
        .await
        .map_err(|e| MycoError::NetworkError(format!("Chunk producer error: {:?}", e)))?;
    if let Some(panic) = aborted {
        std::panic::resume_unwind(panic);
    }

    for (i, stream) in streams.into_iter().enumerate() {
        stream
            .await
            .map_err(|e| MycoError::NetworkError(format!("Task join error for stream {}: {:?}", i, e)))?
            .map_err(|e| MycoError::NetworkError(format!("Stream {} error: {}", i, e)))?;
    }

    if cfg!(feature = "bandwidth") {
        crate::logging::BytesMetric::new(bucket_metric, bucket_bytes.load(Ordering::Relaxed)).log();
        crate::logging::BytesMetric::new(notif_metric, notif_bytes.load(Ordering::Relaxed)).log();
    }
    Ok(())
}

/// Remote access with multiple connections for improved throughput
pub struct MultiConnectionServer2Access {
    clients: Vec<Server2ServiceClient<Channel>>,
    next_channel_index: AtomicUsize,
}

impl MultiConnectionServer2Access {
    pub async fn new(server2_addr: &str) -> Result<Self> {
        let cert = fs::read("certs/server-cert.pem")
            .map_err(|e| MycoError::NetworkError(e.to_string()))?;
        let ca_cert = Certificate::from_pem(cert);
        let tls_config = ClientTlsConfig::new()
            .ca_certificate(ca_cert)
            .domain_name("localhost");
            
        let connection_count = S1_S2_CONNECTION_COUNT;
        let mut clients = Vec::with_capacity(connection_count);
        
        println!("Establishing {} connections to Server2...", connection_count);
        
        for i in 0..connection_count {
            let endpoint = Channel::from_shared(server2_addr.to_string())
                .map_err(|e| MycoError::NetworkError(e.to_string()))?
                .tls_config(tls_config.clone())
                .map_err(|e| MycoError::NetworkError(e.to_string()))?
                .http2_keep_alive_interval(Duration::from_secs(60))
                .initial_stream_window_size(HTTP2_STREAM_WINDOW)
                .initial_connection_window_size(HTTP2_CONNECTION_WINDOW);
            let channel = endpoint
                .connect()
                .await
                .map_err(|e| MycoError::NetworkError(e.to_string()))?;
                
            println!("Connection {} established", i+1);
            
            clients.push(
                Server2ServiceClient::new(channel)
                    .max_decoding_message_size(16 * 1024 * 1024)
                    .max_encoding_message_size(16 * 1024 * 1024)
            );
        }
        
        println!("All {} connections to Server2 established successfully", connection_count);
        
        Ok(Self {
            clients,
            next_channel_index: AtomicUsize::new(0),
        })
    }
    
    fn get_next_client(&self) -> Server2ServiceClient<Channel> {
        let index = self.next_channel_index.fetch_add(1, std::sync::atomic::Ordering::SeqCst) % self.clients.len();
        self.clients[index].clone()
    }

    /// Creates all chunk write requests in parallel.
    /// 
    /// These chunks after being created will be sent via channels.
    fn create_chunk_write_requests(pathset: &SparseBinaryTree<Bucket>, start_chunk_idx: usize, end_chunk_idx: usize) -> Vec<ChunkWriteRequest> {        
        let batch_chunks: Vec<ChunkWriteRequest> = (start_chunk_idx..end_chunk_idx)
            .into_par_iter()
            .map(|chunk_idx| {
                let start_bucket_idx = chunk_idx * NUM_BUCKETS_PER_BATCH_WRITE_CHUNK;
                let end_bucket_idx = std::cmp::min(start_bucket_idx + NUM_BUCKETS_PER_BATCH_WRITE_CHUNK, pathset.packed_buckets.len());
                                
                let buckets: Vec<_> = pathset.packed_buckets[start_bucket_idx..end_bucket_idx]
                    .iter()
                    .map(|bucket| bucket.into())
                    .collect();
                    
                let indices: Vec<_> = pathset.packed_indices[start_bucket_idx..end_bucket_idx]
                    .iter()
                    .map(|&idx| idx as u32)
                    .collect();
                
                ChunkWriteRequest { buckets, pathset_indices: indices }
            })
            .collect();

        batch_chunks
    }
    
    /// Creates all notification write requests in parallel.
    /// 
    /// After these notification write requests are created, they will be sent via channels.
    fn create_notif_write_requests(notif_table: &[Bucket], start_chunk_idx: usize, end_chunk_idx: usize) -> Vec<NotifChunkRequest> {
        let batch_chunks: Vec<NotifChunkRequest> = (start_chunk_idx..end_chunk_idx)
            .into_par_iter()
            .map(|chunk_idx| {
                let start_bucket_idx = chunk_idx * NUM_BUCKETS_PER_NOTIFICATION_CHUNK;
                let end_bucket_idx = std::cmp::min(start_bucket_idx + NUM_BUCKETS_PER_NOTIFICATION_CHUNK, notif_table.len());
                                
                let mut raw_data = Vec::with_capacity((end_bucket_idx - start_bucket_idx) * LAMBDA_BYTES * Z_M);
                for i in start_bucket_idx..end_bucket_idx {
                    for block in &notif_table[i].0 {
                        raw_data.extend_from_slice(&block.0);
                    }
                }
                
                NotifChunkRequest {
                    raw_notification_data: raw_data,
                    num_buckets: (end_bucket_idx - start_bucket_idx) as u32,
                    start_index: start_bucket_idx as u32,
                }
            })
            .collect();

        batch_chunks
    }

    /// Send all write requests via the supplied sender channels.
    async fn send_write_requests<T: Send + Sync + 'static + Clone + BandwidthMetric + prost::Message>(&self, senders: Vec<Sender<T>>, requests: Vec<T>, num_connections: usize) {        
        let write_futures: Vec<_> = requests
            .iter()
            .enumerate()
            .map(|(request_idx, request)| {
                let request = request.clone();
                let conn_idx = request_idx % num_connections;
                let sender = senders[conn_idx].clone();
                
                tokio::spawn(async move {
                    if let Err(_) = sender.send(request).await {
                        println!("Warning: Channel to connection {} closed prematurely", conn_idx);
                    }
                })
            })
            .collect();

        let results = futures::future::join_all(write_futures).await;
        for result in results {
            if let Err(e) = result {
                println!("Error sending write request batch: {:?}", e);
            }
        }
        
        #[cfg(feature = "bandwidth")]
        {
            let total_bytes = requests.iter()
                .map(|req| req.encoded_len())
                .sum::<usize>();
            BytesMetric::new(T::metric_name(), total_bytes).log();
        }
    }

    /// Generic function to handle a list of futures and return a Result.
    async fn handle_futures<T: Send + Sync + 'static, E: Send + Sync + 'static + Display>(&self, futures: Vec<tokio::task::JoinHandle<std::result::Result<T, E>>>) -> Result<()> {
        for (i, future) in futures.into_iter().enumerate() {
            match future.await {
                Ok(result) => {
                    if let Err(e) = result {
                        return Err(MycoError::NetworkError(format!("Future {} error: {}", i, e)));
                    }
                }
                Err(e) => {
                    return Err(MycoError::NetworkError(format!("Task join error for future {}: {:?}", i, e)));
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Server2Access for MultiConnectionServer2Access {
    async fn write(
        &self,
        pathset: &SparseBinaryTree<Bucket>, 
        notif_table: &Vec<Bucket>,
        prf_key: &Key<TreeMycoKey>,
    ) -> Result<()> {
        println!("Server2: inside the function now writing the result");
        let num_chunk_write_chunks = (pathset.packed_buckets.len() + NUM_BUCKETS_PER_BATCH_WRITE_CHUNK - 1) / NUM_BUCKETS_PER_BATCH_WRITE_CHUNK;

        let notif_num_chunks = (notif_table.len() + NUM_BUCKETS_PER_NOTIFICATION_CHUNK - 1) / NUM_BUCKETS_PER_NOTIFICATION_CHUNK;
        
        println!("Starting true pipelined processing of {} chunks...", num_chunk_write_chunks);
        let overall_start = std::time::Instant::now();

        let setup_start = std::time::Instant::now();
        
        let num_connections = self.clients.len();
        let mut chunk_write_senders = Vec::with_capacity(num_connections);
        let mut chunk_write_futures = Vec::with_capacity(num_connections);

        let mut notif_senders = Vec::with_capacity(num_connections);
        let mut notif_futures = Vec::with_capacity(num_connections);
        
        for _ in 0..num_connections {
            let (chunk_write_sender, chunk_write_receiver) = tokio::sync::mpsc::channel(1024);
            chunk_write_senders.push(chunk_write_sender);

            let (notif_sender, notif_receiver) = tokio::sync::mpsc::channel(1024);
            notif_senders.push(notif_sender);
            
            let chunk_write_stream = tokio_stream::wrappers::ReceiverStream::new(chunk_write_receiver);
            let notif_stream = tokio_stream::wrappers::ReceiverStream::new(notif_receiver);
            
            let mut client = self.get_next_client();
            let mut client_clone = client.clone();
            chunk_write_futures.push(tokio::spawn(async move {
                client_clone.chunk_write(Request::new(chunk_write_stream)).await
            }));

            notif_futures.push(tokio::spawn(async move {
                client.notif_chunk_stream(Request::new(notif_stream)).await
            }));
        }

        let setup_time = setup_start.elapsed();
        println!("TIMING: Setup phase finished in {:?}", setup_time);

        let overall_write_start = std::time::Instant::now();

        let write_requests = Self::create_notif_write_requests(&notif_table, 0, notif_num_chunks);
        
        self.send_write_requests(notif_senders, write_requests, num_connections).await;
        println!("TIMING: Creating and sending off notification write requests took {:?}", overall_write_start.elapsed());

        const NUM_CHUNKS_PER_BATCH: usize = 500;
        for i in (0..num_chunk_write_chunks).step_by(NUM_CHUNKS_PER_BATCH) {
            let end_chunk_idx = std::cmp::min(i + NUM_CHUNKS_PER_BATCH, num_chunk_write_chunks);
            let write_requests = Self::create_chunk_write_requests(&pathset, i, end_chunk_idx);
            
            self.send_write_requests(chunk_write_senders.clone(), write_requests, num_connections).await;
        }
        println!("TIMING: Creating and sending off chunk write requests took {:?}", overall_write_start.elapsed());
        drop(chunk_write_senders);

        let (chunk_write_result, notif_write_result) = tokio::join!(
            self.handle_futures(chunk_write_futures),
            self.handle_futures(notif_futures)
        );

        chunk_write_result?;
        notif_write_result?;

        let overall_write_time = overall_write_start.elapsed();
        println!("TIMING: Overall write operation finished in {:?}", overall_write_time);
        
        let prf_start = std::time::Instant::now();
        let mut client = self.get_next_client();
        let add_prf_req = AddPrfKeyRequest {
            prf_key: Some(prf_key.clone().into()),
            expected_buckets: 0,
        };
        let _ = client
            .add_prf_key(Request::new(add_prf_req))
            .await
            .map_err(|e| MycoError::NetworkError(e.to_string()))?;
        
        let prf_time = prf_start.elapsed();
        println!("TIMING: Sending PRF key took {:?}", prf_time);
        
        let total_time = overall_start.elapsed();
        println!("TIMING: Complete write operation (pipelined) finished in {:?}", total_time);
        
        println!("\nTIMING SUMMARY:");
        println!("- Setup phase: {:?}", setup_time);
        println!("- Chunk write + notification table write: {:?}", overall_write_time);
        println!("- PRF key sending: {:?}", prf_time);
        println!("- Total operation time: {:?}", total_time);
        
        Ok(())
    }

    async fn write_epoch(
        &self,
        epoch_write: Arc<EpochWrite>,
        prf_key: &Key<TreeMycoKey>,
    ) -> Result<()> {
        let overall_start = std::time::Instant::now();
        let expected_buckets = epoch_write.buckets();
        self.stream_epoch(epoch_write).await?;
        self.finalize_epoch(prf_key, expected_buckets).await?;
        println!("TIMING: Complete write operation (streamed) finished in {:?}", overall_start.elapsed());
        Ok(())
    }

    async fn stream_epoch(&self, epoch_write: Arc<EpochWrite>) -> Result<()> {
        let overall_start = std::time::Instant::now();
        println!(
            "Server2: streaming {} buckets in {} chunks and {} notification chunks over {} connections...",
            epoch_write.buckets(),
            epoch_write.bucket_chunks(),
            epoch_write.notif_chunks(),
            self.clients.len()
        );
        stream_epoch(&self.clients, epoch_write.clone(), ChunkWriteRequest::metric_name(), NotifChunkRequest::metric_name()).await?;
        let overall_write_time = overall_start.elapsed();
        println!("TIMING: Overall write operation finished in {:?}", overall_write_time);
        println!("TIMING: Building the chunks took {:.3} thread-seconds, overlapped with sending", epoch_write.build_seconds());
        Ok(())
    }

    async fn finalize_epoch(&self, prf_key: &Key<TreeMycoKey>, expected_buckets: usize) -> Result<()> {
        let prf_start = std::time::Instant::now();
        let mut client = self.get_next_client();
        let add_prf_req = AddPrfKeyRequest {
            prf_key: Some(prf_key.clone().into()),
            expected_buckets: expected_buckets as u64,
        };
        let _ = client
            .add_prf_key(Request::new(add_prf_req))
            .await
            .map_err(|e| MycoError::NetworkError(e.to_string()))?;
        println!("TIMING: Sending PRF key took {:?}", prf_start.elapsed());
        Ok(())
    }

    async fn get_prf_keys(&self) -> Result<Vec<Key<TreeMycoKey>>> {
        let num_connections = self.clients.len();
        if num_connections == 0 {
            return Err(MycoError::NetworkError("No available connections".to_string()));
        }
        
        let total_clients = NUM_CLIENTS;
        
        let max_clients_per_request = MAX_CLIENTS_PER_PRF_KEY_CHUNK;
        
        let clients_per_connection = (total_clients + num_connections - 1) / num_connections;
        
        let mut all_keys = Vec::new();
        
        let mut futures = Vec::new();
        
        for conn_idx in 0..num_connections {
            let start_client = conn_idx * clients_per_connection;
            if start_client >= total_clients {
                continue;
            }
            
            let conn_clients = std::cmp::min(clients_per_connection, total_clients - start_client);
            if conn_clients == 0 {
                continue;
            }
            
            let mut client = self.clients[conn_idx % self.clients.len()].clone();
            
            futures.push(async move {
                let mut conn_keys = Vec::new();
                let mut packed_key_count = 0usize;
                
                for chunk_start in (0..conn_clients).step_by(max_clients_per_request) {
                    let chunk_size = std::cmp::min(max_clients_per_request, conn_clients - chunk_start);
                    
                    let request = Request::new(GetPrfKeysRequest {
                        num_clients: chunk_size as u32
                    });
                    
                    match client.get_prf_keys(request).await {
                        Ok(response) => {
                            let response = response.into_inner();
                            // Several clients' keys arrive packed; they are counted, not unpacked.
                            packed_key_count += response.packed_keys.len() / LAMBDA_BYTES;
                            conn_keys.extend(response.keys.into_iter().map(|k| k.into()));
                        },
                        Err(e) => {
                            println!("Error getting PRF keys for clients {}-{}: {}",
                                     start_client + chunk_start, 
                                     start_client + chunk_start + chunk_size - 1,
                                     e);
                        }
                    }
                }
                
                (conn_keys, packed_key_count)
            });
        }
        
        let results = futures::future::join_all(futures).await;
        
        let mut packed_keys = 0;
        for (conn_keys, conn_packed_keys) in results {
            all_keys.extend(conn_keys);
            packed_keys += conn_packed_keys;
        }
        
        let total_keys = all_keys.len() + packed_keys;
        
        println!("Total PRF keys collected: {}", total_keys);
        
        let expected_keys = total_clients * DELTA;
        if total_keys != expected_keys {
            println!("Warning: Expected {} keys ({}*{}), but received {}", 
                    expected_keys, total_clients, DELTA, total_keys);
        }
        
        Ok(all_keys)
    }

    async fn read_notifs(&self, notifications: HashMap<u64, Vec<Vec<u8>>>) 
    -> Result<HashMap<u64, Vec<Bucket>>> {
        let mut results = HashMap::new();
        
        for (epoch, indices) in notifications {
            let notification_indices_flat: Vec<Vec<u8>> = indices;
            
            self.process_notification_indices(notification_indices_flat).await?;
            
            results.insert(epoch, Vec::new());
        }
        
        Ok(results)
    }

    async fn get_mega_client_writes(&self) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Key<TreeMycoKey>>, Vec<Vec<u8>>)> {
        let num_connections = self.clients.len();
        let total_clients = NUM_CLIENTS;
        
        let all_cts = Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(total_clients)));
        let all_ct_ntfs = Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(total_clients)));
        let all_fs = Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(total_clients)));
        let all_f_ntfs = Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(total_clients)));
        let all_k_renc_ts = Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(total_clients)));
        let all_c_ss = Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(total_clients)));
        let client_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        
        let chunk_size = NUM_CLIENT_WRITES_PER_CHUNK as u32;
        
        let chunks_needed = (total_clients + chunk_size as usize - 1) / chunk_size as usize;
        
        let mut handles = Vec::with_capacity(num_connections);
        
        for conn_idx in 0..num_connections {
            let all_cts = all_cts.clone();
            let all_ct_ntfs = all_ct_ntfs.clone();
            let all_fs = all_fs.clone();
            let all_f_ntfs = all_f_ntfs.clone();
            let all_k_renc_ts = all_k_renc_ts.clone();
            let all_c_ss = all_c_ss.clone();
            let client_count = client_count.clone();
            
            let mut client = self.clients[conn_idx % num_connections].clone();
            
            let handle = tokio::spawn(async move {
                let mut chunk_index = conn_idx;
                
                while chunk_index < chunks_needed {
                    
                    let request = Request::new(GetMegaClientWritesRequest {
                        chunk_index: chunk_index as u32,
                        chunk_size,
                    });
                    
                    match client.get_mega_client_writes(request).await {
                        Ok(response) => {
                            let mut stream = response.into_inner();
                            let mut any_data_received = false;
                            
                            while let Some(response) = stream.message().await.transpose() {
                                match response {
                                    Ok(response) => {
                                        any_data_received = true;
                                        
                                        let response_cts_len = response.cts.len();
                                        let is_last_chunk = response.is_last_chunk;
                                        
                                        client_count.fetch_add(response_cts_len, std::sync::atomic::Ordering::Relaxed);
                                        
                                        {
                                            let mut cts = all_cts.lock().await;
                                            cts.extend(response.cts);
                                        }
                                        {
                                            let mut ct_ntfs = all_ct_ntfs.lock().await;
                                            ct_ntfs.extend(response.ct_ntfs);
                                        }
                                        {
                                            let mut fs = all_fs.lock().await;
                                            fs.extend(response.fs);
                                        }
                                        {
                                            let mut f_ntfs = all_f_ntfs.lock().await;
                                            f_ntfs.extend(response.f_ntfs);
                                        }
                                        {
                                            let mut k_renc_ts = all_k_renc_ts.lock().await;
                                            k_renc_ts.extend(response.k_renc_ts.into_iter().map(|k| k.into()));
                                        }
                                        {
                                            let mut c_ss = all_c_ss.lock().await;
                                            c_ss.extend(response.c_ss);
                                        }
                                        
                                        if is_last_chunk {
                                            break;
                                        }
                                    },
                                    Err(_) => {
                                        break;
                                    }
                                }
                            }
                            
                            if !any_data_received {
                            }
                        },
                        Err(_) => {
                        }
                    }
                    
                    chunk_index += num_connections;
                }
            });
            
            handles.push(handle);
        }
        
        for (_, handle) in handles.into_iter().enumerate() {
            if let Err(_) = handle.await {
            }
        }
        
        // Every task that filled these has finished: hand the vectors over without copying them.
        let cts = std::mem::take(&mut *all_cts.lock().await);
        let ct_ntfs = std::mem::take(&mut *all_ct_ntfs.lock().await);
        let fs = std::mem::take(&mut *all_fs.lock().await);
        let f_ntfs = std::mem::take(&mut *all_f_ntfs.lock().await);
        let k_renc_ts = std::mem::take(&mut *all_k_renc_ts.lock().await);
        let c_ss = std::mem::take(&mut *all_c_ss.lock().await);
        Ok((cts, ct_ntfs, fs, f_ntfs, k_renc_ts, c_ss))
    }

    async fn read(&self, l: Vec<u8>) -> Result<Vec<Bucket>> {
        let read_indices = vec![l];
        
        self.process_read_indices(read_indices).await?;
        
        Ok(Vec::new())
    }
    
    async fn chunk_process_read(&self, notification_indices: Vec<Vec<u8>>, read_indices: Vec<Vec<u8>>) 
        -> Result<(Vec<Bucket>, Vec<Bucket>, u32)> {
        let mut client = self.get_next_client();
        let request = Request::new(ChunkProcessReadRequest {
            notification_indices,
            read_indices,
        });
        let response = client
            .chunk_process_read(request)
            .await
            .map_err(|e| MycoError::NetworkError(e.to_string()))?
            .into_inner();
        Ok((
            response.read_buckets.into_iter().map(|b| b.into()).collect(),
            response.notification_buckets.into_iter().map(|b| b.into()).collect(),
            response.processing_time_ms,
        ))
    }

    async fn process_read_indices(&self, read_indices: Vec<Vec<u8>>) 
        -> Result<()> {
        if read_indices.is_empty() {
            return Ok(());
        }
        
        let overall_start = std::time::Instant::now();
        
        let connection_count = self.clients.len();
        
        // Each index returns the buckets of one path, less the levels readers skip
        let estimated_buckets_per_index = D + 1 - crate::utils::read_skipped_levels(NUM_CLIENTS);
        
        let estimated_response_size_per_index = estimated_buckets_per_index 
            * BUCKET_SIZE_BYTES;
    
        let indices_per_request = MAX_REQUEST_SIZE / estimated_response_size_per_index;
        
        let indices_per_request = std::cmp::max(1, indices_per_request);
        
        // All requests wait in one queue that every connection takes from, so that a connection
        // that is momentarily slow does not leave its share of the reads for last.
        let requests: Vec<Vec<Vec<u8>>> = read_indices
            .par_chunks(indices_per_request)
            .map(|chunk| chunk.to_vec())
            .collect();
        let requests = Arc::new(std::sync::Mutex::new(requests.into_iter().enumerate()));
        
        let total_buckets_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        
        let mut handles = Vec::new();
        
        for worker in 0..connection_count {
            let conn_idx = worker % connection_count;
            let mut client = self.clients[conn_idx].clone();
            let requests = requests.clone();
            let buckets_counter = total_buckets_count.clone();
            
            let handle = tokio::spawn(async move {
                let mut conn_buckets = 0;
                
                loop {
                    let next = requests.lock().unwrap().next();
                    let Some((req_idx, indices)) = next else { break };
                    let request = tonic::Request::new(ChunkProcessReadIndicesRequest {
                        read_indices: indices.clone(),
                    });
                    
                    match client.chunk_process_read_indices(request).await {
                        Ok(response) => {
                            let response = response.into_inner();
                            
                            let bucket_count = response.read_buckets.len();
                            
                            conn_buckets += bucket_count;
                        },
                        Err(e) => {
                            println!("Error in connection {}, request {}: {}", conn_idx, req_idx, e);
                            
                            if e.code() == tonic::Code::OutOfRange && e.message().contains("message length too large") {
                                let half_indices = if indices.len() <= 1 {
                                    println!("Can't split batch further, skipping {} indices", indices.len());
                                    continue;
                                } else {
                                    let mid = indices.len() / 2;
                                    vec![&indices[..mid], &indices[mid..]]
                                };
                                
                                for (half_idx, half_batch) in half_indices.iter().enumerate() {
                                    let retry_request = tonic::Request::new(ChunkProcessReadIndicesRequest {
                                        read_indices: half_batch.to_vec(),
                                    });
                                    
                                    match client.chunk_process_read_indices(retry_request).await {
                                        Ok(retry_response) => {
                                            let retry_response = retry_response.into_inner();
                                            
                                            let retry_buckets = retry_response.read_buckets.len();
                                            
                                            conn_buckets += retry_buckets;
                                        },
                                        Err(retry_e) => {
                                            println!("Retry {}/{} for connection {}, request {} failed: {}",
                                                    half_idx+1, half_indices.len(), conn_idx, req_idx, retry_e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                buckets_counter.fetch_add(conn_buckets, std::sync::atomic::Ordering::Relaxed);
            });
            
            handles.push(handle);
        }
        
        for handle in handles {
            if let Err(e) = handle.await {
                return Err(MycoError::NetworkError(format!("Task join error: {}", e)));
            }
        }
        
        let total_time = overall_start.elapsed();
        let total_buckets = total_buckets_count.load(std::sync::atomic::Ordering::Relaxed);
        
        println!("Completed processing {} read indices in {:?}", read_indices.len(), total_time);
        println!("Total buckets: {}", total_buckets);
        
        Ok(())
    }

    #[tracing::instrument(skip(self, notification_indices))]
    async fn process_notification_indices(&self, notification_indices: Vec<Vec<u8>>) 
    -> Result<()> {
        if notification_indices.is_empty() {
            return Ok(());
        }
        
        let overall_start = std::time::Instant::now();
        
        let connection_count = self.clients.len();
        
        let max_indices_per_request = std::cmp::max(1, MAX_REQUEST_SIZE / (NOTIF_LOC_BYTES * 10));
        
        let indices_per_connection = (notification_indices.len() + connection_count - 1) / connection_count;
        
        let connection_batches: Vec<Vec<Vec<u8>>> = notification_indices
            .par_chunks(indices_per_connection)
            .map(|chunk| chunk.to_vec())
            .collect();
        
        let total_buckets_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let error_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let success_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        
        let mut handles = Vec::new();
        
        for (conn_idx, conn_indices) in connection_batches.into_iter().enumerate() {
            if conn_indices.is_empty() {
                continue;
            }
            
            let buckets_counter = total_buckets_count.clone();
            let errors_counter = error_count.clone();
            let success_counter = success_count.clone();
            let mut client = self.clients[conn_idx % connection_count].clone();
            
            let handle = tokio::spawn(async move {
                let request_batches: Vec<Vec<Vec<u8>>> = conn_indices
                    .par_chunks(max_indices_per_request)
                    .map(|chunk| chunk.to_vec())
                    .collect();
                                
                let mut conn_buckets = 0;
                
                for (batch_idx, batch) in request_batches.into_iter().enumerate() {                                        
                    let (tx, rx) = tokio::sync::mpsc::channel(64);
                    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
                    
                    let batch_clone = batch.clone();
                    tokio::spawn(async move {
                        let request = ChunkProcessNotifIndicesRequest {
                            notification_indices: batch_clone,
                        };
                        
                        if let Err(_) = tx.send(request).await {
                            return;
                        }
                        drop(tx);
                    });
                    

                    match client.stream_process_notif_indices(Request::new(stream)).await {
                        Ok(response) => {
                            success_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            
                            let mut response_stream = response.into_inner();
                            let mut batch_buckets_received = 0;
                            
                            loop {
                                match response_stream.message().await {
                                    Ok(Some(result)) => {
                                        let num_buckets = result.num_buckets as usize;
                                        
                                        batch_buckets_received += num_buckets;
                                        
                                        if result.is_last_chunk {
                                            break;
                                        }
                                    },
                                    Ok(None) => {
                                        break;
                                    },
                                    Err(e) => {
                                        println!("CLIENT ERROR: Connection {} batch {} stream error: {}", 
                                                 conn_idx, batch_idx, e);
                                        break;
                                    }
                                }
                            }
                            conn_buckets += batch_buckets_received;
                        },
                        Err(_) => {
                            errors_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
                
                buckets_counter.fetch_add(conn_buckets, std::sync::atomic::Ordering::Relaxed);
            });
            
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }
        
        let total_buckets = total_buckets_count.load(std::sync::atomic::Ordering::Relaxed);
        let _ = error_count.load(std::sync::atomic::Ordering::Relaxed);
        let _ = success_count.load(std::sync::atomic::Ordering::Relaxed);
        
        
        println!("CLIENT: Notification processing complete");
        println!("CLIENT: Read {} notification buckets in {:?}", total_buckets, overall_start.elapsed());
        println!("CLIENT: Requests: {} successes, {} failures", success_count.load(std::sync::atomic::Ordering::Relaxed), error_count.load(std::sync::atomic::Ordering::Relaxed));
        
        Ok(())
    }

    async fn get_all_client_prf_keys(&self, num_clients: usize) 
        -> Result<()> {
        let overall_start = std::time::Instant::now();
        let num_connections = self.clients.len();
        
        println!("Starting PRF key retrieval for {} clients", num_clients);
        
        let mut total_keys = 0;
        
        let clients_per_connection = (num_clients + num_connections - 1) / num_connections;
        
        let mut futures = Vec::new();
        
        for conn_idx in 0..num_connections {
            let start_client = conn_idx * clients_per_connection;
            if start_client >= num_clients {
                continue;
            }
            
            let conn_clients = std::cmp::min(clients_per_connection, num_clients - start_client);
            if conn_clients == 0 {
                continue;
            }
            
            let mut client = self.clients[conn_idx % self.clients.len()].clone();
            
            futures.push(async move {
                let mut conn_keys = 0;
                let mut remaining_clients = conn_clients;
                
                loop {
                    if remaining_clients == 0 {
                        break;
                    }
                    
                    let request = Request::new(GetAllClientPrfKeysRequest {
                        num_clients: remaining_clients as u32,
                        start_client_index: start_client as u32,
                    });
                    
                    match client.get_all_client_prf_keys(request).await {
                        Ok(response) => {
                            let response = response.into_inner();
                            
                            conn_keys += response.client_keys.len();
                            
                            if response.remaining_clients > 0 {
                                remaining_clients = response.remaining_clients as usize;
                            } else {
                                break;
                            }
                        },
                        Err(e) => {
                            println!("Error getting PRF keys: {}", e);
                            break;
                        }
                    }
                }
                
                (conn_keys, /* conn_bytes */ 0) 
            });
        }
        
        let results = futures::future::join_all(futures).await;
        
        for (keys, /* bytes */ _) in results {
            total_keys += keys;
        }
        
        println!("Received {} PRF keys in {:?}",
                 total_keys, overall_start.elapsed());
        
        Ok(())
    }

    async fn pre_generate_test_data(&self) -> Result<bool> {
        let mut client = self.get_next_client();
        let request = Request::new(PreGenerateTestDataRequest {});
        let response = client
            .pre_generate_test_data(request)
            .await
            .map_err(|e| MycoError::NetworkError(e.to_string()))?
            .into_inner();
        Ok(response.success)
    }
} 

/// Remote access - serialized network access
pub struct RemoteServer2Access {
    client: Server2ServiceClient<Channel>,
}

impl RemoteServer2Access {
    pub async fn new(server2_addr: &str) -> Result<Self> {
        let cert = fs::read("certs/server-cert.pem")
            .map_err(|e| MycoError::NetworkError(e.to_string()))?;
        let ca_cert = Certificate::from_pem(cert);
        let tls_config = ClientTlsConfig::new()
            .ca_certificate(ca_cert)
            .domain_name("localhost");
        let channel = Channel::from_shared(server2_addr.to_string())
            .map_err(|e| MycoError::NetworkError(e.to_string()))?
            .tls_config(tls_config)
            .map_err(|e| MycoError::NetworkError(e.to_string()))?
            .connect()
            .await
            .map_err(|e| MycoError::NetworkError(e.to_string()))?;
        Ok(Self {
            client: Server2ServiceClient::new(channel)
                .max_decoding_message_size(16 * 1024 * 1024)
                .max_encoding_message_size(16 * 1024 * 1024),
        })
    }

    pub fn from_channel(channel: Channel) -> Self {
        Self {
            client: Server2ServiceClient::new(channel),
        }
    }

    /// A simplified parallel method:
    /// - Breaks the data into chunks
    /// - Spawns parallel tasks with a concurrency limit
    /// - Sends chunked gRPC requests, then finalizes epoch
    pub async fn remote_write(
        &self,
        pathset: SparseBinaryTree<crate::dtypes::Bucket>,
        notif_table: Vec<crate::dtypes::Bucket>,
        prf_key: crate::dtypes::Key<TreeMycoKey>,
    ) -> Result<()> {
        let mut client = self.client.clone();
        let chunk_size = NUM_BUCKETS_PER_BATCH_WRITE_CHUNK;
        
        // Create chunk requests
        let chunk_creation_start = std::time::Instant::now();
        let chunk_requests: Vec<ChunkWriteRequest> = pathset.packed_buckets
            .par_chunks(chunk_size)
            .zip(pathset.packed_indices.par_chunks(chunk_size))
            .map(|(bucket_chunk, indices_chunk)| {
                ChunkWriteRequest {
                    buckets: bucket_chunk.iter().map(|b| b.clone().into()).collect(),
                    pathset_indices: indices_chunk.iter().map(|&x| x as u32).collect(),
                }
            })
            .collect();
        let chunk_creation_time = chunk_creation_start.elapsed();
        println!("Chunk request creation completed in {:?}", chunk_creation_time);
        
        #[cfg(feature = "bandwidth")]
        {
            let total_bucket_bytes: usize = chunk_requests.iter()
                .map(|req| req.buckets.iter().map(|b| b.encoded_len()).sum::<usize>())
                .sum();
            crate::logging::BytesMetric::new("s1_write_bandwidth", total_bucket_bytes).log();
        }

        // Stream bucket write chunks.
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        tokio::spawn(async move {
            for req in chunk_requests.into_iter() {
                if let Err(_) = tx.send(req).await {
                    break;
                }
            }
            drop(tx);
        });

        let bucket_write_start = std::time::Instant::now();
        let _ = client
            .chunk_write(Request::new(stream))
            .await
            .map_err(|e| MycoError::NetworkError(e.to_string()))?;
        println!("Bucket chunk write completed in {:?}", bucket_write_start.elapsed());

        // Prepare notification chunks with optimized format
        let notif_chunk_requests: Vec<NotifChunkRequest> = notif_table
            .par_chunks(NUM_BUCKETS_PER_NOTIFICATION_CHUNK)
            .enumerate()
            .map(|(chunk_idx, chunk)| {
                // Calculate start index for this chunk
                let start_index = (chunk_idx * NUM_BUCKETS_PER_NOTIFICATION_CHUNK) as u32;
                
                // Flatten all bucket data into a single byte vector
                let mut raw_data = Vec::with_capacity(chunk.len() * LAMBDA_BYTES * Z_M);
                for bucket in chunk {
                    for block in &bucket.0 {
                        raw_data.extend_from_slice(&block.0);
                    }
                }
                
                NotifChunkRequest {
                    raw_notification_data: raw_data,
                    num_buckets: chunk.len() as u32,
                    start_index,
                }
            })
            .collect();

        #[cfg(feature = "bandwidth")]
        {
            let total_ntfication_bytes: usize = notif_chunk_requests.iter()
                .map(|req| req.raw_notification_data.len())
                .sum::<usize>() + notif_chunk_requests.iter()
                .map(|req| req.num_buckets as usize)
                .sum::<usize>();
            crate::logging::BytesMetric::new("s1_notif_write_bandwidth", total_ntfication_bytes).log();
        }

        // Stream notification chunks directly from this client
        let (tx2, rx2) = tokio::sync::mpsc::channel(64);
        let stream2 = tokio_stream::wrappers::ReceiverStream::new(rx2);
        tokio::spawn(async move {
            for req in notif_chunk_requests.into_iter() {
                if let Err(_) = tx2.send(req).await {
                    break;
                }
            }
            drop(tx2);
        });
        let notif_write_start = std::time::Instant::now();
        let _ = client
            .notif_chunk_stream(Request::new(stream2))
            .await
            .map_err(|e| MycoError::NetworkError(e.to_string()))?;
        println!("Notification chunk write completed in {:?}", notif_write_start.elapsed());

        // Send the PRF key as a separate request.
        let add_prf_req = AddPrfKeyRequest {
            prf_key: Some(prf_key.clone().into()),
            expected_buckets: 0,
        };
        let _ = client
            .add_prf_key(Request::new(add_prf_req))
            .await
            .map_err(|e| MycoError::NetworkError(e.to_string()))?;

        Ok(())
    }

    async fn remote_get_prf_keys(&self) -> Result<Vec<crate::dtypes::Key<TreeMycoKey>>> {
        let mut client = self.client.clone();
        let request = Request::new(GetPrfKeysRequest { num_clients:1 });

        #[cfg(feature = "bandwidth")]
        {
            let request_size = request.get_ref().encoded_len();
            crate::logging::BytesMetric::new("client_get_prf_keys_request_bandwidth", request_size).log();
        }

        let response = client
            .get_prf_keys(request)
            .await
            .map_err(|e| MycoError::NetworkError(e.to_string()))?
            .into_inner();

        #[cfg(feature = "bandwidth")]
        {
            let response_size = response.encoded_len();
            crate::logging::BytesMetric::new("client_get_prf_keys_response_bandwidth", response_size).log();
        }

        Ok(response.keys.into_iter().map(|k| k.into()).collect())
    }

    /// Read notifications from Server2
    pub async fn remote_read_notifs(
        &self,
        ls: HashMap<u64, Vec<Index>>,
    ) -> Result<HashMap<u64, Vec<crate::dtypes::Bucket>>> {
        let mut client = self.client.clone();
        // Convert the HashMap to a suitable request format
        let request = ReadNotifsRequest {
            notifications: ls.into_iter().map(|(epoch, indices)| {
                (epoch, myco::read_notifs_request::Indices { 
                    index: indices.into_iter().map(|index| index.into()).collect::<Vec<_>>()
                })
            }).collect(),
        };

        #[cfg(feature = "bandwidth")]
        {
            let request_size = request.encoded_len();
            crate::logging::BytesMetric::new("client_read_notifs_request_bandwidth", request_size).log();
        }

        // Send the request and await the response
        let response = client
            .read_notifs(Request::new(request))
            .await
            .map_err(|e| MycoError::NetworkError(e.to_string()))?
            .into_inner();

        #[cfg(feature = "bandwidth")]
        {
            let response_size = response.encoded_len();
            crate::logging::BytesMetric::new("client_read_notifs_response_bandwidth", response_size).log();
        }

        // Convert the response into the expected HashMap format using parallel processing
        let epoch_buckets: HashMap<u64, Vec<crate::dtypes::Bucket>> = response.epoch_buckets
            .into_iter()
            .collect::<Vec<_>>()  
            .into_par_iter() 
            .map(|(epoch, buckets)| {
                let converted_buckets = buckets.bucket
                    .into_par_iter()  
                    .map(|b| b.into())
                    .collect();
                (epoch, converted_buckets)
            })
            .collect();  
        Ok(epoch_buckets)
    }
}

#[async_trait]
impl Server2Access for RemoteServer2Access {

    async fn write(
        &self,
        pathset: &SparseBinaryTree<crate::dtypes::Bucket>,
        notif_table: &Vec<crate::dtypes::Bucket>,
        prf_key: &crate::dtypes::Key<TreeMycoKey>,
    ) -> Result<()> {
        self.remote_write(pathset.clone(), notif_table.clone(), prf_key.clone()).await
    }

    async fn write_epoch(
        &self,
        epoch_write: Arc<EpochWrite>,
        prf_key: &crate::dtypes::Key<TreeMycoKey>,
    ) -> Result<()> {
        stream_epoch(std::slice::from_ref(&self.client), epoch_write, "s1_write_bandwidth", "s1_notif_write_bandwidth").await?;

        let mut client = self.client.clone();
        let add_prf_req = AddPrfKeyRequest {
            prf_key: Some(prf_key.clone().into()),
            expected_buckets: 0,
        };
        let _ = client
            .add_prf_key(Request::new(add_prf_req))
            .await
            .map_err(|e| MycoError::NetworkError(e.to_string()))?;
        Ok(())
    }

    async fn get_prf_keys(&self) -> Result<Vec<crate::dtypes::Key<TreeMycoKey>>> {
        self.remote_get_prf_keys().await
    }

    async fn read_notifs(
        &self,
        ls: HashMap<u64, Vec<Index>>,
    ) -> Result<HashMap<u64, Vec<crate::dtypes::Bucket>>> {
        self.remote_read_notifs(ls).await
    }

    async fn read(&self, l: Vec<u8>) -> Result<Vec<crate::dtypes::Bucket>> {
        let mut client = self.client.clone();
        let request = ReadRequest { index: l };
        
        #[cfg(feature = "bandwidth")]
        {
            let request_size = request.encoded_len();
            crate::logging::BytesMetric::new("client_read_request_bandwidth", request_size).log();
        }
        
        let response = client.read(Request::new(request))
            .await
            .map_err(|e| MycoError::NetworkError(e.to_string()))?
            .into_inner();
            
        #[cfg(feature = "bandwidth")]
        {
            let response_size = response.encoded_len();
            crate::logging::BytesMetric::new("client_read_response_bandwidth", response_size).log();
        }
        
        Ok(response.buckets.into_iter().map(|b| b.into()).collect())
    }

    async fn get_mega_client_writes(&self) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<crate::dtypes::Key<TreeMycoKey>>, Vec<Vec<u8>>)> {
        unimplemented!("get_mega_client_writes is not implemented for remote access")
    }

    async fn chunk_process_read(&self, _notification_indices: Vec<Vec<u8>>, _read_indices: Vec<Vec<u8>>) 
        -> Result<(Vec<crate::dtypes::Bucket>, Vec<crate::dtypes::Bucket>, u32)> {
        unimplemented!("chunk_process_read is not implemented for remote access")
    }

    async fn process_read_indices(&self, _read_indices: Vec<Vec<u8>>) 
        -> Result<()> {
        unimplemented!("process_read_indices is not implemented for remote access")
    }

    async fn process_notification_indices(&self, _notification_indices: Vec<Vec<u8>>) 
        -> Result<()> {
        unimplemented!("process_notification_indices is not implemented for remote access")
    }

    async fn get_all_client_prf_keys(&self, _num_clients: usize) 
        -> Result<()> {
        unimplemented!("get_all_client_prf_keys is not implemented for remote access")
    }
    
    async fn pre_generate_test_data(&self) -> Result<bool> {
        unimplemented!("pre_generate_test_data is not implemented for remote access")
    }
}