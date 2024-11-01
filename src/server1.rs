use crate::client::Client;
use crate::network::{Command, LocalServer1Access, LocalServer2Access, RemoteServer2Access, Server2Access};
use crate::tls_server::TlsServer;
use crate::tree::SparseBinaryTree;
use crate::{
    constants::*, decrypt, encrypt, prf, server2::Server2, tree::BinaryTree, Block, Bucket,
    EncryptionType, Key, Metadata, OramError, Path,
};
use bincode::{deserialize, serialize};
use dashmap::DashMap;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use crate::logging::{LatencyMetric, BytesMetric, initialize_logging};

pub struct Server1 {
    pub epoch: u64,
    pub k_s1_t: Key,
    pub num_clients: usize,
    pub s2: Box<dyn Server2Access>,
    pub p: SparseBinaryTree<Bucket>,
    pub pt: SparseBinaryTree<Bucket>,
    pub metadata_pt: SparseBinaryTree<Metadata>,
    pub metadata: BinaryTree<Metadata>,
    pub pathset_indices: Vec<usize>,
    pub message_queue: DashMap<usize, Vec<(Vec<u8>, Key, u64, Path)>>,
}

impl Server1 {
    pub fn new(s2: Box<dyn Server2Access>) -> Self {
        Self {
            epoch: 0,
            k_s1_t: Key::new(vec![]),
            num_clients: 0,
            s2,
            p: SparseBinaryTree::new(),
            pt: SparseBinaryTree::new(),
            metadata_pt: SparseBinaryTree::new(),
            metadata: BinaryTree::new_with_depth(D),
            pathset_indices: vec![],
            message_queue: DashMap::new(),
        }
    }

    pub fn batch_init(&mut self, num_clients: usize) {
        let mut rng = ChaCha20Rng::from_entropy();

        let paths = (0..(NU * num_clients))
            .map(|_| Path::random(&mut rng))
            .collect::<Vec<Path>>();
        self.pathset_indices = self.get_path_indices(paths);

        let buckets: Vec<Bucket> = self.s2.read_paths(self.pathset_indices.clone()).unwrap();
        let bucket_size = buckets.len();
        self.p = SparseBinaryTree::new_with_data(buckets, self.pathset_indices.clone());
        self.pt = SparseBinaryTree::new_with_data(
            vec![Bucket::default(); bucket_size],
            self.pathset_indices.clone(),
        );
        self.metadata_pt = SparseBinaryTree::new_with_data(
            vec![Metadata::default(); bucket_size],
            self.pathset_indices.clone(),
        );

        self.num_clients = num_clients;
        self.k_s1_t = Key::random(&mut rng);
        println!("Server1: Initialized batch for epoch {}/{}", self.epoch + 1, DELTA);
    }

    /// Queues an individual write. Must be finalized with finalize_batch_write. Every time you finalize
    /// an epoch, each queued write is written to pt and metadata_pt.
    pub fn queue_write(
        &mut self,
        ct: Vec<u8>,
        f: Vec<u8>,
        k_oram_t: Key,
        cs: Vec<u8>,
    ) -> Result<(), OramError> {
        let t_exp = if self.epoch < DB_SIZE as u64 {
            DB_SIZE as u64 
        } else {
            self.epoch + DELTA as u64
        };
        let l: Vec<u8> = prf(&self.k_s1_t.0, &[&f[..], &cs[..]].concat()).expect("PRF failed");
        let intended_message_path = Path::from(l);
        let (lca_idx, _) = self
            .pt
            .lca_idx(&intended_message_path)
            .ok_or(OramError::LcaNotFound)?;

        // Queue the write.
        self.message_queue.entry(lca_idx).or_default().push((
            ct,
            k_oram_t,
            t_exp,
            intended_message_path,
        ));

        Ok(())
    }

    pub fn batch_write(&mut self) -> Result<(), OramError> {
        #[cfg(feature = "perf-logging")]
        let total_latency = LatencyMetric::new("batch_write_total");

        // Log the size of data being processed
        #[cfg(feature = "perf-logging")]
        BytesMetric::new(
            "batch_write_data_size", 
            self.p.packed_buckets.len() * std::mem::size_of::<Bucket>()
        ).log();

        // Measure just the bucket processing time
        #[cfg(feature = "perf-logging")]
        let bucket_latency = LatencyMetric::new("bucket_processing");

        let mut rng = ChaCha20Rng::from_entropy();
        let seed: [u8; 32] = rng.gen();

        // Measure processing of buckets and metadata
        let bucket_processing_start = Instant::now();
        self.p
            .zip_with_binary_tree(&self.metadata)
            .par_iter()
            .for_each(|(bucket, metadata_bucket, _)| {
                if let (Some(bucket), Some(metadata_bucket)) = (bucket, metadata_bucket) {
                    (0..bucket.len()).for_each(|b| {
                        if let Some(metadata_block) = metadata_bucket.get(b) {
                            let (l, k_oram_t, t_exp) = metadata_block;
                            if self.epoch < *t_exp {
                                let c_msg = bucket.get(b).unwrap();
                                // Decrypt to get the first layer of decryption (client).
                                let ct = decrypt(&k_oram_t.0, &c_msg.0).unwrap();
                                let (lca_idx, _) = self.pt.lca_idx(&l).unwrap();
                                self.message_queue.entry(lca_idx).or_default().push((
                                    ct,
                                    k_oram_t.clone(),
                                    *t_exp,
                                    l.clone(),
                                ));
                            }
                        }
                    });
                }
            });

        // This enumerated index doesn't match the index inside of the message queue.
        self.pt
            .zip_mut(&mut self.metadata_pt)
            .par_iter_mut()
            .enumerate()
            .for_each(|(idx, (bucket, metadata_bucket, bucket_path))| {
                // Get the original index in the p and metadata tree from the index in pt.
                let original_idx = self.pathset_indices[idx];

                // Insert both the new and non-expired messages into the pt and metadata_pt.
                if let Some(blocks) = self.message_queue.get(&original_idx) {
                    for (ct, k_oram_t, t_exp, intended_message_path) in blocks.iter() {
                        let c_msg = encrypt(&k_oram_t.0, &ct, EncryptionType::DoubleEncrypt)
                            .map_err(|_| OramError::EncryptionFailed)
                            .unwrap();

                        // Insert the message into the pt bucket.
                        if let Some(bucket) = bucket.as_mut() {
                            bucket.push(Block::new(c_msg));
                        }

                        // Insert the metadata into the metadata_pt bucket.
                        if let Some(metadata_bucket) = metadata_bucket.as_mut() {
                            metadata_bucket.push(
                                intended_message_path.clone(),
                                k_oram_t.clone(),
                                *t_exp,
                            );
                        }
                    }
                }

                // Insert blocks into the pt bucket and metadata_pt bucket.
                if let Some(bucket) = bucket {
                    #[cfg(feature = "no-enc")]
                    {
                        // Just push the block, no padding or shuffling needed
                    }

                    #[cfg(not(feature = "no-enc"))]
                    {
                        let mut rng = ChaCha20Rng::from_seed(seed);
                        // Add random padding blocks
                        (bucket.len()..Z).for_each(|_| {
                            bucket.push(Block::new_random());
                        });

                        bucket.shuffle(&mut rng);
                    }
                    assert!(
                        bucket.len() <= Z,
                        "Bucket length exceeds Z in epoch {}: bucket length={}, expected<={}",
                        self.epoch,
                        bucket.len(),
                        Z
                    );
                }
                if let Some(metadata_bucket) = metadata_bucket {
                    #[cfg(feature = "no-enc")]
                    {
                        // Just push the metadata, no padding or shuffling needed
                    }

                    #[cfg(not(feature = "no-enc"))]
                    {
                        let mut rng = ChaCha20Rng::from_seed(seed);
                        // Add random padding metadata
                        (metadata_bucket.len()..Z).for_each(|_| {
                            metadata_bucket.push(bucket_path.clone(), Key::new(vec![]), 0);
                        });

                        metadata_bucket.shuffle(&mut rng);
                    }
                    assert!(
                        metadata_bucket.len() <= Z,
                        "Metadata bucket length exceeds Z: bucket length={}, expected<={}",
                        metadata_bucket.len(),
                        Z
                    );
                }
            });
        let bucket_processing_duration = bucket_processing_start.elapsed();

        #[cfg(feature = "perf-logging")]
        bucket_latency.finish();

        // Reset the message queue
        self.message_queue.clear();

        // Measure metadata overwrite time
        self.metadata.overwrite_from_sparse(&self.metadata_pt);


        println!("Server1: Writing to Server2");
        let write_result = self.s2.write(self.pt.packed_buckets.clone(), self.k_s1_t.clone());
        let result = match write_result {
            Ok(_) => {
                println!("Server1: Successfully wrote to Server2");
                self.epoch += 1;

                #[cfg(feature = "perf-logging")]
                total_latency.finish();
                Ok(())
            },
            Err(e) => {
                println!("Server1: Error writing to Server2: {:?}", e);
                Err(e)
            }
        };

        result
    }

    pub fn get_path_indices(&self, paths: Vec<Path>) -> Vec<usize> {
        let mut pathset: HashSet<usize> = HashSet::new();
        pathset.insert(1);
        paths.iter().for_each(|p| {
            p.clone().into_iter().fold(1, |acc, d| {
                let idx = 2 * acc + u8::from(d) as usize;
                pathset.insert(idx);
                idx
            });
        });
        pathset.into_iter().collect()
    }

    pub async fn run_server(addr: &str, cert_path: &str, key_path: &str) -> Result<(), OramError> {
        let server = TlsServer::new(addr, cert_path, key_path, "Server1".to_string()).await?;
        
        // Create a dedicated Server2 connection for Server1
        let server2_connection = RemoteServer2Access::connect("localhost:8444", cert_path).await?;
        let server1 = Arc::new(Mutex::new(Server1::new(Box::new(server2_connection))));
        // Initialize with a default number of clients (e.g., 1)
        {
            let mut server1_guard = server1.lock().unwrap();
            server1_guard.batch_init(1);
        }

        server.run(move |command| {

            let command: Command = deserialize(command).map_err(|_| OramError::DeserializationError)?;
            let mut server1_guard = server1.lock().unwrap();

            match command {
                Command::Server1Write(ct, f, k_oram_t, cs) => {
                    server1_guard.queue_write(ct, f, k_oram_t, cs)?;
                            
                    // Spawn a background task to handle batch write
                    let server1_clone = server1.clone();
                    tokio::spawn(async move {
                        let queue_size = server1_clone.lock().unwrap().message_queue.len();
                        if queue_size >= 1 {
                            if let Err(e) = server1_clone.lock().unwrap().batch_write() {
                                eprintln!("Error in batch_write: {:?}", e);
                            }
                    }
                    });
                    let response = serialize(&Command::Success).unwrap();


                    Ok(response)
                }
                _ => Err(OramError::InvalidCommand),
            }   
        }).await;

        Ok(())
    }

    pub async fn run_server_with_simulation<F>(
        addr: &str,
        cert_path: &str,
        key_path: &str,
        simulation_key: Key,
        progress_callback: F,
    ) -> Result<(), OramError>
    where
        F: Fn(usize) + Send + Sync + 'static,
    {
        #[cfg(feature = "perf-logging")]
        initialize_logging("server1_latency.csv", "server1_bytes.csv");

        // Initial setup
        let server2_connection = RemoteServer2Access::connect("localhost:8444", cert_path).await?;
        let server1 = Arc::new(Mutex::new(Self::new(Box::new(server2_connection))));
        
        // Create channel for batch_init completion signal
        let (init_tx, init_rx) = tokio::sync::mpsc::channel(1);
        let (batch_tx, mut batch_rx) = tokio::sync::mpsc::channel(1);
        
        // Create simulation clients once at the start
        println!("Creating {} simulation clients...", NUM_CLIENTS);
        let mut simulation_clients = Vec::new();
        for i in 0..NUM_CLIENTS {
            let client_name = format!("SimClient_{}", i);
            let s2_access = Box::new(LocalServer2Access { 
                server: Arc::new(Mutex::new(Server2::new()))
            });
            let s1_access = Box::new(LocalServer1Access { server: server1.clone() });
            let mut client = Client::new(client_name, s1_access, s2_access);
            client.setup(&simulation_key)?;
            simulation_clients.push(client);
        }

        println!("Starting simulation...");

        // Create a future that will complete when we want to shut down
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        
        // Spawn tasks without immediately aborting them
        let init_handle = tokio::spawn({
            let server1 = server1.clone();
            let init_tx = init_tx.clone(); // Clone for init_handle
            async move {
                loop {
                    let should_init = {
                        let server = server1.lock().unwrap();
                        // Check if we need to initialize a new batch
                        server.message_queue.is_empty() && server.epoch < DELTA as u64
                    };

                    if should_init {
                        println!("Server1: Starting new epoch {}/{}", server1.lock().unwrap().epoch + 1, DELTA);
                        {
                            let mut server = server1.lock().unwrap();
                            server.batch_init(NUM_CLIENTS);
                        }
                        println!("Server1: batch_init complete, signaling for client writes");
                        
                        if init_tx.send(()).await.is_err() {
                            println!("Server1: Failed to signal batch_init completion");
                            break;
                        }
                    }

                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        });

        let write_handle = tokio::spawn({
            let server1 = server1.clone();
            let init_tx = init_tx.clone(); // Clone for write_handle
            async move {
                while let Some(()) = batch_rx.recv().await {
                    println!("Server1: Received batch write signal");
                    
                    let result = tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        async {
                            let mut server = server1.lock().unwrap();
                            println!("Server1: Preparing batch write...");
                            let buckets = server.pt.packed_buckets.clone();
                            let key = server.k_s1_t.clone();
                            drop(server);
                            
                            let write_result = server1.lock().unwrap().s2.write(buckets, key);
                            
                            if let Ok(_) = write_result {
                                let mut server = server1.lock().unwrap();
                                server.epoch += 1;
                                println!("Server1: Successfully incremented epoch to {}", server.epoch);
                            }
                            
                            write_result
                        }
                    ).await;
                    
                    match result {
                        Ok(Ok(_)) => {
                            println!("Server1: Successfully completed batch write");
                            // Signal for next batch_init
                            if let Err(e) = init_tx.send(()).await {
                                eprintln!("Failed to signal next batch_init: {:?}", e);
                            }
                        },
                        Ok(Err(e)) => eprintln!("Server1: Error in batch_write: {:?}", e),
                        Err(_) => eprintln!("Server1: Timeout writing to Server2"),
                    }
                }
            }
        });

        let clients_handle = tokio::spawn({
            let batch_tx = batch_tx;
            async move {
                let mut init_rx = init_rx;
                while let Some(()) = init_rx.recv().await {
                    println!("Starting writes for {} clients...", NUM_CLIENTS);
                    let mut clients = simulation_clients.iter_mut();
                    for (i, client) in clients.enumerate() {
                        let message = vec![1u8; 16];
                        if let Err(e) = client.write(&message, &simulation_key) {
                            eprintln!("Error in client write: {:?}", e);
                        }
                    }
                    // Signal batch write after all clients have written
                    if batch_tx.send(()).await.is_err() {
                        eprintln!("Failed to signal batch write");
                    }
                    println!("Completed all client writes for this batch");
                    progress_callback(server1.lock().unwrap().epoch as usize);
                }
                println!("Client handler ending...");
            }
        });

        // Wait for shutdown signal
        let _ = shutdown_rx.await;

        // Clean up gracefully
        init_handle.abort();
        write_handle.abort();
        clients_handle.abort();

        // Wait for all handles to complete
        let _ = tokio::try_join!(init_handle, write_handle, clients_handle);

        Ok(())
    }
}