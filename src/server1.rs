use crate::client::Client;
use crate::logging::{initialize_logging, BytesMetric, LatencyMetric};
use crate::network::{
    Command, LocalServer1Access, LocalServer2Access, RemoteServer2Access, Server2Access,
};
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
use tokio::sync::Mutex as TokioMutex;

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

    pub async fn async_batch_init(&mut self, num_clients: usize) {
        let mut rng = ChaCha20Rng::from_entropy();

        let paths = (0..(NU * num_clients))
            .map(|_| Path::random(&mut rng))
            .collect::<Vec<Path>>();
        self.pathset_indices = self.get_path_indices(paths);

        println!("Server1: Reading paths from Server2");
        let buckets: Vec<Bucket> = self
            .s2
            .read_paths(self.pathset_indices.clone())
            .await
            .unwrap();
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
        println!(
            "Server1: Initialized batch for epoch {}/{}",
            self.epoch + 1,
            DELTA
        );
    }

    pub fn batch_init(&mut self, num_clients: usize) {
        let mut rng = ChaCha20Rng::from_entropy();

        let paths = (0..(NU * num_clients))
            .map(|_| Path::random(&mut rng))
            .collect::<Vec<Path>>();
        self.pathset_indices = self.get_path_indices(paths);

        let buckets: Vec<Bucket> =
            futures::executor::block_on(self.s2.read_paths(self.pathset_indices.clone())).unwrap();
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
        println!(
            "Server1: Initialized batch for epoch {}/{}",
            self.epoch + 1,
            DELTA
        );
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
            self.p.packed_buckets.len() * std::mem::size_of::<Bucket>(),
        )
        .log();

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
        let write_result = futures::executor::block_on(
            self.s2
                .write(self.pt.packed_buckets.clone(), self.k_s1_t.clone()),
        );
        let result = match write_result {
            Ok(_) => {
                println!("Server1: Successfully wrote to Server2");
                self.epoch += 1;

                #[cfg(feature = "perf-logging")]
                total_latency.finish();
                Ok(())
            }
            Err(e) => {
                println!("Server1: Error writing to Server2: {:?}", e);
                Err(e)
            }
        };

        result.map_err(|_| OramError::NoMessageFound)
    }

    pub async fn async_batch_write(&mut self) -> Result<(), OramError> {
        #[cfg(feature = "perf-logging")]
        let total_latency = LatencyMetric::new("batch_write_total");

        // Log the size of data being processed
        #[cfg(feature = "perf-logging")]
        BytesMetric::new(
            "batch_write_data_size",
            self.p.packed_buckets.len() * std::mem::size_of::<Bucket>(),
        )
        .log();

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
        let write_result = self
            .s2
            .write(self.pt.packed_buckets.clone(), self.k_s1_t.clone())
            .await;
        let result = match write_result {
            Ok(_) => {
                println!("Server1: Successfully wrote to Server2");
                self.epoch += 1;

                #[cfg(feature = "perf-logging")]
                total_latency.finish();
                Ok(())
            }
            Err(e) => {
                println!("Server1: Error writing to Server2: {:?}", e);
                Err(e)
            }
        };

        result.map_err(|_| OramError::NoMessageFound)
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
}
