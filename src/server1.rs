use crate::client::Client;
use crate::get_path_indices;
use crate::logging::{BytesMetric, LatencyMetric};
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
        let end_to_end_latency = LatencyMetric::new("server1_batch_init_end_to_end");
        let mut local_latency = LatencyMetric::new("server1_batch_init_local");
        let mut rng = ChaCha20Rng::from_entropy();

        let paths = (0..(NU * num_clients))
            .map(|_| Path::random(&mut rng))
            .collect::<Vec<Path>>();
        self.pathset_indices = get_path_indices(paths);

        local_latency.pause();
        let buckets: Vec<Bucket> = self
            .s2
            .read_paths(self.pathset_indices.clone())
            .await
            .unwrap();
        local_latency.resume();
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
        end_to_end_latency.finish();
        local_latency.finish();
    }

    pub fn batch_init(&mut self, num_clients: usize) {
        let mut rng = ChaCha20Rng::from_entropy();

        let paths = (0..(NU * num_clients))
            .map(|_| Path::random(&mut rng))
            .collect::<Vec<Path>>();
        self.pathset_indices = get_path_indices(paths);

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
        let mut rng = ChaCha20Rng::from_entropy();
        let seed: [u8; 32] = rng.gen();

        // Measure processing of buckets and metadata
        let bucket_processing_start = Instant::now();
        self.p
            .zip_with_binary_tree(&self.metadata)
            .par_iter()
            .for_each(|(bucket, metadata_bucket, _)| {
                if let (Some(bucket), Some(metadata_bucket)) = (bucket, metadata_bucket) {
                    let mut real_decrypt_count = 0;
                    (0..bucket.len()).for_each(|b| {
                        if let Some(metadata_block) = metadata_bucket.get(b) {
                            let (l, k_oram_t, t_exp) = metadata_block;
                            if self.epoch < *t_exp {
                                let c_msg = bucket.get(b).unwrap();
                                // Real decryption
                                let ct = decrypt(&k_oram_t.0, &c_msg.0).unwrap();
                                let (lca_idx, _) = self.pt.lca_idx(&l).unwrap();
                                self.message_queue.entry(lca_idx).or_default().push((
                                    ct,
                                    k_oram_t.clone(),
                                    *t_exp,
                                    l.clone(),
                                ));
                                real_decrypt_count += 1;
                            }
                        }
                    });

                    // Perform fake decryptions
                    let fake_decrypt_count = Z - real_decrypt_count;
                    for _ in 0..fake_decrypt_count {
                        // Fake decryption
                        let _ = decrypt(&[0u8; 32], &[0u8; BLOCK_SIZE]).unwrap_or_default();
                    }
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
                let mut real_encrypt_count = 0;
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
                        real_encrypt_count += 1;
                    }
                }

                // Perform fake encryptions
                let fake_encrypt_count = Z - real_encrypt_count;
                for _ in 0..fake_encrypt_count {
                    // Fake encryption
                    let _ = encrypt(&[0u8; 32], &[0u8; BLOCK_SIZE], EncryptionType::DoubleEncrypt)
                        .unwrap_or_default();
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
                self.epoch += 1;
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
        let end_to_end_latency = LatencyMetric::new("server1_batch_write_end_to_end");  
        let mut local_latency = LatencyMetric::new("server1_batch_write_local");
        let mut rng = ChaCha20Rng::from_entropy();
        let seed: [u8; 32] = rng.gen();

        // Measure processing of buckets and metadata
        let queue_old_buckets_latency: LatencyMetric = LatencyMetric::new("server1_batch_write_queue_old_buckets");
        self.p
            .zip_with_binary_tree(&self.metadata)
            .par_iter()
            .for_each(|(bucket, metadata_bucket, _)| {
                if let (Some(bucket), Some(metadata_bucket)) = (bucket, metadata_bucket) {
                    let mut real_decrypt_count = 0;
                    (0..bucket.len()).for_each(|b| {
                        if let Some(metadata_block) = metadata_bucket.get(b) {
                            let (l, k_oram_t, t_exp) = metadata_block;
                            if self.epoch < *t_exp {
                                let c_msg = bucket.get(b).unwrap();
                                // Real decryption
                                let ct = decrypt(&k_oram_t.0, &c_msg.0).unwrap();
                                let (lca_idx, _) = self.pt.lca_idx(&l).unwrap();
                                self.message_queue.entry(lca_idx).or_default().push((
                                    ct,
                                    k_oram_t.clone(),
                                    *t_exp,
                                    l.clone(),
                                ));
                                real_decrypt_count += 1;
                            }
                        }
                    });

                    // Perform fake decryptions to prevent timing attacks
                    #[cfg(not(feature = "no-enc"))]
                    {
                        let fake_decrypt_count = Z - real_decrypt_count;
                        for _ in 0..fake_decrypt_count {
                        // Fake decryption
                            let _ = decrypt(&[0u8; 32], &[0u8; BLOCK_SIZE]).unwrap_or_default();
                        }
                    }
                }
            });
        queue_old_buckets_latency.finish();

        // This enumerated index doesn't match the index inside of the message queue.
        let process_queued_buckets_latency = LatencyMetric::new("server1_batch_write_process_queued_buckets");
        self.pt
            .zip_mut(&mut self.metadata_pt)
            .par_iter_mut()
            .enumerate()
            .for_each(|(idx, (bucket, metadata_bucket, bucket_path))| {
                // Get the original index in the p and metadata tree from the index in pt.
                let original_idx = self.pathset_indices[idx];

                // Insert both the new and non-expired messages into the pt and metadata_pt.
                let mut real_encrypt_count = 0;
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
                        real_encrypt_count += 1;
                    }
                }

                // Perform fake encryptions to prevent timing attacks
                #[cfg(not(feature = "no-enc"))]
                {
                    let fake_encrypt_count = Z - real_encrypt_count;
                    for _ in 0..fake_encrypt_count {
                    // Fake encryption
                    let _ = encrypt(&[0u8; 32], &[0u8; BLOCK_SIZE], EncryptionType::DoubleEncrypt)
                        .unwrap_or_default();
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
                }
            });
        process_queued_buckets_latency.finish();

        // Reset the message queue
        self.message_queue.clear();

        // Measure metadata overwrite time
        let metadata_overwrite_latency = LatencyMetric::new("server1_batch_write_metadata_overwrite");
        self.metadata.overwrite_from_sparse(&self.metadata_pt);
        metadata_overwrite_latency.finish();

        local_latency.finish();

        let write_to_server2_latency = LatencyMetric::new("server1_batch_write_write_to_server2");
        let write_result = self
            .s2
            .write(self.pt.packed_buckets.clone(), self.k_s1_t.clone())
            .await;
        let result = match write_result {
            Ok(_) => {
                println!("Server1: Successfully wrote to Server2");
                self.epoch += 1;
                end_to_end_latency.finish();
                write_to_server2_latency.finish();
                Ok(())
            }
            Err(e) => {
                println!("Server1: Error writing to Server2: {:?}", e);
                Err(e)
            }
        };

        result.map_err(|_| OramError::NoMessageFound)
    }
}
