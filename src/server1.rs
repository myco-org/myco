use crate::network::{Command, Local, ReadType, WriteType};
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

pub struct Server1 {
    pub epoch: u64,
    pub k_s1_t: Key,
    pub num_clients: usize,
    pub s2: Arc<Mutex<Server2>>,
    pub p: SparseBinaryTree<Bucket>,
    pub pt: SparseBinaryTree<Bucket>,
    pub metadata_pt: SparseBinaryTree<Metadata>,
    pub metadata: BinaryTree<Metadata>,
    pub pathset_indices: Vec<usize>,
    // Each index can have multiple buckets.
    pub message_queue: DashMap<usize, Vec<(Vec<u8>, Key, u64, Path)>>,
}

#[cfg(feature = "network")]
impl Local for Server1 {
    fn send(&self, command: &[u8]) -> Result<Vec<u8>, OramError> {
        match deserialize::<Command>(command).unwrap() {
            Command::Server2Write(write_type) => {
                match write_type {
                    WriteType::Write(buckets) => self.s2.lock().unwrap().write(buckets),
                    WriteType::AddPrfKey(key) => self.s2.lock().unwrap().add_prf_key(&key),
                }
                Ok(vec![])
            }
            Command::Server2Read(read_type) => match read_type {
                ReadType::Read(path) => self.s2.lock().unwrap().read(&path).map_err(|_| OramError::SerializationFailed),
                ReadType::ReadPaths(pathset) => Ok(serialize(&self.s2.lock().unwrap().read_paths(pathset.clone())?.as_slice()).unwrap()),
                ReadType::GetPrfKeys => self.s2.lock().unwrap().get_prf_keys().map_err(|_| OramError::SerializationFailed)  ,
            },
            Command::Server1Write(_, _, _, _) => Err(OramError::InvalidCommand),
        }
    }
}

impl Server1 {
    pub fn new(s2: Arc<Mutex<Server2>>) -> Self {
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

        #[cfg(feature = "network")]
        let buckets: Vec<Bucket> = {
            let bytes = self
                .send(
                    &serialize(&Command::Server2Read(ReadType::ReadPaths(
                        self.pathset_indices.clone(),
                    )))
                    .unwrap(),
                )
                .unwrap();
            deserialize(&bytes)
                .map_err(|_| OramError::SerializationFailed)
                .unwrap()
        };

        #[cfg(not(feature = "network"))]
        let buckets: Vec<Bucket> = self
            .s2
            .lock()
            .unwrap()
            .read_paths(self.pathset_indices.clone())
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

        // Reset the message queue
        self.message_queue.clear();

        // Measure metadata overwrite time
        self.metadata.overwrite_from_sparse(&self.metadata_pt);

        #[cfg(feature = "network")]
        {
            self.send(
                &serialize(&Command::Server2Write(WriteType::Write(
                    self.pt.packed_buckets.clone(),
                )))
                .unwrap(),
            )
            .unwrap();
            self.send(
                &serialize(&Command::Server2Write(WriteType::AddPrfKey(
                    self.k_s1_t.clone(),
                )))
                .unwrap(),
            )
            .unwrap();
        }

        #[cfg(not(feature = "network"))]
        {
            self.s2.lock().unwrap().write(self.pt.packed_buckets.clone());
            self.s2.lock().unwrap().add_prf_key(&self.k_s1_t);
        }

        // Increment epoch
        self.epoch += 1;

        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_same_shuffle() {
        let seed: [u8; 32] = [0; 32];
        let mut rng1 = ChaCha20Rng::from_seed(seed);
        let mut rng2 = ChaCha20Rng::from_seed(seed);
        let mut v1 = (0..10).collect::<Vec<_>>();
        let mut v2 = v1.clone();
        v1.shuffle(&mut rng1);
        v2.shuffle(&mut rng2);
        assert_eq!(v1, v2);
    }
}
