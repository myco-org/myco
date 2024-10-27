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
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use std::collections::{HashMap, HashSet};

pub struct Server1 {
    pub epoch: u64,
    pub k_s1_t: Key,
    pub num_clients: usize,
    pub s2: Arc<RwLock<Server2>>,
    pub p: SparseBinaryTree<Bucket>,
    pub pt: SparseBinaryTree<Bucket>,
    pub metadata_pt: SparseBinaryTree<Metadata>,
    pub metadata: BinaryTree<Metadata>,
    pub pathset_indices: Vec<usize>,
}

impl Local for Server1 {
    fn send(&self, command: &[u8]) -> Result<Vec<u8>, OramError> {
        match deserialize::<Command>(command).unwrap() {
            Command::Server2Write(write_type) => {
                if let WriteType::SavePathset(pathset) = write_type {
                    return self.s2.write().unwrap().save_pathset(pathset)
                } else {
                    match write_type {
                        WriteType::Write(buckets) =>  self.s2.write().unwrap().write(buckets),
                        WriteType::AddPrfKey(key) => self.s2.write().unwrap().add_prf_key(&key),
                        _ => (),
                    }
                    Ok(vec![])
                }
            }
            Command::Server2Read(read_type) => {
                match read_type {
                    ReadType::Read(path) => self.s2.read().unwrap().read(&path),
                    ReadType::GetPrfKeys => self.s2.read().unwrap().get_prf_keys(),
                }
            }
            Command::Server1Write(_, _, _, _) => Err(OramError::InvalidCommand),
        }
    }
}

impl Server1 {
    pub fn new(s2: Arc<RwLock<Server2>>) -> Self {
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
        }
    }

    pub fn batch_init(&mut self, num_clients: usize) {
        println!("=== Starting Epoch {:?} ===", self.epoch);

        let mut rng = ChaCha20Rng::from_entropy();
        
        // These are fast operations, so there's no need to parallelize them.
        let pathset = (0..(NU * num_clients))
            .map(|_| Path::random(&mut rng))
            .collect::<Vec<Path>>();
        self.pathset_indices = self.get_path_indices(pathset);

        let bytes = self.send(&serialize(&Command::Server2Write(WriteType::SavePathset(self.pathset_indices.clone()))).unwrap()).unwrap();
        let buckets: Vec<Bucket> = deserialize(&bytes).map_err(|_| OramError::SerializationFailed).unwrap();
        
        let bucket_size = buckets.len();
        
        // Initialize each of these objects in parallel using rayon::join. These trees are initializing a lot of data.
        // Specifically, they use BLOCK_SIZE * Z * len(pathset_indices) bytes of memory.
        let (p, (pt, metadata_pt)) = rayon::join(
            || SparseBinaryTree::new_with_data(&buckets, &self.pathset_indices),
            || rayon::join(
                || SparseBinaryTree::new_with_data(&vec![Bucket::default(); bucket_size], &self.pathset_indices),
                || SparseBinaryTree::new_with_data(
                    &vec![Metadata::default(); bucket_size],
                    &self.pathset_indices,
                )
            )
        );
        self.p = p;
        self.pt = pt;
        self.metadata_pt = metadata_pt;

        self.num_clients = num_clients;
        self.k_s1_t = Key::random(&mut rng);
    }

    pub fn write(
        &mut self,
        ct: Vec<u8>,
        f: Vec<u8>,
        k_oram_t: Key,
        cs: Vec<u8>,
    ) -> Result<(), OramError> {
        let t_exp = self.epoch + DELTA as u64;
        let l: Vec<u8> = prf(&self.k_s1_t.0, &[&f[..], &cs[..]].concat());
        let l_path = Path::from(l);
        // TODO: This should queue the message instead of inserting it immediately.
        self.insert_message(&ct, &l_path, &k_oram_t, t_exp)
    }

    pub fn insert_message(
        &mut self,
        ct: &Vec<u8>,
        l: &Path,
        k_oram_t: &Key,
        t_exp: u64,
    ) -> Result<(), OramError> {
        let c_msg = encrypt(&k_oram_t.0, &ct, EncryptionType::DoubleEncrypt)
            .map_err(|_| OramError::EncryptionFailed)?;

        let (bucket, path) = self.pt.lca(&l).ok_or(OramError::LcaNotFound)?;
        let mut metadata_bucket = self
            .metadata_pt
            .get(&path)
            .ok_or(OramError::MetadataBucketNotFound)?
            .clone();

        bucket.push(Block::new(c_msg));
        metadata_bucket.push(l.clone(), k_oram_t.clone(), t_exp);
        self.metadata_pt.write(metadata_bucket, path);
        Ok(())
    }

    pub fn batch_write(&mut self) -> Result<(), OramError> {
        let mut rng = ChaCha20Rng::from_entropy();
        let seed: [u8; 32] = rng.gen();

        // Measure processing of buckets and metadata
        let bucket_processing_start = Instant::now();

        let mut message_queue: DashMap<usize, Vec<(Block, Key, u64)>> = DashMap::new();
        self.p.zip_with_binary_tree(&self.metadata).par_iter().for_each(|(bucket, metadata_bucket, path)| {
            if let Some(bucket) = bucket {
                (0..bucket.len()).for_each(|b| {
                    if let Some(metadata_bucket) = metadata_bucket {
                        if let Some(metadata) = metadata_bucket.get(b) {     
                            let (l, k_oram_t, t_exp) = metadata;
                            let c_msg = bucket.get(b).ok_or(OramError::BucketIndexError(b)).unwrap();
                            let (lca_idx, _) = self.pt.lca_idx(&path).ok_or(OramError::LcaNotFound).unwrap();
                            message_queue.entry(lca_idx).or_default().push((c_msg.clone(), k_oram_t.clone(), *t_exp));
                        }
                    }
                });
            }
        });

        // This loop is for old messages that need to be moved to the new pathset.
        self.p
            .zip_with_binary_tree(&self.metadata)
            .iter()
            .try_for_each(|(bucket, metadata_bucket, _)| {
                let res = if let Some(bucket) = bucket {
                    (0..bucket.len()).try_for_each(|b| {
                        metadata_bucket
                            .as_ref()
                        .ok_or(OramError::MetadataBucketNotFound)
                        .and_then(|metadata_bucket| {
                            let (l, k_oram_t, t_exp) = metadata_bucket
                                .get(b)
                                .ok_or(OramError::MetadataIndexError(b))?;
                            if self.epoch < *t_exp {
                                let c_msg = bucket.get(b).ok_or(OramError::BucketIndexError(b))?;
                                if let Ok(ct) = decrypt(&k_oram_t.0, &c_msg.0) {
                                    self.insert_message(&ct, l, k_oram_t, *t_exp)?;
                                }
                            }
                            Ok(())
                        })
                    })
                } else {
                    Ok(())
                };
                res
            })?;
        let bucket_processing_duration = bucket_processing_start.elapsed();
        println!("Bucket processing time: {:?}", bucket_processing_duration);

        // Measure processing of pt and metadata_pt
        let pt_processing_start = Instant::now();

        // Adds dummy blocks to fill out buckets that are not filled and then reshuffles the blocks inside of a bucket.
        // Note: Using parallelism here isn't that effective because the amount of time in each loop is quite small, so Rayon introduces a lot of overhead.
        self.pt.packed_indices.iter().enumerate().for_each(|(i, _full_tree_idx)| {
            let bucket = &mut self.pt.packed_buckets[i];
            let metadata_bucket = &mut self.metadata_pt.packed_buckets[i];

            (bucket.len()..Z).for_each(|_| {
                bucket.push(Block::new_random());
            });
            (metadata_bucket.len()..Z).for_each(|_| {
                metadata_bucket.push(Path::default(), Key::new(vec![]), 0);
            });

            assert_eq!(
                bucket.len(),
                Z,
                "Bucket length is not Z in epoch {}: bucket length={}, expected={}",
                self.epoch,
                bucket.len(),
                Z
            );
            assert_eq!(metadata_bucket.len(), Z, "Metadata bucket length is not Z");

            let mut rng1 = ChaCha20Rng::from_seed(seed);
            let mut rng2 = ChaCha20Rng::from_seed(seed);
            bucket.shuffle(&mut rng1);
            metadata_bucket.shuffle(&mut rng2);
        });

        let pt_processing_duration = pt_processing_start.elapsed();
        println!(
            "PT and metadata_pt processing time: {:?}",
            pt_processing_duration
        );

        // Measure metadata overwrite time
        let metadata_overwrite_start = Instant::now();
        self.metadata.overwrite_from_sparse(&self.metadata_pt);
        let metadata_overwrite_duration = metadata_overwrite_start.elapsed();
        println!("Metadata overwrite time: {:?}", metadata_overwrite_duration);

        // Measure server lock and write time
        let server_write_start = Instant::now();
        self.send(&serialize(&Command::Server2Write(WriteType::Write(self.pt.packed_buckets.clone()))).unwrap()).unwrap();
        self.send(&serialize(&Command::Server2Write(WriteType::AddPrfKey(self.k_s1_t.clone()))).unwrap()).unwrap();
        let server_write_duration = server_write_start.elapsed();
        println!(
            "Server2 overwrite time: {:?}",
            server_write_duration
        );

        // Increment epoch
        self.epoch += 1;

        Ok(())
    }

    /// This fetches the indices of all of the nodes covered by any of the paths in the pathset.
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
