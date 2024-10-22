use crate::{
    constants::*, decrypt, encrypt, prf, server2::Server2, tree::BinaryTree, Block, Bucket,
    EncryptionType, Key, Metadata, OramError, Path,
};
use dashmap::DashMap;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

pub struct Server1 {
    pub epoch: u64,
    pub k_s1_t: Key,
    pub num_clients: usize,
    pub s2: Arc<RwLock<Server2>>,
    /// Permanent tree that stores the data.
    pub p: BinaryTree<Bucket>,
    /// Temporary tree used to store the new data in every epoch.
    pub pt: BinaryTree<Bucket>,
    pub metadata_pt: BinaryTree<Metadata>,
    pub metadata: BinaryTree<Metadata>,
    /// LCA index to (Block, Key, t_exp). Used to write in parallel.
    /// Clear this map after each epoch.
    pub lca_idx_to_block_key_t_exp: DashMap<usize, Vec<(Block, Key, u64)>>,
}

impl Server1 {
    pub fn new(s2: Arc<RwLock<Server2>>) -> Self {
        let metadata = BinaryTree::<Metadata>::new_with_depth(D);
        Self {
            epoch: 0,
            k_s1_t: Key::new(vec![]),
            num_clients: 0,
            s2,
            p: BinaryTree::new_empty(),
            pt: BinaryTree::new_empty(),
            metadata_pt: BinaryTree::new_empty(),
            metadata,
            lca_idx_to_block_key_t_exp: DashMap::new(),
        }
    }

    pub fn batch_init(&mut self, num_clients: usize) {
        let mut rng = ChaCha20Rng::from_entropy();

        let paths = (0..(NU * num_clients))
            .map(|_| Path::random(&mut rng))
            .collect::<Vec<Path>>();

        let buckets_and_paths: Vec<(Vec<Bucket>, Path)> = paths
            .iter()
            .map(|path| {
                let bucket = self.s2.read().unwrap().read(&path);
                (bucket, path.clone())
            })
            .collect();

        let pt_data: Vec<(Vec<Bucket>, Path)> = paths
            .iter()
            .map(|path| (vec![Bucket::default(); D], path.clone()))
            .collect();

        let metadata_pt_data: Vec<(Vec<Metadata>, Path)> = paths
            .iter()
            .map(|path| (vec![Metadata::default(); D], path.clone()))
            .collect();

        self.p = BinaryTree::<Bucket>::from_vec_with_paths(buckets_and_paths.clone());
        // The same nodes exist, but they're empty for the _pt trees.
        self.pt = BinaryTree::<Bucket>::from_vec_with_paths(pt_data);
        self.metadata_pt = BinaryTree::<Metadata>::from_vec_with_paths(metadata_pt_data);

        self.num_clients = num_clients;
        self.k_s1_t = Key::random(&mut rng);
    }

    /// Queues an individual write. Must be finalized with finalize_batch_write. Every time you finalize
    /// an epoch, each queued write is written to pt and metadata_pt.
    pub fn queue_write(
        &self,
        ct: Vec<u8>,
        f: Vec<u8>,
        k_oram_t: Key,
        cs: Vec<u8>,
    ) -> Result<(), OramError> {
        let t_exp = self.epoch + DELTA;
        let l: Vec<u8> = prf(&self.k_s1_t.0, &[&f[..], &cs[..]].concat());
        let (lca_idx, _) = self.p.lca(&Path::from(l)).ok_or(OramError::LcaNotFound)?;

        // Queue the write.
        self.lca_idx_to_block_key_t_exp
            .entry(lca_idx)
            .or_default()
            .push((Block::new(ct), k_oram_t, t_exp));

        Ok(())
    }

    /// Writes a single message to pt and metadata_pt.
    pub fn write(
        &mut self,
        ct: Vec<u8>,
        f: Vec<u8>,
        k_oram_t: Key,
        cs: Vec<u8>,
    ) -> Result<(), OramError> {
        let t_exp = self.epoch + DELTA;
        let l: Vec<u8> = prf(&self.k_s1_t.0, &[&f[..], &cs[..]].concat());
        let (_, lca_path) = self.p.lca(&Path::from(l)).ok_or(OramError::LcaNotFound)?;
        self.insert_message(&ct, &lca_path, &k_oram_t, t_exp)?;

        Ok(())
    }

    pub fn insert_message(
        &mut self,
        ct: &Vec<u8>,
        lca_path: &Path,
        k_oram_t: &Key,
        t_exp: u64,
    ) -> Result<(), OramError> {
        // Encrypt the ct.
        let c_msg = encrypt(&k_oram_t.0, &ct, EncryptionType::DoubleEncrypt)
            .map_err(|_| OramError::EncryptionFailed)?;

        // Metadata bucket at the LCA.
        let metadata_bucket = self
            .metadata_pt
            .get_mut(&lca_path)
            .ok_or(OramError::MetadataBucketNotFound)?;

        // Bucket at the LCA.
        let bucket = self
            .pt
            .get_mut(&lca_path)
            .ok_or(OramError::BucketNotFound)?;

        bucket.push(Block::new(c_msg));
        metadata_bucket.push(lca_path.clone(), k_oram_t.clone(), t_exp);
        Ok(())
    }

    /// 1. Queues all of the unexpired messages in the metadata bucket for all nodes in the tree.
    /// 2. Writes all of the queued messages in self.lca_idx_to_block_key_t_exp to pt and metadata_pt.
    /// 3. Shuffle the buckets and fill them up with random blocks up to Z.
    pub fn batch_write(&mut self) -> Result<(), OramError> {
        self.queue_batch_write()?;
        self.finalize_batch_write()?;
        Ok(())
    }

    /// Queues all of the unexpired messages in the metadata bucket for all nodes in the tree.
    pub fn queue_batch_write(&mut self) -> Result<(), OramError> {
        // Goes through the metadata bucket for all unexpired messages. If it's not expired, then we add
        // it to the map as it needs to be updated in pt.
        self.p
            .zip(&self.metadata)
            .par_iter()
            .try_for_each(|(bucket, metadata_bucket, _)| {
                let bucket = bucket.clone().ok_or(OramError::BucketNotFound)?;
                (0..bucket.len()).try_for_each(|b| {
                    let metadata_bucket: Metadata = metadata_bucket
                        .clone()
                        .ok_or(OramError::MetadataBucketNotFound)?;
                    // To know whether the real block should be deleted or not, we need to check
                    // the metadata tree to see if the block is expired. If not, we need
                    // to re-randomize it. Write it back to new location at the LCA and then also
                    // update the metadata tree.
                    metadata_bucket
                        .get(b)
                        .ok_or(OramError::MetadataIndexError(b))
                        .and_then(|metadata_bucket| {
                            let (l, k_oram_t, t_exp) = metadata_bucket;
                            if self.epoch < *t_exp {
                                let c_msg = bucket.get(b).ok_or(OramError::BucketIndexError(b))?;

                                let (lca_idx, _) = self.pt.lca(l).ok_or(OramError::LcaNotFound)?;
                                self.lca_idx_to_block_key_t_exp
                                    .entry(lca_idx)
                                    .or_default()
                                    .push((c_msg.clone(), k_oram_t.clone(), *t_exp));
                            }
                            Ok(())
                        })
                })
            })?;
        Ok(())
    }

    /// 1. Writes all of the queued messages in self.lca_idx_to_block_key_t_exp to pt and metadata_pt.
    /// 2. Shuffle the buckets and fill them up with random blocks up to Z.
    pub fn finalize_batch_write(&mut self) -> Result<(), OramError> {
        let mut rng = ChaCha20Rng::from_entropy();
        let seed: [u8; 32] = rng.gen();

        // If the block is unexpired, we push a new block to pt and metadata_pt at that index.
        self.pt
            .zip(&self.metadata_pt)
            .par_iter_mut()
            .enumerate()
            .filter(|(idx, _)| !self.lca_idx_to_block_key_t_exp.contains_key(&idx))
            .for_each(|(idx, (bucket, metadata_bucket, path))| {
                if let Some(blocks) = self.lca_idx_to_block_key_t_exp.get(&idx) {
                    for (block, key, t_exp) in blocks.iter() {
                        if let Ok(ct) = decrypt(&key.0, &block.0) {
                            if let Some(bucket) = bucket.as_mut() {
                                bucket.push(Block::new(ct));
                            }
                            if let Some(metadata_bucket) = metadata_bucket.as_mut() {
                                metadata_bucket.push(path.clone(), key.clone(), *t_exp);
                            }
                        }
                    }
                }
            });

        // Takes all of the existing indices and fills them up with random blocks up to Z.
        // Shuffle the buckets after.
        self.pt
            .zip(&mut self.metadata_pt)
            .par_iter_mut()
            .try_for_each(|(bucket, metadata_bucket, path)| {
                let bucket = bucket.as_mut().ok_or(OramError::BucketNotFound)?;
                let metadata_bucket: &mut Metadata = metadata_bucket
                    .as_mut()
                    .ok_or(OramError::MetadataBucketNotFound)?;
                (bucket.len()..Z).for_each(|_| {
                    bucket.push(Block::new_random());
                });
                (metadata_bucket.len()..Z).for_each(|_| {
                    metadata_bucket.push(path.clone(), Key::new(vec![]), 0);
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
                Ok(())
            })?;

        // Overwrites metadata with metadata_pt.
        self.metadata.overwrite(&self.metadata_pt);

        let mut server2 = self.s2.write().unwrap();

        // Overwrites p with pt inside of server2.
        server2.write(self.pt.clone());
        server2.add_prf_keys(&self.k_s1_t);

        // Reset the map for the next epoch.
        self.lca_idx_to_block_key_t_exp.clear();

        self.epoch += 1;
        Ok(())
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
