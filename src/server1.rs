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
use std::sync::{Arc, Mutex};

pub struct Server1 {
    pub epoch: u64,
    pub k_s1_t: Key,
    pub num_clients: usize,
    pub s2: Arc<Mutex<Server2>>,
    pub p: BinaryTree<Bucket>,
    pub pt: BinaryTree<Bucket>,
    pub metadata_pt: BinaryTree<Metadata>,
    pub metadata: BinaryTree<Metadata>,
}

impl Server1 {
    pub fn new(s2: Arc<Mutex<Server2>>) -> Self {
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
                let bucket = self.s2.lock().unwrap().read(&path);
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
        self.pt = BinaryTree::<Bucket>::from_vec_with_paths(pt_data);
        self.metadata_pt = BinaryTree::<Metadata>::from_vec_with_paths(metadata_pt_data);

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

    pub fn batch_write(&mut self) -> Result<(), OramError> {
        let mut rng = ChaCha20Rng::from_entropy();
        let seed: [u8; 32] = rng.gen();

        // If the message is valid, then we re-assign it (e.g. it's not expired).
        // Everything that's not expired, we need to re-insert into the tree
        // with the LCA for the new pathset.

        // Store the LCA Path -> (Block, Key, t_exp)
        // Get the ct from decrypt(key, block).
        let lca_idx_to_block_key_t_exp: DashMap<usize, Vec<(Block, Key, u64)>> = DashMap::new();

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
                                lca_idx_to_block_key_t_exp
                                    .entry(lca_idx)
                                    .or_default()
                                    .push((c_msg.clone(), k_oram_t.clone(), *t_exp));
                            }
                            Ok(())
                        })
                })
            })?;

        // Loop over all the indices in the metadata tree and the bucket tree.
        self.p
            .zip(&self.metadata_pt)
            .par_iter_mut()
            .enumerate()
            .filter(|(idx, _)| !lca_idx_to_block_key_t_exp.contains_key(&idx))
            .for_each(|(idx, (bucket, metadata_bucket, path))| {
                if let Some(blocks) = lca_idx_to_block_key_t_exp.get(&idx) {
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
        self.pt.zip(&mut self.metadata_pt).iter_mut().try_for_each(
            |(bucket, metadata_bucket, path)| {
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
            },
        )?;
        self.metadata.overwrite(&self.metadata_pt);

        let mut server2 = self.s2.lock().unwrap();
        server2.write(self.pt.clone());
        server2.add_prf_keys(&self.k_s1_t);

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