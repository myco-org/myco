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

    /// Queues an individual write from a client.
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

        let c_msg = encrypt(&k_oram_t.0, &ct, EncryptionType::DoubleEncrypt)
            .map_err(|_| OramError::EncryptionFailed)?;

        // Queue the write.
        self.lca_idx_to_block_key_t_exp
            .entry(lca_idx)
            .or_default()
            .push((Block::new(c_msg), k_oram_t, t_exp));

        Ok(())
    }

    pub fn batch_write(&mut self) -> Result<(), OramError> {
        let mut rng = ChaCha20Rng::from_entropy();
        let seed: [u8; 32] = rng.gen();

        let t1 = std::time::Instant::now();
        self.p
            .zip(&self.metadata)
            .par_iter()
            .try_for_each(|(bucket, metadata_bucket, _)| {
                let bucket = bucket.clone().ok_or(OramError::BucketNotFound)?;
                (0..bucket.len()).try_for_each(|b| {
                    metadata_bucket
                        .as_ref()
                        .ok_or(OramError::MetadataBucketNotFound)
                        .and_then(|metadata_bucket| {
                            let (l, k_oram_t, t_exp) = metadata_bucket
                                .get(b)
                                .ok_or(OramError::BucketIndexError(b))?;
                            if self.epoch < *t_exp {
                                let c_msg = bucket.get(b).ok_or(OramError::BucketIndexError(b))?;
                                let ct = decrypt(&k_oram_t.0, &c_msg.0)
                                    .map_err(|_| OramError::DecryptionFailed)?;
                                let c_msg_new: Vec<u8> = encrypt(&k_oram_t.0, &ct, EncryptionType::DoubleEncrypt)
                                    .map_err(|_| OramError::EncryptionFailed)?;

                                let (lca_idx, _) = self.pt.lca(l).ok_or(OramError::LcaNotFound)?;
                                self.lca_idx_to_block_key_t_exp
                                    .entry(lca_idx)
                                    .or_default()
                                    .push((Block::new(c_msg_new), k_oram_t.clone(), *t_exp));
                            }
                            Ok(())
                        })
                })
            })?;
            let t2 = std::time::Instant::now();
            println!("Time taken for batch_write: {:?}", t2.duration_since(t1));

            self.pt
                .zip_mut(&mut self.metadata_pt)
                .par_iter_mut()
                .enumerate()
                .filter(|(idx, _)| self.lca_idx_to_block_key_t_exp.contains_key(&idx))
                .for_each(|(idx, (bucket, metadata_bucket, path))| {
                    if let Some(blocks) = self.lca_idx_to_block_key_t_exp.get(&idx) {
                        for (block, key, t_exp) in blocks.iter() {
                            if let Some(bucket) = bucket.as_mut() {
                                bucket.push(Block::new(block.0.clone()));
                            }
                            if let Some(metadata_bucket) = metadata_bucket.as_mut() {
                                metadata_bucket.push(path.clone(), key.clone(), *t_exp);
                            }
                        }
                    }
                });
            let t3 = std::time::Instant::now();
            println!("Time taken for batch_write_2: {:?}", t3.duration_since(t2));
                
            // self.print_non_none_buckets();

            self.pt.zip_mut(&mut self.metadata_pt).iter_mut().filter(|(bucket, _, _)| bucket.is_some()).try_for_each(
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
        let t4 = std::time::Instant::now();

        self.metadata.overwrite(&self.metadata_pt);
        println!("Time taken for metadata overwrite: {:?}", t4.duration_since(t3));

        let t5 = std::time::Instant::now();
        let mut server2 = self.s2.lock().unwrap();
        println!("Time taken for server2 lock: {:?}", t5.duration_since(t4));


        let t6 = std::time::Instant::now();
        server2.write(self.pt.clone());
        println!("Time taken for server2 write: {:?}", t6.duration_since(t5));

        let t7 = std::time::Instant::now();
        server2.add_prf_keys(&self.k_s1_t);
        println!("Time taken for server2 add_prf_keys: {:?}", t7.duration_since(t6));

        self.epoch += 1;
        Ok(())
    }
    
    pub fn print_non_none_buckets(&self) {
        for (index, bucket) in self.pt.value.iter().enumerate() {
            if let Some(ref bucket_value) = bucket {
                println!("Bucket at index {}: {:?}", index, bucket_value);
            }
        }
        for (index, bucket) in self.metadata_pt.value.iter().enumerate() {
            if let Some(ref bucket_value) = bucket {
                println!("Bucket at index {}: {:?}", index, bucket_value);
            }
        }
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