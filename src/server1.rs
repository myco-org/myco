use std::{borrow::BorrowMut, cell::RefCell, cmp::min, path, rc::Rc, sync::{Arc, Mutex}};

use crate::{
    constants::*, decrypt, encrypt, prf, server2::Server2, tree::{BinaryTree, TreeValue}, Block, Bucket, CryptoError, Key, Metadata, Path
};
use rand::{seq::SliceRandom, thread_rng, Rng, SeedableRng};
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
        Self { epoch: 0, k_s1_t: Key::new(vec![]), num_clients: 0, s2, p: BinaryTree::new_empty(), pt: BinaryTree::new_empty(), metadata_pt: BinaryTree::new_empty(), metadata }
    }

    pub fn batch_init(&mut self, num_clients: usize) {
        let mut rng = thread_rng();

        let paths = (0..(NU * num_clients)).map(|_| Path::random(&mut rng)).collect::<Vec<Path>>();

        let buckets_and_paths: Vec<(Vec<Bucket>, Path)> = paths.iter().map(|path| {
            let bucket = self.s2.lock().unwrap().read(&path);
            (bucket, path.clone())
        }).collect();

        let pt_data: Vec<(Vec<Bucket>, Path)> = paths.iter().map(|path| {
            (vec![Bucket::default(); D], path.clone())
        }).collect();

        let metadata_pt_data: Vec<(Vec<Metadata>, Path)> = paths.iter().map(|path| {
            (vec![Metadata::default(); D], path.clone())
        }).collect();

        self.p = BinaryTree::<Bucket>::from_vec_with_paths(buckets_and_paths.clone());
        self.pt = BinaryTree::<Bucket>::from_vec_with_paths(pt_data);
        self.metadata_pt = BinaryTree::<Metadata>::from_vec_with_paths(metadata_pt_data);

        self.num_clients = num_clients;
        self.k_s1_t = Key::random(&mut rng);
    }

    pub fn write(&mut self, ct: Vec<u8>, f: Vec<u8>, k_oram_t: Key, cw: Vec<u8>) -> Result<(), CryptoError> {
        let t_exp = self.epoch + DELTA; 
        let l: Vec<u8> = prf(&self.k_s1_t.0, &[&f[..], &cw[..]].concat());
        self.insert_message(&ct, &Path::from(l), &k_oram_t, t_exp);

        Ok(())
    }

    pub fn insert_message(&mut self, ct: &Vec<u8>, l: &Path, k_oram_t: &Key, t_exp: u64) {
        let c_msg = encrypt(&k_oram_t.0, &ct).unwrap();
        let (bucket, path) = self.pt.lca(&l).unwrap();

        let mut metadata_bucket = self.metadata_pt.get(&path).unwrap().clone();

        assert_eq!(bucket.len(), metadata_bucket.len(), "Bucket and metadata bucket are not the same length");
        assert!(bucket.len() < Z, "Bucket is full");

        bucket.push(Block::new(c_msg));
        metadata_bucket.push(l.clone(), k_oram_t.clone(), t_exp);
        self.metadata_pt.write(metadata_bucket, path);
    }

    pub fn batch_write(&mut self) {
        let mut rng = thread_rng();
        let seed: [u8; 32] = rng.gen();

        self.p.zip_flatten_tree(&self.metadata).iter().for_each(|(bucket, metadata_bucket, path)| {
            let bucket = bucket.clone().expect("Bucket should exist");
            (0..bucket.len()).for_each(|b| {
                metadata_bucket.as_ref().map(|metadata_bucket| {
                    let (l, k_oram_t, t_exp) = metadata_bucket.get(b).expect("Failed to get metadata bucket at index {b}");
                    if self.epoch < *t_exp {
                        let c_msg = bucket.get(b).expect("Failed to get bucket at index {b}");
                        if let Ok(ct) = decrypt(&k_oram_t.0, &c_msg.0) {
                            self.insert_message(&ct, l, k_oram_t, *t_exp);
                        }
                    }
                });
            });
        });

        self.pt.zip_flatten_tree(&mut self.metadata_pt).iter_mut().for_each(|(bucket, metadata_bucket, path)| {
            let bucket = bucket.as_mut().expect("Bucket should exist");
            let metadata_bucket: &mut Metadata = metadata_bucket.as_mut().expect("Metadata bucket should exist");
            (0..min(bucket.len(), Z)).for_each(|b| {
                bucket[b] = Block::new_random();
            });

            let mut rng1 = rand::rngs::StdRng::from_seed(seed);
            let mut rng2 = rand::rngs::StdRng::from_seed(seed);
            bucket.shuffle(&mut rng1);
            metadata_bucket.shuffle(&mut rng2);
        });

        self.metadata.overwrite_tree(&self.metadata_pt);
        let mut server2 = self.s2.lock().unwrap();
        server2.write(self.pt.clone());
        server2.add_prf_keys(&self.k_s1_t);

        self.epoch += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_same_shuffle() {
        let seed: [u8; 32] = [0; 32]; // Use a fixed seed
        let mut rng1 = rand::rngs::StdRng::from_seed(seed);
        let mut rng2 = rand::rngs::StdRng::from_seed(seed);
        let mut v1 = (0..10).collect::<Vec<_>>();
        let mut v2 = v1.clone();
        v1.shuffle(&mut rng1);
        v2.shuffle(&mut rng2); // Use the same RNG instance
        assert_eq!(v1, v2); // The vectors should be equal after shuffling with the same RNG
    }
}