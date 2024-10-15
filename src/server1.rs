use std::{borrow::BorrowMut, cell::RefCell, cmp::min, path, rc::Rc, sync::{Arc, Mutex}};

use crate::{
    tree::BinaryTree,
    constants::*,
    decrypt,
    prf,
    Block,
    Bucket,
    CryptoError,
    Key,
    Metadata,
    Path,
    server2::Server2,
};
use rand::{seq::SliceRandom, thread_rng, Rng, SeedableRng};
pub struct Server1 {
    pub epoch: u64,
    pub k_s1_t: Key,
    pub counter: usize,
    pub num_clients: usize,
    pub s2: Arc<Mutex<Server2>>,
    pub p: Option<BinaryTree<Bucket>>,
    pub pt: BinaryTree<Bucket>,
    pub metadata_pt: BinaryTree<Metadata>,  
    pub metadata: BinaryTree<Metadata>,
}

impl Server1 {
    pub fn new(s2: Arc<Mutex<Server2>>) -> Self {
        Self { epoch: 0, k_s1_t: Key::new(vec![]), counter: 0, num_clients: 0, s2, p: None, pt: BinaryTree::new_empty(), metadata_pt: BinaryTree::new_empty(), metadata: BinaryTree::new_with_depth(D) }
    }

    pub fn batch_init(&mut self, num_clients: usize) {
        let mut rng = thread_rng();
        let buckets_and_paths: Vec<(Vec<Bucket>, Path)> = (0..(NU * self.num_clients))
            .map(|_| {
                let l = Path::new((0..D).map(|_| rng.gen_range(0..2).into()).collect());
                (self.s2.lock().unwrap().read(&l), l)
            })
            .collect();
    
        self.p = Some(BinaryTree::<Bucket>::from_vec_with_paths(buckets_and_paths));
        self.pt = BinaryTree::new(vec![]);
        self.metadata_pt = BinaryTree::new(vec![]);
        self.num_clients = num_clients;
        self.k_s1_t = Key::random(&mut rng);
    }

    pub fn write(&mut self, ct: Vec<u8>, l: Vec<u8>, k_oram_t: Key, cw: Vec<u8>) -> Result<(), CryptoError> {
        let t_exp = self.epoch + DELTA; 
        let l = prf(&l, &cw);
        self.insert_message(&ct, &Path::from(l), &k_oram_t, t_exp);
        Ok(())
    }

    pub fn insert_message(&mut self, ct: &Vec<u8>, l: &Path, k_oram_t: &Key, t_exp: u64) {
        let c_msg = crate::encrypt(&k_oram_t.0, &[&Into::<Vec<u8>>::into(l.clone())[..], &ct[..]].concat()).expect("Failed to encrypt message");
        let (bucket, path) = self.pt.lca(&l).unwrap();
        bucket.push(Block::new(c_msg));
        self.metadata_pt.write(vec![(l.clone(), k_oram_t.clone(), t_exp)], path);
    }

    pub fn batch_write(&mut self) {
        if self.p.is_none() {
            return;
        }
        println!("self.pt:\n{}", self.pt);
        let mut rng = thread_rng();
        let seed: [u8; 32] = rng.gen();

        self.p.as_ref().unwrap().zip_flatten_tree(&self.metadata).iter().for_each(|(bucket, metadata_bucket, path)| {
            (0..Z).for_each(|b| {
                let bucket = bucket.as_ref().expect("Bucket should exist");
                metadata_bucket.as_ref().map(|metadata_bucket| {
                    let (l, k_oram_t, t_exp) = metadata_bucket.get(b).expect("Failed to get metadata bucket at index {b}");
                    if self.epoch < *t_exp {
                        let c_msg = bucket.get(b).expect("Failed to get bucket at index {b}");
                        let ct = decrypt(&k_oram_t.0, &c_msg.0).expect("Failed to decrypt message");
                        self.insert_message(&ct, l, k_oram_t, *t_exp);
                    }
                });
            });
        });

        self.pt.zip_flatten_tree(&mut self.metadata_pt).iter_mut().for_each(|(bucket, metadata_bucket, path)| {
            let bucket = bucket.as_mut().expect("Bucket should exist");
            let metadata_bucket = metadata_bucket.as_mut().expect("Metadata bucket should exist");
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