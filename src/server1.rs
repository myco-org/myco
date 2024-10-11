use crate::tree::BinaryTree;
use crate::{constants::*, new_bid, prf, Block, CryptoError, Key, Metadata, Path, Timestamp};
use crate::server2::Server2;
use rand::{thread_rng, Rng};
use std::borrow::BorrowMut;
use std::{cell::RefCell, rc::Rc};

pub struct Server1 {
    pub epoch: u64,
    pub counter: usize,
    pub num_clients: usize,
    pub s2: Rc<RefCell<Server2>>,
    pub p: Option<BinaryTree<Vec<Block>>>,
    pub pt: Option<BinaryTree<Path>>,
    pub metadata_pt: Option<BinaryTree<Metadata>>,  
    pub metadata: BinaryTree<Metadata>,
}

impl Server1 {
    pub fn new(s2: Rc<RefCell<Server2>>) -> Self {
        Self { epoch: 0, counter: 0, num_clients: 0, s2, p: None, pt: None, metadata_pt: None, metadata: BinaryTree::new_with_depth(D) }
    }

    pub fn batch_init(&mut self, num_clients: usize, s2: Rc<RefCell<Server2>>) {
        let mut rng = thread_rng();
        let blocks_and_paths: Vec<(Vec<Block>, Path)> = (0..(NU * self.num_clients))
            .map(|_| {
                let l = Path::new((0..D).map(|_| rng.gen_range(0..2).into()).collect());
                (self.s2.borrow().read(&l), l)
            })
            .collect();
    
        self.p = Some(BinaryTree::from_vec_with_paths(blocks_and_paths));
        self.pt = None;
        self.metadata_pt = None;
        self.num_clients = num_clients;
        self.s2 = s2;
    }

    pub fn write(&mut self, ct: Vec<u8>, l: Vec<u8>, k_oram_t: Vec<u8>, cw: Vec<u8>) -> Result<(), CryptoError> {
        let t_exp = self.epoch + DELTA; 
        let l = prf(&l, &cw);
        self.insert_message(ct, Path::from(l), k_oram_t, t_exp);
        Ok(())
    }

    pub fn insert_message(&mut self, ct: Vec<u8>, l: Path, k_oram_t: Vec<u8>, t_exp: u64) {
        let c_msg = crate::encrypt(&k_oram_t.clone(), &[&Into::<Vec<u8>>::into(l.clone())[..], &ct[..]].concat()).expect("Failed to encrypt message");
        let (bucket, path) = self.p.as_ref().map(|p| p.lca(&l).unwrap()).expect("Failed to get bucket");
        let mut bucket = bucket.clone();
        bucket.push(Block::new(new_bid(), c_msg));
        self.p.as_mut().map(|p| p.borrow_mut().write(bucket, path));
    }

    pub fn batch_write(&mut self) {
        if self.p.is_none() {
            return;
        }

        let mut p = self.p.clone().expect("Failed to get p");
        let mut pt = self.pt.clone().expect("Failed to get pt");

        p.zip_flatten_tree(&self.metadata).iter().for_each(|(bucket, metadata_bucket, path)| {
            (0..Z).for_each(|b| {
                metadata_bucket.as_ref().map(|bucket| {
                    if let Some((l, k_oram_t, t_exp)) = bucket.get(b) {
                        if self.epoch < *t_exp {
                            if let Some(block) = bucket.get(b) {
                                let c_msg = &block.1;
                                // Use c_msg here as needed
                            }
                        }
                    }
                });
            });
        });

    }
}