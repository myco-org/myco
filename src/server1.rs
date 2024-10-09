use crate::tree::BinaryTree;
use crate::{constants::*, prf, Block, CryptoError, Key, Metadata, Path, Timestamp};
use crate::server2::Server2;
use rand::{thread_rng, Rng};
use std::{cell::RefCell, rc::Rc};

pub struct Server1 {
    pub epoch: u64,
    pub counter: usize,
    pub num_clients: usize,
    pub s2: Rc<RefCell<Server2>>,
    pub p: Option<BinaryTree<Vec<Block>>>,
    pub pt: Option<BinaryTree<Path>>,
    pub metadata_pt: Option<BinaryTree<Metadata>>, 
}

impl Server1 {

    pub fn batch_init(&mut self, num_clients: usize, s2: Rc<RefCell<Server2>>) {
        let mut rng = thread_rng();
        let blocks_and_paths: Vec<(Vec<Block>, Path)> = (0..(NU * self.num_clients))
            .map(|_| {
                let l: Path = (0..D).map(|_| rng.gen_range(0..2).into()).collect();
                (self.s2.borrow_mut().read(&l), l)
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
        self.insert_message(ct, l, k_oram_t, t_exp);
        Ok(())
    }

    pub fn insert_message(&mut self, ct: Vec<u8>, l: Vec<u8>, k_oram_t: Vec<u8>, t_exp: u64) {
        let c_msg = crate::encrypt(&k_oram_t.clone(), &[&l[..], &ct[..]].concat()).expect("Failed to encrypt message");
    }

    pub fn batch_write(&mut self) {

    }
}