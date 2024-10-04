use crate::{constants::*, prf, Block, CryptoError, Key, Metadata, Path, Timestamp};
use crate::server2::Server2;
use rand::{thread_rng, Rng};
use std::cmp::Ordering;
use std::{cell::RefCell, rc::Rc};

pub struct Server1 {
    pub epoch: u64,
    pub counter: usize,
    pub num_clients: usize,
    pub s2: Rc<RefCell<Server2>>,
    pub p: Vec<Vec<Block>>,
    pub pt: Vec<Path>,
    pub metadata_pt: Vec<Metadata>,
}

impl Server1 {

    pub fn batch_init(&mut self, num_clients: usize, s2: Rc<RefCell<Server2>>) {
        let mut rng = thread_rng();
        let blocks_and_paths: Vec<(Vec<Block>, Path)> = (0..(NU * self.num_clients))
            .map(|_| {
                let l: Vec<bool> = (0..D).map(|_| rng.gen_bool(0.5)).collect();
                (self.s2.borrow_mut().read(&l), l)
            })
            .collect();
    
        self.p = blocks_and_paths.iter().map(|(blocks, _)| blocks.clone()).collect();
        self.pt = vec![];
        self.metadata_pt = vec![];
        self.num_clients = num_clients;
        self.s2 = s2;
    }

    pub fn write(&mut self, ct: Vec<u8>, l: Vec<u8>, k_oram_t: Vec<u8>) -> Result<(), CryptoError> {
        let expiration = self.epoch + DELTA; 
        let l = prf(l, input);
    }

    pub fn batch_write(&mut self) {
        // In a real implementation, this would write to S2
        self.write_queue.clear();
        self.counter = 0;
        self.epoch += 1;
    }
}