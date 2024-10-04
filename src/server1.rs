use crate::{constants::*, Block, CryptoError, Key, Timestamp};
use crate::server2::Server2;
use rand::{thread_rng, Rng};
use std::cmp::Ordering;
use std::{cell::RefCell, rc::Rc};
use thiserror::Error;


struct Metadata {
    root: Option<Box<Node>>,
}

#[derive(Debug, Clone)]
struct Node {
    key: String,
    value: (Key, Timestamp),
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}

impl Metadata {
    fn new() -> Self {
        Metadata { root: None }
    }

    fn insert(&mut self, key: String, value: (Key, Timestamp)) {
        self.root = Self::insert_node(self.root.take(), key, value);
    }

    fn insert_node(
        node: Option<Box<Node>>,
        key: String,
        value: (Key, Timestamp),
    ) -> Option<Box<Node>> {
        match node {
            Some(mut current) => {
                match key.cmp(&current.key) {
                    Ordering::Less => {
                        current.left = Self::insert_node(current.left.take(), key, value);
                    }
                    Ordering::Greater => {
                        current.right = Self::insert_node(current.right.take(), key, value);
                    }
                    Ordering::Equal => {
                        current.value = value; // Update existing key
                    }
                }
                Some(current)
            }
            None => Some(Box::new(Node {
                key,
                value,
                left: None,
                right: None,
            })),
        }
    }

    fn get(&self, key: &str) -> Option<&(Key, Timestamp)> {
        Self::get_node(&self.root, key)
    }

    fn get_node<'a>(node: &'a Option<Box<Node>>, key: &str) -> Option<&'a (Key, Timestamp)> {
        match node {
            Some(current) => match key.cmp(&current.key) {
                Ordering::Less => Self::get_node(&current.left, key),
                Ordering::Greater => Self::get_node(&current.right, key),
                Ordering::Equal => Some(&current.value),
            },
            None => None,
        }
    }
}

pub struct Server1 {
    pub metadata: Metadata,
    pub epoch: u64,
    pub counter: usize,
    pub write_queue: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    pub num_clients: usize,
    pub s2: Rc<RefCell<Server2>>,
}

impl Server1 {
    pub fn new(num_clients: usize, s2: Rc<RefCell<Server2>>) -> Self {
        Server1 {
            metadata: Metadata::new(),
            epoch: 0,
            counter: 0,
            write_queue: Vec::new(),
            num_clients,
            s2,
        }
    }

    pub fn batch_init(&mut self) {
        let mut rng = thread_rng();
        let p: Vec<(Vec<Block>, Vec<u8>)> = (0..(NU * self.num_clients))
            .map(|_| {
                let l: Vec<u8> = (0..D).map(|_| rng.gen_bool(0.5) as u8).collect();
                (self.s2.borrow_mut().read(&l), l)
            })
            .collect();
        for (path, l) in p {
            let mut node = self.metadata.root.as_mut();
            for (block, child) in path.iter().zip(l.iter()) {
                match node.take() {
                    Some(current_node) => {
                        if current_node.value.1 < self.epoch
                            || crate::decrypt(&current_node.value.0, &block.data).is_ok()
                        {
                            break;
                        }
                        node = if *child == 0 {
                            current_node.left.as_mut()
                        } else {
                            current_node.right.as_mut()
                        };
                    }
                    None => break,
                }
            }
        }
    }

    pub fn write(&mut self, ct: Vec<u8>, l: Vec<u8>, k_oram_t: Vec<u8>) -> Result<(), CryptoError> {
        let expiration = self.epoch + 10; // Arbitrary expiration period
        let c_msg = crate::encrypt(&k_oram_t.clone(), &[&l[..], &ct[..]].concat())?;
        self.metadata
            .insert(hex::encode(&l), (k_oram_t.clone(), expiration));
        self.write_queue
            .push((c_msg.clone(), l.clone(), k_oram_t.clone()));
        self.counter += 1;

        if self.counter == NUM_WRITES_PER_EPOCH {
            self.batch_write();
        }
        Ok(())
    }

    pub fn batch_write(&mut self) {
        // In a real implementation, this would write to S2
        self.write_queue.clear();
        self.counter = 0;
        self.epoch += 1;
    }
}