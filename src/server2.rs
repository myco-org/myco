use std::{collections::HashSet, sync::{Arc, Mutex}};

use bincode::{deserialize, serialize};
use tokio::stream;

use crate::{error::OramError, network::{Command, ReadType, WriteType, ReadResponse}, tls_server::TlsServer, tree::BinaryTree, Bucket, Key, Path, D, DELTA};

pub struct Server2 {
    pub tree: BinaryTree<Bucket>,
    pub prf_keys: Vec<Key>,
    pub epoch: u64,
    pathset_indices: Vec<usize>,
}

impl Server2 {
    pub fn new() -> Self {
        let mut tree = BinaryTree::new_with_depth(D);
        tree.fill(Bucket::default());

        Server2 {
            tree,
            prf_keys: vec![],
            epoch: 0,
            pathset_indices: vec![],
        }
    }

    /// l is the leaf block.
    pub fn read(&mut self, l: &Path) -> Result<Vec<Bucket>, OramError> {
        Ok(self.tree.get_all_nodes_along_path(l))
    }

    /// Get a reference to the tree
    pub fn get_tree(&self) -> &BinaryTree<Bucket> {
        &self.tree
    }

    pub fn write(&mut self, packed_buckets: Vec<Bucket>) {
        // Ensure the number of elements in packed_buckets matches the number of pathset_indices
        assert_eq!(
            self.pathset_indices.len(),
            packed_buckets.len(),
            "Mismatched number of indices and buckets"
        );

        // Iterate over self.pathset_indices and packed_buckets, and overwrite corresponding values in self.tree
        for (index, bucket) in self.pathset_indices.iter().zip(packed_buckets.iter()) {
            self.tree.value[*index] = Some(bucket.clone());
        }

        // Increment the epoch
        self.epoch += 1;
    }
    
    pub fn get_prf_keys(&self) -> Result<Vec<Key>, OramError> {
        Ok(self.prf_keys.clone())
    }

    pub fn add_prf_key(&mut self, key: &Key) {
        self.prf_keys.push(key.clone());

        if self.epoch >= DELTA as u64 {
            self.prf_keys.remove(0);
        }
    }

    pub fn read_paths(&mut self, pathset: Vec<usize>) -> Result<Vec<Bucket>, OramError> {
        self.pathset_indices = pathset.clone();

        let buckets: Vec<Bucket> = pathset
            .iter()
            .map(|i| self.tree.value[*i].clone().unwrap())
            .collect();

        Ok(buckets)
    }

    pub async fn run_server(addr: &str, cert_path: &str, key_path: &str) -> Result<(), OramError> {
        let server2 = Arc::new(Mutex::new(Self::new()));
        let server = TlsServer::new(addr, cert_path, key_path).await?;
        
        println!("Server2: Started and waiting for commands");
        
        server.run(move |command| {
            let command: Command = deserialize(command).map_err(|_| OramError::DeserializationError)?;
            println!("Server2: Received command: {:?}", command);
            
            match command { 
                Command::Server2Write(write_type) => {
                    match write_type {
                        WriteType::Write(buckets, prf_key) => {
                            println!("Server2: Processing write of {} buckets", buckets.len());
                            server2.lock().unwrap().write(buckets);
                            server2.lock().unwrap().add_prf_key(&prf_key);
                            println!("Server2: Write and PRF key update completed");
                            Ok(vec![])
                        }
                    }
                }
                Command::Server2Read(read_type) => {
                    match read_type {
                        ReadType::Read(path) => serialize(&server2.lock().unwrap().read(&path)?),
                        ReadType::ReadPaths(indices) => serialize(&server2.lock().unwrap().read_paths(indices)?),
                        ReadType::GetPrfKeys => serialize(&server2.lock().unwrap().get_prf_keys()?),
                    }.map_err(|_| OramError::SerializationFailed)
                }
                _ => Err(OramError::InvalidCommand),
            }
        }).await
    }
}
