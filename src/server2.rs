use std::{collections::HashSet, sync::{Arc, Mutex}};

use bincode::{deserialize, serialize};
use tokio::stream;

use crate::{error::OramError, network::{Command, ReadType, WriteType}, tls_server::TlsServer, tree::BinaryTree, Bucket, Key, Path, D, DELTA};

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
        let buckets = self.tree.get_all_nodes_along_path(l);
        Ok(buckets)
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

    pub async fn run_server(client_addr: &str, s1_addr: &str, cert_path: &str, key_path: &str) -> Result<(), OramError> {
        let server2 = Arc::new(Mutex::new(Self::new()));
        
        // Create two TLS servers
        let client_server = TlsServer::new(client_addr, cert_path, key_path, "Server2-Client".to_string()).await?;
        let s1_server = TlsServer::new(s1_addr, cert_path, key_path, "Server2-S1".to_string()).await?;
                
        // Clone Arc for second server
        let server2_s1 = Arc::clone(&server2);
        
        // Run both servers concurrently
        tokio::try_join!(
            client_server.run(move |command| {
                let command: Command = deserialize(command).map_err(|_| OramError::DeserializationError)?;
                
                match command { 
                    Command::Server2Read(read_type) => {
                        match read_type {
                            ReadType::Read(path) => serialize(&server2.lock().unwrap().read(&path)?),
                            ReadType::ReadPaths(indices) => serialize(&server2.lock().unwrap().read_paths(indices)?),
                            ReadType::GetPrfKeys => serialize(&server2.lock().unwrap().get_prf_keys()?),
                        }.map_err(|_| OramError::SerializationFailed)
                    }
                    _ => Err(OramError::InvalidCommand),
                }
            }),
            s1_server.run(move |command| {
                let command: Command = deserialize(command).map_err(|_| OramError::DeserializationError)?;
                
                match command {
                    Command::Server2Write(write_type) => {
                        match write_type {
                            WriteType::Write(buckets, prf_key) => {
                                server2_s1.lock().unwrap().write(buckets);
                                server2_s1.lock().unwrap().add_prf_key(&prf_key);
                                Ok(serialize(&Command::Success).unwrap())
                            }
                        }
                    } 
                    Command::Server2Read(read_type) => {
                        match read_type {
                            ReadType::Read(path) => serialize(&server2_s1.lock().unwrap().read(&path)?),
                            ReadType::ReadPaths(indices) => serialize(&server2_s1.lock().unwrap().read_paths(indices)?),
                            ReadType::GetPrfKeys => serialize(&server2_s1.lock().unwrap().get_prf_keys()?),
                        }.map_err(|_| OramError::SerializationFailed)
                    }
                    _ => Err(OramError::InvalidCommand),
                }
            })
        )?;

        Ok(())
    }

    pub async fn run_server_with_simulation<F>(
        client_addr: &str,
        s1_addr: &str,
        cert_path: &str,
        key_path: &str,
        simulation_key: Key,
        progress_callback: F,
    ) -> Result<(), OramError>
    where
        F: Fn(usize) + Send + Sync + 'static,
    {
        let server2 = Arc::new(Mutex::new(Self::new()));
        
        println!("Server2: Ready for connections");
        
        // Create two TLS servers
        let client_server = TlsServer::new(client_addr, cert_path, key_path, "Server2-Client".to_string()).await?;
        let s1_server = TlsServer::new(s1_addr, cert_path, key_path, "Server2-S1".to_string()).await?;
        
        println!("Server2: TLS servers initialized");
        
        // Clone Arc for second server
        let server2_s1 = Arc::clone(&server2);
        
        tokio::try_join!(
            client_server.run(move |command| {
                let command: Command = deserialize(command).map_err(|_| OramError::DeserializationError)?;
                
                match command { 
                    Command::Server2Read(read_type) => {
                        match read_type {
                            ReadType::Read(path) => serialize(&server2.lock().unwrap().read(&path)?),
                            ReadType::ReadPaths(indices) => serialize(&server2.lock().unwrap().read_paths(indices)?),
                            ReadType::GetPrfKeys => serialize(&server2.lock().unwrap().get_prf_keys()?),
                        }.map_err(|_| OramError::SerializationFailed)
                    }
                    _ => Err(OramError::InvalidCommand),
                }
            }),
            s1_server.run(move |command| {
                let command: Command = deserialize(command).map_err(|_| OramError::DeserializationError)?;
                println!("Server2: Received command from S1");
                match command {
                    Command::Server2Write(write_type) => {
                        match write_type {
                            WriteType::Write(buckets, prf_key) => {
                                server2_s1.lock().unwrap().write(buckets);
                                server2_s1.lock().unwrap().add_prf_key(&prf_key);
                                progress_callback(server2_s1.lock().unwrap().epoch as usize);
                                Ok(serialize(&Command::Success).unwrap())
                            }
                        }
                    }
                    Command::Server2Read(read_type) => {
                        match read_type {
                            ReadType::Read(path) => serialize(&server2_s1.lock().unwrap().read(&path)?),
                            ReadType::ReadPaths(indices) => serialize(&server2_s1.lock().unwrap().read_paths(indices)?),
                            ReadType::GetPrfKeys => serialize(&server2_s1.lock().unwrap().get_prf_keys()?),
                        }.map_err(|_| OramError::SerializationFailed)
                    }
                    _ => Err(OramError::InvalidCommand),
                }
            })
        )?;

        Ok(())
    }
}
