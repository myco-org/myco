//! Client
//! 
//! In Myco, clients in Myco participate in two main activities: sending (writing) and receiving 
//! (reading) messages. When sending, a client encrypts their message using a shared key, derives a 
//! pseudorandom location using another shared key, and sends this encrypted message to S1 along with 
//! a specially derived encryption key for that epoch. When receiving, a client computes where their 
//! message should be located using shared keys and the epoch information, downloads the corresponding 
//! path from S2's tree structure, and then decrypts their message using their shared keys. 
//! Importantly, clients must participate in every epoch by either sending real messages or fake ones 
//! ("cover traffic"), and must perform a fixed number of reads per epoch (using fake reads to fill 
//! any gaps) to maintain privacy.

use crate::constants::{BLOCK_SIZE, D};
use crate::dtypes::{Bucket, Key, Path};
use crate::error::MycoError;
use crate::logging::LatencyMetric;
use crate::network::{
    Server1Access, Server2Access,
};
use crate::tree::SparseBinaryTree;
use crate::utils::trim_zeros;
use crate::{get_path_indices, utils::{kdf, prf, EncryptionType, encrypt, decrypt}, BATCH_SIZE};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;

/// A Myco client (user).
pub struct Client {
    /// The client's ID.
    pub id: String,
    /// The current epoch of the client.
    pub epoch: usize,
    /// The client's keys.
    pub keys: HashMap<Key, (Vec<u8>, Vec<u8>, Vec<u8>)>,
    /// Access to Server1.
    pub s1: Box<dyn Server1Access>,
    /// Access to Server2.
    pub s2: Box<dyn Server2Access>,
}

impl Client {
    /// Create a new Client instance.
    pub fn new(id: String, s1: Box<dyn Server1Access>, s2: Box<dyn Server2Access>) -> Self {
        Client {
            id,
            epoch: 0,
            keys: HashMap::new(),
            s1,
            s2,
        }
    }

    /// Setup the client with a key.
    pub fn setup(&mut self, k: &Key) -> Result<(), MycoError> {
        let end_to_end_latency = LatencyMetric::new("client_setup_end_to_end");
        let k_msg = kdf(&k.0, "MSG")?;
        let k_oblv = kdf(&k.0, "ORAM")?;
        let k_prf = kdf(&k.0, "PRF")?;
        self.keys.insert(k.clone(), (k_msg, k_oblv, k_prf));
        end_to_end_latency.finish();
        Ok(())
    }

    /// Asynchronously write a message to Server1.
    pub async fn async_write(&mut self, msg: &[u8], k: &Key) -> Result<(), MycoError> {
        let end_to_end_latency = LatencyMetric::new("client_write_end_to_end");
        let local_latency = LatencyMetric::new("client_write_local");
        let epoch = self.epoch;
        let cs = self.id.clone().into_bytes();

        let (k_msg, k_oblv, k_prf) = self.keys.get(k).unwrap();
        let f = prf(k_prf, &epoch.to_be_bytes())?;
        let k_oblv_t = kdf(k_oblv, &epoch.to_string())?;
        let ct = encrypt(k_msg, msg, EncryptionType::Encrypt)?;

        self.epoch += 1;
        local_latency.finish();
        self.s1.queue_write(ct, f, Key::new(k_oblv_t), cs).await;
        end_to_end_latency.finish();
        Ok(())
    }

    /// Write a message to Server1.
    pub fn write(&mut self, msg: &[u8], k: &Key) -> Result<(), MycoError> {
        let epoch = self.epoch;
        let cs = self.id.clone().into_bytes();

        let (k_msg, k_oblv, k_prf) = self.keys.get(k).unwrap();
        let f = prf(k_prf, &epoch.to_be_bytes())?;
        let k_oblv_t = kdf(k_oblv, &epoch.to_string())?;
        let ct = encrypt(k_msg, msg, EncryptionType::Encrypt)?;

        self.epoch += 1;
        futures::executor::block_on(self.s1.queue_write(ct, f, Key::new(k_oblv_t), cs))
    }

    /// Asynchronously read messages from Server2.
    pub async fn async_read(
        &self,
        keys: Vec<Key>,
        cs: String,
        epoch_past: usize,
        batch_size: usize,
    ) -> Result<Vec<Vec<u8>>, MycoError> {
        if keys.len() != batch_size {
            return Err(MycoError::InvalidBatchSize);
        }

        let end_to_end_latency =
            LatencyMetric::new(&format!("client_read_end_to_end_{}", batch_size));
        let mut local_latency = LatencyMetric::new(&format!("client_read_local_{}", batch_size));
        let epoch = self.epoch - 1 - epoch_past;
        let cs: Vec<u8> = cs.into_bytes();

        // Get PRF keys from server2
        local_latency.pause();
        let get_prf_keys_latency =
            LatencyMetric::new(&format!("client_read_get_prf_keys_{}", batch_size));
        let server_keys = self
            .s2
            .get_prf_keys()
            .await
            .map_err(|_| MycoError::NoMessageFound)?;
        get_prf_keys_latency.finish();
        local_latency.resume();

        if server_keys.is_empty() || epoch_past >= server_keys.len() {
            return Err(MycoError::NoMessageFound);
        }

        let k_s1_t = server_keys.get(server_keys.len() - 1 - epoch_past).unwrap();

        // Calculate paths for all keys
        let mut paths = Vec::with_capacity(batch_size);
        let mut key_data = Vec::with_capacity(batch_size);

        for k in keys {
            let (k_msg, k_oblv, k_prf) = self.keys.get(&k).unwrap();
            let k_oblv_t =
                kdf(k_oblv, &epoch.to_string()).map_err(|_| MycoError::NoMessageFound)?;
            let f = prf(&k_prf, &epoch.to_be_bytes())?;

            let l = prf(k_s1_t.0.as_slice(), &[&f[..], &cs[..]].concat())?;
            let l_path = Path::from(l);
            paths.push(l_path);
            key_data.push((k_msg.clone(), k_oblv_t));
        }

        // Get path indices and read paths
        let indices = get_path_indices(paths.clone());

        local_latency.pause();
        let read_latency = LatencyMetric::new(&format!("client_read_read_paths_{}", batch_size));
        let buckets = self
            .s2
            .read_paths_client(indices.clone(), batch_size)
            .await
            .map_err(|_| MycoError::NoMessageFound)?;
        read_latency.finish();
        local_latency.resume();

        // Try to decrypt messages from all paths
        let mut messages = Vec::new();

        // First, convert buckets into a BinaryTree
        let bucket_tree = SparseBinaryTree::new_with_data(buckets, indices);

        // Now process each key along its specific path
        for ((k_msg, k_oblv_t), path) in key_data.into_iter().zip(paths.iter()) {
            let mut found = false;
            // Only check buckets along this key's path
            let path_buckets = bucket_tree.get_all_nodes_along_path(&path);

            for bucket in path_buckets {
                for block in bucket.iter() {
                    if let Ok(ct) = decrypt(&k_oblv_t, &block.0) {
                        if let Ok(msg) = decrypt(&k_msg, &ct) {
                            messages.push(trim_zeros(&msg));
                            found = true;
                            break;
                        }
                    }
                }
                if found {
                    break;
                }
            }
            if !found {
                messages.push(Vec::new()); // Push empty message if nothing found for this key
            }
        }

        local_latency.finish();
        end_to_end_latency.finish();

        Ok(messages)
    }

    /// Read messages from Server2.
    pub fn read(&self, k: &Key, cs: String, epoch_past: usize) -> Result<Vec<u8>, MycoError> {
        let epoch = self.epoch - 1 - epoch_past;
        let cs = cs.into_bytes();

        let (k_msg, k_oblv, k_prf) = self.keys.get(&k).unwrap();
        let k_oblv_t = kdf(k_oblv, &epoch.to_string()).map_err(|_| MycoError::NoMessageFound)?;
        let f = prf(&k_prf, &epoch.to_be_bytes())?;

        let keys = futures::executor::block_on(self.s2.get_prf_keys())
            .map_err(|_| MycoError::NoMessageFound)?;
        if keys.is_empty() {
            return Err(MycoError::NoMessageFound);
        }

        // Add bounds checking
        if epoch_past >= keys.len() {
            return Err(MycoError::NoMessageFound);
        }

        let k_s1_t = keys.get(keys.len() - 1 - epoch_past).unwrap();
        let l = prf(k_s1_t.0.as_slice(), &[&f[..], &cs[..]].concat())?;
        let l_path = Path::from(l);

        let indices = get_path_indices(vec![l_path]);
        let path = futures::executor::block_on(self.s2.read_paths_client(indices, BATCH_SIZE))
            .map_err(|_| MycoError::NoMessageFound)?;

        for bucket in path {
            for block in bucket {
                if let Ok(ct) = decrypt(&k_oblv_t, &block.0) {
                    return decrypt(k_msg, &ct).map(|buf| trim_zeros(&buf));
                }
            }
        }
        Err(MycoError::NoMessageFound)
    }

    /// Generate fake write data.
    pub fn fake_write(&self) -> Result<(), MycoError> {
        let mut rng = ChaCha20Rng::from_entropy();
        let l: Vec<u8> = (0..D).map(|_| rng.gen()).collect();
        let k_oblv_t: Key = Key::random(&mut rng);
        let ct: Vec<u8> = (0..BLOCK_SIZE).map(|_| rng.gen()).collect();
        let cs: Vec<u8> = self.id.clone().into_bytes();
        futures::executor::block_on(self.s1.queue_write(ct, l, k_oblv_t, cs))
    }

    /// Generate fake read data.
    pub fn fake_read(&self) -> Vec<Bucket> {
        let mut rng = ChaCha20Rng::from_entropy();
        let l: Vec<u8> = (0..D).map(|_| rng.gen()).collect();

        let indices = get_path_indices(vec![Path::from(l)]);
        futures::executor::block_on(self.s2.read_paths_client(indices, BATCH_SIZE)).unwrap()
    }
}
