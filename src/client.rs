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

use crate::{
    constants::{BATCH_SIZE, BLOCK_SIZE, D},
    crypto::{decrypt, encrypt, kdf, prf, EncryptionType},
    dtypes::{Bucket, Key, Path},
    error::MycoError,
    logging::LatencyMetric,
    network::{Server1Access, Server2Access},
    tree::SparseBinaryTree,
    utils::{get_path_indices, trim_zeros},
};
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

        // Insert keys into the client
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
        let f = prf(k_prf, &epoch.to_be_bytes())?; // PRF for this epoch
        let k_oblv_t = kdf(k_oblv, &epoch.to_string())?; // Oblivious key for this epoch
        let ct = encrypt(k_msg, msg, EncryptionType::Encrypt)?; // Encrypt the message

        self.epoch += 1;
        local_latency.finish();

        // Upload the message to Server1
        self.s1
            .queue_write(ct, f, Key::new(k_oblv_t), cs)
            .await
            .map_err(|_| MycoError::NoMessageFound)?;
        end_to_end_latency.finish();
        Ok(())
    }

    /// Write a message to Server1.
    pub fn write(&mut self, msg: &[u8], k: &Key) -> Result<(), MycoError> {
        let epoch = self.epoch;
        let cs = self.id.clone().into_bytes();

        let (k_msg, k_oblv, k_prf) = self.keys.get(k).unwrap(); // Get the keys for this key
        let f = prf(k_prf, &epoch.to_be_bytes())?; // PRF for this epoch
        let k_oblv_t = kdf(k_oblv, &epoch.to_string())?; // Oblivious key for this epoch
        let ct = encrypt(k_msg, msg, EncryptionType::Encrypt)?; // Encrypt the message

        self.epoch += 1;
        futures::executor::block_on(self.s1.queue_write(ct, f, Key::new(k_oblv_t), cs))
        // Upload the message to Server1
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
        let cs: Vec<u8> = cs.into_bytes(); // Convert the client ID to a byte vector

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

        let k_s1_t = server_keys.get(server_keys.len() - 1 - epoch_past).unwrap(); // Get the S1 key for this epoch

        // Calculate paths for all keys
        let mut paths = Vec::with_capacity(batch_size);
        let mut key_data = Vec::with_capacity(batch_size);

        // For each key, derive the necessary cryptographic values for the current epoch
        for k in keys {
            let (k_msg, k_oblv, k_prf) = self.keys.get(&k).unwrap();
            let k_oblv_t =
                kdf(k_oblv, &epoch.to_string()).map_err(|_| MycoError::NoMessageFound)?;
            let f = prf(&k_prf, &epoch.to_be_bytes())?;

            // Calculate the path location using the server's key and the derived PRF value
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

            // Iterate over each bucket along the path to find and decrypt the message
            for bucket in path_buckets {
                for block in bucket.iter() {
                    // Attempt to decrypt the block with the oblivious key
                    if let Ok(ct) = decrypt(&k_oblv_t, &block.0) {
                        // If successful, attempt to decrypt the ciphertext with the message key
                        if let Ok(msg) = decrypt(&k_msg, &ct) {
                            // If decryption is successful, trim any padding and add the message to the list
                            messages.push(trim_zeros(&msg));
                            found = true;
                            break; // Exit the loop once the message is found
                        }
                    }
                }
                if found {
                    break; // Exit the outer loop if the message has been found
                }
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

        // Retrieve the cryptographic keys for the given key and derive the necessary values for the current epoch
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

        // Retrieve the server's key for the specified past epoch and calculate the path location
        let k_s1_t = keys.get(keys.len() - 1 - epoch_past).unwrap();
        let l = prf(k_s1_t.0.as_slice(), &[&f[..], &cs[..]].concat())?;
        let l_path = Path::from(l);

        // Calculate path indices and read the corresponding paths from Server2
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

        // Generate random data for a fake write operation
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
