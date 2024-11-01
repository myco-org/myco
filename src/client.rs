use crate::constants::{BLOCK_SIZE, D};
use crate::dtypes::{Bucket, Key, Path};
use crate::error::OramError;
use crate::logging::LatencyMetric;
use crate::network::{
    Command, Local, LocalServer1Access, LocalServer2Access, ReadType, Server1Access, Server2Access,
    WriteType,
};
use crate::tree::SparseBinaryTree;
use crate::{decrypt, encrypt, get_path_indices, kdf, prf, trim_zeros, EncryptionType, BATCH_SIZE};
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use bincode::{deserialize, serialize};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use ring::{digest, hkdf, pbkdf2};
use std::collections::HashMap;

/// A Myco client (user).
pub struct Client {
    pub id: String,
    pub epoch: usize,
    pub keys: HashMap<Key, (Vec<u8>, Vec<u8>, Vec<u8>)>,
    pub s1: Box<dyn Server1Access>,
    pub s2: Box<dyn Server2Access>,
}

impl Client {
    pub fn new(id: String, s1: Box<dyn Server1Access>, s2: Box<dyn Server2Access>) -> Self {
        Client {
            id,
            epoch: 0,
            keys: HashMap::new(),
            s1,
            s2,
        }
    }

    pub fn setup(&mut self, k: &Key) -> Result<(), OramError> {
        let end_to_end_latency = LatencyMetric::new("client_setup_end_to_end");
        let k_msg = kdf(&k.0, "MSG")?;
        let k_oram = kdf(&k.0, "ORAM")?;
        let k_prf = kdf(&k.0, "PRF")?;
        self.keys.insert(k.clone(), (k_msg, k_oram, k_prf));
        end_to_end_latency.finish();
        Ok(())
    }

    pub async fn async_write(&mut self, msg: &[u8], k: &Key) -> Result<(), OramError> {
        let end_to_end_latency = LatencyMetric::new("client_write_end_to_end");
        let local_latency = LatencyMetric::new("client_write_local");
        let epoch = self.epoch;
        let cs = self.id.clone().into_bytes();

        let (k_msg, k_oram, k_prf) = self.keys.get(k).unwrap();
        let f = prf(k_prf, &epoch.to_be_bytes())?;
        let k_oram_t = kdf(k_oram, &epoch.to_string())?;
        let ct = encrypt(k_msg, msg, EncryptionType::Encrypt)?;

        self.epoch += 1;
        local_latency.finish();
        self.s1.queue_write(ct, f, Key::new(k_oram_t), cs).await;
        end_to_end_latency.finish();
        Ok(())
    }

    pub fn write(&mut self, msg: &[u8], k: &Key) -> Result<(), OramError> {
        let epoch = self.epoch;
        let cs = self.id.clone().into_bytes();

        let (k_msg, k_oram, k_prf) = self.keys.get(k).unwrap();
        let f = prf(k_prf, &epoch.to_be_bytes())?;
        let k_oram_t = kdf(k_oram, &epoch.to_string())?;
        let ct = encrypt(k_msg, msg, EncryptionType::Encrypt)?;

        self.epoch += 1;
        futures::executor::block_on(self.s1.queue_write(ct, f, Key::new(k_oram_t), cs))
    }

    pub async fn async_read(
        &self,
        keys: Vec<Key>,
        cs: String,
        epoch_past: usize
    ) -> Result<Vec<Vec<u8>>, OramError> {
        if keys.len() != BATCH_SIZE {
            return Err(OramError::InvalidBatchSize);
        }

        let end_to_end_latency = LatencyMetric::new("client_read_end_to_end");
        let mut local_latency = LatencyMetric::new("client_read_local");
        let epoch = self.epoch - 1 - epoch_past;
        let cs: Vec<u8> = cs.into_bytes();

        // Get PRF keys from server2
        local_latency.pause();
        let get_prf_keys_latency = LatencyMetric::new("client_read_get_prf_keys");
        let server_keys = self
            .s2
            .get_prf_keys()
            .await
            .map_err(|_| OramError::NoMessageFound)?;
        get_prf_keys_latency.finish();
        local_latency.resume();

        if server_keys.is_empty() || epoch_past >= server_keys.len() {
            return Err(OramError::NoMessageFound);
        }

        let k_s1_t = server_keys.get(server_keys.len() - 1 - epoch_past).unwrap();
        
        // Calculate paths for all keys
        let mut paths = Vec::with_capacity(BATCH_SIZE);
        let mut key_data = Vec::with_capacity(BATCH_SIZE);

        for k in keys {
            let (k_msg, k_oram, k_prf) = self.keys.get(&k).unwrap();
            let k_oram_t = kdf(k_oram, &epoch.to_string()).map_err(|_| OramError::NoMessageFound)?;
            let f = prf(&k_prf, &epoch.to_be_bytes())?;
            
            let l = prf(k_s1_t.0.as_slice(), &[&f[..], &cs[..]].concat())?;
            let l_path = Path::from(l);
            paths.push(l_path);
            key_data.push((k_msg.clone(), k_oram_t));
        }

        // Get path indices and read paths
        let indices = get_path_indices(paths.clone());
        println!("Client: Read paths: {:?}", indices);

        local_latency.pause();
        let read_latency = LatencyMetric::new("client_read_read_paths");
        let buckets = self.s2.read_paths_client(indices.clone())
            .await
            .map_err(|_| OramError::NoMessageFound)?;
        read_latency.finish();
        local_latency.resume();

        // Try to decrypt messages from all paths
        let mut messages = Vec::new();
        
        // First, convert buckets into a BinaryTree
        let mut bucket_tree = SparseBinaryTree::new_with_data(buckets, indices);

        // Now process each key along its specific path
        for ((k_msg, k_oram_t), path) in key_data.into_iter().zip(paths.iter()) {
            let mut found = false;
            // Only check buckets along this key's path
            let path_buckets = bucket_tree.get_all_nodes_along_path(&path);
            
            for bucket in path_buckets {
                for block in bucket.iter() {
                    if let Ok(ct) = decrypt(&k_oram_t, &block.0) {
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

    pub fn read(&self, k: &Key, cs: String, epoch_past: usize) -> Result<Vec<u8>, OramError> {
        let epoch = self.epoch - 1 - epoch_past;
        let cs = cs.into_bytes();

        let (k_msg, k_oram, k_prf) = self.keys.get(&k).unwrap();
        let k_oram_t = kdf(k_oram, &epoch.to_string()).map_err(|_| OramError::NoMessageFound)?;
        let f = prf(&k_prf, &epoch.to_be_bytes())?;

        let keys = futures::executor::block_on(self.s2.get_prf_keys())
            .map_err(|_| OramError::NoMessageFound)?;
        if keys.is_empty() {
            return Err(OramError::NoMessageFound);
        }

        // Add bounds checking
        if epoch_past >= keys.len() {
            return Err(OramError::NoMessageFound);
        }

        let k_s1_t = keys.get(keys.len() - 1 - epoch_past).unwrap();
        let l = prf(k_s1_t.0.as_slice(), &[&f[..], &cs[..]].concat())?;
        let l_path = Path::from(l);

        let indices = get_path_indices(vec![l_path]);
        let path = futures::executor::block_on(self.s2.read_paths_client(indices))
            .map_err(|_| OramError::NoMessageFound)?;

        for bucket in path {
            for block in bucket {
                if let Ok(ct) = decrypt(&k_oram_t, &block.0) {
                    return decrypt(k_msg, &ct).map(|buf| trim_zeros(&buf));
                }
            }
        }
        Err(OramError::NoMessageFound)
    }

    pub fn fake_write(&self) -> Result<(), OramError> {
        let mut rng = ChaCha20Rng::from_entropy();
        let l: Vec<u8> = (0..D).map(|_| rng.gen()).collect();
        let k_oram_t: Key = Key::random(&mut rng);
        let ct: Vec<u8> = (0..BLOCK_SIZE).map(|_| rng.gen()).collect();
        let cs: Vec<u8> = self.id.clone().into_bytes();
        futures::executor::block_on(self.s1.queue_write(ct, l, k_oram_t, cs))
    }

    pub fn fake_read(&self) -> Vec<Bucket> {
        let mut rng = ChaCha20Rng::from_entropy();
        let l: Vec<u8> = (0..D).map(|_| rng.gen()).collect();

        let indices = get_path_indices(vec![Path::from(l)]);
        futures::executor::block_on(self.s2.read_paths_client(indices)).unwrap()
    }
}
