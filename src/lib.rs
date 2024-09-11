use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::Rng;
use sha2::{Digest, Sha256};
use thiserror::Error;

const NONCE_SIZE: usize = 12;
const DELTA_EXP: u64 = 1000;

#[derive(Error, Debug)]
enum McOsamError {
    #[error("AES error")]
    AesError,
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Invalid nonce size")]
    InvalidNonceSize,
    #[error("Invalid metadata")]
    InvalidMetadata,
}

impl From<aes_gcm::Error> for McOsamError {
    fn from(_: aes_gcm::Error) -> Self {
        McOsamError::AesError
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EncryptedData {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

struct MultiClientObliviousMessaging {
    s1: Server1,
    s2: Server2,
    num_writes_per_epoch: usize,
}

struct Server1 {
    k_s1: Vec<u8>,
    counter: u64,
    t: u64,
    depth: usize,
}

struct ORAMNode {
    bucket: Vec<EncryptedData>,
}

impl ORAMNode {
    fn new(size: usize, dummy_block: EncryptedData) -> Self {
        Self {
            bucket: vec![dummy_block; size],
        }
    }
}

struct Server2 {
    root: ORAMNode,
    depth: usize,
}

impl MultiClientObliviousMessaging {
    fn new(num_writes_per_epoch: usize, depth: usize, dummy_block: EncryptedData) -> Self {
        Self {
            s1: Server1::new(depth),
            s2: Server2::new(depth, dummy_block),
            num_writes_per_epoch,
        }
    }

    fn write(&mut self, w: &str, r: &str, m: &[u8], t: u64) -> Result<(), McOsamError> {
        let shared_key = derive_shared_key(w, r);
        let k_prf = derive_key(&format!("{}-{}-prf", w, r), &shared_key);
        let k_oram = derive_key(&format!("{}-{}-oram", w, r), &shared_key);

        let l = prf(&k_prf, &t.to_string());
        let k_oram_t = kdf(t, &k_oram);

        let ct = encrypt(&k_oram_t, m)?;
        self.s1.receive_write(ct, l, k_oram_t, t, &mut self.s2)
    }

    fn read(
        &self,
        w: &str,
        r: &str,
        t: u64,
        is_real: bool,
    ) -> Result<Option<Vec<u8>>, McOsamError> {
        let shared_key = derive_shared_key(w, r);
        let k_oram = derive_key(&format!("{}-{}-oram", w, r), &shared_key);
        let k_oram_t = kdf(t, &k_oram);

        let k_prf = derive_key(&format!("{}-{}-prf", w, r), &shared_key);
        let l = prf(&k_prf, &t.to_string());

        let counter = t * self.num_writes_per_epoch as u64 + self.get_client_index(w, r);
        let bid = format!("{}||{}", counter, hex::encode(&l));

        let path = self.s2.rs_osam_read(&bid);

        if is_real {
            for c_msg in path {
                if let Ok(ct) = decrypt(&k_oram_t, &c_msg) {
                    let k_msg = derive_key(&format!("{}-{}-msg", w, r), &shared_key);
                    if let Ok(m) = decrypt(
                        &k_msg,
                        &EncryptedData {
                            nonce: ct[..NONCE_SIZE].to_vec(),
                            ciphertext: ct[NONCE_SIZE..].to_vec(),
                        },
                    ) {
                        return Ok(Some(m));
                    }
                }
            }
        }
        Ok(None)
    }

    fn get_client_index(&self, w: &str, r: &str) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(format!("{}-{}", w, r).as_bytes());
        let result = hasher.finalize();
        let index = u64::from_be_bytes(result[0..8].try_into().unwrap());
        index % self.num_writes_per_epoch as u64
    }

    fn evict(&mut self, v: usize) {
        self.s1.evict(v, &mut self.s2);
    }
}

impl Server1 {
    fn new(depth: usize) -> Self {
        Self {
            k_s1: random_bytes(32),
            counter: 0,
            t: 0,
            depth,
        }
    }

    fn receive_write(
        &mut self,
        ct: EncryptedData,
        l: Vec<u8>,
        k_oram_t: Vec<u8>,
        t: u64,
        s2: &mut Server2,
    ) -> Result<(), McOsamError> {
        let t_exp = t + DELTA_EXP;

        let c_msg = encrypt(&k_oram_t, &ct.ciphertext)?;
        let c_metadata = encrypt(
            &self.k_s1,
            &format!("{},{}", t_exp, hex::encode(&k_oram_t)).as_bytes(),
        )?;

        let bid = self.rs_osam_alloc(&l);
        self.rs_osam_write(&c_msg, &c_metadata, &bid, s2);
        Ok(())
    }

    fn evict(&mut self, nu: usize, s2: &mut Server2) {
        for d in 0..s2.depth {
            let buckets_at_depth = 1 << d;
            let eviction_count = nu.min(buckets_at_depth);
            let mut rng = rand::thread_rng();

            for _ in 0..eviction_count {
                let bucket_index = rng.gen_range(0..buckets_at_depth);
                self.evict_bucket(d, bucket_index, s2);
            }
        }
    }

    fn evict_bucket(&self, depth: usize, bucket_index: usize, s2: &mut Server2) {
        let path = self.get_path_to_bucket(depth, bucket_index);
        let dummy_bid = format!("{}||{}", self.counter, hex::encode(&path));

        let blocks_to_evict = s2.rs_osam_read(&dummy_bid);

        for block in blocks_to_evict {
            let new_path = self.get_random_path();
            s2.write(&hex::encode(&new_path), block);
        }
    }

    fn rs_osam_alloc(&mut self, l: &[u8]) -> String {
        let leaf = if l.is_empty() {
            (0..self.depth).map(|_| rand::random::<u8>()).collect()
        } else {
            l.to_vec()
        };

        let bid = format!("{}||{}", self.counter, hex::encode(&leaf));
        self.counter += 1;
        bid
    }

    fn rs_osam_write(
        &self,
        c_msg: &EncryptedData,
        c_metadata: &EncryptedData,
        bid: &str,
        s2: &mut Server2,
    ) {
        // Convert fixed-size array to slice and call `concat()`
        let combined_ciphertext: Vec<u8> =
            [&c_msg.ciphertext[..], &c_metadata.ciphertext[..]].concat();
        s2.write(
            bid,
            EncryptedData {
                nonce: vec![],
                ciphertext: combined_ciphertext,
            },
        );
    }

    fn get_path_to_bucket(&self, depth: usize, bucket_index: usize) -> Vec<u8> {
        (0..depth)
            .map(|d| ((bucket_index >> (depth - d - 1)) & 1) as u8)
            .collect()
    }

    fn get_random_path(&self) -> Vec<u8> {
        (0..self.depth).map(|_| rand::random::<u8>() & 1).collect()
    }
}

impl Server2 {
    fn new(depth: usize, dummy_block: EncryptedData) -> Self {
        Self {
            root: ORAMNode::new(depth, dummy_block),
            depth,
        }
    }

    fn write(&mut self, _bid: &str, data: EncryptedData) {
        // No need for `mut` here
        let current = &mut self.root;
        current.bucket.push(data);
    }

    fn rs_osam_read(&self, _bid: &str) -> Vec<EncryptedData> {
        // No need for `mut` here
        let path = vec![self.root.bucket.clone()].concat();
        path
    }
}

// Utility functions (prf, kdf, encrypt, decrypt, etc.)

fn derive_shared_key(w: &str, r: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}-{}", w, r).as_bytes());
    hasher.finalize().to_vec()
}

fn prf(key: &[u8], data: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(data.as_bytes());
    hasher.finalize().to_vec()
}

fn kdf(t: u64, key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(t.to_be_bytes());
    hasher.update(key);
    hasher.finalize().to_vec()
}

fn encrypt(key: &[u8], data: &[u8]) -> Result<EncryptedData, McOsamError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| McOsamError::InvalidKeyLength)?;
    let nonce_bytes = random_bytes(NONCE_SIZE);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, data)?;
    Ok(EncryptedData {
        nonce: nonce_bytes,
        ciphertext,
    })
}

fn decrypt(key: &[u8], data: &EncryptedData) -> Result<Vec<u8>, McOsamError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| McOsamError::InvalidKeyLength)?;
    if data.nonce.len() != NONCE_SIZE {
        return Err(McOsamError::InvalidNonceSize);
    }
    let nonce = Nonce::from_slice(&data.nonce);
    let plaintext = cipher.decrypt(nonce, data.ciphertext.as_ref())?;
    Ok(plaintext)
}

fn derive_key(info: &str, shared_key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(shared_key);
    hasher.update(info.as_bytes());
    hasher.finalize().to_vec()
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut rng = OsRng;
    (0..n).map(|_| rng.gen()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_and_read() {
        let dummy_block = EncryptedData {
            nonce: vec![0; NONCE_SIZE],
            ciphertext: vec![0; 16],
        };
        let mut mcosam = MultiClientObliviousMessaging::new(10, 4, dummy_block);
        let message = b"Hello, World!";
        let w = "alice";
        let r = "bob";
        let t = 1;

        mcosam.write(w, r, message, t).unwrap();

        let read_result = mcosam.read(w, r, t, true).unwrap();
        assert_eq!(read_result, Some(message.to_vec()));

        let wrong_read = mcosam.read("mallory", r, t, true).unwrap();
        assert_eq!(wrong_read, None);
    }

    #[test]
    fn test_multiple_writes_and_reads() {
        let dummy_block = EncryptedData {
            nonce: vec![0; NONCE_SIZE],
            ciphertext: vec![0; 16],
        };
        let mut mcosam = MultiClientObliviousMessaging::new(10, 4, dummy_block);
        let messages = vec![
            (b"Message 1".to_vec(), "alice", "bob", 1),
            (b"Message 2".to_vec(), "bob", "charlie", 2),
            (b"Message 3".to_vec(), "charlie", "alice", 3),
        ];

        for (m, w, r, t) in &messages {
            mcosam.write(w, r, m, *t).unwrap();
        }

        for (m, w, r, t) in &messages {
            let read_result = mcosam.read(w, r, *t, true).unwrap();
            assert_eq!(read_result, Some(m.clone()));
        }
    }

    #[test]
    fn test_eviction() {
        let dummy_block = EncryptedData {
            nonce: vec![0; NONCE_SIZE],
            ciphertext: vec![0; 16],
        };
        let mut mcosam = MultiClientObliviousMessaging::new(10, 4, dummy_block);
        let message = b"Eviction test";
        let w = "alice";
        let r = "bob";
        let t = 1;

        mcosam.write(w, r, message, t).unwrap();

        mcosam.evict(5);

        let read_result = mcosam.read(w, r, t, true).unwrap();
        assert_eq!(read_result, Some(message.to_vec()));
    }
}
