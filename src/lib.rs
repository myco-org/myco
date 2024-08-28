use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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
}

impl From<aes_gcm::Error> for McOsamError {
    fn from(_: aes_gcm::Error) -> Self {
        McOsamError::AesError
    }
}

#[derive(Clone, Debug)]
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
}

struct Server2 {
    tree: HashMap<String, EncryptedData>,
}

impl MultiClientObliviousMessaging {
    fn new(num_writes_per_epoch: usize) -> Self {
        Self {
            s1: Server1::new(),
            s2: Server2::new(),
            num_writes_per_epoch,
        }
    }

    fn write(&mut self, w: &str, r: &str, m: &[u8], t: u64) -> Result<(), McOsamError> {
        let k_msg = derive_key(&format!("{}-{}-msg", w, r));
        let k_prf = derive_key(&format!("{}-{}-prf", w, r));
        let k_oram = derive_key(&format!("{}-{}-oram", w, r));

        let ct = encrypt(&k_msg, m)?;
        let l = prf(&k_prf, &t.to_string());
        let k_oram_t = kdf(t, &k_oram);

        self.s1.receive_write(ct, l, k_oram_t, t, &mut self.s2)
    }

    fn read(
        &self,
        w: &str,
        r: &str,
        t: u64,
        is_real: bool,
    ) -> Result<Option<Vec<u8>>, McOsamError> {
        let k_oram = derive_key(&format!("{}-{}-oram", w, r));
        let k_prf = derive_key(&format!("{}-{}-prf", w, r));

        let k_oram_t = kdf(t, &k_oram);
        let l = prf(&k_prf, &t.to_string());

        let path = self.s2.read(&l);
        if is_real {
            for c_msg in path {
                if let Ok(ct) = decrypt(&k_oram_t, &c_msg) {
                    let k_msg = derive_key(&format!("{}-{}-msg", w, r));
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

    fn evict(&mut self, v: usize) {
        self.s1.evict(v, &mut self.s2);
    }
}

impl Server1 {
    fn new() -> Self {
        Self {
            k_s1: random_bytes(32),
            counter: 0,
            t: 0,
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
        let mut c_msg = ct.nonce.clone();
        c_msg.extend_from_slice(&ct.ciphertext);
        let c_msg = encrypt(&k_oram_t, &c_msg)?;
        let c_metadata = encrypt(
            &self.k_s1,
            &format!("{},{}", t_exp, hex::encode(&k_oram_t)).as_bytes(),
        )?;
        let bid = self.rs_osam_alloc(&l);
        self.rs_osam_write(&c_msg, &c_metadata, &bid, s2);
        Ok(())
    }

    fn evict(&mut self, _v: usize, _s2: &mut Server2) {
        // Implementation of RS-OSAM evict operation
    }

    fn rs_osam_alloc(&mut self, l: &[u8]) -> String {
        let bid = format!("{}||{}", self.counter, hex::encode(l));
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
        // Combine c_msg and c_metadata
        let mut combined = c_msg.nonce.clone();
        combined.extend_from_slice(&c_msg.ciphertext);
        combined.extend_from_slice(&c_metadata.nonce);
        combined.extend_from_slice(&c_metadata.ciphertext);

        // Write to S2's tree
        s2.tree.insert(
            bid.to_string(),
            EncryptedData {
                nonce: vec![],
                ciphertext: combined,
            },
        );
    }
}

impl Server2 {
    fn new() -> Self {
        Self {
            tree: HashMap::new(),
        }
    }

    fn read(&self, _l: &[u8]) -> Vec<EncryptedData> {
        // This is a simplified read operation
        // In a real implementation, this would traverse the ORAM tree
        self.tree.values().cloned().collect()
    }
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

fn derive_key(info: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
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
        let mut mcosam = MultiClientObliviousMessaging::new(10);
        let message = b"Hello, World!";
        let w = "alice";
        let r = "bob";
        let t = 1;

        // Write a message
        mcosam.write(w, r, message, t).unwrap();

        // Read the message
        let read_result = mcosam.read(w, r, t, true).unwrap();
        assert_eq!(read_result, Some(message.to_vec()));

        // Try to read with wrong parameters
        let wrong_read = mcosam.read("mallory", r, t, true).unwrap();
        assert_eq!(wrong_read, None);
    }

    #[test]
    fn test_multiple_writes_and_reads() {
        let mut mcosam = MultiClientObliviousMessaging::new(10);
        let messages = vec![
            (b"Message 1".to_vec(), "alice", "bob", 1),
            (b"Message 2".to_vec(), "bob", "charlie", 2),
            (b"Message 3".to_vec(), "charlie", "alice", 3),
        ];

        // Write messages
        for (m, w, r, t) in &messages {
            mcosam.write(w, r, m, *t).unwrap();
        }

        // Read messages
        for (m, w, r, t) in &messages {
            let read_result = mcosam.read(w, r, *t, true).unwrap();
            assert_eq!(read_result, Some(m.clone()));
        }
    }

    #[test]
    fn test_eviction() {
        let mut mcosam = MultiClientObliviousMessaging::new(10);
        let message = b"Eviction test";
        let w = "alice";
        let r = "bob";
        let t = 1;

        // Write a message
        mcosam.write(w, r, message, t).unwrap();

        // Perform eviction
        mcosam.evict(5);

        // The message should still be readable after eviction
        let read_result = mcosam.read(w, r, t, true).unwrap();
        assert_eq!(read_result, Some(message.to_vec()));
    }

    #[test]
    fn test_encryption_decryption() {
        let key = random_bytes(32);
        let data = b"Test data";

        let encrypted = encrypt(&key, data).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_prf_and_kdf() {
        let key = random_bytes(32);
        let data = "test_data";
        let t = 1234;

        let prf_result = prf(&key, data);
        assert_eq!(prf_result.len(), 32);

        let kdf_result = kdf(t, &key);
        assert_eq!(kdf_result.len(), 32);
    }
}
