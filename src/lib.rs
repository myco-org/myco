use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use ::hkdf::Hkdf;
use rand::{thread_rng, Rng, RngCore};
use ring::{digest, hkdf, pbkdf2};
use sha2::Sha256;
use std::{collections::HashMap, num::NonZeroU32, sync::{Arc, Mutex}};
use thiserror::Error;

// Add module declarations
mod constants;
mod server1;
mod server2;
mod tree;
mod dtypes;

// Import constants and server modules
use constants::*;
use server1::Server1;
use server2::Server2;
use dtypes::*;

#[derive(Debug, Error)]
enum CryptoError {
    #[error("HKDF expansion failed")]
    HkdfExpansionFailed,
    #[error("HKDF fill failed")]
    HkdfFillFailed,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
}

pub(crate) fn u8_vec_to_path_vec(input: Vec<u8>) -> Path {
    Path::new(input
        .into_iter()
        .flat_map(|byte| {
            (0..8).rev().map(move |i| ((byte >> i) & 1).into())
        }).collect())
}

// Key Derivation Function (KDF)
fn kdf(key: &[u8], info: &str) -> Result<Vec<u8>, CryptoError> {
    let salt = digest::digest(&digest::SHA256, b"MC-OSAM-Salt");
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt.as_ref()).extract(key);
    let binding = [info.as_bytes()];
    let okm = prk
        .expand(&binding, hkdf::HKDF_SHA256)
        .map_err(|_| CryptoError::HkdfExpansionFailed)?;
    let mut result = vec![0u8; 32];
    okm.fill(&mut result)
        .map_err(|_| CryptoError::HkdfFillFailed)?;
    Ok(result)
}

// Pseudorandom Function (PRF)
// Make this an arbitrary-length PRF
fn prf(key: &[u8], input: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(1000).unwrap(),
        key,
        input,
        &mut result,
    );
    result
}

const NONCE_SIZE: usize = 12; // GCM standard nonce size is 12 bytes

fn encrypt(key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Step 1: Derive a 32-byte key for AES-256 using HKDF
    let hk = Hkdf::<Sha256>::new(None, key);
    let mut aes_key = [0u8; 32];
    hk.expand(b"encryption_key", &mut aes_key)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    // Step 2: Initialize AES-256-GCM with the derived key
    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|_| CryptoError::EncryptionFailed)?;
    
    // Step 3: Generate a random nonce
    let mut rng = rand::thread_rng();
    let nonce = rng.gen::<[u8; NONCE_SIZE]>();
    let nonce = Nonce::from_slice(&nonce);
    
    // Step 4: Encrypt the data
    let ciphertext = cipher.encrypt(nonce, message)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    // Concatenate the nonce and ciphertext
    Ok([nonce.as_slice(), ciphertext.as_slice()].concat())
}

fn decrypt(key: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if encrypted_data.len() < NONCE_SIZE {
        return Err(CryptoError::DecryptionFailed);
    }

    // Step 1: Derive the same 32-byte key for AES-256 using HKDF
    let hk = Hkdf::<Sha256>::new(None, key);
    let mut aes_key = [0u8; 32];
    hk.expand(b"encryption_key", &mut aes_key)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    // Step 2: Initialize AES-256-GCM with the derived key
    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|_| CryptoError::DecryptionFailed)?;

    // Step 3: Separate the nonce and the ciphertext
    let (nonce, ciphertext) = encrypted_data.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce);

    // Step 4: Decrypt the data
    cipher.decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}



struct Client {
    id: String,
    keys: HashMap<Key, (Vec<u8>, Vec<u8>, Vec<u8>)>,
    s1: Arc<Mutex<Server1>>,
    s2: Arc<Mutex<Server2>>,
}

impl Client {
    fn new(id: String, s1: Arc<Mutex<Server1>>, s2: Arc<Mutex<Server2>>) -> Self {
        Client {
            id,
            keys: HashMap::new(),
            s1,
            s2,
        }
    }

    fn setup(&mut self, k: &Key) -> Result<(), CryptoError> {
        let k_msg = kdf(&k.0, "MSG")?;
        let k_oram = kdf(&k.0, "ORAM")?;
        let k_prf = kdf(&k.0, "PRF")?;
        self.keys.insert(k.clone(), (k_msg, k_oram, k_prf));
        Ok(())
    }

    fn write(&mut self, msg: &[u8], k: &Key) -> Result<(), CryptoError> {
        let epoch  = self.s1.lock().unwrap().epoch;
        let cw = self.id.clone().into_bytes();

        // 1: {kmsg, koram, kprf } ← keys[k]
        let (k_msg, k_oram, k_prf) = self.keys.get(k).unwrap();

        // 2: ℓ = PRF_kprf (t)
        let l = prf(k_prf, &epoch.to_be_bytes());

        // 3: koram,t = KDF(koram, t)
        println!("epoch: {:?}", epoch);
        let k_oram_t = kdf(k_oram, &epoch.to_string())?;

        // 4: ct = Enckmsg (m)
        let ct = encrypt(k_msg, msg)?;
        // 5: return S1.Write(ct, ℓ, koram,t)
        self.s1.lock().unwrap().write(ct, l, Key::new(k_oram_t), cw)
    }

    fn read(&self, k: &Key) -> Result<Vec<u8>, CryptoError> {
        let epoch  = self.s1.lock().unwrap().epoch - 1;

        // 1: koram,t = KDF(koram, t)
        let (k_msg, k_oram, k_prf) = self.keys.get(&k).unwrap();
        let k_oram_t =
            kdf(k_oram, &epoch.to_string()).map_err(|_| CryptoError::DecryptionFailed)?;

        let f = prf(&k_prf, &epoch.to_be_bytes());

        // 2: ℓ = PRFkprf (t)
        let l = prf(k_prf, &[&f[..], &self.id.as_bytes()[..]].concat());

        // 3: p ← S2.Read(ℓ)
        let path = self.s2.lock().unwrap().read(&Path::from(l.clone()));

        // 4: for block ∈ p do
        for bucket in path {
            for block in bucket {
                if let Ok(c_msg)= decrypt(&k_oram_t, &block.0) {
                    return decrypt(k_msg, &c_msg);
                }
            }
        }
        // 8: end for
        Err(CryptoError::DecryptionFailed)
    }

    fn fake_write(&self) -> Result<(), CryptoError> {
        let mut rng = thread_rng();
        let l: Vec<u8> = (0..D).map(|_| rng.gen()).collect();
        let k_oram_t = Key::random(&mut rng);
        let ct: Vec<u8> = (0..64).map(|_| rng.gen()).collect();
        let cw = self.id.clone().into_bytes();
        self.s1.lock().unwrap().write(ct, l, k_oram_t, cw)
    }

    fn fake_read(&self) -> Vec<Bucket> {
        // 1: ℓ′ $ ←− {0, 1}^D
        let mut rng = thread_rng();
        let ll: Vec<u8> = (0..D).map(|_| rng.gen()).collect();
        // 2: S2.Read(ℓ′)
        self.s2.lock().unwrap().read(&u8_vec_to_path_vec(ll))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn try_to_decrypt_data_on_path(path: Vec<Bucket>, k_oram_t: &Key, k_msg: &Key) -> Result<Vec<u8>, CryptoError> {
        for bucket in path {
            for block in bucket {
                if let Ok(c_msg)= decrypt(&k_oram_t.0, &block.0) {
                    return decrypt(&k_msg.0, &c_msg);
                }
            }
        }
        Err(CryptoError::DecryptionFailed)
    }

    #[test]
    fn test_kdf() {
        let key = b"original key";
        let info1 = "purpose1";
        let info2 = "purpose2";

        let derived1 = kdf(key, info1).expect("KDF failed");
        let derived2 = kdf(key, info2).expect("KDF failed");

        assert_ne!(derived1, derived2);
        assert_eq!(derived1.len(), 32);
        assert_eq!(derived2.len(), 32);
    }

    #[test]
    fn test_prf() {
        let key = b"prf key";
        let input1 = b"input1";
        let input2 = b"input2";

        let output1 = prf(key, input1);
        let output2 = prf(key, input2);

        assert_ne!(output1, output2);
        assert_eq!(output1.len(), 32);
        assert_eq!(output2.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = kdf(b"encryption key", "enc").expect("KDF failed");
        let message = b"Hello, World!";

        let ciphertext = encrypt(&key, message).expect("Encryption failed");
        let decrypted = decrypt(&key, &ciphertext).expect("Decryption failed");

        assert_ne!(ciphertext, message);
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_client_setup() {
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s1 = Arc::new(Mutex::new(Server1::new(s2.clone())));
        let mut alice = Client::new("Alice".to_string(), s1, s2);
        let k = Key::random(&mut thread_rng());
        alice.setup(&k).expect("Setup failed");
        assert!(alice.keys.contains_key(&k));
    }

    #[test]
    fn test_write_and_read() {
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s1 = Arc::new(Mutex::new(Server1::new(s2.clone())));
        let mut alice = Client::new("Alice".to_string(), s1.clone(), s2);
        let k = Key::random(&mut thread_rng());
        alice.setup(&k).expect("Setup failed");

        s1.lock().unwrap().batch_init(1);

        alice.write(&[1, 2, 3], &k).expect("Write failed");
        s1.lock().unwrap().batch_write();

        let msg = alice.read(&k).expect("Read failed");
        assert_eq!(msg, vec![1, 2, 3]);
    }

    #[test]
    fn test_fake_operations() {
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s1 = Arc::new(Mutex::new(Server1::new(s2.clone())));
        let mut alice = Client::new("Alice".to_string(), s1.clone(), s2.clone());

        s1.lock().unwrap().batch_init(1);

        // Perform multiple fake writes
        for _ in 0..10 {
            alice.fake_write().expect("Fake write failed");
        }

        // Check that the server state hasn't changed
        let server_state_before = s1.lock().unwrap().pt.clone();
        s1.lock().unwrap().batch_write();
        let server_state_after = s1.lock().unwrap().pt.clone();
        assert_eq!(server_state_before, server_state_after, "Server state changed after fake writes");

        // Perform multiple fake reads
        for _ in 0..10 {
            let fake_read = alice.fake_read();
            assert_eq!(fake_read.len(), 1, "Fake read should return a single block");
            assert!(!fake_read[0].is_empty(), "Fake read block should be full of dummy data");
        }
        // Perform a real write and read operation
        let k = Key::random(&mut thread_rng());
        alice.setup(&k).expect("Setup failed");

        alice.write(&[1, 2, 3], &k).expect("Real write failed");
        s1.lock().unwrap().batch_write();

        let real_read = alice.read(&k).expect("Real read failed");
        assert_eq!(real_read, vec![1, 2, 3], "Real read should return the written data");

        // Extract keys for later use in decryption attempts
        let (k_msg, k_oram, _) = alice.keys.get(&k).unwrap();
        let epoch = s1.lock().unwrap().epoch;
        let k_oram_t = Key::new(kdf(k_oram, &epoch.to_string()).expect("KDF failed"));
        let k_msg = Key::new(k_msg.clone());

        // Perform more fake reads, ensure they don't return the real data
        for _ in 0..10 {
            let fake_read = alice.fake_read();
            let decrypted = try_to_decrypt_data_on_path(fake_read, &k_oram_t, &k_msg);
            assert!(decrypted.is_err(), "Fake read should not return real data");
        }

        // Verify that a real read returns the correct data
        let real_read = alice.read(&k).expect("Real read failed");
        assert_eq!(real_read, vec![1, 2, 3], "Real read should return the written data");
    }

//     #[test]
//     fn test_server1_batch_write() {
//         let mut s1 = Server1::new(0, Rc::new(RefCell::new(Server2::new())));
//         let dummy_data = vec![0; 64];
//         let dummy_l = vec![0; 32];
//         let dummy_k_oram_t = vec![0; 32];

//         for _ in 0..NUM_WRITES_PER_EPOCH {
//             s1.write(dummy_data.clone(), dummy_l.clone(), dummy_k_oram_t.clone())
//                 .expect("Server1 write failed");
//         }

//         assert_eq!(s1.epoch, 1);
//         assert_eq!(s1.counter, 0);
//         assert!(s1.write_queue.is_empty());
//     }

//     #[test]
//     fn test_server2_eviction() {
//         let mut s2 = Server2::new();
//         let dummy_block = Block {
//             bid: vec![0; 32],
//             data: vec![1; 64],
//         };

//         // Fill the tree
//         for _ in 0..(1 << TREE_HEIGHT) * BUCKET_SIZE {
//             s2.write(vec![dummy_block.clone()]);
//         }

//         // Perform eviction
//         s2.evict();

//         // Check if eviction happened (this is a simple check, might need adjustment)
//         let total_blocks: usize = s2.tree.iter().map(|level| level.len()).sum();
//         assert!(total_blocks < (1 << TREE_HEIGHT) * BUCKET_SIZE);
//     }

    #[test]
    fn test_encrypt_decrypt_different_key_sizes() {
        use crate::{encrypt, decrypt, Key};
        use rand::{thread_rng, RngCore};

        let mut rng = thread_rng();

        // Test cases with 128-bit and 256-bit key sizes
        let key_sizes = [128, 256]; // AES-128, AES-256
        let message = b"Hello, World!";

        for &key_size in &key_sizes {
            // Generate a random key of the specified size
            let mut key_data = vec![0u8; key_size];
            rng.fill_bytes(&mut key_data);
            let key = Key::new(key_data);

            // Encrypt the message
            let encrypted = encrypt(&key.0, message).expect("Encryption failed");

            // Decrypt the message
            let decrypted = decrypt(&key.0, &encrypted).expect("Decryption failed");

            // Check if the decrypted message matches the original
            assert_eq!(decrypted, message, "Decryption failed for key size: {} bits", key_size * 8);

            // Ensure the encrypted message is different from the original
            assert_ne!(encrypted, message, "Encryption didn't change the message for key size: {} bits", key_size * 8);
        }
    }


}
