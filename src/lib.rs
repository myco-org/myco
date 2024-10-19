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
    NoMessageFound,
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
        return Err(CryptoError::NoMessageFound);
    }

    // Step 1: Derive the same 32-byte key for AES-256 using HKDF
    let hk = Hkdf::<Sha256>::new(None, key);
    let mut aes_key = [0u8; 32];
    hk.expand(b"encryption_key", &mut aes_key)
        .map_err(|_| CryptoError::NoMessageFound)?;

    // Step 2: Initialize AES-256-GCM with the derived key
    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|_| CryptoError::NoMessageFound)?;

    // Step 3: Separate the nonce and the ciphertext
    let (nonce, ciphertext) = encrypted_data.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce);

    // Step 4: Decrypt the data
    let decrypted = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::NoMessageFound)?;

    // Ok(decrypted.into_iter().rev().skip_while(|&x| x == 0).collect::<Vec<_>>().into_iter().rev().collect())
    Ok(decrypted)
}



struct Client {
    id: String,
    epoch: usize,
    keys: HashMap<Key, (Vec<u8>, Vec<u8>, Vec<u8>)>,
    s1: Arc<Mutex<Server1>>,
    s2: Arc<Mutex<Server2>>,
}

impl Client {
    fn new(id: String, s1: Arc<Mutex<Server1>>, s2: Arc<Mutex<Server2>>) -> Self {
        Client {
            id,
            epoch: 0,
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
        let epoch  = self.epoch;
        let cw = self.id.clone().into_bytes();

        // 1: {kmsg, koram, kprf } ← keys[k]
        let (k_msg, k_oram, k_prf) = self.keys.get(k).unwrap();

        // 2: ℓ = PRF_kprf (t)
        let f = prf(k_prf, &epoch.to_be_bytes());

        // 3: koram,t = KDF(koram, t)
        let k_oram_t = kdf(k_oram, &epoch.to_string())?;

        // 4: ct = Enckmsg (m)
        let ct = encrypt(k_msg, msg)?;

        self.epoch += 1;
        // 5: return S1.Write(ct, ℓ, koram,t)
        self.s1.lock().unwrap().write(ct, f, Key::new(k_oram_t), cw)
    }

    fn read(&self, k: &Key, cw: String) -> Result<Vec<u8>, CryptoError> {
        let epoch  = self.epoch - 1;
        let cw = cw.into_bytes();

        // 1: koram,t = KDF(koram, t)
        let (k_msg, k_oram, k_prf) = self.keys.get(&k).unwrap();
        let k_oram_t =
            kdf(k_oram, &epoch.to_string()).map_err(|_| CryptoError::NoMessageFound)?;


        let f = prf(&k_prf, &epoch.to_be_bytes());

        let k_s1_t = self.s1.lock().unwrap().k_s1_t.clone();

        // 2: ℓ = PRFkprf (t)
        let l = prf(k_s1_t.0.as_slice(), &[&f[..], &cw[..]].concat());

        // 3: p ← S2.Read(ℓ)
        let path = self.s2.lock().unwrap().read(&Path::from(l.clone()));


        // 4: for block ∈ p do
        for bucket in path {
            for block in bucket {
                if let Ok(ct) = decrypt(&k_oram_t, &block.0) {
                    return decrypt(k_msg, &ct);
                }
            }
        }
        // 8: end for
        Err(CryptoError::NoMessageFound)
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
mod e2e_tests {
    use super::*;

    fn try_to_decrypt_data_on_path(path: Vec<Bucket>, k_oram_t: &Key, k_msg: &Key) -> Result<Vec<u8>, CryptoError> {
        for bucket in path {
            for block in bucket { 
                if let Ok(c_msg)= decrypt(&k_oram_t.0, &block.0) {
                    return decrypt(&k_msg.0, &c_msg);
                }
            }
        }
        Err(CryptoError::NoMessageFound)
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
    fn test_encrypt_decrypt_with_kdf_key() {
        // Test with KDF-derived key
        let key = kdf(b"encryption key", "enc").expect("KDF failed");
        let message = b"1234";

        let ciphertext = encrypt(&key, message).expect("Encryption failed");
        let decrypted = decrypt(&key, &ciphertext).expect("Decryption failed");

        assert_ne!(ciphertext, message);
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_encrypt_decrypt_with_random_key() {
        // Test with random key
        let random_key = Key::random(&mut thread_rng());
        let random_message = b"123987234789234";

        let random_ciphertext = encrypt(&random_key.0, random_message).expect("Encryption failed");
        let random_decrypted = decrypt(&random_key.0, &random_ciphertext).expect("Decryption failed");

        assert_ne!(random_ciphertext, random_message);
        assert_eq!(random_decrypted, random_message);
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

        alice.write(&[1], &k).expect("Write failed");
        s1.lock().unwrap().batch_write();

        let msg = alice.read(&k, "Alice".to_string()).expect("Read failed");
        assert_eq!(msg, vec![1]);
    }

    #[test]
    fn test_multiple_clients_one_epoch() {
        for _ in 0..1000 {
            let s2 = Arc::new(Mutex::new(Server2::new()));
            let s1 = Arc::new(Mutex::new(Server1::new(s2.clone())));
            let mut alice = Client::new("Alice".to_string(), s1.clone(), s2.clone());
            let mut bob = Client::new("Bob".to_string(), s1.clone(), s2.clone());

            let k1 = Key::random(&mut thread_rng());
            let k2 = Key::random(&mut thread_rng());

            alice.setup(&k1).expect("Setup failed");
            alice.setup(&k2).expect("Setup failed");

            bob.setup(&k1).expect("Setup failed");
            bob.setup(&k2).expect("Setup failed");

            s1.lock().unwrap().batch_init(2);

            alice.write(&[1], &k1).expect("Write failed");
            bob.write(&[2], &k2).expect("Write failed");

            s1.lock().unwrap().batch_write();

            let msg = alice.read(&k2, "Bob".to_string()).expect("Read failed");
            assert_eq!(msg, vec![2]);

            let msg = bob.read(&k1, "Alice".to_string()).expect("Read failed");
            assert_eq!(msg, vec![1]);
        }
    }

    #[test]
    fn test_multiple_writes_and_reads() {
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s1 = Arc::new(Mutex::new(Server1::new(s2.clone())));
        let mut alice = Client::new("Alice".to_string(), s1.clone(), s2);
        
        let num_operations = 5;

        // Perform multiple writes
        for i in 0..num_operations {
            let k = Key::random(&mut thread_rng());
            let msg = vec![i as u8, (i + 1) as u8, (i + 2) as u8];

            alice.setup(&k).expect("Setup failed");
            s1.lock().unwrap().batch_init(1);
            alice.write(&msg, &k).expect("Write failed");
            s1.lock().unwrap().batch_write();
            let read_msg = alice.read(&k, "Alice".to_string()).expect("Read failed");

            assert_eq!(read_msg, msg, "Read message doesn't match written message for key {}", i);
        }
    }

    #[test]
    fn test_multiple_clients_multiple_epochs() {
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s1 = Arc::new(Mutex::new(Server1::new(s2.clone())));
        
        let mut alice = Client::new("Alice".to_string(), s1.clone(), s2.clone());
        let mut bob = Client::new("Bob".to_string(), s1.clone(), s2.clone());
        
        let mut rng = thread_rng();
        
        // Initialize the first epoch
        
        for _ in 0..5 {
            s1.lock().unwrap().batch_init(2);

            // Perform writes for both clients
            let k_alice_to_bob = Key::random(&mut rng);
            let k_bob_to_alice = Key::random(&mut rng);

            alice.setup(&k_alice_to_bob).expect("Setup failed");
            alice.setup(&k_bob_to_alice).expect("Setup failed");

            bob.setup(&k_bob_to_alice).expect("Setup failed");
            bob.setup(&k_alice_to_bob).expect("Setup failed");

            let alice_msg: Vec<u8> = (0..16).map(|_| rng.next_u32() as u8).collect();
            let bob_msg: Vec<u8> = (0..16).map(|_| rng.next_u32() as u8).collect();
            alice.write(&alice_msg, &k_alice_to_bob).expect("Write failed");
            bob.write(&bob_msg, &k_bob_to_alice).expect("Write failed");
            
            // Perform batch write
            s1.lock().unwrap().batch_write();
            
            let alice_read = alice.read(&k_bob_to_alice, "Bob".to_string()).expect("Read failed");
            assert_eq!(bob_msg, alice_read, "Read message doesn't match written message for bob");
            
            let bob_read = bob.read(&k_alice_to_bob, "Alice".to_string()).expect("Read failed");
            assert_eq!(alice_msg, bob_read, "Read message doesn't match written message for alice");
        }
    }

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
