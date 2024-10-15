// Standard library imports
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};

// External crate imports
use rand::{thread_rng, Rng};
use ring::{aead, digest, hkdf, pbkdf2, rand::SecureRandom};

// Internal module declarations
mod constants;
mod server1;
mod server2;
mod tree;
mod dtypes;
mod error;

// Internal module imports
use constants::*;
use server1::Server1;
use server2::Server2;
use dtypes::*;
use error::McOsamError;

/// Converts a vector of u8 to a Path.
///
/// This function takes a vector of bytes and converts it to a Path by
/// expanding each byte into its individual bits.
///
/// # Arguments
///
/// * `input` - A vector of u8 to be converted to a Path.
///
/// # Returns
///
/// A Path object representing the binary expansion of the input vector.
pub(crate) fn u8_vec_to_path_vec(input: Vec<u8>) -> Path {
    Path::new(input
        .into_iter()
        .flat_map(|byte| {
            (0..8).rev().map(move |i| ((byte >> i) & 1).into())
        }).collect())
}

/// Key Derivation Function (KDF)
///
/// This function derives a new key from an input key and some context information.
///
/// # Arguments
///
/// * `key` - The input key material.
/// * `info` - Additional context information for the key derivation.
///
/// # Returns
///
/// A Result containing either the derived key as a Vec<u8>, or a McOsamError.
fn kdf(key: &[u8], info: &str) -> Result<Vec<u8>, McOsamError> {
    let salt = digest::digest(&digest::SHA256, b"MC-OSAM-Salt");
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt.as_ref()).extract(key);
    let binding = [info.as_bytes()];
    let okm = prk
        .expand(&binding, hkdf::HKDF_SHA256)
        .map_err(|_| McOsamError::HkdfExpansionFailed)?;
    let mut result = vec![0u8; 32];
    okm.fill(&mut result)
        .map_err(|_| McOsamError::HkdfFillFailed)?;
    Ok(result)
}

/// Pseudorandom Function (PRF)
///
/// This function generates a pseudorandom output based on a key and input.
///
/// # Arguments
///
/// * `key` - The key for the PRF.
/// * `input` - The input data for the PRF.
///
/// # Returns
///
/// A Vec<u8> containing the pseudorandom output.
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

/// Encryption function
///
/// This function encrypts a message using AES-256-GCM.
///
/// # Arguments
///
/// * `key` - The encryption key.
/// * `message` - The message to be encrypted.
///
/// # Returns
///
/// A Result containing either the encrypted message as a Vec<u8>, or a McOsamError.
fn encrypt(key: &[u8], message: &[u8]) -> Result<Vec<u8>, McOsamError> {
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| McOsamError::EncryptionFailed)?;
    let mut sealing_key: aead::LessSafeKey = aead::LessSafeKey::new(key);

    let mut nonce = [0u8; 12];
    ring::rand::SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| McOsamError::EncryptionFailed)?;

    let mut in_out = message.to_vec();
    sealing_key
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut in_out,
        )
        .map_err(|_| McOsamError::EncryptionFailed)?;

    let mut result = nonce.to_vec();
    result.extend(in_out);
    Ok(result)
}

/// Decryption function
///
/// This function decrypts a ciphertext using AES-256-GCM.
///
/// # Arguments
///
/// * `key` - The decryption key.
/// * `ciphertext` - The ciphertext to be decrypted.
///
/// # Returns
///
/// A Result containing either the decrypted message as a Vec<u8>, or a McOsamError.
fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, McOsamError> {
    if ciphertext.len() < 12 + 16 {
        return Err(McOsamError::DecryptionFailed);
    }

    let key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| McOsamError::DecryptionFailed)?;
    let opening_key = aead::LessSafeKey::new(key);

    let nonce = aead::Nonce::try_assume_unique_for_key(&ciphertext[..12])
        .map_err(|_| McOsamError::DecryptionFailed)?;
    let mut in_out = ciphertext[12..].to_vec();

    opening_key
        .open_in_place(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| McOsamError::DecryptionFailed)?;

    in_out.truncate(in_out.len() - 16); // Remove the tag
    Ok(in_out)
}

/// Represents a client in the MC-OSAM system.
struct Client {
    /// The client's identifier.
    id: String,
    /// A map of keys for communicating with other clients.
    keys: HashMap<String, (Vec<u8>, Vec<u8>, Vec<u8>)>,
    /// A reference to Server1.
    s1: Arc<RwLock<Server1>>,
    /// A reference to Server2.
    s2: Arc<RwLock<Server2>>,
}

impl Client {
    /// Creates a new Client instance.
    ///
    /// # Arguments
    ///
    /// * `id` - The client's identifier.
    /// * `s1` - A reference to Server1.
    /// * `s2` - A reference to Server2.
    ///
    /// # Returns
    ///
    /// A new Client instance.
    fn new(id: String, s1: Arc<RwLock<Server1>>, s2: Arc<RwLock<Server2>>) -> Self {
        Client {
            id,
            keys: HashMap::new(),
            s1,
            s2,
        }
    }

    /// Sets up the client's keys for communicating with other clients.
    ///
    /// # Arguments
    ///
    /// * `other_clients` - A slice of strings representing other clients' identifiers.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure.
    fn setup(&mut self, other_clients: &[String]) -> Result<(), McOsamError> {
        for client in other_clients {
            let k: Vec<u8> = (0..32).map(|_| thread_rng().gen()).collect();
            let k_msg = kdf(&k, "MSG")?;
            let k_oram = kdf(&k, "ORAM")?;
            let k_prf = kdf(&k, "PRF")?;
            self.keys.insert(client.clone(), (k_msg, k_oram, k_prf));
        }
        Ok(())
    }

    /// Writes a message to another client.
    ///
    /// # Arguments
    ///
    /// * `msg` - The message to be written.
    /// * `recipient` - The recipient's identifier.
    /// * `cw` - Additional write information.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure.
    fn write(&mut self, msg: &[u8], recipient: &str, cw: Vec<u8>) -> Result<(), McOsamError> {
        let epoch = self.s1.read().map_err(|_| McOsamError::ServerLockFailed)?.epoch;
        let (k_msg, k_oram, k_prf) = self.keys.get(recipient).unwrap();
        let l = prf(k_prf, &epoch.to_be_bytes());
        let k_oram_t = kdf(k_oram, &epoch.to_string())?;
        let ct = encrypt(k_msg, msg)?;
        self.s1.write().map_err(|_| McOsamError::ServerLockFailed)?.write(ct, l, Key::new(k_oram_t), cw)
    }

    /// Reads a message from another client.
    ///
    /// # Arguments
    ///
    /// * `sender` - The sender's identifier.
    ///
    /// # Returns
    ///
    /// A Result containing either the decrypted message or an error.
    fn read(&self, sender: &str) -> Result<Vec<u8>, McOsamError> {
        let epoch = self.s1.read().map_err(|_| McOsamError::ServerLockFailed)?.epoch;
        let (k_msg, k_oram, k_prf) = self.keys.get(sender).unwrap();
        let k_oram_t = kdf(k_oram, &epoch.to_string())?;
        let f = prf(&k_prf, &epoch.to_be_bytes());
        let l = prf(k_prf, &[&f[..], &sender.as_bytes()[..]].concat());
        let path = self.s2.read().map_err(|_| McOsamError::ServerLockFailed)?.read(&Path::from(l.clone()));

        for bucket in path {
            for block in bucket {
                if let Ok(c_msg) = decrypt(&k_oram_t, &block.0) {
                    return decrypt(k_msg, &c_msg);
                }
            }
        }
        Err(McOsamError::DecryptionFailed)
    }

    /// Performs a fake write operation.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure.
    fn fake_write(&self) -> Result<(), McOsamError> {
        let mut rng = thread_rng();
        let l: Vec<u8> = (0..D).map(|_| rng.gen()).collect();
        let k_oram_t: Vec<u8> = (0..LAMBDA).map(|_| rng.gen()).collect();
        let ct: Vec<u8> = (0..64).map(|_| rng.gen()).collect();
        todo!()
    }

    /// Performs a fake read operation.
    ///
    /// # Returns
    ///
    /// A vector of Buckets.
    fn fake_read(&self) -> Vec<Bucket> {
        let mut rng = thread_rng();
        let ll: Vec<u8> = (0..D).map(|_| rng.gen()).collect();
        self.s2.read().unwrap().read(&u8_vec_to_path_vec(ll))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let s2 = Arc::new(RwLock::new(Server2::new()));
        let s1 = Arc::new(RwLock::new(Server1::new(s2.clone())));
        let mut alice = Client::new("Alice".to_string(), s1, s2);
        alice.setup(&["Bob".to_string()]).expect("Setup failed");
        assert!(alice.keys.contains_key("Bob"));
    }

    #[test]
    fn test_write_and_read() {
        let s2 = Arc::new(RwLock::new(Server2::new()));
        let s1 = Arc::new(RwLock::new(Server1::new(s2.clone())));
        let mut alice = Client::new("Alice".to_string(), s1.clone(), s2);
        alice.setup(&["Bob".to_string()]).expect("Setup failed");

        s1.write().unwrap().batch_init(1).expect("Batch init failed");

        alice.write(&[1, 2, 3], "Bob", vec![]).expect("Write failed");
        s1.write().unwrap().batch_write().expect("Batch write failed");

        let msg = alice.read("Bob").expect("Read failed");
        assert_eq!(msg, vec![1, 2, 3]);
    }
}