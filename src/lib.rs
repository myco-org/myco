use rand::{thread_rng, Rng};
use ring::{aead, digest, hkdf, pbkdf2, rand::SecureRandom};
use std::{cell::RefCell, cmp::Ordering, collections::HashMap, num::NonZeroU32, rc::Rc};
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

// Encryption
fn encrypt(key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let mut sealing_key: aead::LessSafeKey = aead::LessSafeKey::new(key);

    let mut nonce = [0u8; 12];
    ring::rand::SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut in_out = message.to_vec();
    sealing_key
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut in_out,
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut result = nonce.to_vec();
    result.extend(in_out);
    Ok(result)
}

// Decryption
fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < 12 + 16 {
        return Err(CryptoError::DecryptionFailed);
    }

    let key = aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let opening_key = aead::LessSafeKey::new(key);

    let nonce = aead::Nonce::try_assume_unique_for_key(&ciphertext[..12])
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let mut in_out = ciphertext[12..].to_vec();

    opening_key
        .open_in_place(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    in_out.truncate(in_out.len() - 16); // Remove the tag
    Ok(in_out)
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Block(Vec<u8>);

pub(crate) fn new_bid() -> Vec<u8> {
    let mut rng = thread_rng();
    (0..D).map(|_| rng.gen()).collect()
}

impl Block {
    pub(crate) fn new(data: Vec<u8>) -> Self {
        Block(data)
    }

    pub(crate) fn new_random() -> Self {
        let mut rng = thread_rng();
        Block((0..64).map(|_| rng.gen()).collect())
    }
}

struct Client {
    id: String,
    keys: HashMap<String, (Vec<u8>, Vec<u8>, Vec<u8>)>,
    s1: Rc<RefCell<Server1>>,
    s2: Rc<RefCell<Server2>>,
}

impl Client {
    fn new(id: String, s1: Rc<RefCell<Server1>>, s2: Rc<RefCell<Server2>>) -> Self {
        Client {
            id,
            keys: HashMap::new(),
            s1,
            s2,
        }
    }

    fn setup(&mut self, other_clients: &[String]) -> Result<(), CryptoError> {
        // 2: for k ∈ K: do
        for client in other_clients {
            // 3: kmsg = KDF(k, “MSG”)
            let k: Vec<u8> = (0..32).map(|_| thread_rng().gen()).collect();
            let k_msg = kdf(&k, "MSG")?;
            // 4: koram = KDF(k, “ORAM”)
            let k_oram = kdf(&k, "ORAM")?;
            // 5: kprf = KDF(k, “PRF”)
            let k_prf = kdf(&k, "PRF")?;
            // 6: client.keys[k] = {kmsg, koram, kprf }
            self.keys.insert(client.clone(), (k_msg, k_oram, k_prf));
        }
        // 7: end for
        Ok(())
    }

    fn write(&self, msg: &[u8], recipient: &str, epoch: u64) -> Result<(), CryptoError> {
        // 1: {kmsg, koram, kprf } ← keys[k]
        let (k_msg, k_oram, k_prf) = self.keys.get(recipient).unwrap();

        // 2: ℓ = PRF_kprf (t)
        let l = prf(k_prf, &epoch.to_be_bytes());

        // 3: koram,t = KDF(koram, t)
        let k_oram_t = kdf(k_oram, &epoch.to_string())?;

        // 4: ct = Enckmsg (m)
        let ct = encrypt(k_msg, msg)?;

        // 5: return S1.Write(ct, ℓ, koram,t)
        // self.s1.borrow_mut().write(ct, l, k_oram_t)
        todo!()
    }

    fn read(&self, sender: &str, epoch: u64) -> Result<Vec<u8>, CryptoError> {
        // 1: koram,t = KDF(koram, t)
        let (k_msg, k_oram, k_prf) = self.keys.get(sender).unwrap();
        let k_oram_t =
            kdf(k_oram, &epoch.to_string()).map_err(|_| CryptoError::DecryptionFailed)?;

        let f = prf(&k_prf, &epoch.to_be_bytes());

        // 2: ℓ = PRFkprf (t)
        let l = prf(k_prf, &[&f[..], &sender.as_bytes()[..]].concat());

        // 3: p ← S2.Read(ℓ)
        let path = self.s2.borrow().read(&u8_vec_to_path_vec(l));

        // 4: for block ∈ p do
        for block in path {
            // 5: if ℓ||ct ← Deckoram,t (block) succeeds then
            if let Ok(decrypted) = decrypt(&k_oram_t, &block.0) {
                let (block_l, ct) = decrypted.split_at(32);
                // if block_l == l {
                //     // 6: return m ← Deckmsg (ct)
                //     return decrypt(k_msg, ct);
                // }
            }
        }
        // 8: end for
        Err(CryptoError::DecryptionFailed)
    }

    fn fake_write(&self) -> Result<(), CryptoError> {
        let mut rng = thread_rng();
        // 1: ℓ′ $ ←− {0, 1}D
        let l: Vec<u8> = (0..D).map(|_| rng.gen()).collect();
        // 2: k′ oram,t $ ←− {0, 1}λ
        let k_oram_t: Vec<u8> = (0..LAMBDA).map(|_| rng.gen()).collect();
        // 3: ct′ $ ←− {0, 1}|ct|
        let ct: Vec<u8> = (0..64).map(|_| rng.gen()).collect();
        // 4: S1.Write(ct′, ℓ′, k′ oram,t)
        // self.s1.borrow_mut().write(ct, l, k_oram_t)
        todo!()
    }

    fn fake_read(&self) -> Vec<Block> {
        // 1: ℓ′ $ ←− {0, 1}^D
        let mut rng = thread_rng();
        let ll: Vec<u8> = (0..D).map(|_| rng.gen()).collect();
        // 2: S2.Read(ℓ′)
        self.s2.borrow().read(&u8_vec_to_path_vec(ll))
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_kdf() {
//         let key = b"original key";
//         let info1 = "purpose1";
//         let info2 = "purpose2";

//         let derived1 = kdf(key, info1).expect("KDF failed");
//         let derived2 = kdf(key, info2).expect("KDF failed");

//         assert_ne!(derived1, derived2);
//         assert_eq!(derived1.len(), 32);
//         assert_eq!(derived2.len(), 32);
//     }

//     #[test]
//     fn test_prf() {
//         let key = b"prf key";
//         let input1 = b"input1";
//         let input2 = b"input2";

//         let output1 = prf(key, input1);
//         let output2 = prf(key, input2);

//         assert_ne!(output1, output2);
//         assert_eq!(output1.len(), 32);
//         assert_eq!(output2.len(), 32);
//     }

//     #[test]
//     fn test_encrypt_decrypt() {
//         let key = kdf(b"encryption key", "enc").expect("KDF failed");
//         let message = b"Hello, World!";

//         let ciphertext = encrypt(&key, message).expect("Encryption failed");
//         let decrypted = decrypt(&key, &ciphertext).expect("Decryption failed");

//         assert_ne!(ciphertext, message);
//         assert_eq!(decrypted, message);
//     }

//     #[test]
//     fn test_client_setup() {
//         let s1 = Server1::new(0, Rc::new(RefCell::new(Server2::new())));
//         let s1 = Rc::new(RefCell::new(s1));
//         let s2 = Rc::new(RefCell::new(Server2::new()));
//         let mut alice = Client::new("Alice".to_string(), s1.clone(), s2.clone());
//         alice.setup(&["Bob".to_string()]).expect("Setup failed");
//         assert!(alice.keys.contains_key("Bob"));
//     }

//     #[test]
//     fn test_write_and_read() {
//         let (s1, s2) = (
//             Rc::new(RefCell::new(Server1::new(0, Rc::new(RefCell::new(Server2::new()))))),
//             Rc::new(RefCell::new(Server2::new())),
//         );
//         let mut alice = Client::new("Alice".to_string(), s1.clone(), s2.clone());
//         let mut bob = Client::new("Bob".to_string(), s1.clone(), s2.clone());

//         alice.setup(&["Bob".to_string()]).expect("Setup failed");
//         bob.setup(&["Alice".to_string()]).expect("Setup failed");
//     }

//     #[test]
//     fn test_fake_operations() {
//         let (s1, s2) = (
//             Rc::new(RefCell::new(Server1::new(0, Rc::new(RefCell::new(Server2::new()))))),
//             Rc::new(RefCell::new(Server2::new())),
//         );
//         let alice = Client::new("Alice".to_string(), s1.clone(), s2.clone());

//         alice.fake_write().expect("Fake write failed");

//         let fake_read = alice.fake_read();
//         assert_eq!(fake_read.len(), 32);
//     }

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
// }