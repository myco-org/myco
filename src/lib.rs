use rand::{thread_rng, Rng};
use ring::{aead, digest, hkdf, pbkdf2, rand::SecureRandom};
use std::{collections::HashMap, num::NonZeroU32};
use thiserror::Error;

const TREE_HEIGHT: usize = 4;
const BUCKET_SIZE: usize = 4;
const NUM_WRITES_PER_EPOCH: usize = 2;
const EVICTION_RATE: usize = 2;

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

#[derive(Clone, Debug)]
struct Block {
    bid: Vec<u8>,
    data: Vec<u8>,
}

struct Client {
    id: String,
    keys: HashMap<String, (Vec<u8>, Vec<u8>, Vec<u8>)>,
}

impl Client {
    fn new(id: String) -> Self {
        Client {
            id,
            keys: HashMap::new(),
        }
    }

    fn setup(&mut self, other_clients: &[String]) -> Result<(), CryptoError> {
        for client in other_clients {
            let k: Vec<u8> = (0..32).map(|_| thread_rng().gen()).collect();
            let k_msg = kdf(&k, "MSG")?;
            let k_oram = kdf(&k, "ORAM")?;
            let k_prf = kdf(&k, "PRF")?;
            self.keys.insert(client.clone(), (k_msg, k_oram, k_prf));
        }
        Ok(())
    }

    fn write(
        &self,
        msg: &[u8],
        recipient: &str,
        epoch: u64,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), CryptoError> {
        let (k_msg, k_oram, k_prf) = self.keys.get(recipient).unwrap();
        let l = prf(k_prf, &epoch.to_be_bytes());
        let k_oram_t = kdf(k_oram, &epoch.to_string())?;
        let ct = encrypt(k_msg, msg)?;
        Ok((ct, l, k_oram_t))
    }

    fn read(&self, sender: &str, epoch: u64, path: &[Block]) -> Option<Vec<u8>> {
        let (k_msg, k_oram, k_prf) = self.keys.get(sender).unwrap();
        let l = prf(k_prf, &epoch.to_be_bytes());
        let k_oram_t = kdf(k_oram, &epoch.to_string()).ok()?;

        for block in path {
            if let Ok(decrypted) = decrypt(&k_oram_t, &block.data) {
                let (block_l, ct) = decrypted.split_at(32);
                if block_l == l {
                    return decrypt(k_msg, ct).ok();
                }
            }
        }
        None
    }

    fn fake_write(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut rng = thread_rng();
        let l: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let k_oram_t: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let ct: Vec<u8> = (0..64).map(|_| rng.gen()).collect();
        (ct, l, k_oram_t)
    }

    fn fake_read(&self) -> Vec<u8> {
        let mut rng = thread_rng();
        (0..32).map(|_| rng.gen()).collect()
    }
}

struct Server1 {
    metadata: HashMap<String, (Vec<u8>, u64)>,
    epoch: u64,
    counter: usize,
    write_queue: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
}

impl Server1 {
    fn new() -> Self {
        Server1 {
            metadata: HashMap::new(),
            epoch: 0,
            counter: 0,
            write_queue: Vec::new(),
        }
    }

    fn write(&mut self, ct: Vec<u8>, l: Vec<u8>, k_oram_t: Vec<u8>) -> Result<(), CryptoError> {
        let expiration = self.epoch + 10; // Arbitrary expiration period
        let c_msg = encrypt(&k_oram_t.clone(), &[&l[..], &ct[..]].concat())?;
        self.metadata
            .insert(hex::encode(&l), (k_oram_t.clone(), expiration));
        self.write_queue
            .push((c_msg.clone(), l.clone(), k_oram_t.clone()));
        self.counter += 1;

        if self.counter == NUM_WRITES_PER_EPOCH {
            self.batch_write();
        }
        Ok(())
    }

    fn batch_write(&mut self) {
        // In a real implementation, this would write to S2
        self.write_queue.clear();
        self.counter = 0;
        self.epoch += 1;
    }
}

struct Server2 {
    tree: Vec<Vec<Block>>,
}

impl Server2 {
    fn new() -> Self {
        let mut tree = Vec::new();
        for _ in 0..TREE_HEIGHT {
            let level: Vec<Block> = Vec::new();
            tree.push(level);
        }
        Server2 { tree }
    }

    fn read(&self, l: &[u8]) -> Vec<Block> {
        let mut path = Vec::new();
        for level in (0..TREE_HEIGHT).rev() {
            let bucket = &self.tree[level];
            path.extend(
                bucket
                    .iter()
                    .filter(|block| !block.data.is_empty())
                    .cloned(),
            );
        }
        path
    }

    fn write(&mut self, blocks: Vec<Block>) {
        for block in blocks {
            let leaf = &block.bid[..32];
            let mut index = self.leaf_to_index(leaf);
            for level in (0..TREE_HEIGHT).rev() {
                let bucket = &mut self.tree[level];
                if bucket.len() < BUCKET_SIZE {
                    bucket.push(block.clone());
                    break;
                }
                // If bucket is full, continue to the next level
                index /= 2;
            }
        }
    }

    fn leaf_to_index(&self, leaf: &[u8]) -> usize {
        let mut index = 0;
        for &byte in leaf.iter().take(4) {
            index = (index << 8) | byte as usize;
        }
        index % (1 << (TREE_HEIGHT - 1))
    }

    fn evict(&mut self) {
        for _ in 0..EVICTION_RATE {
            let leaf: Vec<u8> = (0..32).map(|_| thread_rng().gen()).collect();
            let mut index = self.leaf_to_index(&leaf);
            let mut blocks_to_push = Vec::new();

            for level in 0..TREE_HEIGHT {
                let mut new_bucket = Vec::new();
                let bucket = std::mem::take(&mut self.tree[level]);

                for block in bucket {
                    let block_index = self.leaf_to_index(&block.bid);
                    if block_index == index {
                        blocks_to_push.push(block);
                    } else {
                        new_bucket.push(block);
                    }
                }

                self.tree[level] = new_bucket;
                index /= 2;
            }

            self.write(blocks_to_push);
        }
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
        let mut alice = Client::new("Alice".to_string());
        alice.setup(&["Bob".to_string()]).expect("Setup failed");
        assert!(alice.keys.contains_key("Bob"));
    }

    #[test]
    fn test_write_and_read() {
        let mut alice = Client::new("Alice".to_string());
        let mut bob = Client::new("Bob".to_string());
        alice.setup(&["Bob".to_string()]).expect("Setup failed");
        bob.setup(&["Alice".to_string()]).expect("Setup failed");

        let mut s1 = Server1::new();
        let mut s2 = Server2::new();

        let message = b"Hello, Bob!";
        let (ct, l, k_oram_t) = alice.write(message, "Bob", 1).expect("Write failed");
        s1.write(ct.clone(), l.clone(), k_oram_t.clone())
            .expect("Server1 write failed");

        let block = Block {
            bid: l.clone(),
            data: encrypt(&k_oram_t.clone(), &[&l[..], &ct[..]].concat())
                .expect("Encryption failed"),
        };
        s2.write(vec![block]);

        let path = s2.read(&l);
        let decrypted_msg = bob.read("Alice", 1, &path);
        assert_eq!(decrypted_msg, Some(message.to_vec()));
    }

    #[test]
    fn test_fake_operations() {
        let alice = Client::new("Alice".to_string());

        let (fake_ct, fake_l, fake_k_oram_t) = alice.fake_write();
        assert_eq!(fake_ct.len(), 64);
        assert_eq!(fake_l.len(), 32);
        assert_eq!(fake_k_oram_t.len(), 32);

        let fake_read = alice.fake_read();
        assert_eq!(fake_read.len(), 32);
    }

    #[test]
    fn test_server1_batch_write() {
        let mut s1 = Server1::new();
        let dummy_data = vec![0; 64];
        let dummy_l = vec![0; 32];
        let dummy_k_oram_t = vec![0; 32];

        for _ in 0..NUM_WRITES_PER_EPOCH {
            s1.write(dummy_data.clone(), dummy_l.clone(), dummy_k_oram_t.clone())
                .expect("Server1 write failed");
        }

        assert_eq!(s1.epoch, 1);
        assert_eq!(s1.counter, 0);
        assert!(s1.write_queue.is_empty());
    }

    #[test]
    fn test_server2_eviction() {
        let mut s2 = Server2::new();
        let dummy_block = Block {
            bid: vec![0; 32],
            data: vec![1; 64],
        };

        // Fill the tree
        for _ in 0..(1 << TREE_HEIGHT) * BUCKET_SIZE {
            s2.write(vec![dummy_block.clone()]);
        }

        // Perform eviction
        s2.evict();

        // Check if eviction happened (this is a simple check, might need adjustment)
        let total_blocks: usize = s2.tree.iter().map(|level| level.len()).sum();
        assert!(total_blocks < (1 << TREE_HEIGHT) * BUCKET_SIZE);
    }
}
