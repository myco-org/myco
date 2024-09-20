use rand::{thread_rng, Rng};
use ring::{aead, digest, hkdf, pbkdf2, rand::SecureRandom};
use std::{cell::RefCell, cmp::Ordering, collections::HashMap, num::NonZeroU32, rc::Rc};
use thiserror::Error;

const TREE_HEIGHT: usize = 4;
const BUCKET_SIZE: usize = 4;
const NUM_WRITES_PER_EPOCH: usize = 2;
const EVICTION_RATE: usize = 2;
const NU: usize = 4;
const D: usize = 32;
const LAMBDA: usize = 128;

type Key = Vec<u8>;
type Timestamp = u64;

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
        self.s1.borrow_mut().write(ct, l, k_oram_t)
    }

    fn read(&self, sender: &str, epoch: u64) -> Result<Vec<u8>, CryptoError> {
        // 1: koram,t = KDF(koram, t)
        let (k_msg, k_oram, k_prf) = self.keys.get(sender).unwrap();
        let k_oram_t =
            kdf(k_oram, &epoch.to_string()).map_err(|_| CryptoError::DecryptionFailed)?;

        // 2: ℓ = PRFkprf (t)
        let l = prf(k_prf, &epoch.to_be_bytes());

        // 3: p ← S2.Read(ℓ)
        let path = self.s2.borrow().read(&l);

        // 4: for block ∈ p do
        for block in path {
            // 5: if ℓ||ct ← Deckoram,t (block) succeeds then
            if let Ok(decrypted) = decrypt(&k_oram_t, &block.data) {
                let (block_l, ct) = decrypted.split_at(32);
                if block_l == l {
                    // 6: return m ← Deckmsg (ct)
                    return decrypt(k_msg, ct);
                }
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
        self.s1.borrow_mut().write(ct, l, k_oram_t)
    }

    fn fake_read(&self) -> Vec<Block> {
        // 1: ℓ′ $ ←− {0, 1}^D
        let mut rng = thread_rng();
        let ll: Vec<u8> = (0..D).map(|_| rng.gen()).collect();
        // 2: S2.Read(ℓ′)
        self.s2.borrow().read(&ll)
    }
}

struct Metadata {
    root: Option<Box<Node>>,
}

struct Node {
    key: String,
    value: (Key, Timestamp),
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}

impl Metadata {
    fn new() -> Self {
        Metadata { root: None }
    }

    fn insert(&mut self, key: String, value: (Key, Timestamp)) {
        self.root = Self::insert_node(self.root.take(), key, value);
    }

    fn insert_node(
        node: Option<Box<Node>>,
        key: String,
        value: (Key, Timestamp),
    ) -> Option<Box<Node>> {
        match node {
            Some(mut current) => {
                match key.cmp(&current.key) {
                    Ordering::Less => {
                        current.left = Self::insert_node(current.left.take(), key, value);
                    }
                    Ordering::Greater => {
                        current.right = Self::insert_node(current.right.take(), key, value);
                    }
                    Ordering::Equal => {
                        current.value = value; // Update existing key
                    }
                }
                Some(current)
            }
            None => Some(Box::new(Node {
                key,
                value,
                left: None,
                right: None,
            })),
        }
    }

    // Optionally, you can implement a get method if needed
    fn get(&self, key: &str) -> Option<&(Key, Timestamp)> {
        Self::get_node(&self.root, key)
    }

    fn get_node<'a>(node: &'a Option<Box<Node>>, key: &str) -> Option<&'a (Key, Timestamp)> {
        match node {
            Some(current) => match key.cmp(&current.key) {
                Ordering::Less => Self::get_node(&current.left, key),
                Ordering::Greater => Self::get_node(&current.right, key),
                Ordering::Equal => Some(&current.value),
            },
            None => None,
        }
    }
}

struct Server1 {
    metadata: Metadata,
    epoch: u64,
    counter: usize,
    write_queue: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    num_clients: usize,
    s2: Rc<RefCell<Server2>>,
}

impl Server1 {
    fn new(num_clients: usize, s2: Rc<RefCell<Server2>>) -> Self {
        Server1 {
            metadata: Metadata::new(),
            epoch: 0,
            counter: 0,
            write_queue: Vec::new(),
            num_clients,
            s2,
        }
    }

    fn batch_init(&mut self) {
        let mut rng = thread_rng();
        let p: Vec<(Vec<Block>, Vec<u8>)> = (0..(NU * self.num_clients))
            .map(|_| {
                let l: Vec<u8> = (0..D).map(|_| rng.gen_bool(0.5) as u8).collect();
                (self.s2.borrow_mut().read(&l), l)
            })
            .collect();
        for (path, l) in p {
            let mut node = self.metadata.root.as_mut().expect("Root is None");
            for (block, child) in path.iter().zip(l.iter()) {
                if *child == 0 {
                    node = node.left.as_mut().expect("Left child is None");
                } else {
                    node = node.right.as_mut().expect("Right child is None");
                }
            }
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
        let s1 = Server1::new();
        let s1 = Rc::new(RefCell::new(s1));
        let s2 = Rc::new(RefCell::new(Server2::new()));
        let mut alice = Client::new("Alice".to_string(), s1.clone(), s2.clone());
        alice.setup(&["Bob".to_string()]).expect("Setup failed");
        assert!(alice.keys.contains_key("Bob"));
    }

    #[test]
    fn test_write_and_read() {
        let (s1, s2) = (
            Rc::new(RefCell::new(Server1::new())),
            Rc::new(RefCell::new(Server2::new())),
        );
        let mut alice = Client::new("Alice".to_string(), s1.clone(), s2.clone());
        let mut bob = Client::new("Bob".to_string(), s1.clone(), s2.clone());

        alice.setup(&["Bob".to_string()]).expect("Setup failed");
        bob.setup(&["Alice".to_string()]).expect("Setup failed");
    }

    #[test]
    fn test_fake_operations() {
        let (s1, s2) = (
            Rc::new(RefCell::new(Server1::new())),
            Rc::new(RefCell::new(Server2::new())),
        );
        let alice = Client::new("Alice".to_string(), s1.clone(), s2.clone());

        alice.fake_write().expect("Fake write failed");

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
