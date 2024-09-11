use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;

const NONCE_SIZE: usize = 12;
const DELTA_EXP: u64 = 1000;
const BUCKET_SIZE: usize = 4; // Fixed size for each ORAM node bucket

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

impl fmt::Display for EncryptedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EncryptedData {{ nonce: {:?}, ciphertext: {:?} }}",
            self.nonce, self.ciphertext
        )
    }
}

struct MultiClientObliviousMessaging {
    s1: Server1,
    s2: Server2,
    num_writes_per_epoch: usize,
}

impl fmt::Display for MultiClientObliviousMessaging {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MultiClientObliviousMessaging {{ s1: {}, s2: {}, num_writes_per_epoch: {} }}",
            self.s1, self.s2, self.num_writes_per_epoch
        )
    }
}

struct Server1 {
    k_s1: Vec<u8>,
    counter: u64,
    t: u64,
    depth: usize,
}

impl fmt::Display for Server1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Server1 {{ k_s1: {:?}, counter: {}, t: {}, depth: {} }}",
            self.k_s1, self.counter, self.t, self.depth
        )
    }
}

#[derive(Debug)]
struct ORAMNode {
    bucket: [Option<(String, EncryptedData)>; BUCKET_SIZE],
    left: Option<Box<ORAMNode>>,
    right: Option<Box<ORAMNode>>,
}

impl ORAMNode {
    fn new() -> Self {
        Self {
            bucket: Default::default(),
            left: None,
            right: None,
        }
    }
}

impl fmt::Display for ORAMNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ORAMNode {{ bucket: {:?}, left: {:?}, right: {:?} }}",
            self.bucket, self.left, self.right
        )
    }
}

struct Server2 {
    root: ORAMNode,
    depth: usize,
}

impl fmt::Display for Server2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Server2 {{ root: {}, depth: {} }}",
            self.root, self.depth
        )
    }
}

impl MultiClientObliviousMessaging {
    fn new(num_writes_per_epoch: usize, depth: usize) -> Self {
        Self {
            s1: Server1::new(depth),
            s2: Server2::new(depth),
            num_writes_per_epoch,
        }
    }

    fn write(&mut self, w: &str, r: &str, m: &[u8], t: u64) -> Result<(), McOsamError> {
        // 1: Client derives {koram, kprf} from k (can be preprocessed).
        let k_prf = derive_key(&format!("{}-{}-prf", w, r));
        let k_oram = derive_key(&format!("{}-{}-oram", w, r));

        // 2: Client computes ℓ = PRFkprf(t)
        let l = prf(&k_prf, &t.to_string());

        // 3: Client computes koram,t = KDF(t, koram)
        let k_oram_t = kdf(t, &k_oram);

        // 4: Client sends {data, ℓ, koram,t} to S1
        let ct = encrypt(&k_oram, m)?;
        self.s1.receive_write(ct, l, k_oram_t, t, &mut self.s2)
    }

    fn read(
        &self,
        w: &str,
        r: &str,
        t: u64,
        is_real: bool,
    ) -> Result<Option<Vec<u8>>, McOsamError> {
        // 1: Client computes koram,t = KDF(t, koram)
        let k_oram = derive_key(&format!("{}-{}-oram", w, r));
        let k_oram_t = kdf(t, &k_oram);

        // 2: Client computes ℓ = PRFkprf (t)
        let k_prf = derive_key(&format!("{}-{}-prf", w, r));
        let l = prf(&k_prf, &t.to_string());

        // Construct the bid (block identifier)
        let counter = t * self.num_writes_per_epoch as u64 + self.get_client_index(w, r);
        let bid = format!("{}||{}", counter, hex::encode(&l));

        // 3: Client queries S2 at index ℓ and downloads the
        // entire path's worth of cmsg values by calling
        // RS-OSAMRead(bid)
        let path = self.s2.rs_osam_read(&bid);

        // 4: if isReal then
        if is_real {
            // 5: Client trial decrypts the path with koram,t
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
                        // 6: return data
                        return Ok(Some(m));
                    }
                }
            }
        }
        // 7: end if
        Ok(None)
    }

    fn get_client_index(&self, w: &str, r: &str) -> u64 {
        // This function should return a unique index for each (w, r) pair
        // For simplicity, we'll use a hash of the pair modulo num_writes_per_epoch
        let mut hasher = Sha256::new();
        hasher.update(format!("{}-{}", w, r).as_bytes());
        let result = hasher.finalize();
        let index = u64::from_be_bytes(result[0..8].try_into().unwrap());
        index % self.num_writes_per_epoch as u64
    }

    fn evict(&mut self, v: usize) {
        // Algorithm 3 Evict(ν, t)
        // 1: return RS-OSAMEvict(ν, ExtraEvictCond)
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
        // Client sends {data, ℓ, koram,t} to S1
        // 5: S1 computes the expiration epoch of this message as
        // texp = t + ∆exp
        let t_exp = t + DELTA_EXP;

        // 6: S1 computes cmsg = Enckoram,t (ct)
        let mut c_msg = ct.nonce.clone();
        c_msg.extend_from_slice(&ct.ciphertext);
        let c_msg = encrypt(&k_oram_t, &c_msg)?;

        // 7: S1 computes cmetadata = EnckS1 (texp, koram,t)
        let c_metadata = encrypt(
            &self.k_s1,
            &format!("{},{}", t_exp, hex::encode(&k_oram_t)).as_bytes(),
        )?;

        // 8: bid ← RS-OSAMAlloc(ℓ, numWritesPerEpoch)
        let bid = self.rs_osam_alloc(&l);

        // 9: At the end of the epoch, S1 writes (cmsg, cmetadata) to
        // S2 by calling RS-OSAMWrite(cmsg||cmetadata, bid)
        self.rs_osam_write(&c_msg, &c_metadata, &bid, s2);
        Ok(())
    }

    fn evict(&mut self, nu: usize, s2: &mut Server2) {
        // Algorithm 8 RS-OSAMEvict(ν, ExtraEvictCond)
        // 1: for d = 0 to D − 1 do
        for d in 0..s2.depth {
            // 2: Let S denote the set of all buckets at depth d
            let buckets_at_depth = 1 << d;
            // 3: A ← UniformRandomν (S)
            let eviction_count = nu.min(buckets_at_depth);
            let mut rng = rand::thread_rng();

            // 4: for each bucket ∈ A do
            for _ in 0..eviction_count {
                let bucket_index = rng.gen_range(0..buckets_at_depth);
                // 5-13: Implemented in evict_bucket function
                self.evict_bucket(d, bucket_index, s2);
            }
        }
    }

    fn evict_bucket(&self, depth: usize, bucket_index: usize, s2: &mut Server2) {
        // 1: Get the current bucket at this depth
        let path = self.get_path_to_bucket(depth, bucket_index);
        let current_bucket = s2.get_bucket(&path).cloned().unwrap_or_default();

        // 2: This bucket has a left child and a right child bucket in the binary tree
        let mut left_child_path = path.clone();
        left_child_path.push(0);
        let mut right_child_path = path.clone();
        right_child_path.push(1);

        let mut left_child_bucket = s2.get_bucket(&left_child_path).cloned().unwrap_or_default();
        let mut right_child_bucket = s2
            .get_bucket(&right_child_path)
            .cloned()
            .unwrap_or_default();

        // 3: Get the data block within this bucket that we just popped
        for entry in current_bucket.iter().filter_map(|e| e.clone()) {
            let (bid, data) = entry;
            let l = hex::decode(&bid).unwrap_or_default();

            // 6: b ← (d + 1)-st bit of ℓ
            let b = (l[depth] & 1) as usize;

            // 7: if ExtraEvictCond(data) == true then
            let (block_b, block_1_minus_b) = if self.extra_evict_cond(&data) {
                // 8: blockb ←⊥, block1−b ←⊥
                (
                    Some((
                        bid.clone(),
                        EncryptedData {
                            nonce: random_bytes(NONCE_SIZE),
                            ciphertext: random_bytes(32),
                        },
                    )),
                    Some((
                        bid.clone(),
                        EncryptedData {
                            nonce: random_bytes(NONCE_SIZE),
                            ciphertext: random_bytes(32),
                        },
                    )),
                )
            } else {
                // 10: blockb ← (bid, data||ℓ), block1−b ←⊥
                (
                    Some((bid.clone(), data.clone())),
                    Some((
                        bid.clone(),
                        EncryptedData {
                            nonce: random_bytes(NONCE_SIZE),
                            ciphertext: random_bytes(32),
                        },
                    )),
                )
            };

            // 12: ∀b ∈ {0, 1} : Childb(bucket).Write(blockb)
            if b == 0 {
                left_child_bucket[bucket_index] = block_b;
                right_child_bucket[bucket_index] = block_1_minus_b;
            } else {
                left_child_bucket[bucket_index] = block_1_minus_b;
                right_child_bucket[bucket_index] = block_b;
            }
        }

        // 6: All edited buckets need to be re-randomized entirely, including the current bucket and both of its children.
        s2.set_bucket(&path, self.randomize_bucket(current_bucket));
        s2.set_bucket(&left_child_path, self.randomize_bucket(left_child_bucket));
        s2.set_bucket(&right_child_path, self.randomize_bucket(right_child_bucket));
    }

    fn randomize_bucket(
        &self,
        bucket: [Option<(String, EncryptedData)>; BUCKET_SIZE],
    ) -> [Option<(String, EncryptedData)>; BUCKET_SIZE] {
        bucket
            .iter()
            .map(|entry| {
                if let Some((bid, data)) = entry {
                    Some((
                        bid.clone(),
                        EncryptedData {
                            nonce: random_bytes(NONCE_SIZE),
                            ciphertext: random_bytes(32),
                        },
                    ))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn get_path_to_bucket(&self, depth: usize, bucket_index: usize) -> Vec<u8> {
        let mut path = Vec::with_capacity(depth);
        for d in 0..depth {
            path.push(((bucket_index >> (depth - d - 1)) & 1) as u8);
        }
        path
    }

    fn get_random_path(&self) -> Vec<u8> {
        (0..self.depth).map(|_| rand::random::<u8>() & 1).collect()
    }

    fn decrypt_metadata(&self, data: &EncryptedData) -> Result<(u64, Vec<u8>), McOsamError> {
        let plaintext = decrypt(&self.k_s1, data)?;
        let parts: Vec<&str> = std::str::from_utf8(&plaintext)
            .map_err(|_| McOsamError::InvalidMetadata)?
            .split(',')
            .collect();
        if parts.len() != 2 {
            return Err(McOsamError::InvalidMetadata);
        }
        let t_exp = parts[0].parse().map_err(|_| McOsamError::InvalidMetadata)?;
        let k_oram_t = hex::decode(parts[1]).map_err(|_| McOsamError::InvalidMetadata)?;
        Ok((t_exp, k_oram_t))
    }

    fn rs_osam_alloc(&mut self, l: &[u8]) -> String {
        // 1: if ℓ ==⊥ then
        let leaf = if l.is_empty() {
            // 2: ℓ $←− [N ] // Uniformly sample a leaf
            (0..self.depth).map(|_| rand::random::<u8>()).collect()
        } else {
            l.to_vec()
        };
        // 3: end if

        // 4: bid ← counter||ℓ
        let bid = format!("{}||{}", self.counter, hex::encode(&leaf));

        // 5: counter ← counter + increment
        // By default, we only write one message per bid, so increment is 1
        self.counter += 1;

        // 6: return bid
        bid
    }

    fn rs_osam_write(
        &self,
        c_msg: &EncryptedData,
        c_metadata: &EncryptedData,
        bid: &str,
        s2: &mut Server2,
    ) {
        let mut combined = c_msg.nonce.clone();
        combined.extend_from_slice(&c_msg.ciphertext);
        combined.extend_from_slice(&c_metadata.nonce);
        combined.extend_from_slice(&c_metadata.ciphertext);

        s2.write(
            bid,
            EncryptedData {
                nonce: vec![],
                ciphertext: combined,
            },
        );
    }

    fn extra_evict_cond(&self, data: &EncryptedData) -> bool {
        // 2: S1 computes texp, koram,t = DeckS1 (cmetadata)
        if let Ok((t_exp, _k_oram_t)) = self.decrypt_metadata(data) {
            // 3: return t ≥ texp
            self.t >= t_exp
        } else {
            false
        }
    }
}

impl Server2 {
    fn new(depth: usize) -> Self {
        Self {
            root: ORAMNode::new(),
            depth,
        }
    }

    fn write(&mut self, bid: &str, data: EncryptedData) {
        let mut current = &mut self.root;
        for _ in 0..self.depth {
            if let Some(slot) = current.bucket.iter_mut().find(|slot| slot.is_none()) {
                *slot = Some((bid.to_string(), data.clone()));
            }
            let bit = rand::random::<bool>();
            current = if bit {
                current
                    .right
                    .get_or_insert_with(|| Box::new(ORAMNode::new()))
            } else {
                current
                    .left
                    .get_or_insert_with(|| Box::new(ORAMNode::new()))
            };
        }
    }

    fn get_bucket(&self, path: &[u8]) -> Option<&[Option<(String, EncryptedData)>; BUCKET_SIZE]> {
        let mut current = &self.root;
        for &bit in path.iter().take(self.depth) {
            current = if bit & 1 == 1 {
                current.right.as_ref().unwrap()
            } else {
                current.left.as_ref().unwrap()
            }
        }
        Some(&current.bucket)
    }

    fn set_bucket(&mut self, path: &[u8], bucket: [Option<(String, EncryptedData)>; BUCKET_SIZE]) {
        let mut current = &mut self.root;
        for &bit in path.iter().take(self.depth) {
            current = if bit & 1 == 1 {
                current
                    .right
                    .get_or_insert_with(|| Box::new(ORAMNode::new()))
            } else {
                current
                    .left
                    .get_or_insert_with(|| Box::new(ORAMNode::new()))
            }
        }
        current.bucket = bucket;
    }

    fn get_random_path(&self) -> Vec<u8> {
        (0..self.depth).map(|_| rand::random::<u8>() & 1).collect()
    }

    fn rs_osam_read(&self, bid: &str) -> Vec<EncryptedData> {
        let parts: Vec<&str> = bid.split("||").collect();
        if parts.len() != 2 {
            return Vec::new();
        }
        let l = hex::decode(parts[1]).unwrap_or_default();

        // 1: data ←⊥
        let mut data = None;

        // 2: // Path from leaf ℓ to root
        let mut path = Vec::new();
        let mut current = &self.root;

        // 3: for each bucket on P(ℓ) do
        path.extend(
            current
                .bucket
                .iter()
                .filter_map(|entry| entry.clone().map(|(_, data)| data)),
        );

        for &bit in l.iter().take(self.depth) {
            current = if bit & 1 == 1 {
                current
                    .right
                    .as_ref()
                    .unwrap_or(&current.left.as_ref().unwrap())
            } else {
                current
                    .left
                    .as_ref()
                    .unwrap_or(&current.right.as_ref().unwrap())
            };

            // 4: if (data0||ℓ0) ← bucket.Read(bid)̸ =⊥ then
            if let Some(found_data) = current.bucket.iter().find_map(|entry| {
                if let Some((entry_bid, data)) = entry {
                    if entry_bid == bid {
                        return Some(data.clone());
                    }
                }
                None
            }) {
                // 5: data ← data0 // Notice that ℓ = ℓ0
                data = Some(found_data);
            }
            // 6: end if

            path.extend(
                current
                    .bucket
                    .iter()
                    .filter_map(|entry| entry.clone().map(|(_, data)| data)),
            );
        }
        // 7: end for

        // 8: return data (Note: We're returning the path instead of just the data)
        path
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
        let mut mcosam = MultiClientObliviousMessaging::new(10, 4);
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
        let mut mcosam = MultiClientObliviousMessaging::new(10, 4);
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
        let mut mcosam = MultiClientObliviousMessaging::new(10, 4);
        let message = b"Eviction test";
        let w = "alice";
        let r = "bob";
        let t = 1;

        mcosam.write(w, r, message, t).unwrap();

        mcosam.evict(5);

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

    #[test]
    fn test_oram_tree() {
        let mut s2 = Server2::new(4);
        let data = EncryptedData {
            nonce: vec![1, 2, 3],
            ciphertext: vec![4, 5, 6],
        };

        let bid = "test_bid||01010101"; // Example bid
        s2.write(bid, data.clone());

        let read_result = s2.rs_osam_read(bid);

        assert!(read_result.iter().any(|d| d == &data));
    }

    #[test]
    fn test_extra_evict_cond() {
        let mut s1 = Server1::new(4);
        let t_exp = s1.t + DELTA_EXP - 1;
        let k_oram_t = random_bytes(32);
        let metadata = format!("{},{}", t_exp, hex::encode(&k_oram_t));
        let encrypted_metadata = encrypt(&s1.k_s1, metadata.as_bytes()).unwrap();

        assert!(!s1.extra_evict_cond(&encrypted_metadata));

        s1.t = t_exp + 1;
        assert!(s1.extra_evict_cond(&encrypted_metadata));
    }
}
