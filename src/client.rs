use std::collections::HashMap;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use bincode::{deserialize, serialize};
use crate::error::OramError;
use crate::network::{Command, Local, ReadType, WriteType, Server1Access, Server2Access, LocalServer1Access, LocalServer2Access};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use ring::{digest, hkdf, pbkdf2};
use crate::{kdf, prf, encrypt, decrypt, trim_zeros, EncryptionType};
use crate::constants::{D, BLOCK_SIZE};
use crate::dtypes::{Bucket, Path, Key};

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
        let k_msg = kdf(&k.0, "MSG")?;
        let k_oram = kdf(&k.0, "ORAM")?;
        let k_prf = kdf(&k.0, "PRF")?;
        self.keys.insert(k.clone(), (k_msg, k_oram, k_prf));
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
        self.s1.queue_write(ct, f, Key::new(k_oram_t), cs)
    }

    pub fn read(&self, k: &Key, cs: String, epoch_past: usize) -> Result<Vec<u8>, OramError> {
        let epoch = self.epoch - 1 - epoch_past;
        let cs = cs.into_bytes();
        
        let (k_msg, k_oram, k_prf) = self.keys.get(&k).unwrap();
        let k_oram_t = kdf(k_oram, &epoch.to_string()).map_err(|_| OramError::NoMessageFound)?;
        let f = prf(&k_prf, &epoch.to_be_bytes())?;
        
        let keys = self.s2.get_prf_keys()?;
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
        
        let path = self.s2.read(&l_path)?;

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
        self.s1.queue_write(ct, l, k_oram_t, cs)
    }

    pub fn fake_read(&self) -> Vec<Bucket> {
        let mut rng = ChaCha20Rng::from_entropy();
        let l: Vec<u8> = (0..D).map(|_| rng.gen()).collect();
        self.s2.read(&Path::from(l)).unwrap()
    }
}
