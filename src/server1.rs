// Standard library imports
use std::cmp::min;
use std::sync::{Arc, Mutex};

// External crate imports
use rand::{seq::SliceRandom, thread_rng, Rng, SeedableRng};

// Internal imports
use crate::{
    constants::*,
    decrypt,
    encrypt,
    prf,
    server2::Server2,
    tree::BinaryTree,
    Block,
    Bucket,
    McOsamError,
    Key,
    Metadata,
    Path
};

/// Represents Server1 in the MC-OSAM system.
pub struct Server1 {
    /// The current epoch.
    pub epoch: u64,
    /// The server's key for the current epoch.
    pub k_s1_t: Key,
    /// The number of clients in the system.
    pub num_clients: usize,
    /// A reference to Server2.
    pub s2: Arc<Mutex<Server2>>,
    /// The main ORAM tree.
    pub p: Option<BinaryTree<Bucket>>,
    /// The temporary ORAM tree.
    pub pt: BinaryTree<Bucket>,
    /// The temporary metadata tree.
    pub metadata_pt: BinaryTree<Metadata>,  
    /// The main metadata tree.
    pub metadata: BinaryTree<Metadata>,
}

impl Server1 {
    /// Creates a new Server1 instance.
    ///
    /// # Arguments
    ///
    /// * `s2` - A reference to Server2.
    ///
    /// # Returns
    ///
    /// A new Server1 instance.
    pub fn new(s2: Arc<Mutex<Server2>>) -> Self {
        Self { epoch: 0, k_s1_t: Key::new(vec![]), num_clients: 0, s2, p: None, pt: BinaryTree::new_empty(), metadata_pt: BinaryTree::new_empty(), metadata: BinaryTree::new_with_depth(D) }
    }

    /// Initializes the server for a batch of clients.
    ///
    /// # Arguments
    ///
    /// * `num_clients` - The number of clients to initialize for.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure.
    pub fn batch_init(&mut self, num_clients: usize) -> Result<(), McOsamError> {
        let mut rng = thread_rng();
        let buckets_and_paths: Vec<(Vec<Bucket>, Path)> = (0..(NU * self.num_clients))
            .map(|_| {
                let l = Path::new((0..D).map(|_| rng.gen_range(0..2).into()).collect());
                let s2 = self.s2.lock()
                    .map_err(|_| McOsamError::ServerLockFailed)?;
                Ok((s2.read(&l), l))
            })
            .collect::<Result<Vec<_>, McOsamError>>()?;
    
        self.p = Some(BinaryTree::<Bucket>::from_vec_with_paths(buckets_and_paths));
        self.pt = BinaryTree::new(vec![]);
        self.metadata_pt = BinaryTree::new(vec![]);
        self.num_clients = num_clients;
        self.k_s1_t = Key::random(&mut rng);
        Ok(())
    }

    /// Writes a message to the ORAM.
    ///
    /// # Arguments
    ///
    /// * `ct` - The ciphertext to be written.
    /// * `l` - The path to write to.
    /// * `k_oram_t` - The ORAM key for the current epoch.
    /// * `cw` - Additional write information.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure.
    pub fn write(&mut self, ct: Vec<u8>, l: Vec<u8>, k_oram_t: Key, cw: Vec<u8>) -> Result<(), McOsamError> {
        let t_exp = self.epoch + DELTA; 
        let l = prf(&l, &cw);
        self.insert_message(&ct, &Path::from(l), &k_oram_t, t_exp)?;
        Ok(())
    }

    /// Inserts a message into the ORAM.
    ///
    /// # Arguments
    ///
    /// * `ct` - The ciphertext to be inserted.
    /// * `l` - The path to insert to.
    /// * `k_oram_t` - The ORAM key for the current epoch.
    /// * `t_exp` - The expiration epoch for this message.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure.
    pub fn insert_message(&mut self, ct: &Vec<u8>, l: &Path, k_oram_t: &Key, t_exp: u64) -> Result<(), McOsamError> {
        let c_msg = encrypt(&k_oram_t.0, &ct)
            .map_err(|_| McOsamError::EncryptionFailed)?;
        let (bucket, path) = self.pt.lca(&l)
            .ok_or(McOsamError::TreeOperationFailed)?;
        bucket.push(Block::new(c_msg));
        self.metadata_pt.write(vec![(l.clone(), k_oram_t.clone(), t_exp)], path);
        Ok(())
    }

    /// Performs a batch write operation.
    ///
    /// This method processes all pending writes and updates the ORAM structure.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure.
    pub fn batch_write(&mut self) -> Result<(), McOsamError> {
        if self.p.is_none() {
            return Ok(());
        }
        let mut rng = thread_rng();
        let seed: [u8; 32] = rng.gen();

        self.p.as_ref().unwrap().zip_flatten_tree(&self.metadata).iter().try_for_each(|(bucket, metadata_bucket, path)| -> Result<(), McOsamError> {
            (0..Z).try_for_each(|b| -> Result<(), McOsamError> {
                let bucket = bucket.as_ref()
                    .ok_or(McOsamError::BucketAccessFailed)?;
                if let Some(metadata_bucket) = metadata_bucket.as_ref() {
                    let (l, k_oram_t, t_exp) = metadata_bucket.get(b)
                        .ok_or(McOsamError::MetadataAccessFailed)?;
                    if self.epoch < *t_exp {
                        let c_msg = bucket.get(b)
                            .ok_or(McOsamError::BucketAccessFailed)?;
                        let ct = decrypt(&k_oram_t.0, &c_msg.0)
                            .map_err(|_| McOsamError::DecryptionFailed)?;
                        self.insert_message(&ct, l, k_oram_t, *t_exp)?;
                    }
                }
                Ok(())
            })
        })?;

        self.pt.zip_flatten_tree(&mut self.metadata_pt).iter_mut().try_for_each(|(bucket, metadata_bucket, path)| -> Result<(), McOsamError> {
            let bucket = bucket.as_mut()
                .ok_or(McOsamError::BucketAccessFailed)?;
            let metadata_bucket = metadata_bucket.as_mut()
                .ok_or(McOsamError::MetadataAccessFailed)?;
            (0..min(bucket.len(), Z)).for_each(|b| {
                bucket[b] = Block::new_random();
            });

            let mut rng1 = rand::rngs::StdRng::from_seed(seed);
            let mut rng2 = rand::rngs::StdRng::from_seed(seed);
            bucket.shuffle(&mut rng1);
            metadata_bucket.shuffle(&mut rng2);
            Ok(())
        })?;

        self.metadata.overwrite_tree(&self.metadata_pt);
        let mut server2 = self.s2.lock()
            .map_err(|_| McOsamError::ServerLockFailed)?;
        server2.write(self.pt.clone());
        server2.add_prf_keys(&self.k_s1_t);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_same_shuffle() {
        let seed: [u8; 32] = [0; 32]; // Use a fixed seed
        let mut rng1 = rand::rngs::StdRng::from_seed(seed);
        let mut rng2 = rand::rngs::StdRng::from_seed(seed);
        let mut v1 = (0..10).collect::<Vec<_>>();
        let mut v2 = v1.clone();
        v1.shuffle(&mut rng1);
        v2.shuffle(&mut rng2); // Use the same RNG instance
        assert_eq!(v1, v2); // The vectors should be equal after shuffling with the same RNG
    }
}
