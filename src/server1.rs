use crate::{
    constants::*, decrypt, encrypt, prf, server2::Server2, tree::BinaryTree, Block, Bucket,
    EncryptionType, Key, Metadata, OramError, Path,
};
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::{Arc, Mutex};

pub struct Server1 {
    pub epoch: u64,
    pub k_s1_t: Key,
    pub num_clients: usize,
    pub s2: Arc<Mutex<Server2>>,
    pub p: BinaryTree<Bucket>,
    pub pt: BinaryTree<Bucket>,
    pub metadata_pt: BinaryTree<Metadata>,
    pub metadata: BinaryTree<Metadata>,
}

impl Server1 {
    pub fn new(s2: Arc<Mutex<Server2>>) -> Self {
        let metadata = BinaryTree::<Metadata>::new_with_depth(D);
        Self {
            epoch: 0,
            k_s1_t: Key::new(vec![]),
            num_clients: 0,
            s2,
            p: BinaryTree::new_empty(),
            pt: BinaryTree::new_empty(),
            metadata_pt: BinaryTree::new_empty(),
            metadata,
        }
    }

    pub fn batch_init(&mut self, num_clients: usize) {
        let mut rng = ChaCha20Rng::from_entropy();

        let paths = (0..(NU * num_clients))
            .map(|_| Path::random(&mut rng))
            .collect::<Vec<Path>>();

        let (buckets, idx) = self.s2.lock().unwrap().read_paths(paths.clone());

        let bucket_size = buckets.len();
        self.p = BinaryTree::from_array(buckets, idx.clone());
        self.pt = BinaryTree::from_array(vec![Bucket::default(); bucket_size], idx.clone());
        self.metadata_pt = BinaryTree::from_array(
            vec![Metadata::default(); bucket_size],
            idx,
        );

        self.num_clients = num_clients;
        self.k_s1_t = Key::random(&mut rng);
    }

    pub fn write(
        &mut self,
        ct: Vec<u8>,
        f: Vec<u8>,
        k_oram_t: Key,
        cs: Vec<u8>,
    ) -> Result<(), OramError> {
        let t_exp = self.epoch + DELTA;
        let l: Vec<u8> = prf(&self.k_s1_t.0, &[&f[..], &cs[..]].concat());
        self.insert_message(&ct, &Path::from(l), &k_oram_t, t_exp);

        Ok(())
    }

    pub fn insert_message(
        &mut self,
        ct: &Vec<u8>,
        l: &Path,
        k_oram_t: &Key,
        t_exp: u64,
    ) -> Result<(), OramError> {
        let c_msg = encrypt(&k_oram_t.0, &ct, EncryptionType::DoubleEncrypt)
            .map_err(|_| OramError::EncryptionFailed)?;
        let (bucket, path) = self.pt.lca(&l).ok_or(OramError::LcaNotFound)?;
        let mut metadata_bucket = self
            .metadata_pt
            .get(&path)
            .ok_or(OramError::MetadataBucketNotFound)?
            .clone();

        bucket.push(Block::new(c_msg));
        metadata_bucket.push(l.clone(), k_oram_t.clone(), t_exp);
        self.metadata_pt.write(metadata_bucket, path);
        Ok(())
    }

    pub fn batch_write(&mut self) -> Result<(), OramError> {
        let mut rng = ChaCha20Rng::from_entropy();
        let seed: [u8; 32] = rng.gen();

        self.p
            .zip(&self.metadata)
            .iter()
            .try_for_each(|(bucket, metadata_bucket, _)| {
                let bucket = bucket.clone().ok_or(OramError::BucketNotFound)?;
                (0..bucket.len()).try_for_each(|b| {
                    metadata_bucket
                        .as_ref()
                        .ok_or(OramError::MetadataBucketNotFound)
                        .and_then(|metadata_bucket| {
                            let (l, k_oram_t, t_exp) = metadata_bucket
                                .get(b)
                                .ok_or(OramError::MetadataIndexError(b))?;
                            if self.epoch < *t_exp {
                                let c_msg = bucket.get(b).ok_or(OramError::BucketIndexError(b))?;
                                if let Ok(ct) = decrypt(&k_oram_t.0, &c_msg.0) {
                                    self.insert_message(&ct, l, k_oram_t, *t_exp)?;
                                }
                            }
                            Ok(())
                        })
                })
            })?;

        self.pt.zip(&mut self.metadata_pt).iter_mut().try_for_each(
            |(bucket, metadata_bucket, path)| {
                let bucket = bucket.as_mut().ok_or(OramError::BucketNotFound)?;
                let metadata_bucket: &mut Metadata = metadata_bucket
                    .as_mut()
                    .ok_or(OramError::MetadataBucketNotFound)?;
                (bucket.len()..Z).for_each(|_| {
                    bucket.push(Block::new_random());
                });
                (metadata_bucket.len()..Z).for_each(|_| {
                    metadata_bucket.push(path.clone(), Key::new(vec![]), 0);
                });

                assert_eq!(
                    bucket.len(),
                    Z,
                    "Bucket length is not Z in epoch {}: bucket length={}, expected={}",
                    self.epoch,
                    bucket.len(),
                    Z
                );
                assert_eq!(metadata_bucket.len(), Z, "Metadata bucket length is not Z");

                let mut rng1 = ChaCha20Rng::from_seed(seed);
                let mut rng2 = ChaCha20Rng::from_seed(seed);
                bucket.shuffle(&mut rng1);
                metadata_bucket.shuffle(&mut rng2);
                Ok(())
            },
        )?;

        self.metadata.overwrite(&self.metadata_pt);

        let mut server2 = self.s2.lock().unwrap();
        server2.write(self.pt.clone());
        server2.add_prf_keys(&self.k_s1_t);

        self.epoch += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_same_shuffle() {
        let seed: [u8; 32] = [0; 32];
        let mut rng1 = ChaCha20Rng::from_seed(seed);
        let mut rng2 = ChaCha20Rng::from_seed(seed);
        let mut v1 = (0..10).collect::<Vec<_>>();
        let mut v2 = v1.clone();
        v1.shuffle(&mut rng1);
        v2.shuffle(&mut rng2);
        assert_eq!(v1, v2);
    }
}
