use crate::tree::SparseBinaryTree;
use crate::{
    constants::*, decrypt, encrypt, prf, server2::Server2, tree::BinaryTree, Block, Bucket,
    EncryptionType, Key, Metadata, OramError, Path,
};
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::collections::HashSet;

pub struct Server1 {
    pub epoch: u64,
    pub k_s1_t: Key,
    pub num_clients: usize,
    pub s2: Arc<Mutex<Server2>>,
    pub p: SparseBinaryTree<Bucket>,
    pub pt: SparseBinaryTree<Bucket>,
    pub metadata_pt: SparseBinaryTree<Metadata>,
    pub metadata: BinaryTree<Metadata>,
    pathset_indices: Vec<usize>,
}

impl Server1 {
    pub fn new(s2: Arc<Mutex<Server2>>) -> Self {
        let metadata = BinaryTree::<Metadata>::new_with_depth(D);
        Self {
            epoch: 0,
            k_s1_t: Key::new(vec![]),
            num_clients: 0,
            s2,
            p: SparseBinaryTree::new(),
            pt: SparseBinaryTree::new(),
            metadata_pt: SparseBinaryTree::new(),
            metadata,
            pathset_indices: vec![],
        }
    }

    pub fn batch_init(&mut self, num_clients: usize) {
    println!("=== Starting Epoch {:?} ===", self.epoch);
        let mut rng = ChaCha20Rng::from_entropy();
        
        let paths = (0..(NU * num_clients))
            .map(|_| Path::random(&mut rng))
            .collect::<Vec<Path>>();
        // println!("Pathset {:?}", paths);
        self.pathset_indices = self.get_path_indices(paths);

        // println!("Pathset indices {:?}", self.pathset_indices);
        let buckets = self.s2.lock().unwrap().read_paths(self.pathset_indices.clone());
        
        let bucket_size = buckets.len();
        self.p = SparseBinaryTree::new_with_data(buckets, self.pathset_indices.clone());
        self.pt = SparseBinaryTree::new_with_data(vec![Bucket::default(); bucket_size], self.pathset_indices.clone());
        
        self.metadata_pt = SparseBinaryTree::new_with_data(
            vec![Metadata::default(); bucket_size],
            self.pathset_indices.clone(),
        );

        // println!("P before {:?}", self.p);
        // println!("Metadata pt before {:?}", self.metadata_pt);
        // println!("Metadata before {:?}", self.metadata);

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
        let l_path = Path::from(l);
        self.insert_message(&ct, &l_path, &k_oram_t, t_exp);

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

        // println!("Message intended path: {:?}", l);
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

        // Measure processing of buckets and metadata
        let bucket_processing_start = Instant::now();
        self.p
            .zip_with_binary_tree(&self.metadata)
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
        let bucket_processing_duration = bucket_processing_start.elapsed();
        println!("Bucket processing time: {:?}", bucket_processing_duration);

        // Measure processing of pt and metadata_pt
        let pt_processing_start = Instant::now();
        self.pt
            .zip_mut(&mut self.metadata_pt)
            .iter_mut()
            .try_for_each(|(bucket, metadata_bucket, path)| {
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
            })?;
        let pt_processing_duration = pt_processing_start.elapsed();
        println!(
            "PT and metadata_pt processing time: {:?}",
            pt_processing_duration
        );

        // Measure metadata overwrite time
        let metadata_overwrite_start = Instant::now();
        self.metadata.overwrite_from_sparse(&self.metadata_pt);
        let metadata_overwrite_duration = metadata_overwrite_start.elapsed();
        println!("Metadata overwrite time: {:?}", metadata_overwrite_duration);

        // Measure server lock and write time
        let server_write_start = Instant::now();
        let mut server2 = self.s2.lock().unwrap();
        // println!("Pt after {:?}", self.pt);
        // println!("Metadata pt after {:?}", self.metadata_pt);
        // println!("Metadata after {:?}", self.metadata);

        server2.write(self.pt.packed_buckets.clone());
        server2.add_prf_keys(&self.k_s1_t);
        let server_write_duration = server_write_start.elapsed();
        println!(
            "Server2 overwrite time: {:?}",
            server_write_duration
        );

        // Increment epoch
        self.epoch += 1;

        Ok(())
    }

    pub fn get_path_indices(&self, paths: Vec<Path>) -> Vec<usize> {
        let mut pathset: HashSet<usize> = HashSet::new();
        pathset.insert(1);
        paths.iter().for_each(|p| {
            p.clone().into_iter().fold(1, |acc, d| {
                let idx = 2 * acc + u8::from(d) as usize;
                pathset.insert(idx);
                idx
            });
        });
        pathset.into_iter().collect()
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
