use std::{
    cmp::min,
    collections::HashSet,
    sync::{Arc, Mutex},
};

use bincode::{deserialize, serialize};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tokio::stream;

use crate::{
    error::OramError,
    logging::LatencyMetric,
    network::{Command, ReadType, WriteType},
    tree::{BinaryTree, TreeValue},
    Bucket, Key, Path, D, DELTA, NUM_BUCKETS_PER_BATCH_WRITE_CHUNK,
    NUM_BUCKETS_PER_READ_PATHS_CHUNK,
};

pub struct Server2 {
    pub tree: BinaryTree<Bucket>,
    pub prf_keys: Vec<Key>,
    pub epoch: u64,
    pathset_indices: Vec<usize>,
}

impl Server2 {
    pub fn new() -> Self {
        let mut tree = BinaryTree::new_with_depth(D);

        #[cfg(feature = "perf-logging")]
        let (tree, prf_keys) = {
            tree.fill(Bucket::new_random());
            // Initialize DELTA random PRF keys
            let mut rng = ChaCha20Rng::from_entropy();
            let prf_keys = (0..DELTA).map(|_| Key::random(&mut rng)).collect();
            (tree, prf_keys)
        };

        #[cfg(not(feature = "perf-logging"))]
        let (tree, prf_keys) = {
            tree.fill(Bucket::default());
            (tree, vec![])
        };

        Server2 {
            tree,
            prf_keys,
            epoch: 0,
            pathset_indices: vec![],
        }
    }

    /// l is the leaf block.
    pub fn read(&self, l: &Path) -> Result<Vec<Bucket>, OramError> {
        let read_latency = LatencyMetric::new("server2_read");
        let buckets = self.tree.get_all_nodes_along_path(l);
        read_latency.finish();
        Ok(buckets)
    }

    /// Get a reference to the tree
    pub fn get_tree(&self) -> &BinaryTree<Bucket> {
        &self.tree
    }

    pub fn write(&mut self, packed_buckets: Vec<Bucket>) {
        let write_latency = LatencyMetric::new("server2_write");
        // Ensure the number of elements in packed_buckets matches the number of pathset_indices
        assert_eq!(
            self.pathset_indices.len(),
            packed_buckets.len(),
            "Mismatched number of indices and buckets"
        );

        // Iterate over self.pathset_indices and packed_buckets, and overwrite corresponding values in self.tree
        for (index, bucket) in self.pathset_indices.iter().zip(packed_buckets.iter()) {
            self.tree.value[*index] = Some(bucket.clone());
        }

        // Increment the epoch
        self.epoch += 1;
        write_latency.finish();
    }

    /// Write a single chunk of buckets to the server.
    pub fn chunk_write(&mut self, buckets: Vec<Bucket>, chunk_idx: usize) {
        let write_latency = LatencyMetric::new("server2_write");

        // The start and end indices of the chunk within the pathset_indices vector.
        let start_idx = chunk_idx * NUM_BUCKETS_PER_BATCH_WRITE_CHUNK;
        let end_idx = start_idx + NUM_BUCKETS_PER_BATCH_WRITE_CHUNK;

        // The last chunk may not have NUM_BUCKETS_PER_CHUNK buckets.
        let correct_end_idx = min(end_idx, self.pathset_indices.len());

        // Write buckets to the tree at the indices specified by pathset_indices
        self.pathset_indices[start_idx..correct_end_idx]
            .iter()
            .zip(buckets)
            .for_each(|(idx, bucket)| {
                self.tree.value[*idx] = Some(bucket);
            });
        write_latency.finish();
    }

    /// Increments the epoch and adds the new PRF key.
    pub fn finalize_epoch(&mut self, key: &Key) {
        // Increment the epoch.
        self.epoch += 1;

        self.add_prf_key(key);
    }

    pub fn get_prf_keys(&self) -> Result<Vec<Key>, OramError> {
        Ok(self.prf_keys.clone())
    }

    pub fn add_prf_key(&mut self, key: &Key) {
        let add_prf_key_latency = LatencyMetric::new("server2_add_prf_key");
        self.prf_keys.push(key.clone());

        if self.epoch >= DELTA as u64 {
            self.prf_keys.remove(0);
        }
        add_prf_key_latency.finish();
    }

    /// Store the pathset indices.
    pub fn store_path_indices(&mut self, pathset: Vec<usize>) {
        self.pathset_indices = pathset;
    }

    /// Read a chunk of buckets from the server.
    pub fn read_pathset_chunk(&self, chunk_idx: usize) -> Result<Vec<Bucket>, OramError> {
        let start_idx = chunk_idx * NUM_BUCKETS_PER_READ_PATHS_CHUNK;
        let end_idx = start_idx + NUM_BUCKETS_PER_READ_PATHS_CHUNK;
        let correct_end_idx = min(end_idx, self.pathset_indices.len());
        Ok(self.pathset_indices[start_idx..correct_end_idx]
            .iter()
            .map(|i| self.tree.value[*i].clone().unwrap())
            .collect())
    }

    /// This is S2's pathset indices. When we read the paths from the pathset, we also update the pathset indices here.
    pub fn read_and_store_path_indices(
        &mut self,
        pathset: Vec<usize>,
    ) -> Result<Vec<Bucket>, OramError> {
        let read_paths_latency = LatencyMetric::new("server2_read_paths");
        self.pathset_indices = pathset.clone();

        let buckets: Vec<Bucket> = pathset
            .iter()
            .map(|i| self.tree.value[*i].clone().unwrap())
            .collect();
        read_paths_latency.finish();
        Ok(buckets)
    }

    pub fn read_paths_client(&self, pathset: Vec<usize>) -> Result<Vec<Bucket>, OramError> {
        let read_paths_latency = LatencyMetric::new("server2_read_paths_client");
        let buckets: Vec<Bucket> = pathset
            .iter()
            .map(|i| self.tree.value[*i].clone().unwrap())
            .collect();
        read_paths_latency.finish();
        Ok(buckets)
    }
}
