//! Server2
//!
//! S2 (Server 2) functions as a storage server, maintaining a tree-based data structure for message
//! storage and handling client read operations. It receives batched updates from S1 with re-encrypted
//! and reorganized messages, but cannot discern their intended locations. Clients read messages by
//! downloading paths from S2's tree, but S2 cannot link these reads to previous writes due to the
//! random path selection. S2 also stores and provides PRF keys for clients to compute message paths,
//! ensuring privacy by preventing correlation between writes and reads.

use std::cmp::min;

use crate::{
    constants::{D, DELTA, NUM_BUCKETS_PER_BATCH_WRITE_CHUNK, NUM_BUCKETS_PER_READ_PATHS_CHUNK},
    dtypes::{Bucket, Key, Path},
    error::MycoError,
    logging::LatencyMetric,
    tree::BinaryTree,
};

cfg_if::cfg_if! {
    if #[cfg(feature = "perf-logging")] {
        use crate::tree::TreeValue;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
    }
}

/// The main server2 struct.
pub struct Server2 {
    /// The tree storing the buckets.
    pub tree: BinaryTree<Bucket>,
    /// The PRF keys.
    pub prf_keys: Vec<Key>,
    /// The current epoch.
    pub epoch: u64,
    /// The pathset indices.
    pathset_indices: Vec<usize>,
}

impl Server2 {
    /// Create a new Server2 instance.
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

    /// Read a path from the tree.
    pub fn read(&self, l: &Path) -> Result<Vec<Bucket>, MycoError> {
        let read_latency = LatencyMetric::new("server2_read");
        let buckets = self.tree.get_all_nodes_along_path(l);
        read_latency.finish();
        Ok(buckets)
    }

    /// Get a reference to the tree
    pub fn get_tree(&self) -> &BinaryTree<Bucket> {
        &self.tree
    }

    /// Write a batch of buckets to the tree.
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

    /// Get the PRF keys.
    pub fn get_prf_keys(&self) -> Result<Vec<Key>, MycoError> {
        Ok(self.prf_keys.clone())
    }

    /// Add a PRF key to the server.
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
    pub fn read_pathset_chunk(&self, chunk_idx: usize) -> Result<Vec<Bucket>, MycoError> {
        let read_paths_latency: LatencyMetric = LatencyMetric::new("server2_read_paths");
        let start_idx = chunk_idx * NUM_BUCKETS_PER_READ_PATHS_CHUNK;
        let end_idx = start_idx + NUM_BUCKETS_PER_READ_PATHS_CHUNK;
        let correct_end_idx = min(end_idx, self.pathset_indices.len());
        let buckets = self.pathset_indices[start_idx..correct_end_idx]
            .iter()
            .map(|i| self.tree.value[*i].clone().unwrap())
            .collect();
        read_paths_latency.finish();
        Ok(buckets)
    }

    /// Read a chunk of buckets from the server for a client request.
    pub fn read_paths_client_chunk(
        &self,
        chunk_idx: usize,
        indices: Vec<usize>,
    ) -> Result<Vec<Bucket>, MycoError> {
        let read_paths_latency: LatencyMetric = LatencyMetric::new("server2_read_paths_client");
        let start_idx = chunk_idx * NUM_BUCKETS_PER_READ_PATHS_CHUNK;
        let end_idx = start_idx + NUM_BUCKETS_PER_READ_PATHS_CHUNK;
        let correct_end_idx = min(end_idx, indices.len());
        let buckets = indices[start_idx..correct_end_idx]
            .iter()
            .map(|i| self.tree.value[*i].clone().unwrap())
            .collect();
        read_paths_latency.finish();
        Ok(buckets)
    }

    /// This is S2's pathset indices. When we read the paths from the pathset, we also update the pathset indices here.
    pub fn read_and_store_path_indices(
        &mut self,
        pathset: Vec<usize>,
    ) -> Result<Vec<Bucket>, MycoError> {
        let read_paths_latency = LatencyMetric::new("server2_read_paths");
        self.pathset_indices = pathset.clone();

        let buckets: Vec<Bucket> = pathset
            .iter()
            .map(|i| self.tree.value[*i].clone().unwrap())
            .collect();
        read_paths_latency.finish();
        Ok(buckets)
    }

    /// Read a chunk of buckets from the server for a client request.
    pub fn read_paths_client(&self, pathset: Vec<usize>) -> Result<Vec<Bucket>, MycoError> {
        let read_paths_latency = LatencyMetric::new("server2_read_paths_client!");
        let buckets: Vec<Bucket> = pathset
            .iter()
            .map(|i| self.tree.value[*i].clone().unwrap())
            .collect();
        read_paths_latency.finish();
        Ok(buckets)
    }
}
