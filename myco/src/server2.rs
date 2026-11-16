//! Server2
//! 
//! S2 (Server 2) functions as a storage server, maintaining a tree-based data structure for message 
//! storage and handling client read operations. It receives batched updates from S1 with re-encrypted 
//! and reorganized messages, but cannot discern their intended locations. Clients read messages by 
//! downloading paths from S2's tree, but S2 cannot link these reads to previous writes due to the 
//! random path selection. S2 also stores and provides PRF keys for clients to compute message paths, 
//! ensuring privacy by preventing correlation between writes and reads.

use std::collections::HashMap;

use crate::{constants::{BLOCK_SIZE, D, DELTA, LAMBDA_BYTES, NOTIFICATION_BUCKET_SIZE_BYTES, Q, Z}, dtypes::{Block, Bucket, Key}, error::MycoError, logging::LatencyMetric};
use crate::{dtypes::{Path, TreeMycoKey}, tree::{BinaryTree, SparseBinaryTree}, utils::{l_to_u64, Index}};
use ed25519_dalek::SIGNATURE_LENGTH;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use dashmap;
use sys_info::mem_info;
use tracing::info;

/// The main server2 struct.
pub struct Server2 {
    /// The tree storing the buckets.
    pub tree: BinaryTree<Bucket>,
    /// The PRF keys.
    pub prf_keys: Vec<Key<TreeMycoKey>>,
    /// The current epoch.
    pub epoch: u64,
    /// The t-tables. Each table is one flat byte buffer in which notification bucket `i`
    /// occupies bytes `[i * NOTIFICATION_BUCKET_SIZE_BYTES, (i + 1) * NOTIFICATION_BUCKET_SIZE_BYTES)`.
    pub notification_tables: Vec<Vec<u8>>,
    /// The number of clients.
    pub num_clients: usize,
    /// The index of the latest notification table.
    pub latest_notif_table_idx: usize,
}

impl Server2 {
    /// Create a new Server2 instance.
    pub fn new(num_clients: usize) -> Self {
        // Initialize a binary tree with fixed depth
        let mut tree = BinaryTree::new_with_depth(D);

        tree.fill(Bucket::default());
        
        // Generate PRF keys
        let prf_keys: Vec<Key<TreeMycoKey>> = (0..DELTA).map(|_| Key::<TreeMycoKey>::random(&mut rand::thread_rng())).collect();
            
        println!("Server2::new: Created server with D={}, DB_SIZE={}, num_clients={}, DELTA={}",
                crate::constants::D, 1 << crate::constants::D, num_clients, crate::constants::DELTA);
        
        // Pre-allocate all notification tables (DELTA of them)
        let notification_tables = vec![Vec::new(); DELTA as usize];
                 
        // Server2 instance.
        Server2 {
            tree,
            notification_tables,
            prf_keys,
            epoch: 0,
            num_clients,
            latest_notif_table_idx: 0,
        }
    }

    /// Create a new Server2 instance whose tree is already full: every bucket holds a
    /// full-size placeholder, as it does once each bucket has been written at least once.
    /// Benchmarks use this so that memory use and read sizes are at their steady-state
    /// values from the first epoch instead of growing as paths are written for the first time.
    pub fn new_prefilled(num_clients: usize) -> Self {
        let mut server2 = Self::new(num_clients);

        println!("Filling up the tree...");
        let mut data = vec![0u8; Z * BLOCK_SIZE];
        ChaCha20Rng::from_entropy().fill_bytes(&mut data);
        server2.tree.fill(Bucket::contiguous(data, Some(vec![0u8; SIGNATURE_LENGTH])));

        server2
    }

    /// Read a path from the tree.
    pub fn read(&self, l: Vec<u8>) -> Result<Vec<Bucket>, MycoError> {
        let local_latency = LatencyMetric::new("server2_read");
        let path = Path::from(l);
        let buckets = self.tree.get_all_nodes_along_path(&path);
        local_latency.finish();
        Ok(buckets)
    }
    /// Write a batch of buckets to the tree.
    pub fn write(&mut self, pt: SparseBinaryTree<Bucket>) {
        let local_latency = LatencyMetric::new("server2_write_local");
        // Iterate over self.pathset_indices and packed_buckets, and overwrite corresponding values in self.tree
        for (index, bucket) in pt.packed_indices.iter().zip(pt.packed_buckets.iter()) {
            self.tree.value[*index] = Some(bucket.clone());
        }
        // Increment the epoch
        self.epoch += 1;
        local_latency.finish();
    }

    /// Write a single chunk of buckets to the server.
    pub fn chunk_write(&mut self, buckets: Vec<Bucket>, pathset_indices: Vec<usize>) {
        let local_latency = LatencyMetric::new("server2_chunk_write");
        
        // Write buckets to the tree at the indices specified by pathset_indices
        pathset_indices
            .iter()
            .zip(buckets)
            .for_each(|(idx, bucket)| {
                self.tree.value[*idx] = Some(bucket);
            });
            
        local_latency.finish();
    }

    /// Increments the epoch and adds the new PRF key.
    pub fn finalize_epoch(&mut self, key: &Key<TreeMycoKey>) {
        // Increment the epoch.
        self.epoch += 1;

        self.add_prf_key(key);
    }

    /// Logs the memory usage of the server.
    pub fn log_memory_usage(&self) {
        let _num_buckets = self.tree.value.len();

        let mut total_tree_size = 0;
        for bucket in self.tree.value.iter() {
            let mut total_size_of_bucket = 0;
            if let Some(bucket) = bucket {
                for block in bucket.iter() {
                    total_size_of_bucket += block.0.len();
                }
                total_size_of_bucket += bucket.1.as_ref().map_or(0, |x| x.len());
            }
            total_tree_size += total_size_of_bucket;
        }

        let total_ntf_size: usize = self.notification_tables.iter().map(|table| table.len()).sum();

        let server_2_data_structure_mem_usage = total_tree_size + total_ntf_size;

        let (used_gb, total_gb) = get_system_memory_stats();
        info!("{} - Tree size: {:.2} GB", "Server2::finalize_epoch", total_tree_size as f64 / (1024.0 * 1024.0 * 1024.0));
        info!("{} - Notif table size: {:.2} GB", "Server2::finalize_epoch", total_ntf_size as f64 / (1024.0 * 1024.0 * 1024.0));
        info!("{} - Total \"data\" memory: {:.2} GB", "Server2::finalize_epoch", server_2_data_structure_mem_usage as f64 / (1024.0 * 1024.0 * 1024.0));
        info!("{} - Process memory usage: {:.2}/{:.2} GB ({:.1}%)", "Server2::finalize_epoch", used_gb, total_gb, (used_gb / total_gb) * 100.0);
    }

    /// Get the PRF keys.
    pub fn get_prf_keys(&self) -> Result<Vec<Key<TreeMycoKey>>, MycoError> {
        Ok(self.prf_keys.clone())
    }

    /// Add a PRF key to the server.
    pub fn add_prf_key(&mut self, key: &Key<TreeMycoKey>) {
        let local_latency = LatencyMetric::new("server2_add_prf_key");
        self.prf_keys.push(key.clone());
        self.prf_keys.remove(0);
        self.latest_notif_table_idx = (self.latest_notif_table_idx + 1) % DELTA as usize;
        local_latency.finish();
    }

    /// Get the notification tables.
    pub fn read_notifs(&self, ls: HashMap<u64, Vec<Index>>) -> Result<HashMap<u64, Vec<Bucket>>, MycoError> {
        let local_latency = LatencyMetric::new("server2_read_notifs");
        let mut epoch_buckets: HashMap<u64, Vec<Bucket>> = HashMap::with_capacity(ls.len());
        // Process each epoch
        for (&delta, indices) in &ls {
            // Get the notification table for this epoch using modular arithmetic
            let index = (self.latest_notif_table_idx + DELTA as usize - delta as usize) % DELTA as usize;
            let t_table_ntf = &self.notification_tables[index];

            // Pre-allocate the vector to avoid reallocations
            let mut buckets = Vec::with_capacity(indices.len());
            
            // For smaller sets of indices, sequential is faster than parallel
            if indices.len() < 100 {
                // Sequential processing - avoids parallelization overhead for small sets
                for l in indices {
                    let idx = l_to_u64(l, self.num_clients) as usize;
                    // Use unchecked access if we're confident indices are valid, otherwise keep the get()
                    if let Some(bucket) = notif_bucket(t_table_ntf, idx) {
                        buckets.push(unpack_notif_bucket(bucket));
                    }
                }
            } else {
                // Use parallelization only for larger workloads where it makes sense
                buckets = indices
                    .par_iter()
                    .map(|l| {
                        let idx = l_to_u64(l, self.num_clients) as usize;
                        unpack_notif_bucket(notif_bucket(t_table_ntf, idx).unwrap())
                    })
                    .collect();
            }
            epoch_buckets.insert(delta, buckets);
        }
        local_latency.finish();
        Ok(epoch_buckets)
    }

    /// Get the notification tables without cloning, returning each bucket's bytes.
    pub fn read_notifs_refs<'a>(&'a self, ls: HashMap<u64, Vec<Index>>) -> Result<HashMap<u64, Vec<&'a [u8]>>, MycoError> {
        let local_latency = LatencyMetric::new("server2_read_notifs_refs");
        
        if self.notification_tables.is_empty() {
            return Ok(HashMap::new());
        }
                 
        // Use DashMap for concurrent access
        let results = dashmap::DashMap::with_capacity(ls.len());
        
        // Process each delta and indices
        let process_result = ls.into_par_iter().try_for_each(|(delta, indices)| {
            // Get the notification table for this epoch using modular arithmetic
            let table_idx = (self.latest_notif_table_idx + DELTA as usize - delta as usize) % DELTA as usize;
            let t_table_ntf = &self.notification_tables[table_idx];
            
            // Collect buckets based on indices
            let buckets: Vec<&[u8]> = if indices.len() > 10000 {
                indices.par_chunks(1000)
                    .flat_map_iter(|chunk| {
                        chunk.iter().map(|l| {
                            let idx = l_to_u64(l, self.num_clients) as usize;
                            notif_bucket(t_table_ntf, idx)
                        }).filter_map(|x| x)
                    })
                    .collect()
            } else {
                indices.iter()
                    .filter_map(|l| {
                        let idx = l_to_u64(l, self.num_clients) as usize;
                        notif_bucket(t_table_ntf, idx)
                    })
                    .collect()
            };
            
            results.insert(delta, buckets);
            Ok::<_, MycoError>(())
        });
        
        if let Err(e) = process_result {
            return Err(e);
        }
        
        // Convert DashMap back to HashMap
        let results = results.into_iter().collect();
        
        local_latency.finish();
        Ok(results)
    }

    pub fn write_notifs(&mut self, notif_buckets: Vec<Bucket>) {
        let local_latency = LatencyMetric::new("server2_write_notifs");
        
        // Write to the current notification table using latest_notif_table_idx
        let current_idx = self.latest_notif_table_idx;
        let mut table = vec![0u8; notif_buckets.len() * NOTIFICATION_BUCKET_SIZE_BYTES];
        for (bucket, slot) in notif_buckets.iter().zip(table.chunks_mut(NOTIFICATION_BUCKET_SIZE_BYTES)) {
            pack_notif_bucket(bucket, slot);
        }
        self.notification_tables[current_idx] = table;
        
        local_latency.finish();
    }

    /// Write a contiguous run of notification buckets, given as their concatenated bytes,
    /// starting at bucket `start_index` of the current table.
    pub fn write_notifs_chunk(&mut self, start_index: usize, raw: &[u8]) {
        let local_latency = LatencyMetric::new("server2_write_notifs_with_indices");

        // Get the current table using modular arithmetic
        let current_idx = self.latest_notif_table_idx;
        let current_table_ntf = &mut self.notification_tables[current_idx];

        // Make sure the table has enough capacity
        let start = start_index * NOTIFICATION_BUCKET_SIZE_BYTES;
        let end_bucket = start_index + (raw.len() + NOTIFICATION_BUCKET_SIZE_BYTES - 1) / NOTIFICATION_BUCKET_SIZE_BYTES;
        let required_len = std::cmp::max(end_bucket, self.num_clients * Q) * NOTIFICATION_BUCKET_SIZE_BYTES;
        if current_table_ntf.len() < required_len {
            current_table_ntf.resize(required_len, 0);
        }

        current_table_ntf[start..start + raw.len()].copy_from_slice(raw);

        local_latency.finish();
    }

    /// Read multiple paths from the tree in parallel.
    pub fn parallel_read(&self, indices: Vec<Vec<u8>>) -> Result<Vec<Vec<Bucket>>, MycoError> {        
        // Process all indices in parallel using Rayon
        let results: Vec<Vec<Bucket>> = indices.par_iter()
            .map(|l| {
                let path = Path::from(l.clone());
                self.tree.get_all_nodes_along_path(&path)
            })
            .collect();
            
        Ok(results)
    }
}

/// Returns the bytes of notification bucket `idx` in `table`, if the table holds it.
fn notif_bucket(table: &[u8], idx: usize) -> Option<&[u8]> {
    table.get(idx * NOTIFICATION_BUCKET_SIZE_BYTES..(idx + 1) * NOTIFICATION_BUCKET_SIZE_BYTES)
}

/// Rebuilds a notification bucket (one block per notification) from its stored bytes.
fn unpack_notif_bucket(bytes: &[u8]) -> Bucket {
    Bucket(bytes.chunks(LAMBDA_BYTES).map(|block| Block::new(block.to_vec())).collect(), None)
}

/// Copies a notification bucket's blocks into its fixed-size slot of a table.
fn pack_notif_bucket(bucket: &Bucket, slot: &mut [u8]) {
    let mut at = 0;
    for block in bucket.iter() {
        let n = block.0.len().min(slot.len() - at);
        slot[at..at + n].copy_from_slice(&block.0[..n]);
        at += n;
    }
}

/// Get the memory usage in GB for used and total memory.
fn get_system_memory_stats() -> (f64, f64) {
    match mem_info() {
        Ok(info) => {
            let used_gb = (info.total - info.free) as f64 / (1024.0 * 1024.0);
            let total_gb = info.total as f64 / (1024.0 * 1024.0);
            (used_gb, total_gb)
        },
        Err(e) => {
            println!("Failed to get memory info: {}", e);
            (0.0, 0.0)
        },
    }
}