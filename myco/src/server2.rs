//! Server2
//! 
//! S2 (Server 2) functions as a storage server, maintaining a tree-based data structure for message 
//! storage and handling client read operations. It receives batched updates from S1 with re-encrypted 
//! and reorganized messages, but cannot discern their intended locations. Clients read messages by 
//! downloading paths from S2's tree, but S2 cannot link these reads to previous writes due to the 
//! random path selection. S2 also stores and provides PRF keys for clients to compute message paths, 
//! ensuring privacy by preventing correlation between writes and reads.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::{constants::{BLOCK_SIZE, D, DELTA, LAMBDA_BYTES, NOTIFICATION_BUCKET_SIZE_BYTES, Q, Z}, dtypes::{Block, Bucket, Key}, error::MycoError, logging::LatencyMetric};
use crate::{dtypes::{Path, TreeMycoKey}, tree::{BinaryTree, SparseBinaryTree}, utils::{l_to_u64, read_skipped_levels, Index}};
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
    /// Buckets received for the epoch being written. [`Server2::finalize_epoch`] moves them
    /// into the tree, so readers see the previous epoch until the new one is complete.
    staged_buckets: Mutex<Vec<(Vec<usize>, Vec<Bucket>)>>,
    /// Notification table of the epoch being written, made current by [`Server2::finalize_epoch`].
    staged_notifs: Mutex<Vec<u8>>,
    /// Bytes of notification buckets received for the epoch being written.
    staged_notif_bytes: Mutex<usize>,
    /// Bucket buffers that are not part of the tree. [`Server2::stage_wire_chunk`] copies
    /// incoming buckets into them, and the buckets an epoch replaces come back here, so that
    /// after the first epoch no bucket memory is allocated or freed.
    spare_buckets: Mutex<Vec<Bucket>>,
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
            staged_buckets: Mutex::new(Vec::new()),
            staged_notifs: Mutex::new(Vec::new()),
            staged_notif_bytes: Mutex::new(0),
            spare_buckets: Mutex::new(Vec::new()),
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

        // The notification tables too: one per epoch of a message's lifetime, each at its full
        // size, with every page written. Otherwise each of the first DELTA epochs allocates a
        // table while it is being received.
        println!("Filling up the notification tables...");
        let table_bytes = num_clients * Q * NOTIFICATION_BUCKET_SIZE_BYTES;
        server2.notification_tables = (0..DELTA).into_par_iter().map(|_| vec![0xA5u8; table_bytes]).collect();

        server2
    }

    /// Read a path from the tree.
    pub fn read(&self, l: Vec<u8>) -> Result<Vec<Bucket>, MycoError> {
        let local_latency = LatencyMetric::new("server2_read");
        let path = Path::from(l);
        let buckets = self.tree.get_nodes_along_path_from(&path, read_skipped_levels(self.num_clients));
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

    /// Receives a chunk of buckets for the epoch being written without changing the tree.
    ///
    /// Takes `&self`, so chunks can arrive while clients are still reading the current epoch.
    /// The buckets replace the tree's at the next [`Server2::finalize_epoch`].
    pub fn stage_chunk_write(&self, buckets: Vec<Bucket>, pathset_indices: Vec<usize>) {
        assert_eq!(buckets.len(), pathset_indices.len(), "A chunk must have one tree index per bucket");
        self.staged_buckets.lock().unwrap().push((pathset_indices, buckets));
    }

    /// Receives a chunk of buckets in wire form for the epoch being written, like
    /// [`Server2::stage_chunk_write`], copying each into a spare buffer when one of the right
    /// size is available. The buffers of the incoming chunk are then freed by the thread that
    /// just allocated them, and the tree's own memory is reused from epoch to epoch.
    pub fn stage_wire_chunk(&self, buckets: Vec<crate::proto::myco::Bucket>, pathset_indices: Vec<usize>) {
        assert_eq!(buckets.len(), pathset_indices.len(), "A chunk must have one tree index per bucket");
        let mut spares = {
            let mut pool = self.spare_buckets.lock().unwrap();
            let keep = pool.len().saturating_sub(buckets.len());
            pool.split_off(keep)
        };
        let staged: Vec<Bucket> = buckets
            .into_iter()
            .map(|wire| match spares.pop() {
                Some(mut spare) if fits(&spare, &wire) => {
                    spare.0[0].0.copy_from_slice(&wire.data);
                    spare.1.as_mut().unwrap().copy_from_slice(&wire.signature);
                    spare
                }
                _ => wire.into_stored(),
            })
            .collect();
        self.staged_buckets.lock().unwrap().push((pathset_indices, staged));
    }

    /// Receives a contiguous run of notification buckets for the epoch being written, given as
    /// their concatenated bytes starting at bucket `start_index`, without changing the table
    /// clients read. The table becomes current at the next [`Server2::finalize_epoch`].
    pub fn stage_notifs_chunk(&self, start_index: usize, raw: &[u8]) {
        let mut table = self.staged_notifs.lock().unwrap();
        let start = start_index * NOTIFICATION_BUCKET_SIZE_BYTES;
        let end_bucket = start_index + (raw.len() + NOTIFICATION_BUCKET_SIZE_BYTES - 1) / NOTIFICATION_BUCKET_SIZE_BYTES;
        let required_len = std::cmp::max(end_bucket, self.num_clients * Q) * NOTIFICATION_BUCKET_SIZE_BYTES;
        if table.is_empty() {
            // A fresh zeroed allocation costs nothing until its pages are written.
            *table = vec![0u8; required_len];
        } else if table.len() < required_len {
            table.resize(required_len, 0);
        }
        table[start..start + raw.len()].copy_from_slice(raw);
        drop(table);
        *self.staged_notif_bytes.lock().unwrap() += raw.len();
    }

    /// Like [`Server2::finalize_epoch`], but first checks that the whole epoch arrived:
    /// `expected_buckets` tree buckets (the size of Server1's path-set) and every notification
    /// bucket of the table, each once. Otherwise nothing is applied: the staged data is discarded,
    /// the epoch and the PRF keys stay as they are, and an error is returned. So a stream that
    /// broke off is never applied, alone or mixed with the chunks of a later epoch.
    pub fn finalize_epoch_checked(&mut self, key: &Key<TreeMycoKey>, expected_buckets: usize) -> Result<(), MycoError> {
        let buckets: usize = self.staged_buckets.get_mut().unwrap().iter().map(|(indices, _)| indices.len()).sum();
        let notif_bytes = *self.staged_notif_bytes.get_mut().unwrap();
        let expected_notif_bytes = self.num_clients * Q * NOTIFICATION_BUCKET_SIZE_BYTES;
        if buckets != expected_buckets || notif_bytes != expected_notif_bytes {
            self.discard_staged();
            return Err(MycoError::ServerError(format!(
                "incomplete epoch: {} of {} tree buckets and {} of {} notification bytes; nothing applied",
                buckets, expected_buckets, notif_bytes, expected_notif_bytes
            )));
        }
        self.finalize_epoch(key);
        Ok(())
    }

    /// Discards everything staged for the epoch being written. The staged notification buffer is
    /// kept for reuse: a later epoch is applied only once it has overwritten all of it.
    pub fn discard_staged(&mut self) {
        let staged = std::mem::take(self.staged_buckets.get_mut().unwrap());
        rayon::spawn(move || drop(staged));
        *self.staged_notif_bytes.get_mut().unwrap() = 0;
    }

    /// Ends the epoch being written: moves the staged buckets into the tree, makes the staged
    /// notification table current, increments the epoch and adds the new PRF key.
    pub fn finalize_epoch(&mut self, key: &Key<TreeMycoKey>) {
        let staged = std::mem::take(self.staged_buckets.get_mut().unwrap());
        if !staged.is_empty() {
            let spares = self.spare_buckets.get_mut().unwrap();
            spares.reserve(staged.iter().map(|(indices, _)| indices.len()).sum());
            let mut discarded = Vec::new();
            for (indices, buckets) in staged {
                for (index, bucket) in indices.into_iter().zip(buckets) {
                    match std::mem::replace(&mut self.tree.value[index], Some(bucket)) {
                        // A full-size bucket is kept as a spare buffer for a later epoch.
                        Some(replaced) if replaced.0.len() == 1 && replaced.1.is_some() => spares.push(replaced),
                        replaced => discarded.push(replaced),
                    }
                }
            }
            // The caller holds the server exclusively: free what is not kept elsewhere.
            if !discarded.is_empty() {
                rayon::spawn(move || drop(discarded));
            }
        }

        *self.staged_notif_bytes.get_mut().unwrap() = 0;
        let staged_notifs = self.staged_notifs.get_mut().unwrap();
        if !staged_notifs.is_empty() {
            // The table swapped out is DELTA epochs old. Its buffer receives the next epoch's
            // notifications, which overwrite all of it.
            std::mem::swap(staged_notifs, &mut self.notification_tables[self.latest_notif_table_idx]);
        }

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
                self.tree.get_nodes_along_path_from(&path, read_skipped_levels(self.num_clients))
            })
            .collect();
            
        Ok(results)
    }
}

/// Whether `spare` can take the contents of `wire` without changing size.
fn fits(spare: &Bucket, wire: &crate::proto::myco::Bucket) -> bool {
    spare.0.len() == 1
        && spare.0[0].0.len() == wire.data.len()
        && !wire.signature.is_empty()
        && spare.1.as_ref().map_or(false, |signature| signature.len() == wire.signature.len())
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