//! Server1
//!
//! S1 (Server 1) acts as the entry point for client writes in Myco, coordinating a tree-based
//! oblivious data structure system. When clients write messages, S1 receives encrypted message
//! content along with a pseudorandom location value and encryption key. S1 effectively functions
//! as an "ORAM-like client" that mediates between the writing clients and S2's storage tree.
//!
//! Each epoch has three steps:
//!
//! 1. [`Server1::batch_init`] samples one random root-to-leaf path per client. The buckets on
//!    those paths (the path set) are the ones rewritten this epoch.
//! 2. [`Server1::queue_write`] places each incoming message in the deepest path-set bucket on
//!    the way to the message's leaf.
//! 3. [`Server1::batch_write`] moves the unexpired messages already stored in the path set's
//!    buckets the same way, then hands Server2 an [`EpochWrite`]. The buckets are encrypted,
//!    padded with dummy blocks, shuffled and signed chunk by chunk as they are sent, so that
//!    this work overlaps with the transfer and no bucket is held in memory longer than needed.
//!
//! Server1 keeps its own copy of the tree without the dummy blocks: for each bucket, the real
//! messages it holds together with each message's re-encryption key, leaf and expiry epoch.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rand::{seq::SliceRandom, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;

use crate::{
    constants::*,
    crypto::{decrypt_into, encrypt_into, BlockDecryptor},
    dtypes::{Direction, Key, Path, TreeMycoKey},
    error::MycoError,
    logging::LatencyMetric,
    multisign::{sign_many, SIGN_PREFIX},
    network::server2::Server2Access,
    proto::myco::{Bucket as WireBucket, ChunkWriteRequest, NotifChunkRequest},
    utils::{l_to_u64, notification_location, read_skipped_levels, tree_location},
};

// Leaves are handled as `u32` values with one bit per tree level.
const _: () = assert!(D >= 1 && D <= 31);

/// A message as Server1 keeps it between epochs.
struct Held {
    /// The message's block in Server2's bucket: the client's ciphertext encrypted under `key`.
    block: [u8; BLOCK_SIZE],
    /// The message's re-encryption key.
    key: [u8; LAMBDA_BYTES],
    /// The leaf the message is headed for.
    leaf: u32,
    /// The epoch at which the message expires.
    t_exp: u64,
}

/// A message waiting to be written in the current epoch.
struct Queued {
    /// The client's ciphertext.
    ct: [u8; INNER_BLOCK_SIZE],
    /// The message's re-encryption key.
    key: [u8; LAMBDA_BYTES],
    /// The leaf the message is headed for.
    leaf: u32,
    /// The epoch at which the message expires.
    t_exp: u64,
}

/// Converts a path given as bytes (bit `i` of the bytes, least significant bit of each byte
/// first, is the direction taken at depth `i`) into a leaf number whose most significant of
/// `D` bits is the first direction. Agrees with `Path::from(Vec<u8>)`.
fn leaf_from_bytes(path: &[u8]) -> u32 {
    let mut leaf = 0u32;
    for depth in 0..D {
        let bit = path.get(depth / 8).map_or(0, |byte| (byte >> (depth % 8)) & 1);
        leaf = (leaf << 1) | bit as u32;
    }
    leaf
}

/// The leaf number of a full-length path.
fn leaf_from_path(path: &Path) -> u32 {
    path.into_iter().take(D).fold(0u32, |leaf, &direction| (leaf << 1) | u8::from(direction) as u32)
}

/// The path to a leaf.
fn path_from_leaf(leaf: u32) -> Path {
    Path::new((0..D).map(|depth| Direction::from(((leaf >> (D - 1 - depth)) & 1) as u8)).collect())
}

/// A message held by Server1, as shown to tests and diagnostics.
#[derive(Clone, Debug, PartialEq)]
pub struct HeldMessage {
    /// The message's block as Server2 stores it.
    pub block: Vec<u8>,
    /// The message's re-encryption key.
    pub key: Key<TreeMycoKey>,
    /// The path to the leaf the message is headed for.
    pub path: Path,
    /// The epoch at which the message expires.
    pub t_exp: u64,
}

/// Tree index of the bucket at `depth` on the path to `leaf` (the root is index 1 at depth 0).
fn bucket_on_path(leaf: u32, depth: usize) -> usize {
    (1usize << depth) | (leaf as usize >> (D - depth))
}

/// The buckets Server1 rewrites in one epoch: every bucket on the paths it sampled.
pub struct PathSet {
    /// Tree indices of the buckets, in ascending order.
    indices: Vec<usize>,
    /// Bit `i` is set when bucket `i` is in the set.
    bits: Vec<u64>,
    /// For each 64-bit word of `bits`, the number of set bits in the words before it.
    rank: Vec<u32>,
}

impl PathSet {
    /// The union of the root-to-leaf paths to `leaves`. Always contains the root.
    fn from_leaves(leaves: &[u32]) -> Self {
        let mut bits = vec![0u64; ((1usize << (D + 1)) + 63) / 64];
        bits[0] |= 1 << 1;
        for &leaf in leaves {
            // Walk up from the leaf; once a bucket is already present, so are its ancestors.
            for depth in (0..=D).rev() {
                let index = bucket_on_path(leaf, depth);
                let (word, bit) = (index / 64, 1u64 << (index % 64));
                if bits[word] & bit != 0 {
                    break;
                }
                bits[word] |= bit;
            }
        }

        let mut rank = Vec::with_capacity(bits.len());
        let mut indices = Vec::new();
        for (word_index, &word) in bits.iter().enumerate() {
            rank.push(indices.len() as u32);
            let mut remaining = word;
            while remaining != 0 {
                indices.push(word_index * 64 + remaining.trailing_zeros() as usize);
                remaining &= remaining - 1;
            }
        }
        PathSet { indices, bits, rank }
    }

    /// A path set with no buckets, used before the first `batch_init`.
    fn empty() -> Self {
        PathSet { indices: Vec::new(), bits: Vec::new(), rank: Vec::new() }
    }

    /// Number of buckets in the set.
    pub fn len(&self) -> usize {
        self.indices.len()
    }

    /// Whether the set has no buckets.
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }

    /// Tree indices of the buckets, in ascending order.
    pub fn indices(&self) -> &[usize] {
        &self.indices
    }

    /// Whether the bucket with tree index `index` is in the set.
    pub fn contains(&self, index: usize) -> bool {
        self.bits.get(index / 64).map_or(false, |word| word & (1u64 << (index % 64)) != 0)
    }

    /// Position in `indices` of a bucket that is in the set.
    fn position(&self, index: usize) -> usize {
        let below = self.bits[index / 64] & ((1u64 << (index % 64)) - 1);
        self.rank[index / 64] as usize + below.count_ones() as usize
    }

    /// Tree index of the deepest bucket of the set on `path`, which must be a full-length path.
    pub fn deepest_on(&self, path: &Path) -> usize {
        self.indices[self.deepest_on_path(leaf_from_path(path))]
    }

    /// Position of the deepest bucket of the set on the path to `leaf`: where a message headed
    /// for `leaf` is written this epoch.
    fn deepest_on_path(&self, leaf: u32) -> usize {
        for depth in (1..=D).rev() {
            let index = bucket_on_path(leaf, depth);
            if self.contains(index) {
                return self.position(index);
            }
        }
        self.position(1)
    }
}

/// Everything Server2 is sent in one epoch, produced chunk by chunk.
///
/// `bucket_chunk` and `notif_chunk` each build one request of the existing wire format and may
/// be called from several threads at once, each chunk at most once. Building a bucket chunk is
/// where the per-bucket cryptography happens.
pub struct EpochWrite {
    epoch: u64,
    pathset: Arc<PathSet>,
    /// Messages to write, by position of their bucket in the path set. Emptied as chunks are built.
    queues: Vec<Mutex<Vec<Queued>>>,
    /// For each bucket of the path set, how many of its previous blocks were decrypted while
    /// moving its messages. The remaining decryptions up to Z are done when the bucket is built.
    decrypted: Vec<u8>,
    /// This epoch's notifications as (notification bucket, ciphertext), sorted by bucket.
    notifs: Vec<(usize, [u8; LAMBDA_BYTES])>,
    /// Number of buckets in the notification table.
    notif_buckets: usize,
    /// Depth of the first level readers download (0 unless short reads are enabled).
    first_read_level: usize,
    /// Seed of the per-chunk random streams used for dummy keys, filler and shuffles.
    seed: [u8; 32],
    /// What Server1 keeps of each bucket chunk that was built: the messages of each bucket.
    built: Vec<Mutex<Option<Vec<Vec<Held>>>>>,
    /// Total time spent building chunks, summed over threads, in nanoseconds.
    build_nanos: AtomicU64,
}

/// Random stream identifiers: bucket chunks and notification chunks never share a stream.
const BUCKET_STREAMS: u64 = 0;
const NOTIF_STREAMS: u64 = 1 << 32;

impl EpochWrite {
    /// Number of bucket chunks.
    pub fn bucket_chunks(&self) -> usize {
        self.pathset.len().div_ceil(NUM_BUCKETS_PER_BATCH_WRITE_CHUNK)
    }

    /// Number of notification chunks.
    pub fn notif_chunks(&self) -> usize {
        self.notif_buckets.div_ceil(NUM_BUCKETS_PER_NOTIFICATION_CHUNK)
    }

    /// Number of buckets written this epoch.
    pub fn buckets(&self) -> usize {
        self.pathset.len()
    }

    /// Total time spent building chunks so far, summed over threads.
    pub fn build_seconds(&self) -> f64 {
        self.build_nanos.load(Ordering::Relaxed) as f64 / 1e9
    }

    fn chunk_rng(&self, stream: u64) -> ChaCha20Rng {
        let mut rng = ChaCha20Rng::from_seed(self.seed);
        rng.set_stream(stream);
        rng
    }

    /// Builds bucket chunk `chunk`: for each of its buckets, encrypts the bucket's messages
    /// under their re-encryption keys, fills the rest of the bucket with dummy blocks, places
    /// the blocks in random order and signs the bucket together with its tree index. The
    /// signatures are the ones `crypto::sign` gives, computed for several buckets at a time.
    ///
    /// Each bucket involves Z decryptions and Z encryptions in total, whatever its number of
    /// real messages.
    pub fn bucket_chunk(&self, chunk: usize) -> ChunkWriteRequest {
        let started = Instant::now();
        let start = chunk * NUM_BUCKETS_PER_BATCH_WRITE_CHUNK;
        let end = (start + NUM_BUCKETS_PER_BATCH_WRITE_CHUNK).min(self.pathset.len());
        let mut rng = self.chunk_rng(BUCKET_STREAMS + chunk as u64);

        const BUCKET_BYTES: usize = Z * BLOCK_SIZE;
        const INDEX_BYTES: usize = std::mem::size_of::<usize>();
        // What a bucket's signature covers: its tree index followed by its blocks. Buckets are
        // signed several at a time (see `multisign`), so a few of them are laid out side by
        // side, each after the scratch space signing needs.
        const SIGNED_TOGETHER: usize = 8;
        const BUFFER_BYTES: usize = SIGN_PREFIX + INDEX_BYTES + BUCKET_BYTES;
        let mut buffers = vec![0u8; SIGNED_TOGETHER * BUFFER_BYTES];
        let mut slots: [usize; Z] = std::array::from_fn(|slot| slot);
        let zero_inner = [0u8; INNER_BLOCK_SIZE];
        let mut scratch = [0u8; INNER_BLOCK_SIZE];
        // The padding decryptions all use the same key: set it up once for the chunk.
        let padding_key = BlockDecryptor::new(&[0u8; LAMBDA_BYTES]).expect("Key setup failed");

        let mut buckets = Vec::with_capacity(end - start);
        let mut kept = Vec::with_capacity(end - start);
        for group_start in (start..end).step_by(SIGNED_TOGETHER) {
            let group_end = (group_start + SIGNED_TOGETHER).min(end);
            for (position, buffer) in (group_start..group_end).zip(buffers.chunks_exact_mut(BUFFER_BYTES)) {
                let tree_index = self.pathset.indices[position];
                let queued = std::mem::take(&mut *self.queues[position].lock().unwrap());
                assert!(
                    queued.len() <= Z,
                    "Bucket length exceeds Z in epoch {}: bucket length={}, expected<={}",
                    self.epoch,
                    queued.len(),
                    Z
                );

                assert!(
                    queued.is_empty() || tree_index >> self.first_read_level != 0,
                    "A message was placed in bucket {} in epoch {}, above the first level readers download ({})",
                    tree_index,
                    self.epoch,
                    self.first_read_level
                );

                for _ in self.decrypted[position] as usize..Z {
                    let _ = padding_key.decrypt_into(&[0u8; BLOCK_SIZE], &mut scratch);
                }

                let (index_bytes, blocks) = buffer[SIGN_PREFIX..].split_at_mut(INDEX_BYTES);
                index_bytes.copy_from_slice(&tree_index.to_be_bytes());
                slots.shuffle(&mut rng);
                let mut held = Vec::with_capacity(queued.len());
                for (nth, &slot) in slots.iter().enumerate() {
                    let block = &mut blocks[slot * BLOCK_SIZE..(slot + 1) * BLOCK_SIZE];
                    match queued.get(nth) {
                        Some(message) => {
                            encrypt_into(&message.key, &message.ct, block).expect("Encryption failed");
                            held.push(Held {
                                block: (&*block).try_into().unwrap(),
                                key: message.key,
                                leaf: message.leaf,
                                t_exp: message.t_exp,
                            });
                        }
                        None => {
                            let mut dummy_key = [0u8; LAMBDA_BYTES];
                            rng.fill_bytes(&mut dummy_key);
                            encrypt_into(&dummy_key, &zero_inner, block).expect("Encryption failed");
                        }
                    }
                }
                kept.push(held);
            }

            let mut to_sign: Vec<&mut [u8]> = buffers.chunks_exact_mut(BUFFER_BYTES).take(group_end - group_start).collect();
            let signatures = sign_many(&mut to_sign);
            for (buffer, signature) in to_sign.iter().zip(signatures) {
                buckets.push(WireBucket { data: buffer[SIGN_PREFIX + INDEX_BYTES..].to_vec(), signature: signature.to_vec() });
            }
        }

        *self.built[chunk].lock().unwrap() = Some(kept);
        self.build_nanos.fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        ChunkWriteRequest {
            buckets,
            pathset_indices: self.pathset.indices[start..end].iter().map(|&index| index as u32).collect(),
        }
    }

    /// Builds notification chunk `chunk`: a run of notification buckets, each holding its real
    /// notifications in random slots and random filler in the others.
    pub fn notif_chunk(&self, chunk: usize) -> NotifChunkRequest {
        let started = Instant::now();
        let start = chunk * NUM_BUCKETS_PER_NOTIFICATION_CHUNK;
        let end = (start + NUM_BUCKETS_PER_NOTIFICATION_CHUNK).min(self.notif_buckets);
        let mut rng = self.chunk_rng(NOTIF_STREAMS + chunk as u64);

        let mut raw = vec![0u8; (end - start) * NOTIFICATION_BUCKET_SIZE_BYTES];
        rng.fill_bytes(&mut raw);

        let first = self.notifs.partition_point(|(bucket, _)| *bucket < start);
        let last = self.notifs.partition_point(|(bucket, _)| *bucket < end);
        let mut slots: [usize; Z_M] = std::array::from_fn(|slot| slot);
        let mut at = first;
        while at < last {
            let bucket = self.notifs[at].0;
            let mut next = at;
            while next < last && self.notifs[next].0 == bucket {
                next += 1;
            }
            assert!(
                next - at <= Z_M,
                "Notification bucket {} overflowed in epoch {}: {} notifications, capacity {}",
                bucket,
                self.epoch,
                next - at,
                Z_M
            );
            slots.shuffle(&mut rng);
            for (&slot, (_, ct_ntf)) in slots.iter().zip(&self.notifs[at..next]) {
                let offset = (bucket - start) * NOTIFICATION_BUCKET_SIZE_BYTES + slot * LAMBDA_BYTES;
                raw[offset..offset + LAMBDA_BYTES].copy_from_slice(ct_ntf);
            }
            at = next;
        }

        self.build_nanos.fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        NotifChunkRequest {
            raw_notification_data: raw,
            num_buckets: (end - start) as u32,
            start_index: start as u32,
        }
    }
}

/// The main server1 struct.
pub struct Server1 {
    /// The current epoch of the server.
    pub epoch: u64,
    /// The key used for server1 transactions.
    pub k_s1_t: Key<TreeMycoKey>,
    /// The number of clients connected to the server.
    pub num_clients: usize,
    /// Access to Server2.
    pub s2: Box<dyn Server2Access>,
    /// Server1's copy of the tree without dummy blocks: the messages held by each bucket.
    held: Vec<Vec<Held>>,
    /// The buckets rewritten this epoch.
    pathset: Arc<PathSet>,
    /// Messages queued this epoch, by position of their bucket in the path set.
    queues: Vec<Mutex<Vec<Queued>>>,
    /// Notifications queued this epoch as (notification bucket, ciphertext).
    notifs: Vec<(usize, [u8; LAMBDA_BYTES])>,
    rng: ChaCha20Rng,
    /// Tree buckets sent by the last [`Server1::batch_write_stream`], for Server2's check at
    /// [`Server1::batch_write_finalize`].
    streamed_buckets: usize,
    /// Set when writing an epoch to Server2 failed. Server1's copy of the tree then no longer
    /// matches Server2's, so no further epoch is started.
    failed: bool,
}

impl Server1 {
    /// Create a new Server1 instance.
    pub fn new(s2: Box<dyn Server2Access>, num_clients: usize) -> Self {
        Self {
            epoch: 0,
            k_s1_t: Key::new(vec![]),
            num_clients,
            s2,
            held: (0..1usize << (D + 1)).map(|_| Vec::new()).collect(),
            pathset: Arc::new(PathSet::empty()),
            queues: Vec::new(),
            notifs: Vec::new(),
            rng: ChaCha20Rng::from_entropy(),
            streamed_buckets: 0,
            failed: false,
        }
    }

    /// The buckets rewritten this epoch.
    pub fn pathset(&self) -> &PathSet {
        &self.pathset
    }

    /// The messages Server1 holds for the bucket with tree index `index`.
    pub fn held_in_bucket(&self, index: usize) -> Vec<HeldMessage> {
        self.held.get(index).map_or(Vec::new(), |bucket| {
            bucket
                .iter()
                .map(|message| HeldMessage {
                    block: message.block.to_vec(),
                    key: Key::new(message.key.to_vec()),
                    path: path_from_leaf(message.leaf),
                    t_exp: message.t_exp,
                })
                .collect()
        })
    }

    /// The number of messages Server1 holds at each depth of the tree, from the root down.
    pub fn held_by_depth(&self) -> Vec<usize> {
        (0..=D).map(|depth| self.held[1 << depth..1 << (depth + 1)].iter().map(|bucket| bucket.len()).sum()).collect()
    }

    /// Initialize the server for a new batch: sample one path per client and start an empty
    /// queue for each bucket on those paths.
    pub fn batch_init(&mut self) -> Result<(), MycoError> {
        if self.failed {
            return Err(MycoError::ServerError("an earlier epoch failed to reach Server2; Server1 must be restarted".to_string()));
        }
        let local_latency = LatencyMetric::new("server1_batch_init");

        let leaves: Vec<u32> = (0..NU * self.num_clients).map(|_| self.rng.gen::<u32>() >> (32 - D)).collect();
        let pathset = PathSet::from_leaves(&leaves);
        self.queues = (0..pathset.len()).into_par_iter().map(|_| Mutex::new(Vec::new())).collect();
        self.notifs.clear();
        self.pathset = Arc::new(pathset);
        self.k_s1_t = Key::random(&mut self.rng);

        local_latency.finish();
        Ok(())
    }

    /// Works out where a write goes: the position of its bucket in the path set, the message
    /// to queue there, and its notification.
    fn place_write(
        &self,
        ct: &[u8],
        ct_ntf: &[u8],
        f: &[u8],
        f_ntf: &[u8],
        k_renc_t: &Key<TreeMycoKey>,
        c_s: &[u8],
    ) -> Result<(usize, Queued, (usize, [u8; LAMBDA_BYTES])), MycoError> {
        if self.pathset.is_empty() {
            return Err(MycoError::ServerError("queue_write called before batch_init".to_string()));
        }
        if ct.len() > INNER_BLOCK_SIZE {
            return Err(MycoError::ServerError(format!("Ciphertext is {} bytes, expected at most {}", ct.len(), INNER_BLOCK_SIZE)));
        }
        let key: [u8; LAMBDA_BYTES] = k_renc_t.bytes[..]
            .try_into()
            .map_err(|_| MycoError::ServerError(format!("Re-encryption key is {} bytes, expected {}", k_renc_t.bytes.len(), LAMBDA_BYTES)))?;
        let ct_ntf: [u8; LAMBDA_BYTES] = ct_ntf
            .try_into()
            .map_err(|_| MycoError::ServerError(format!("Notification is {} bytes, expected {}", ct_ntf.len(), LAMBDA_BYTES)))?;

        if f.len() != LAMBDA_BYTES || f_ntf.len() != LAMBDA_BYTES {
            return Err(MycoError::ServerError(format!("f and f_ntf are {} and {} bytes, expected {}", f.len(), f_ntf.len(), LAMBDA_BYTES)));
        }

        let l = tree_location(&self.k_s1_t.bytes, f, c_s)
            .map_err(|e| MycoError::ServerError(format!("PRF computation failed: {:?}", e)))?;
        let leaf = leaf_from_bytes(&l);
        let position = self.pathset.deepest_on_path(leaf);

        let l_ntf = notification_location(&self.k_s1_t.bytes, f_ntf, c_s, self.num_clients)
            .map_err(|e| MycoError::ServerError(format!("PRF computation for notification failed: {:?}", e)))?;
        let notif_bucket = l_to_u64(&l_ntf, self.num_clients) as usize;

        // A ciphertext shorter than a block is padded with zeros, as encryption pads its input.
        let mut padded = [0u8; INNER_BLOCK_SIZE];
        padded[..ct.len()].copy_from_slice(ct);
        let queued = Queued { ct: padded, key, leaf, t_exp: self.epoch + DELTA as u64 };
        Ok((position, queued, (notif_bucket, ct_ntf)))
    }

    /// Queues an individual write.
    pub fn queue_write(
        &mut self,
        ct: Vec<u8>,
        ct_ntf: Vec<u8>,
        f: Vec<u8>,
        f_ntf: Vec<u8>,
        k_renc_t: Key<TreeMycoKey>,
        c_s: Vec<u8>,
    ) -> Result<(), MycoError> {
        let local_latency = LatencyMetric::new("server1_queue_write");

        let (position, queued, notif) = self.place_write(&ct, &ct_ntf, &f, &f_ntf, &k_renc_t, &c_s)?;
        self.queues[position].get_mut().unwrap().push(queued);
        self.notifs.push(notif);

        local_latency.finish();
        Ok(())
    }

    /// Queue multiple writes in parallel from megaclient
    pub fn megaclient_queue_write(
        &mut self,
        cts: Vec<Vec<u8>>,
        ct_ntfs: Vec<Vec<u8>>,
        fs: Vec<Vec<u8>>,
        f_ntfs: Vec<Vec<u8>>,
        k_renc_ts: Vec<Key<TreeMycoKey>>,
        c_ss: Vec<Vec<u8>>,
    ) -> Result<(), MycoError> {
        let local_latency = LatencyMetric::new("server1_megaclient_queue_write");

        let notifs: Vec<(usize, [u8; LAMBDA_BYTES])> = (0..cts.len())
            .into_par_iter()
            .map(|i| {
                let (position, queued, notif) = self.place_write(&cts[i], &ct_ntfs[i], &fs[i], &f_ntfs[i], &k_renc_ts[i], &c_ss[i])?;
                self.queues[position].lock().unwrap().push(queued);
                Ok(notif)
            })
            .collect::<Result<_, MycoError>>()?;
        self.notifs.extend(notifs);

        local_latency.finish();
        Ok(())
    }

    /// Moves the unexpired messages stored in the path set's buckets to where they belong this
    /// epoch and packages the epoch's writes for Server2.
    fn prepare_epoch_write(&mut self) -> EpochWrite {
        let pathset = self.pathset.clone();
        let queues = std::mem::take(&mut self.queues);
        let epoch = self.epoch;

        // Take the previous contents of the path set's buckets out of Server1's copy of the
        // tree. Tree order is the order of the path set's positions.
        let previous: Vec<Vec<Held>> = self
            .held
            .par_iter_mut()
            .enumerate()
            .filter(|(index, _)| pathset.contains(*index))
            .map(|(_, bucket)| std::mem::take(bucket))
            .collect();

        // Decrypt each unexpired message and queue it at the deepest bucket of this epoch's
        // path set on its path. Expired messages are dropped.
        let decrypted: Vec<u8> = previous
            .into_par_iter()
            .map(|bucket| {
                let mut count = 0u8;
                for message in bucket {
                    if epoch < message.t_exp {
                        let mut ct = [0u8; INNER_BLOCK_SIZE];
                        decrypt_into(&message.key, &message.block, &mut ct).expect("Decryption of a stored message failed");
                        let position = pathset.deepest_on_path(message.leaf);
                        queues[position].lock().unwrap().push(Queued { ct, key: message.key, leaf: message.leaf, t_exp: message.t_exp });
                        count += 1;
                    }
                }
                count
            })
            .collect();

        let mut notifs = std::mem::take(&mut self.notifs);
        notifs.par_sort_unstable_by_key(|(bucket, _)| *bucket);

        let bucket_chunks = pathset.len().div_ceil(NUM_BUCKETS_PER_BATCH_WRITE_CHUNK);
        EpochWrite {
            epoch,
            pathset,
            queues,
            decrypted,
            notifs,
            notif_buckets: Q * self.num_clients,
            first_read_level: read_skipped_levels(self.num_clients),
            seed: self.rng.gen(),
            built: (0..bucket_chunks).map(|_| Mutex::new(None)).collect(),
            build_nanos: AtomicU64::new(0),
        }
    }

    /// Records the epoch's buckets in Server1's copy of the tree.
    fn finish_epoch_write(&mut self, epoch_write: &EpochWrite) {
        for chunk in 0..epoch_write.bucket_chunks() {
            // A chunk is only missing here if writing to Server2 stopped early. Build it now so
            // that Server1's copy stays complete.
            if epoch_write.built[chunk].lock().unwrap().is_none() {
                epoch_write.bucket_chunk(chunk);
            }
            let kept = epoch_write.built[chunk].lock().unwrap().take().unwrap();
            let start = chunk * NUM_BUCKETS_PER_BATCH_WRITE_CHUNK;
            for (offset, bucket) in kept.into_iter().enumerate() {
                self.held[epoch_write.pathset.indices[start + offset]] = bucket;
            }
        }
    }

    /// Asynchronous batch write using Server2.
    pub async fn async_batch_write(&mut self) -> Result<(), MycoError> {
        let end_to_end_latency = LatencyMetric::new("server1_batch_write_end_to_end");

        let local_latency = LatencyMetric::new("server1_batch_write_local");
        let epoch_write = Arc::new(self.prepare_epoch_write());
        local_latency.finish();

        let write_result = self.s2.write_epoch(epoch_write.clone(), &self.k_s1_t).await;
        self.finish_epoch_write(&epoch_write);
        crate::logging::log_duration_ms("server1_batch_write_build_cpu", epoch_write.build_seconds() * 1000.0);
        self.failed |= write_result.is_err();
        write_result.map_err(|e| MycoError::ServerError(format!("async_batch_write: error writing to Server2: {:?}", e)))?;
        self.epoch += 1;

        end_to_end_latency.finish();
        Ok(())
    }

    /// First half of a batch write for overlapped epochs: sends the epoch to Server2 without
    /// ending it there, so that clients can still be reading the previous epoch meanwhile.
    /// [`Server1::batch_write_finalize`] must follow before the next `batch_init`.
    pub async fn batch_write_stream(&mut self) -> Result<(), MycoError> {
        let stream_latency = LatencyMetric::new("server1_batch_write_stream");

        let local_latency = LatencyMetric::new("server1_batch_write_local");
        let epoch_write = Arc::new(self.prepare_epoch_write());
        local_latency.finish();

        let write_result = self.s2.stream_epoch(epoch_write.clone()).await;
        self.finish_epoch_write(&epoch_write);
        crate::logging::log_duration_ms("server1_batch_write_build_cpu", epoch_write.build_seconds() * 1000.0);
        self.failed |= write_result.is_err();
        self.streamed_buckets = epoch_write.buckets();
        write_result.map_err(|e| MycoError::ServerError(format!("batch_write_stream: error writing to Server2: {:?}", e)))?;

        stream_latency.finish();
        Ok(())
    }

    /// Second half of a batch write for overlapped epochs: tells Server2 to switch to the epoch
    /// sent by [`Server1::batch_write_stream`] and publishes the epoch's PRF key.
    pub async fn batch_write_finalize(&mut self) -> Result<(), MycoError> {
        let finalize_latency = LatencyMetric::new("server1_batch_write_finalize");
        let result = self.s2.finalize_epoch(&self.k_s1_t, self.streamed_buckets).await;
        self.failed |= result.is_err();
        result
            .map_err(|e| MycoError::ServerError(format!("batch_write_finalize: error finalizing the epoch on Server2: {:?}", e)))?;
        self.epoch += 1;
        finalize_latency.finish();
        Ok(())
    }

    /// Synchronous batch write.
    pub fn batch_write(&mut self) -> Result<(), MycoError> {
        futures::executor::block_on(self.async_batch_write())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::get_tree_index_for_bucket;

    #[test]
    fn leaf_numbers_agree_with_paths() {
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        for _ in 0..1000 {
            let bytes: Vec<u8> = (0..D_BYTES).map(|_| rng.gen()).collect();
            let leaf = leaf_from_bytes(&bytes);
            for depth in 0..=D {
                assert_eq!(bucket_on_path(leaf, depth), get_tree_index_for_bucket(&bytes, depth));
            }
        }
    }

    #[test]
    fn leaf_numbers_and_paths_convert_both_ways() {
        let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
        for _ in 0..1000 {
            let bytes: Vec<u8> = (0..D_BYTES).map(|_| rng.gen()).collect();
            let leaf = leaf_from_bytes(&bytes);
            assert_eq!(path_from_leaf(leaf), Path::from(bytes));
            assert_eq!(leaf_from_path(&path_from_leaf(leaf)), leaf);
        }
    }

    #[test]
    fn pathset_matches_its_definition() {
        let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
        let leaves: Vec<u32> = (0..500).map(|_| rng.gen::<u32>() >> (32 - D)).collect();
        let pathset = PathSet::from_leaves(&leaves);

        let mut expected: Vec<usize> = leaves.iter().flat_map(|&leaf| (0..=D).map(move |depth| bucket_on_path(leaf, depth))).collect();
        expected.sort_unstable();
        expected.dedup();
        assert_eq!(pathset.indices(), &expected[..]);
        for (position, &index) in expected.iter().enumerate() {
            assert!(pathset.contains(index));
            assert_eq!(pathset.position(index), position);
        }

        // The deepest bucket of the set on a path is the last one before the path leaves the set.
        for _ in 0..1000 {
            let leaf = rng.gen::<u32>() >> (32 - D);
            let deepest = (0..=D).rev().map(|depth| bucket_on_path(leaf, depth)).find(|index| expected.binary_search(index).is_ok()).unwrap();
            assert_eq!(pathset.indices()[pathset.deepest_on_path(leaf)], deepest);
            assert_eq!(pathset.deepest_on(&path_from_leaf(leaf)), deepest);
        }
    }
}
