//! Constants used in the Myco protocol.

/// Number of epochs a message persists before expiring and being deleted.
/// Set to 1000 to ensure messages remain available long enough for clients 
/// who may temporarily go offline.
pub const DELTA: usize = 10;

/// Depth of the binary tree used to store messages.
/// With D=18, supports a database size of 2^18 = 262,144 messages.
pub const D: usize = 18;

/// Security parameter for cryptographic operations in bits.
/// Standard 128-bit security level for keys and PRFs.
pub const LAMBDA: usize = 128;

/// Number of active clients in the system, calculated as database size / message lifetime.
/// This matches Talek's approach to message time-to-live.
pub const NUM_CLIENTS: usize = DB_SIZE / DELTA;

/// Parameter controlling number of paths sampled per client write.
/// Set to 1 since each client writes exactly one message per epoch.
pub const NU: usize = 1;

/// Size of each bucket in the binary tree.
/// Set to 50 based on empirical analysis showing this prevents overflow
/// while allowing efficient message percolation.
pub const Z: usize = 50;

/// Total size of the message database, calculated as 2^D.
pub const DB_SIZE: usize = 1 << D;

/// Number of messages processed together in a batch.
/// Set to 1 for basic message handling.
pub const BATCH_SIZE: usize = 2;

/// Size of each bucket in bytes, calculated as bucket capacity * block size
pub const BUCKET_SIZE_BYTES: usize = Z * BLOCK_SIZE;

/// Number of iterations for latency benchmarking
pub const LATENCY_BENCH_COUNT: usize = 30;

/// Number of iterations for throughput testing
pub const THROUGHPUT_ITERATIONS: usize = 10;

/// Size of the nonce used in authenticated encryption (AES-GCM)
pub const NONCE_SIZE: usize = 12;

/// Size of the authentication tag for AES-GCM
pub const TAG_SIZE: usize = 16;

/// Total block size including encrypted message and metadata
pub const BLOCK_SIZE: usize = INNER_BLOCK_SIZE + NONCE_SIZE + TAG_SIZE;

/// Size of inner encrypted block including message and metadata
pub const INNER_BLOCK_SIZE: usize = MESSAGE_SIZE + NONCE_SIZE + TAG_SIZE;

/// Size of plaintext message payload in bytes.
/// Set to 228 bytes to match block sizes used in prior PIR systems.
pub const MESSAGE_SIZE: usize = 228;

/// Maximum bytes per request from Server2 to Server1 when reading paths.
/// Increased to 100MB to reduce number of network requests
pub const MAX_REQUEST_SIZE_READ_PATHS: usize = 10 * 1024 * 1024;

/// Maximum bytes per request from Server1 to Server2 when writing batches.
/// Increased to 100MB to reduce number of network requests
pub const MAX_REQUEST_SIZE_BATCH_WRITE: usize = 10 * 1024 * 1024;

/// Number of buckets that can be written in one batch chunk
pub const NUM_BUCKETS_PER_BATCH_WRITE_CHUNK: usize =
    MAX_REQUEST_SIZE_BATCH_WRITE / BUCKET_SIZE_BYTES;

/// Number of buckets that can be read in one path chunk
pub const NUM_BUCKETS_PER_READ_PATHS_CHUNK: usize = 
    MAX_REQUEST_SIZE_READ_PATHS / BUCKET_SIZE_BYTES;

/// Fixed seed for throughput benchmark RNG to ensure reproducible results
pub const FIXED_SEED_TPUT_RNG: [u8; 32] = [1u8; 32];