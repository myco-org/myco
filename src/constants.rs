pub const DELTA: usize = 1000;
pub const D: usize = 18;
pub const LAMBDA: usize = 128;
pub const NUM_CLIENTS: usize = DB_SIZE / DELTA;
pub const NU: usize = 1;
pub const Z: usize = 50;
pub const DB_SIZE: usize = 1 << D;
pub const BATCH_SIZE: usize = 1;
// The size of a bucket in bytes.
pub const BUCKET_SIZE_BYTES: usize = Z * BLOCK_SIZE;

pub const LATENCY_BENCH_COUNT: usize = 30;
pub const THROUGHPUT_ITERATIONS: usize = 10;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const BLOCK_SIZE: usize = INNER_BLOCK_SIZE + NONCE_SIZE + TAG_SIZE;
pub const INNER_BLOCK_SIZE: usize = MESSAGE_SIZE + NONCE_SIZE + TAG_SIZE;
pub const MESSAGE_SIZE: usize = 228;

// The maximum number of bytes to send in a single request from Server2 to Server1 when reading paths.
pub const MAX_REQUEST_SIZE_READ_PATHS: usize = 10 * 1024 * 1024;
// The maximum number of bytes to send in a single request from Server1 to Server2 when writing a batch.
pub const MAX_REQUEST_SIZE_BATCH_WRITE: usize = 10 * 1024 * 1024;
pub const NUM_BUCKETS_PER_BATCH_WRITE_CHUNK: usize =
    MAX_REQUEST_SIZE_BATCH_WRITE / BUCKET_SIZE_BYTES;
pub const NUM_BUCKETS_PER_READ_PATHS_CHUNK: usize = MAX_REQUEST_SIZE_READ_PATHS / BUCKET_SIZE_BYTES;

/// Fixed seed for the RNG used in the tput benchmarks.
pub const FIXED_SEED_TPUT_RNG: [u8; 32] = [1u8; 32];
