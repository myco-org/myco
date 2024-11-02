pub const DELTA: usize = 1000;
pub const D: usize = 23;
pub const LAMBDA: usize = 128;
pub const NUM_CLIENTS: usize = DB_SIZE / DELTA;
pub const NU: usize = 1;
pub const Z: usize = 50;
pub const DB_SIZE: usize = 1 << D;
pub const BATCH_SIZE: usize = 1;

pub const LATENCY_BENCH_COUNT: usize = 20;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const BLOCK_SIZE: usize = INNER_BLOCK_SIZE + NONCE_SIZE + TAG_SIZE;
pub const INNER_BLOCK_SIZE: usize = MESSAGE_SIZE + NONCE_SIZE + TAG_SIZE;
pub const MESSAGE_SIZE: usize = 228;