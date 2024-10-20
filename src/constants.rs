pub const DELTA: u64 = 1000;
pub const D: usize = 20;
pub const LAMBDA: usize = 128;
pub const NUM_WRITES_PER_EPOCH: usize = 10;
pub const NU: usize = 1;
pub const Z: usize = 10;

pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const BLOCK_SIZE: usize = INNER_BLOCK_SIZE + NONCE_SIZE + TAG_SIZE;
pub const INNER_BLOCK_SIZE: usize = 48 + NONCE_SIZE + TAG_SIZE;
