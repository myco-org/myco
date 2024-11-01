pub const DELTA: usize = 1000;
pub const D: usize = 1;
pub const LAMBDA: usize = 128;
// pub const NUM_CLIENTS: usize = DB_SIZE/DELTA;
pub const NUM_CLIENTS: usize = 1;
pub const NU: usize = 1; 
pub const Z: usize = 3;
pub const DB_SIZE: usize = 1 << D;

pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const BLOCK_SIZE: usize = INNER_BLOCK_SIZE + NONCE_SIZE + TAG_SIZE;
pub const INNER_BLOCK_SIZE: usize = 48 + NONCE_SIZE + TAG_SIZE;
