/// Number of epochs before a message expires.
pub const DELTA: usize = 1000;
/// Depth of the binary tree.
pub const D: usize = 20;
/// Security parameter of the scheme.
pub const LAMBDA: usize = 128;
/// Number of "clients" per epoch. 1 client = 1 write.
pub const NUM_WRITES_PER_EPOCH: usize = 1000;
/// Multiple of NUM_WRITES_PER_EPOCH of the number of paths in the pathset.
pub const NU: usize = 1;
/// Bucket size.
pub const Z: usize = 30;

pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const BLOCK_SIZE: usize = INNER_BLOCK_SIZE + NONCE_SIZE + TAG_SIZE;
pub const INNER_BLOCK_SIZE: usize = 48 + NONCE_SIZE + TAG_SIZE;