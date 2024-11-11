//! RPC types for the server-client communication.
use crate::dtypes::{Bucket, Key, Path};
use serde::{Deserialize, Serialize};

// Server1 RPC types
#[derive(Deserialize, Serialize, Debug)]
/// A request to queue a write operation on Server1.
pub struct QueueWriteRequest {
    /// The encrypted message ciphertext.
    pub ct: Vec<u8>,
    /// The encryption flag.
    pub f: Vec<u8>,
    /// The temporary ORAM key for this write.
    pub k_oblv_t: Key,
    /// The encrypted state.
    pub cs: Vec<u8>,
}

#[derive(Deserialize, Serialize, Debug)]
/// A response indicating whether a queue write operation was successful.
pub struct QueueWriteResponse {
    /// Whether the queue write was successful.
    pub success: bool,
}

// Server2 RPC types
#[derive(Deserialize, Serialize, Debug)]
/// A request to read paths from Server2.
pub struct ReadPathsRequest {
    /// The indices of the paths to read.
    pub indices: Vec<usize>,
}

#[derive(Deserialize, Serialize, Debug)]
/// A request from a client to read paths from Server2.
pub struct ReadPathsClientRequest {
    /// The indices of the paths to read.
    pub indices: Vec<usize>,
}

#[derive(Serialize, Deserialize, Debug)]
/// A response containing buckets read from paths.
pub struct ReadPathsResponse {
    /// The buckets read from the paths.
    pub buckets: Vec<Bucket>,
}

#[derive(Deserialize, Serialize, Debug)]
/// A request to read a single path.
pub struct ReadRequest {
    /// The path to read.
    pub path: Path,
}

#[derive(Serialize, Deserialize, Debug)]
/// A response containing buckets from a read path.
pub struct ReadResponse {
    /// The buckets read from the path.
    pub buckets: Vec<Bucket>,
}

#[derive(Deserialize, Serialize, Debug)]
/// A request to store path indices on Server2.
pub struct StorePathIndicesRequest {
    /// The set of path indices to store.
    pub pathset: Vec<usize>,
}

#[derive(Serialize, Deserialize, Debug)]
/// A response indicating whether storing path indices was successful.
pub struct StorePathIndicesResponse {
    /// Whether storing the path indices was successful.
    pub success: bool,
}

#[derive(Deserialize, Serialize, Debug)]
/// A request to read a chunk of paths from Server2.
pub struct ChunkReadPathsRequest {
    /// The index of the chunk to read.
    pub chunk_idx: usize,
}

#[derive(Serialize, Deserialize, Debug)]
/// A response containing buckets from a chunk read.
pub struct ChunkReadPathsResponse {
    /// The buckets read from the chunk.
    pub buckets: Vec<Bucket>,
}

#[derive(Deserialize, Serialize, Debug)]
/// A request from a client to read a chunk of paths from Server2.
pub struct ChunkReadPathsClientRequest {
    /// The indices of the paths to read.
    pub indices: Vec<usize>,
    /// The index of the chunk to read.
    pub chunk_idx: usize,
}

#[derive(Serialize, Deserialize, Debug)]
/// A response containing buckets from a client chunk read.
pub struct ChunkReadPathsClientResponse {
    /// The buckets read from the chunk.
    pub buckets: Vec<Bucket>,
}

#[derive(Serialize, Deserialize, Debug)]
/// A request to finalize the epoch by adding the new PRF key and incrementing the epoch.
pub struct FinalizeEpochRequest {
    /// The PRF key for the next epoch.
    pub prf_key: Key,
}

#[derive(Serialize, Deserialize, Debug)]
/// A response indicating whether finalizing the epoch was successful.
pub struct FinalizeEpochResponse {
    /// Whether finalizing the epoch was successful.
    pub success: bool,
}

#[derive(Deserialize, Serialize, Debug)]
/// A request to write a chunk of buckets to the server.
pub struct ChunkWriteRequest {
    /// The buckets to be written.
    pub buckets: Vec<Bucket>,
    /// The index of the chunk that this write request corresponds to. Zero indexed. Defined by the number of total chunks to be sent / NUM_BUCKETS_PER_CHUNK.
    pub chunk_idx: usize,
    /// The PRF key for the current epoch.
    pub prf_key: Key,
}

#[derive(Serialize, Deserialize, Debug)]
/// A response indicating whether a chunk write was successful.
pub struct ChunkWriteResponse {
    /// Whether the chunk write was successful.
    pub success: bool,
}

#[derive(Deserialize, Serialize, Debug)]
/// A request to write a batch of buckets to the server.
pub struct WriteRequest {
    /// The buckets to be written.
    pub buckets: Vec<Bucket>,
    /// The PRF key for the current epoch.
    pub prf_key: Key,
}

#[derive(Serialize, Deserialize, Debug)]
/// A response indicating whether a write was successful.
pub struct WriteResponse {
    /// Whether the write was successful.
    pub success: bool,
}

#[derive(Serialize, Deserialize, Debug)]
/// A response containing the PRF keys for the current epoch.
pub struct GetPrfKeysResponse {
    /// The PRF keys for the current epoch.
    pub keys: Vec<Key>,
}

#[derive(Deserialize, Serialize, Debug)]
/// A request to initialize a batch of writes.
pub struct BatchInitRequest {
    /// The number of writes to be performed in the batch.
    pub num_writes: usize,
}

#[derive(Serialize, Deserialize, Debug)]
/// A response indicating whether a batch initialization was successful.
pub struct BatchInitResponse {
    /// Whether the batch initialization was successful.
    pub success: bool,
}

#[derive(Serialize, Deserialize, Debug)]
/// A response indicating whether a batch write was successful.
pub struct BatchWriteResponse {
    /// Whether the batch write was successful.
    pub success: bool,
}

#[derive(Serialize, Deserialize, Debug)]
/// A response containing the current epoch number.
pub struct EpochNumberResponse {
    /// The current epoch number.
    pub epoch_number: u64,
}
