use crate::dtypes::{Bucket, Key, Path};
use serde::{Deserialize, Serialize};

// Server1 RPC types
#[derive(Deserialize, Serialize, Debug)]
pub struct QueueWriteRequest {
    pub ct: Vec<u8>,
    pub f: Vec<u8>,
    pub k_oram_t: Key,
    pub cs: Vec<u8>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct QueueWriteResponse {
    pub success: bool,
}

// Server2 RPC types
#[derive(Deserialize, Serialize, Debug)]
pub struct ReadPathsRequest {
    pub indices: Vec<usize>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReadPathsResponse {
    pub buckets: Vec<Bucket>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ReadRequest {
    pub path: Path,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReadResponse {
    pub buckets: Vec<Bucket>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct WriteRequest {
    pub buckets: Vec<Bucket>,
    pub prf_key: Key,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WriteResponse {
    pub success: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetPrfKeysResponse {
    pub keys: Vec<Key>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct BatchInitRequest {
    pub num_writes: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BatchInitResponse {
    pub success: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BatchWriteResponse {
    pub success: bool,
}
