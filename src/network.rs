//! # Myco Network Module
//!
//! This module contains the network communication code for the Myco library.
//!
//! It defines the traits and structures for interacting with the servers over the network.
use anyhow::Result;
use axum::async_trait;
use bincode::{deserialize, serialize};
use futures::{StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use std::sync::{Mutex, RwLock};
use std::{
    io::{Read, Write},
    sync::Arc,
};
use tokio::io::AsyncWriteExt;

use crate::logging::BytesMetric;
use crate::rpc_types::{
    ChunkReadPathsClientRequest, ChunkReadPathsClientResponse, ChunkReadPathsRequest,
    ChunkReadPathsResponse, ChunkWriteRequest, FinalizeEpochRequest, FinalizeEpochResponse,
    GetPrfKeysResponse, QueueWriteRequest, QueueWriteResponse, ReadPathsClientRequest, ReadPathsResponse, StorePathIndicesRequest,
    StorePathIndicesResponse, WriteResponse,
};
use crate::{error::MycoError, server1::Server1, server2::Server2, Bucket, Key, Path};
use crate::{
    NUM_BUCKETS_PER_BATCH_WRITE_CHUNK, NUM_BUCKETS_PER_READ_PATHS_CHUNK,
};

#[derive(Serialize, Deserialize, Debug)]
/// An enum representing the different types of commands that can be sent to the servers
pub enum Command {
    /// Command to write to Server1
    Server1Write(Vec<u8>, Vec<u8>, Key, Vec<u8>),
    /// Command to write to Server2
    Server2Write(WriteType),
    /// Command to read from Server2
    Server2Read(ReadType),
    /// Command to indicate success
    Success,
}

#[derive(Serialize, Deserialize)]
/// A type representing the different types of write commands that can be sent to Server2
pub enum WriteType {
    /// Command to write to Server2
    Write(Vec<Bucket>, Key),
}

// Custom Debug implementation for WriteType to avoid printing bucket contents
impl std::fmt::Debug for WriteType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WriteType::Write(buckets, _) => write!(f, "Write({} buckets)", buckets.len()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
/// A type representing the different types of read commands that can be sent to Server2
pub enum ReadType {
    /// Command to read a single path
    Read(Path),
    /// Command to read multiple paths
    ReadPaths(Vec<usize>),
    /// Command to get PRF keys
    GetPrfKeys,
}

/// A trait for local communication
pub(crate) trait Local {
    fn send(&self, command: &[u8]) -> Result<Vec<u8>, MycoError>;
}

pub(crate) trait Network {
    fn send(&self, command: &[u8]) -> Result<Vec<u8>, MycoError>;
}

/// A trait for remote communication with Server2
#[async_trait]
pub trait Server2Access: Send + Sync {
    /// Read paths from Server2
    async fn read_paths(&self, indices: Vec<usize>) -> Result<Vec<Bucket>>;
    /// Read paths from Server2 in a client-side chunked manner
    async fn read_paths_client(
        &self,
        indices: Vec<usize>,
        batch_size: usize,
    ) -> Result<Vec<Bucket>>;
    /// Read paths from Server2 in a client-side chunked manner
    async fn read_paths_client_chunked(
        &self,
        indices: Vec<usize>,
        batch_size: usize,
    ) -> Result<Vec<Bucket>>;
    /// Write to Server2
    async fn write(&self, buckets: Vec<Bucket>, prf_key: Key) -> Result<()>;
    /// Get PRF keys from Server2
    async fn get_prf_keys(&self) -> Result<Vec<Key>>;
}

/// Local access - direct memory access
#[derive(Clone)]
pub struct LocalServer2Access {
    /// The server instance
    pub server: Arc<Mutex<Server2>>,
}

impl LocalServer2Access {
    /// Create a new LocalServer2Access instance
    pub fn new(server: Arc<Mutex<Server2>>) -> Self {
        Self { server }
    }

    /// Create a new LocalServer2Access instance with a new Server2 instance
    pub fn new_with_server() -> Self {
        Self {
            server: Arc::new(Mutex::new(Server2::new())),
        }
    }
}

#[async_trait]
impl Server2Access for LocalServer2Access {
    /// Read paths from Server2
    async fn read_paths(&self, indices: Vec<usize>) -> Result<Vec<Bucket>> {
        self.server
            .lock()
            .unwrap()
            .read_and_store_path_indices(indices)
            .map_err(|e| e.into())
    }

    /// Read paths from Server2 in a client-side chunked manner
    async fn read_paths_client(
        &self,
        indices: Vec<usize>,
        batch_size: usize,
    ) -> Result<Vec<Bucket>> {
        self.server
            .lock()
            .unwrap()
            .read_paths_client(indices)
            .map_err(|e| e.into())
    }

    //TODO: Clean, for now just use read_paths_client
    async fn read_paths_client_chunked(
        &self,
        indices: Vec<usize>,
        batch_size: usize,
    ) -> Result<Vec<Bucket>> {
        self.server
            .lock()
            .unwrap()
            .read_paths_client(indices)
            .map_err(|e| e.into())
    }

    async fn write(&self, buckets: Vec<Bucket>, prf_key: Key) -> Result<()> {
        let mut server = self.server.lock().unwrap();
        server.write(buckets);
        server.add_prf_key(&prf_key);
        Ok(())
    }

    async fn get_prf_keys(&self) -> Result<Vec<Key>> {
        self.server
            .lock()
            .unwrap()
            .get_prf_keys()
            .map_err(|e| e.into())
    }
}

/// Remote access - serialized network access
pub struct RemoteServer2Access {
    pub(crate) client: reqwest::Client,
    pub(crate) base_url: String,
}

#[async_trait]
impl Server2Access for RemoteServer2Access {
    async fn read_paths(&self, indices: Vec<usize>) -> Result<Vec<Bucket>> {
        // First store the path indices.
        let store_request = StorePathIndicesRequest {
            pathset: indices.clone(),
        };

        #[cfg(feature = "bytes-logging")]
        {
            let store_request_bytes =
                bincode::serialize(&store_request).map_err(|_| MycoError::SerializationFailed)?;
            BytesMetric::new("batch_init_store_path_indices", store_request_bytes.len()).log();
        }

        self.post_bincode::<_, StorePathIndicesResponse>("store_path_indices", store_request)
            .await?;

        // Then read in chunks.
        let chunks: Vec<_> = indices.chunks(NUM_BUCKETS_PER_READ_PATHS_CHUNK).collect();
        let futures = (0..chunks.len()).map(|chunk_idx| {
            let request = ChunkReadPathsRequest { chunk_idx };
            self.post_bincode::<_, ChunkReadPathsResponse>("chunk_read_paths", request)
        });

        let mut all_buckets = Vec::new();
        for response in futures::future::join_all(futures).await {
            let chunk_response = response?;
            all_buckets.extend(chunk_response.buckets);
        }

        #[cfg(feature = "bytes-logging")]
        {
            let total_response_bytes = bincode::serialize(&all_buckets)
                .map_err(|_| MycoError::SerializationFailed)?
                .len();
            BytesMetric::new("batch_init_read_paths_response", total_response_bytes).log();
        }

        Ok(all_buckets)
    }

    async fn read_paths_client_chunked(
        &self,
        indices: Vec<usize>,
        batch_size: usize,
    ) -> Result<Vec<Bucket>> {
        #[cfg(feature = "bytes-logging")]
        {
            let indices_bytes =
                bincode::serialize(&indices).map_err(|_| MycoError::SerializationFailed)?;
            BytesMetric::new(
                &format!("client_read_paths_request_{}", batch_size),
                indices_bytes.len(),
            )
            .log();
        }

        // Then read in chunks.
        let chunks: Vec<_> = indices.chunks(NUM_BUCKETS_PER_READ_PATHS_CHUNK).collect();
        let futures = (0..chunks.len()).map(|chunk_idx| {
            let request = ChunkReadPathsClientRequest {
                indices: indices.clone(),
                chunk_idx,
            };

            self.post_bincode::<_, ChunkReadPathsClientResponse>("chunk_read_paths_client", request)
        });

        let mut all_buckets = Vec::<Bucket>::new();
        for response in futures::future::join_all(futures).await {
            let chunk_response = response?;
            all_buckets.extend(chunk_response.buckets);
        }

        #[cfg(feature = "bytes-logging")]
        {
            let total_response_bytes = bincode::serialize(&all_buckets)
                .map_err(|_| MycoError::SerializationFailed)?
                .len();
            BytesMetric::new(
                &format!("client_read_paths_response_{}", batch_size),
                total_response_bytes,
            )
            .log();
        }

        Ok(all_buckets)
    }

    async fn read_paths_client(
        &self,
        indices: Vec<usize>,
        batch_size: usize,
    ) -> Result<Vec<Bucket>> {
        #[cfg(feature = "bytes-logging")]
        {
            let indices_bytes =
                bincode::serialize(&indices).map_err(|_| MycoError::SerializationFailed)?;
            BytesMetric::new(
                &format!("client_read_paths_request_{}", batch_size),
                indices_bytes.len(),
            )
            .log();
        }

        let request = ReadPathsClientRequest { indices };
        let response: ReadPathsResponse = self
            .post_bincode(&format!("read_paths_client"), &request)
            .await?;

        #[cfg(feature = "bytes-logging")]
        {
            let total_response_bytes = bincode::serialize(&response.buckets)
                .map_err(|_| MycoError::SerializationFailed)?
                .len();
            BytesMetric::new(
                &format!("client_read_paths_response_{}", batch_size),
                total_response_bytes,
            )
            .log();
        }

        Ok(response.buckets)
    }

    async fn write(&self, buckets: Vec<Bucket>, prf_key: Key) -> Result<()> {
        // Measure total request size before chunking

        #[cfg(feature = "bytes-logging")]
        {
            let total_request = ChunkWriteRequest {
                buckets: buckets.clone(),
                prf_key: prf_key.clone(),
                chunk_idx: 0,
            };
            let total_bytes = bincode::serialize(&total_request)
                .map_err(|_| MycoError::SerializationFailed)?
                .len();
            BytesMetric::new("batch_write", total_bytes).log();
        }

        // Set the maximum request size to 10MB, and determine the number of buckets per batch based on this.
        let batches: Vec<_> = buckets.chunks(NUM_BUCKETS_PER_BATCH_WRITE_CHUNK).collect();
        let futures = batches.into_iter().enumerate().map(|(chunk_idx, batch)| {
            let request = ChunkWriteRequest {
                buckets: batch.to_vec(),
                prf_key: prf_key.clone(),
                chunk_idx,
            };
            self.post_bincode::<_, WriteResponse>("chunk_write", request)
        });

        let results = futures::future::join_all(futures).await;
        for result in results {
            result?;
        }

        // Send a new request to finalize the epoch.
        let request = FinalizeEpochRequest { prf_key };
        self.post_bincode::<_, FinalizeEpochResponse>("finalize_epoch", request)
            .await?;

        Ok(())
    }

    async fn get_prf_keys(&self) -> Result<Vec<Key>> {
        let response: GetPrfKeysResponse = self
            .client
            .get(&format!("{}/get_prf_keys", self.base_url))
            .send()
            .await
            .map_err(|_| {
                MycoError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to send request",
                ))
            })?
            .bytes()
            .await
            .map_err(|_| {
                MycoError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to get response bytes",
                ))
            })
            .and_then(|bytes| {
                bincode::deserialize(&bytes).map_err(|_| MycoError::DeserializationError)
            })?;

        Ok(response.keys)
    }
}

impl RemoteServer2Access {
    /// Create a new RemoteServer2Access instance
    pub async fn new(base_url: &str) -> Result<Self, MycoError> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|_| {
                MycoError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to create HTTP client",
                ))
            })?;

        Ok(Self {
            client,
            base_url: base_url.to_string(),
        })
    }

    /// Send a bincoded request to the server
    async fn post_bincode<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        payload: T,
    ) -> Result<R, MycoError> {
        let request_bytes =
            bincode::serialize(&payload).map_err(|_| MycoError::DeserializationError)?;


        let response = self
            .client
            .post(&format!("{}/{}", self.base_url, endpoint))
            .header("Content-Type", "application/octet-stream")
            .body(request_bytes)
            .send()
            .await
            .map_err(|_| {
                MycoError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to send request",
                ))
            })?;

        let bytes = response.bytes().await.map_err(|_| {
            MycoError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to get response bytes",
            ))
        })?;

        Ok(bincode::deserialize(&bytes).map_err(|_| MycoError::DeserializationError)?)
    }
}

/// Remote access - serialized network access
pub struct RemoteServer1Access {
    /// The HTTP client
    pub(crate) client: reqwest::Client,
    pub(crate) base_url: String,
}

impl RemoteServer1Access {
    /// Create a new RemoteServer1Access instance
    pub async fn new(server1_addr: &str) -> Result<Self, MycoError> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|_| {
                MycoError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to create HTTP client",
                ))
            })?;

        Ok(Self {
            client,
            base_url: server1_addr.to_string(),
        })
    }
}

/// A trait for interacting with Server1
#[async_trait]
pub trait Server1Access: Send {
    /// Queue a write to Server1
    async fn queue_write(
        &self,
        ct: Vec<u8>,
        f: Vec<u8>,
        k_oblv_t: Key,
        cs: Vec<u8>,
    ) -> Result<(), MycoError>;
}

/// Local access - direct memory access
#[derive(Clone)]
pub struct LocalServer1Access {
    /// The server instance
    pub server: Arc<RwLock<Server1>>,
}

impl LocalServer1Access {
    /// Create a new LocalServer1Access instance
    pub fn new(server: Arc<RwLock<Server1>>) -> Self {
        Self { server }
    }
}

#[async_trait]
impl Server1Access for LocalServer1Access {
    async fn queue_write(
        &self,
        ct: Vec<u8>,
        f: Vec<u8>,
        k_oblv_t: Key,
        cs: Vec<u8>,
    ) -> Result<(), MycoError> {
        self.server
            .write()
            .unwrap()
            .queue_write(ct, f, k_oblv_t, cs)
    }
}

#[async_trait]
impl Server1Access for RemoteServer1Access {
    async fn queue_write(
        &self,
        ct: Vec<u8>,
        f: Vec<u8>,
        k_oblv_t: Key,
        cs: Vec<u8>,
    ) -> Result<(), MycoError> {
        let queue_write_request = QueueWriteRequest {
            ct,
            f,
            k_oblv_t,
            cs,
        };

        let request_bytes = serialize(&queue_write_request).unwrap();
        let queue_write_bytes_metric = BytesMetric::new("queue_write_bytes", request_bytes.len());
        queue_write_bytes_metric.log();
        let response = self
            .client
            .post(&format!("{}/queue_write", self.base_url))
            .header("Content-Type", "application/octet-stream")
            .body(request_bytes)
            .send()
            .await
            .map_err(|_| {
                MycoError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to send request to Server1",
                ))
            })?;

        let queue_write_response: QueueWriteResponse =
            deserialize(&response.bytes().await.unwrap()).unwrap();

        // Check for success response
        if queue_write_response.success {
            Ok(())
        } else {
            Err(MycoError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Unexpected response from Server1",
            )))
        }
    }
}
