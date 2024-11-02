use anyhow::Result;
use axum::async_trait;
use bincode::{deserialize, serialize};
use rustls::{Certificate, PrivateKey, RootCertStore, ServerName};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::Duration;
use std::{
    io::{Read, Write},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex as TokioMutex,
};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::logging::BytesMetric;
use crate::rpc_types::{
    GetPrfKeysResponse, QueueWriteRequest, QueueWriteResponse, ReadPathsClientRequest, ReadPathsRequest, ReadPathsResponse, ReadRequest, ReadResponse, WriteRequest, WriteResponse
};
use crate::{error::OramError, server1::Server1, server2::Server2, Bucket, Key, Path};

#[derive(Serialize, Deserialize, Debug)]
pub enum Command {
    Server1Write(Vec<u8>, Vec<u8>, Key, Vec<u8>),
    Server2Write(WriteType),
    Server2Read(ReadType),
    Success,
}

#[derive(Serialize, Deserialize)]
pub enum WriteType {
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
pub enum ReadType {
    Read(Path),
    ReadPaths(Vec<usize>),
    GetPrfKeys,
}

pub(crate) trait Local {
    fn send(&self, command: &[u8]) -> Result<Vec<u8>, OramError>;
}

pub(crate) trait Network {
    fn send(&self, command: &[u8]) -> Result<Vec<u8>, OramError>;
}

// Define how we interact with Server2
#[async_trait]
pub trait Server2Access: Send + Sync {
    async fn read_paths(&self, indices: Vec<usize>) -> Result<Vec<Bucket>>;
    async fn read_paths_client(&self, indices: Vec<usize>) -> Result<Vec<Bucket>>;
    async fn write(&self, buckets: Vec<Bucket>, prf_key: Key) -> Result<()>;
    async fn get_prf_keys(&self) -> Result<Vec<Key>>;
}

// Local access - direct memory access
#[derive(Clone)]
pub struct LocalServer2Access {
    pub server: Arc<Mutex<Server2>>,
}

#[async_trait]
impl Server2Access for LocalServer2Access {
    async fn read_paths(&self, indices: Vec<usize>) -> Result<Vec<Bucket>> {
        self.server
            .lock()
            .unwrap()
            .read_paths(indices)
            .map_err(|e| e.into())
    }

    async fn read_paths_client(&self, indices: Vec<usize>) -> Result<Vec<Bucket>> {
        self.server
            .lock()
            .unwrap()
            .read_paths(indices)
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

// Remote access - serialized network access
pub struct RemoteServer2Access {
    pub(crate) client: reqwest::Client,
    pub(crate) base_url: String,
}

#[async_trait]
impl Server2Access for RemoteServer2Access {
    async fn read_paths(&self, indices: Vec<usize>) -> Result<Vec<Bucket>> {
        let request = ReadPathsRequest { indices };
        let response: ReadPathsResponse = self.post_bincode("read_paths", &request).await?;
        Ok(response.buckets)
    }

    async fn read_paths_client(&self, indices: Vec<usize>) -> Result<Vec<Bucket>> {
        let request = ReadPathsClientRequest { indices };
        let response: ReadPathsResponse = self.post_bincode("read_paths_client", &request).await?;
        Ok(response.buckets)
    }

    async fn write(&self, buckets: Vec<Bucket>, prf_key: Key) -> Result<()> {
        let request = WriteRequest { buckets, prf_key };
        let _: WriteResponse = self.post_bincode("write", &request).await?;
        Ok(())
    }

    async fn get_prf_keys(&self) -> Result<Vec<Key>> {
        let response: GetPrfKeysResponse = self
            .client
            .get(&format!("{}/get_prf_keys", self.base_url))
            .send()
            .await
            .map_err(|_| {
                OramError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to send request",
                ))
            })?
            .bytes()
            .await
            .map_err(|_| {
                OramError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to get response bytes",
                ))
            })
            .and_then(|bytes| {
                bincode::deserialize(&bytes).map_err(|_| OramError::DeserializationError)
            })?;

        Ok(response.keys)
    }
}

impl RemoteServer2Access {
    pub async fn new(base_url: &str) -> Result<Self, OramError> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|_| OramError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to create HTTP client",
            )))?;

        Ok(Self {
            client,
            base_url: base_url.to_string(),
        })
    }

    async fn post_bincode<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        payload: &T,
    ) -> Result<R, OramError> {
        let request_bytes =
            bincode::serialize(payload).map_err(|_| OramError::DeserializationError)?;

        
        let request_bytes_metric = BytesMetric::new(&format!("server2_{}", endpoint), request_bytes.len());
        request_bytes_metric.log();

        let response = self
            .client
            .post(&format!("{}/{}", self.base_url, endpoint))
            .header("Content-Type", "application/octet-stream")
            .body(request_bytes)
            .send()
            .await
            .map_err(|_| {
                OramError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to send request",
                ))
            })?;

        let bytes = response.bytes().await.map_err(|_| {
            OramError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to get response bytes",
            ))
        })?;

        bincode::deserialize(&bytes).map_err(|_| OramError::DeserializationError)
    }
}

// Remote access - serialized network access
pub struct RemoteServer1Access {
    pub(crate) client: reqwest::Client,
    pub(crate) base_url: String,
}

impl RemoteServer1Access {
    pub async fn new(server1_addr: &str) -> Result<Self, OramError> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|_| OramError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to create HTTP client",
            )))?;

        Ok(Self {
            client,
            base_url: server1_addr.to_string(),
        })
    }
}
    
// Define how we interact with Server1
#[async_trait]
pub trait Server1Access: Send {
    async fn queue_write(
        &self,
        ct: Vec<u8>,
        f: Vec<u8>,
        k_oram_t: Key,
        cs: Vec<u8>,
    ) -> Result<(), OramError>;
}

// Local access - direct memory access
#[derive(Clone)]
pub struct LocalServer1Access {
    pub server: Arc<Mutex<Server1>>,
}

#[async_trait]
impl Server1Access for LocalServer1Access {
    async fn queue_write(
        &self,
        ct: Vec<u8>,
        f: Vec<u8>,
        k_oram_t: Key,
        cs: Vec<u8>,
    ) -> Result<(), OramError> {
        self.server.lock().unwrap().queue_write(ct, f, k_oram_t, cs)
    }
}

#[async_trait]
impl Server1Access for RemoteServer1Access {
    async fn queue_write(
        &self,
        ct: Vec<u8>,
        f: Vec<u8>,
        k_oram_t: Key,
        cs: Vec<u8>,
    ) -> Result<(), OramError> {
        let queue_write_request = QueueWriteRequest {
            ct,
            f,
            k_oram_t,
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
                OramError::IoError(std::io::Error::new(
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
            Err(OramError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Unexpected response from Server1",
            )))
        }
    }
}
