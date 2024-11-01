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

use crate::rpc_types::{
    GetPrfKeysResponse, QueueWriteRequest, QueueWriteResponse, ReadPathsRequest, ReadPathsResponse,
    ReadRequest, ReadResponse, WriteRequest, WriteResponse,
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
    async fn read(&self, path: &Path) -> Result<Vec<Bucket>>;
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

    async fn read(&self, path: &Path) -> Result<Vec<Bucket>> {
        self.server.lock().unwrap().read(path).map_err(|e| e.into())
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
    // pub(crate) connection: Arc<RemoteConnection>,
    // addr: String,
    // cert_path: String,
}

#[async_trait]
impl Server2Access for RemoteServer2Access {
    async fn read_paths(&self, indices: Vec<usize>) -> Result<Vec<Bucket>> {
        // Send a GET request to the server.
        let read_paths_request = ReadPathsRequest { indices };
        println!("URL: {}", &format!("{}/read_paths", self.base_url));
        let response = self
            .client
            .post(&format!("{}/read_paths", self.base_url))
            .json(&read_paths_request)
            .send()
            .await
            .map_err(|e| {
                anyhow::anyhow!("Failed to send read paths request to Server2: {:?}", e)
            })?;
        let response_json: ReadPathsResponse = response.json().await.map_err(|_| {
            OramError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to parse response from Server2",
            ))
        })?;
        Ok(response_json.buckets)
    }

    async fn read(&self, path: &Path) -> Result<Vec<Bucket>> {
        let read_request = ReadRequest { path: path.clone() };
        let response = self
            .client
            .post(&format!("{}/read", self.base_url))
            .json(&read_request)
            .send()
            .await
            .map_err(|_| {
                OramError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to send read request to Server2",
                ))
            })?;
        let response_json: ReadResponse = response.json().await.map_err(|_| {
            OramError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to parse read response from Server2",
            ))
        })?;
        Ok(response_json.buckets)
    }

    async fn write(&self, buckets: Vec<Bucket>, prf_key: Key) -> Result<()> {
        let write_request = WriteRequest { buckets, prf_key };
        // println!("Write request: {:?}", write_request);
        println!("URL: {}", &format!("{}/write", self.base_url));
        let response = self
            .client
            .post(&format!("{}/write", self.base_url))
            .json(&write_request)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send write request to Server2: {:?}", e))?;

        // Check if the response is an error.
        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Server2 reported failure in write operation: {}",
                response.status()
            ));
        }
        let write_response: WriteResponse = response.json().await.map_err(|_| {
            OramError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to parse write response from Server2",
            ))
        })?;
        println!("Server2Access: Got response from write operation");
        if write_response.success {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Server2 reported failure in write operation"
            ))
        }
    }

    async fn get_prf_keys(&self) -> Result<Vec<Key>> {
        let response = self
            .client
            .get(&format!("{}/get_prf_keys", self.base_url))
            .send()
            .await
            .map_err(|_| {
                OramError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to send get prf keys request to Server2",
                ))
            })?;
        let get_prf_keys_response: GetPrfKeysResponse = response.json().await.map_err(|_| {
            OramError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to parse get prf keys response from Server2",
            ))
        })?;
        Ok(get_prf_keys_response.keys)
    }
}

impl RemoteServer2Access {
    pub async fn new(url: &str) -> Result<Self> {
        let client = reqwest::Client::new();
        Ok(Self {
            client,
            base_url: url.to_string(),
            // connection: Arc::new(RemoteConnection::connect(url, cert_path).await?),
            // addr: url.to_string(),
            // cert_path: cert_path.to_string(),
        })
    }
    // pub async fn connect(addr: &str, cert_path: &str) -> Result<Self, OramError> {
    //     println!("Server2Access: Connecting to Server2");
    //     let (host, port) = addr.split_once(':').ok_or(OramError::InvalidServerName)?;
    //     println!("Server2Access: Split address into host and port");
    //     let port = port.parse().map_err(|_| OramError::InvalidServerName)?;
    //     println!("Server2Access: Parsed port");

    //     let connection = Arc::new(RemoteConnection::connect(host, port, cert_path).await?);
    //     println!("Server2Access: Connected to Server2");
    //     Ok(Self {
    //         connection,
    //         addr: addr.to_string(),
    //         cert_path: cert_path.to_string(),
    //     })
    // }
}

// Remote access - serialized network access
pub struct RemoteServer1Access {
    pub(crate) client: reqwest::Client,
    pub(crate) base_url: String,
    // pub(crate) connection: Arc<RemoteConnection>,
}

impl RemoteServer1Access {
    pub async fn new(server1_addr: &str) -> Result<Self, OramError> {
        // let connection = RemoteConnection::connect(
        //     server1_addr.split(':').next().unwrap(),
        //     server1_addr.split(':').nth(1).unwrap().parse().unwrap(),
        //     cert_path,
        // )
        // .await?;

        let client = reqwest::Client::new();

        Ok(Self {
            client,
            base_url: server1_addr.to_string(),
            // connection: Arc::new(connection),
        })
    }
}
pub struct RemoteConnection {
    stream: Arc<TokioMutex<TlsStream<TcpStream>>>,
    server_name: ServerName,
}

impl RemoteConnection {
    pub async fn connect(host: &str, port: u16, cert_path: &str) -> Result<Self, OramError> {
        // Load and parse certificate
        let cert_file = std::fs::File::open(cert_path)?;
        let mut reader = std::io::BufReader::new(cert_file);
        let certs: Vec<Certificate> = rustls_pemfile::certs(&mut reader)?
            .into_iter()
            .map(Certificate)
            .collect();

        // Connect TCP first
        let stream = TcpStream::connect((host, port)).await?;

        // Then do TLS handshake
        let mut root_store = RootCertStore::empty();
        for cert in certs {
            root_store.add(&cert)?;
        }

        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(host).map_err(|_| OramError::InvalidServerName)?;

        let stream = connector.connect(server_name.clone(), stream).await?;

        Ok(Self {
            stream: Arc::new(TokioMutex::new(stream)),
            server_name,
        })
    }

    pub async fn close(&self) -> Result<(), OramError> {
        let mut stream = self.stream.lock().await;
        futures::executor::block_on(async {
            let _ = stream.shutdown().await;
        });
        Ok(())
    }

    pub async fn send(&self, command: &[u8]) -> Result<Vec<u8>, OramError> {
        let mut retries = 3;
        let mut last_error = None;

        while retries > 0 {
            let result = {
                println!("RemoteConnection: Acquired stream lock for command");

                // Set a timeout for the entire operation
                let timeout = tokio::time::timeout(tokio::time::Duration::from_secs(10), async {
                    {
                        let mut stream = self.stream.lock().await;
                        println!(
                            "RemoteConnection: Writing command length, {}",
                            command.len()
                        );
                        println!("RemoteConnection: Writing command length bytes");
                        stream
                            .write_all(&(command.len() as u32).to_be_bytes())
                            .await?;
                        println!("RemoteConnection: Flushed command length bytes");
                        stream.flush().await?;
                    }

                    {
                        let mut stream = self.stream.lock().await;
                        println!("RemoteConnection: Writing command data");
                        stream.write_all(command).await?;
                        println!("RemoteConnection: Flushed command data");
                        stream.flush().await?;
                    }

                    {
                        let mut stream = self.stream.lock().await;
                        println!("RemoteConnection: Reading response length");
                        let mut len_bytes = [0u8; 4];
                        // Try to acquire lock on stream
                        // Check if stream lock is already held
                        stream.read_exact(&mut len_bytes).await?;
                        println!(
                            "RemoteConnection: Read response length bytes: {:?}",
                            len_bytes
                        );
                        let len = u32::from_be_bytes(len_bytes);

                        println!("RemoteConnection: Reading response data of length {}", len);
                        let mut response = vec![0u8; len as usize];
                        stream.read_exact(&mut response).await?;

                        Ok::<Vec<u8>, std::io::Error>(response)
                    }
                })
                .await;

                println!("RemoteConnection: Timeout result: {:?}", timeout);

                match timeout {
                    Ok(result) => result,
                    Err(_) => Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "Operation timed out",
                    )),
                }
            };
            println!("RemoteConnection: Released stream lock");

            match result {
                Ok(response) => {
                    println!("RemoteConnection: Successfully completed operation");
                    return Ok(response);
                }
                Err(e) => {
                    println!("RemoteConnection: Error in send: {:?}", e);
                    last_error = Some(e);
                    retries -= 1;
                    if retries > 0 {
                        println!(
                            "RemoteConnection: Retrying in 500ms... ({} retries left)",
                            retries
                        );
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                }
            }
        }

        Err(OramError::IoError(last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to send command after multiple retries",
            )
        })))
    }
}

// impl Drop for RemoteConnection {
//     fn drop(&mut self) {
//         // Send a special shutdown command or close the connection gracefully
//         if let Ok(mut stream) = self.stream.lock().await {
//             // Best effort to shutdown the connection
//             let _ = futures::executor::block_on(async { stream.shutdown().await });
//         }
//     }
// }

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
        let response = self
            .client
            .post(&format!("{}/queue_write", self.base_url))
            .json(&queue_write_request)
            .send()
            .await
            .map_err(|_| {
                OramError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to send request to Server1",
                ))
            })?;

        let queue_write_response: QueueWriteResponse = response.json().await.map_err(|_| {
            OramError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to parse response from Server1",
            ))
        })?;

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
