use bincode::{deserialize, serialize};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use rustls::{Certificate, PrivateKey, ServerName, RootCertStore};
use std::io::{Read, Write};

use crate::{error::OramError, server1::Server1, server2::Server2, Bucket, Key, Path};

#[derive(Serialize, Deserialize, Debug)]
pub enum Command {
    Server1Write(Vec<u8>, Vec<u8>, Key, Vec<u8>),
    Server2Write(WriteType),
    Server2Read(ReadType),
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
pub trait Server2Access: Send + Sync {
    fn read_paths(&self, indices: Vec<usize>) -> Result<Vec<Bucket>, OramError>;
    fn read(&self, path: &Path) -> Result<Vec<Bucket>, OramError>;
    fn write(&self, buckets: Vec<Bucket>, prf_key: Key) -> Result<(), OramError>;
    fn get_prf_keys(&self) -> Result<Vec<Key>, OramError>;
}

// Local access - direct memory access
#[derive(Clone)]
pub struct LocalServer2Access {
    pub server: Arc<Mutex<Server2>>,
}

impl Server2Access for LocalServer2Access {
    fn read_paths(&self, indices: Vec<usize>) -> Result<Vec<Bucket>, OramError> {
        self.server.lock().unwrap().read_paths(indices)
    }

    fn read(&self, path: &Path) -> Result<Vec<Bucket>, OramError> {
        self.server.lock().unwrap().read(path)
    }

    fn write(&self, buckets: Vec<Bucket>, prf_key: Key) -> Result<(), OramError> {
        let mut server = self.server.lock().unwrap();
        server.write(buckets);
        server.add_prf_key(&prf_key);
        Ok(())
    }

    fn get_prf_keys(&self) -> Result<Vec<Key>, OramError> {
        self.server.lock().unwrap().get_prf_keys()
    }
}

// Remote access - serialized network access
pub struct RemoteServer2Access {
    pub(crate) connection: Arc<RemoteConnection>,
    addr: String,
    cert_path: String,
}

impl Server2Access for RemoteServer2Access {
    fn read_paths(&self, indices: Vec<usize>) -> Result<Vec<Bucket>, OramError> {
        let command = Command::Server2Read(ReadType::ReadPaths(indices));
        let response = self.connection.send(&serialize(&command).unwrap())?;
        let result = deserialize(&response).map_err(|_| OramError::DeserializationError)?;
        
        // Explicitly close the connection after read paths
        self.connection.close()?;
        Ok(result)
    }

    fn read(&self, path: &Path) -> Result<Vec<Bucket>, OramError> {
        let command = Command::Server2Read(ReadType::Read(path.clone()));
        let response = self.connection.send(&serialize(&command).unwrap())?;
        let read_response: ReadResponse = deserialize(&response).map_err(|_| OramError::DeserializationError)?;
        
        // Store the PRF keys
        // TODO: Store read_response.prf_keys somewhere
        
        Ok(read_response.buckets)
    }

    fn write(&self, buckets: Vec<Bucket>, prf_key: Key) -> Result<(), OramError> {
        println!("RemoteServer2Access: Starting write operation");
        let command = Command::Server2Write(WriteType::Write(buckets, prf_key));
        let response = self.connection.send(&serialize(&command).unwrap())?;
        
        // We expect an empty response for write operations
        if response.is_empty() {
            println!("RemoteServer2Access: Write operation completed successfully");
            Ok(())
        } else {
            println!("RemoteServer2Access: Unexpected response from write operation");
            Err(OramError::IoError(std::io::Error::new(std::io::ErrorKind::Other, "Unexpected response from Server2")))
        }
    }

    fn get_prf_keys(&self) -> Result<Vec<Key>, OramError> {
        let command = Command::Server2Read(ReadType::GetPrfKeys);
        let response = self.connection.send(&serialize(&command).unwrap())?;
        deserialize(&response).map_err(|_| OramError::DeserializationError)
    }
}

impl RemoteServer2Access {
    pub async fn connect(addr: &str, cert_path: &str) -> Result<Self, OramError> {
        let (host, port) = addr.split_once(':')
            .ok_or(OramError::InvalidServerName)?;
        let port = port.parse()
            .map_err(|_| OramError::InvalidServerName)?;
            
        let connection = Arc::new(RemoteConnection::connect(host, port, cert_path).await?);
        Ok(Self { 
            connection,
            addr: addr.to_string(),
            cert_path: cert_path.to_string(),
        })
    }

    // Add method to create a new independent connection
    pub async fn clone_with_new_connection(&self) -> Result<Self, OramError> {
        Self::connect(&self.addr, &self.cert_path).await
    }
}

// Remote access - serialized network access
pub struct RemoteServer1Access {
    pub(crate) connection: Arc<RemoteConnection>,
}

impl RemoteServer1Access {
    pub async fn connect(server1_addr: &str, cert_path: &str) -> Result<Self, OramError> {
        println!("Connecting to Server1 at {}", server1_addr);
        let connection = RemoteConnection::connect(
            server1_addr.split(':').next().unwrap(),
            server1_addr.split(':').nth(1).unwrap().parse().unwrap(),
            cert_path
        ).await?;

        Ok(Self {
            connection: Arc::new(connection)
        })
    }
}
pub struct RemoteConnection {
    stream: Arc<Mutex<TlsStream<TcpStream>>>,
    server_name: ServerName,
}

impl RemoteConnection {
    pub async fn connect(host: &str, port: u16, cert_path: &str) -> Result<Self, OramError> {
        println!("Loading certificates from {}", cert_path);
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
        let server_name = ServerName::try_from(host)
            .map_err(|_| OramError::InvalidServerName)?;

        let stream = connector.connect(server_name.clone(), stream).await?;

        Ok(Self {
            stream: Arc::new(Mutex::new(stream)),
            server_name,
        })
    }

    pub fn close(&self) -> Result<(), OramError> {
        if let Ok(mut stream) = self.stream.lock() {
            futures::executor::block_on(async {
                let _ = stream.shutdown().await;
            });
        }
        Ok(())
    }
}

impl Network for RemoteConnection {
    fn send(&self, command: &[u8]) -> Result<Vec<u8>, OramError> {
        let mut stream = self.stream.lock().unwrap();
        
        println!("RemoteConnection: Sending command of length {}", command.len());
        // Send length prefix
        let len = command.len() as u32;
        if let Err(e) = futures::executor::block_on(stream.write_all(&len.to_be_bytes())) {
            println!("RemoteConnection: Failed to write length: {}", e);
            return Err(OramError::IoError(e));
        }

        // Send command
        if let Err(e) = futures::executor::block_on(stream.write_all(command)) {
            println!("RemoteConnection: Failed to write command: {}", e);
            return Err(OramError::IoError(e));
        }
        println!("RemoteConnection: Command sent successfully");

        // Ensure the command is fully sent
        if let Err(e) = futures::executor::block_on(stream.flush()) {
            println!("RemoteConnection: Failed to flush: {}", e);
            return Err(OramError::IoError(e));
        }

        // Read response length
        println!("RemoteConnection: Attempting to read response length");
        let mut len_bytes = [0u8; 4];
        if let Err(e) = futures::executor::block_on(stream.read_exact(&mut len_bytes)) {
            println!("RemoteConnection: Failed to read response length: {}", e);
            return Err(OramError::IoError(e));
        }
        let len = u32::from_be_bytes(len_bytes);
        println!("RemoteConnection: Response length received: {}", len);

        // Read response data
        let mut response = vec![0u8; len as usize];
        if let Err(e) = futures::executor::block_on(stream.read_exact(&mut response)) {
            println!("RemoteConnection: Failed to read response data: {}", e);
            return Err(OramError::IoError(e));
        }
        println!("RemoteConnection: Response data received successfully");

        Ok(response)
    }
}

impl Drop for RemoteConnection {
    fn drop(&mut self) {
        // Send a special shutdown command or close the connection gracefully
        if let Ok(mut stream) = self.stream.lock() {
            // Best effort to shutdown the connection
            let _ = futures::executor::block_on(async {
                stream.shutdown().await
            });
        }
    }
}

// Define how we interact with Server1
pub trait Server1Access {
    fn queue_write(&self, ct: Vec<u8>, f: Vec<u8>, k_oram_t: Key, cs: Vec<u8>) -> Result<(), OramError>;
}

// Local access - direct memory access
#[derive(Clone)]
pub struct LocalServer1Access {
    pub server: Arc<Mutex<Server1>>,
}

impl Server1Access for LocalServer1Access {
    fn queue_write(&self, ct: Vec<u8>, f: Vec<u8>, k_oram_t: Key, cs: Vec<u8>) -> Result<(), OramError> {
        self.server.lock().unwrap().queue_write(ct, f, k_oram_t, cs)
    }
}

impl Server1Access for RemoteServer1Access {
    fn queue_write(&self, ct: Vec<u8>, f: Vec<u8>, k_oram_t: Key, cs: Vec<u8>) -> Result<(), OramError> {
        println!("Sending write command to Server1");
        let command = Command::Server1Write(ct, f, k_oram_t, cs);
        let response = self.connection.send(&serialize(&command).unwrap())?;
        
        // Check for success response
        if response == vec![1] {
            println!("Write to Server1 completed successfully");
            Ok(())
        } else {
            println!("Unexpected response from Server1: {:?}", response);
            Err(OramError::IoError(std::io::Error::new(std::io::ErrorKind::Other, "Unexpected response from Server1")))
        }
    }
}

// Update the return type for Read operations to include PRF keys
#[derive(Serialize, Deserialize, Debug)]
pub struct ReadResponse {
    pub(crate) buckets: Vec<Bucket>,
    pub(crate) prf_keys: Vec<Key>,
}
