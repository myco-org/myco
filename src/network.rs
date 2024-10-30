use bincode::{deserialize, serialize};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use crate::{error::OramError, server1::Server1, server2::Server2, Bucket, Key, Path};

#[derive(Serialize, Deserialize)]
pub(crate) enum ReadType {
    Read(Path),
    ReadPaths(Vec<usize>),
    GetPrfKeys,
}

#[derive(Serialize, Deserialize)]
pub(crate) enum WriteType {
    Write(Vec<Bucket>),
    AddPrfKey(Key),
}

#[derive(Serialize, Deserialize)]
pub(crate) enum Command {
    Server1Write(Vec<u8>, Vec<u8>, Key, Vec<u8>),
    Server2Write(WriteType),
    Server2Read(ReadType),
}

pub(crate) trait Local {
    fn send(&self, command: &[u8]) -> Result<Vec<u8>, OramError>;
}

pub(crate) trait Network {
    fn send(&self, command: &[u8]) -> Result<Vec<u8>, OramError>;
}

// Define how we interact with Server2
pub trait Server2Access {
    fn read_paths(&self, indices: Vec<usize>) -> Result<Vec<Bucket>, OramError>;
    fn read(&self, path: &Path) -> Result<Vec<Bucket>, OramError>;
    fn write(&self, buckets: Vec<Bucket>) -> Result<(), OramError>;
    fn add_prf_key(&self, key: &Key) -> Result<(), OramError>;
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

    fn write(&self, buckets: Vec<Bucket>) -> Result<(), OramError> {
        self.server.lock().unwrap().write(buckets);
        Ok(())
    }

    fn add_prf_key(&self, key: &Key) -> Result<(), OramError> {
        self.server.lock().unwrap().add_prf_key(key);
        Ok(())
    }

    fn get_prf_keys(&self) -> Result<Vec<Key>, OramError> {
        self.server.lock().unwrap().get_prf_keys()
    }
}

// Remote access - serialized network access
pub struct RemoteServer2Access {
    connection: Arc<RemoteConnection>,
}

impl Server2Access for RemoteServer2Access {
    fn read_paths(&self, indices: Vec<usize>) -> Result<Vec<Bucket>, OramError> {
        let command = Command::Server2Read(ReadType::ReadPaths(indices));
        let response = self.connection.send(&serialize(&command).unwrap())?;
        deserialize(&response).map_err(|_| OramError::SerializationFailed)
    }

    fn read(&self, path: &Path) -> Result<Vec<Bucket>, OramError> {
        let command = Command::Server2Read(ReadType::Read(path.clone()));
        let response = self.connection.send(&serialize(&command).unwrap())?;
        deserialize(&response).map_err(|_| OramError::SerializationFailed)
    }

    fn write(&self, buckets: Vec<Bucket>) -> Result<(), OramError> {
        let command = Command::Server2Write(WriteType::Write(buckets));
        self.connection.send(&serialize(&command).unwrap())?;
        Ok(())
    }

    fn add_prf_key(&self, key: &Key) -> Result<(), OramError> {
        let command = Command::Server2Write(WriteType::AddPrfKey(key.clone()));
        self.connection.send(&serialize(&command).unwrap())?;
        Ok(())
    }

    fn get_prf_keys(&self) -> Result<Vec<Key>, OramError> {
        let command = Command::Server2Read(ReadType::GetPrfKeys);
        let response = self.connection.send(&serialize(&command).unwrap())?;
        deserialize(&response).map_err(|_| OramError::SerializationFailed)
    }
}

pub struct RemoteConnection {
    // Add network connection details here
}

impl Network for RemoteConnection {
    fn send(&self, command: &[u8]) -> Result<Vec<u8>, OramError> {
        // Implement actual network sending logic
        unimplemented!("Implement network sending logic")
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

// Remote access - serialized network access
pub struct RemoteServer1Access {
    connection: Arc<RemoteConnection>,
}

impl Server1Access for RemoteServer1Access {
    fn queue_write(&self, ct: Vec<u8>, f: Vec<u8>, k_oram_t: Key, cs: Vec<u8>) -> Result<(), OramError> {
        let command = Command::Server1Write(ct, f, k_oram_t, cs);
        self.connection.send(&serialize(&command).unwrap())?;
        Ok(())
    }
}
