use serde::{Deserialize, Serialize};

use crate::{error::OramError, Bucket, Key, Path};

#[derive(Serialize, Deserialize)]
pub(crate) enum ReadType {
    Read(Path),
    GetPrfKeys,
}

#[derive(Serialize, Deserialize)]
pub(crate) enum WriteType {
    Write(Vec<Bucket>),
    AddPrfKey(Key),
    SavePathset(Vec<usize>),
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
