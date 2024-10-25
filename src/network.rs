use serde::{Deserialize, Serialize};

use crate::{error::OramError, Bucket, Key, Path};

#[derive(Serialize, Deserialize)]
pub(crate) enum Command {
    Server1Write(Vec<u8>, Vec<u8>, Key, Vec<u8>),
    Server2Write(Vec<Bucket>),
    Server2Read(Path),
    Server2AddPrfKey(Key),
    Server2GetPrfKeys,
    Server2ReadPaths(Vec<usize>),
}


pub(crate) trait Local {
    fn send(&self, command: &[u8]) -> Result<Vec<u8>, OramError>;
}

pub(crate) trait Network {
    fn send(&self, command: &[u8]) -> Result<Vec<u8>, OramError>;
}
