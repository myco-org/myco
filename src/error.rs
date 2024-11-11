use thiserror::Error;

#[derive(Debug, Error)]
pub enum MycoError {
    #[error("HKDF expansion failed")]
    HkdfExpansionFailed,
    #[error("HKDF fill failed")]
    HkdfFillFailed,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("No message found")]
    NoMessageFound,
    #[error("Bucket not found")]
    BucketNotFound,
    #[error("Metadata bucket not found")]
    MetadataBucketNotFound,
    #[error("Failed to get bucket at index {0}")]
    BucketIndexError(usize),
    #[error("Failed to get metadata at index {0}")]
    MetadataIndexError(usize),
    #[error("LCA not found")]
    LcaNotFound,
    #[error("Serialization failed")]
    SerializationFailed,
    #[error("Deserialization failed")]
    DeserializationError,
    #[error("Invalid command")]
    InvalidCommand,
    #[error("{0}")]
    IoError(std::io::Error),
    #[error("{0}")]
    TlsError(rustls::Error),
    #[error("Invalid server name")]
    InvalidServerName,
    #[error("Invalid batch size")]
    InvalidBatchSize,
    #[error("Failed to lock mutex: {0}")]
    MutexLockFailed(String),
    #[error("Failed to join thread: {0}")]
    ThreadJoinFailed(String),
    #[error("Channel send error: {0}")]
    ChannelSendError(String),
    #[error("Channel receive error: {0}")]
    ChannelReceiveError(String),
    #[error("Failed to parse integer: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("Failed to parse float: {0}")]
    ParseFloatError(#[from] std::num::ParseFloatError),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    #[error("Certificate error: {0}")]
    CertificateError(String),
}

impl From<std::io::Error> for MycoError {
    fn from(err: std::io::Error) -> Self {
        MycoError::IoError(err)
    }
}

impl From<rustls::Error> for MycoError {
    fn from(err: rustls::Error) -> Self {
        MycoError::TlsError(err)
    }
}

impl<T> From<std::sync::PoisonError<T>> for MycoError {
    fn from(err: std::sync::PoisonError<T>) -> Self {
        MycoError::MutexLockFailed(err.to_string())
    }
}

impl<T> From<std::sync::mpsc::SendError<T>> for MycoError {
    fn from(err: std::sync::mpsc::SendError<T>) -> Self {
        MycoError::ChannelSendError(err.to_string())
    }
}

impl From<std::sync::mpsc::RecvError> for MycoError {
    fn from(err: std::sync::mpsc::RecvError) -> Self {
        MycoError::ChannelReceiveError(err.to_string())
    }
}
