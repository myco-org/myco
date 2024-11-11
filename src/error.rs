//! # Myco Error Types
//!
//! This module contains the error types used throughout the Myco library.
use thiserror::Error;

#[derive(Debug, Error)]
/// An enum representing the different types of errors that can occur in Myco
pub enum MycoError {
    /// Error that occurs when HKDF expansion fails
    #[error("HKDF expansion failed")]
    HkdfExpansionFailed,
    /// Error that occurs when HKDF fill operation fails
    #[error("HKDF fill failed")]
    HkdfFillFailed,
    /// Error that occurs when encryption operation fails
    #[error("Encryption failed")]
    EncryptionFailed,
    /// Error that occurs when decryption operation fails
    #[error("Decryption failed")]
    DecryptionFailed,
    /// Error that occurs when no message is found
    #[error("No message found")]
    NoMessageFound,
    /// Error that occurs when a bucket is not found
    #[error("Bucket not found")]
    BucketNotFound,
    /// Error that occurs when a metadata bucket is not found
    #[error("Metadata bucket not found")]
    MetadataBucketNotFound,
    /// Error that occurs when a bucket at a given index is not found
    #[error("Failed to get bucket at index {0}")]
    BucketIndexError(usize),
    /// Error that occurs when a metadata at a given index is not found
    #[error("Failed to get metadata at index {0}")]
    MetadataIndexError(usize),
    /// Error that occurs when the LCA is not found
    #[error("LCA not found")]
    LcaNotFound,
    /// Error that occurs when serialization fails
    #[error("Serialization failed")]
    SerializationFailed,
    /// Error that occurs when deserialization fails
    #[error("Deserialization failed")]
    DeserializationError,
    /// Error that occurs when an invalid command is received
    #[error("Invalid command")]
    InvalidCommand,
    /// Error that occurs when an IO error occurs
    #[error("{0}")]
    IoError(std::io::Error),
    /// Error that occurs when a TLS error occurs
    #[error("{0}")]
    TlsError(rustls::Error),
    /// Error that occurs when an invalid server name is received
    #[error("Invalid server name")]
    InvalidServerName,
    /// Error that occurs when an invalid batch size is received
    #[error("Invalid batch size")]
    InvalidBatchSize,
    /// Error that occurs when a mutex lock fails
    #[error("Failed to lock mutex: {0}")]
    MutexLockFailed(String),
    /// Error that occurs when a thread join fails
    #[error("Failed to join thread: {0}")]
    ThreadJoinFailed(String),
    /// Error that occurs when a channel send error occurs
    #[error("Channel send error: {0}")]
    ChannelSendError(String),
    /// Error that occurs when a channel receive error occurs
    #[error("Channel receive error: {0}")]
    ChannelReceiveError(String),
    /// Error that occurs when a parse integer error occurs
    #[error("Failed to parse integer: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    /// Error that occurs when a parse float error occurs
    #[error("Failed to parse float: {0}")]
    ParseFloatError(#[from] std::num::ParseFloatError),
    /// Error that occurs when a configuration error occurs
    #[error("Configuration error: {0}")]
    ConfigError(String),
    /// Error that occurs when a database error occurs
    #[error("Database error: {0}")]
    DatabaseError(String),
    /// Error that occurs when a network error occurs
    #[error("Network error: {0}")]
    NetworkError(String),
    /// Error that occurs when a protocol error occurs
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    /// Error that occurs when a certificate error occurs
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
