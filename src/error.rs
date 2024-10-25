use thiserror::Error;

#[derive(Debug, Error)]
pub enum OramError {
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
    #[error("Invalid command")]
    InvalidCommand,
}
