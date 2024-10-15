use thiserror::Error;

/// Represents errors that can occur in the MC-OSAM system.
#[derive(Debug, Error)]
pub enum McOsamError {
    /// Indicates a failure in the encryption process.
    #[error("Failed to encrypt message")]
    EncryptionFailed,

    /// Indicates a failure in the decryption process.
    #[error("Failed to decrypt message")]
    DecryptionFailed,

    /// Indicates a failure to access a bucket in the ORAM tree.
    #[error("Failed to access bucket")]
    BucketAccessFailed,

    /// Indicates a failure to access metadata in the ORAM tree.
    #[error("Failed to access metadata")]
    MetadataAccessFailed,

    /// Indicates a failure in performing a tree operation.
    #[error("Failed to perform tree operation")]
    TreeOperationFailed,

    /// Indicates a failure to acquire a lock on the server.
    #[error("Failed to lock server")]
    ServerLockFailed,

    /// Indicates a failure in the HKDF expansion process.
    #[error("HKDF expansion failed")]
    HkdfExpansionFailed,

    /// Indicates a failure in the HKDF fill process.
    #[error("HKDF fill failed")]
    HkdfFillFailed,

    /// Indicates a failure in random number generation.
    #[error("Failed to generate random number")]
    RandomGenerationFailed,

    /// Indicates that the ciphertext has an invalid length.
    #[error("Invalid ciphertext length")]
    InvalidCiphertextLength,

    /// Indicates a failure in creating a nonce.
    #[error("Failed to create nonce")]
    NonceCreationFailed,

    /// Indicates a failure in the key derivation process.
    #[error("Failed to perform key derivation")]
    KeyDerivationFailed,
}
