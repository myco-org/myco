//! Crypto helper functions

use ring::{digest, hkdf};
use crate::error::MycoError;
use crate::constants::{INNER_BLOCK_SIZE, MESSAGE_SIZE};
use crate::utils::pad_message;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use rand::Rng;

/// Key Derivation Function (KDF) that derives a 16-byte key from an input key and string.
///
/// Uses HKDF-SHA256 with a fixed salt to derive the key.
///
/// # Arguments
/// * `key` - The input key bytes to derive from
/// * `input` - String input to mix into the derivation
///
/// # Returns
/// * `Ok(Vec<u8>)` - The derived 16-byte key
/// * `Err(MycoError)` - If HKDF expansion or fill fails
pub fn kdf(key: &[u8], input: &str) -> Result<Vec<u8>, MycoError> {
    let salt = digest::digest(&digest::SHA256, b"MC-OSAM-Salt");
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt.as_ref()).extract(key);
    let binding = [input.as_bytes()];
    let okm = prk
        .expand(&binding, hkdf::HKDF_SHA256)
        .map_err(|_| MycoError::HkdfExpansionFailed)?;
    let mut result = vec![0u8; 32];
    okm.fill(&mut result)
        .map_err(|_| MycoError::HkdfFillFailed)?;
    Ok(result[..16].to_vec())
}

/// Pseudorandom Function (PRF) that generates a 32-byte pseudorandom output.
///
/// Uses HKDF-SHA256 with a fixed salt to generate pseudorandom bytes.
///
/// # Arguments
/// * `key` - The key bytes to use as input
/// * `input` - Input bytes to mix into the PRF
///
/// # Returns
/// * `Ok(Vec<u8>)` - 32 bytes of pseudorandom output
/// * `Err(MycoError)` - If HKDF expansion or fill fails
pub fn prf(key: &[u8], input: &[u8]) -> Result<Vec<u8>, MycoError> {
    // Fixed output length of 32 bytes
    let output_length = 32;

    // Using a fixed salt for HKDF
    let salt = digest::digest(&digest::SHA256, b"MC-OSAM-Salt");
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt.as_ref()).extract(key);

    // Use info directly as the context for HKDF expansion
    let binding = [input];
    let okm = prk
        .expand(&binding, hkdf::HKDF_SHA256)
        .map_err(|_| MycoError::HkdfExpansionFailed)?;

    // Allocate output buffer with fixed length of 32 bytes
    let mut result = vec![0u8; output_length];
    okm.fill(&mut result).map_err(|_| MycoError::HkdfFillFailed)?;
    Ok(result)
}


/// An enum representing the type of encryption to perform
#[derive(Debug)]
pub enum EncryptionType {
    /// Single encryption using AES-GCM
    Encrypt,
    /// Double encryption using AES-GCM twice
    DoubleEncrypt,
}


/// Encrypt a padded message using AES-GCM encryption
///
/// # Arguments
/// * `key` - The encryption key
/// * `message` - The message to encrypt
/// * `encryption_type` - Whether to do single or double encryption
///
/// # Returns
/// The encrypted message as a byte vector, or an error if encryption fails
pub fn encrypt(
    key: &[u8],
    message: &[u8],
    encryption_type: EncryptionType,
) -> Result<Vec<u8>, MycoError> {
    // Get the appropriate padding size based on encryption type
    let padding_size = match encryption_type {
        EncryptionType::Encrypt => MESSAGE_SIZE,
        EncryptionType::DoubleEncrypt => INNER_BLOCK_SIZE,
    };

    // Use cfg_if to handle the different compilation features
    cfg_if::cfg_if! {
        if #[cfg(feature = "no-enc")] {
            // In no-enc mode, just pad the message and return it
            Ok(pad_message(message, padding_size))
        } else {
            // Full encryption implementation
            {
                let cipher = Aes128Gcm::new_from_slice(key)
                    .map_err(|_| MycoError::EncryptionFailed)?;
                
                let nonce_bytes = rand::thread_rng().gen::<[u8; 12]>();
                let nonce = Nonce::from_slice(&nonce_bytes);
                
                let mut buffer = pad_message(message, padding_size);
                
                cipher
                    .encrypt_in_place(nonce, b"", &mut buffer)
                    .map_err(|_| MycoError::EncryptionFailed)?;
                
                Ok([nonce.as_slice(), buffer.as_slice()].concat())
            }
        }
    }
}

/// Decrypt a ciphertext
pub fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, MycoError> {
    cfg_if::cfg_if! {
        if #[cfg(feature = "no-enc")] {
            // In no-enc mode, just return the input
            Ok(ciphertext.to_vec())
        } else {
            {
                if ciphertext.len() < 12 {
                    return Err(MycoError::NoMessageFound);
                }

                let cipher = Aes128Gcm::new_from_slice(key)
                    .map_err(|_| MycoError::NoMessageFound)?;
                
                let (nonce, ciphertext) = ciphertext.split_at(12);
                let nonce = Nonce::from_slice(nonce);
                
                let mut buffer = Vec::from(ciphertext);
                cipher
                    .decrypt_in_place(nonce, b"", &mut buffer)
                    .map_err(|_| MycoError::NoMessageFound)?;
                
                Ok(buffer)
            }
        }
    }
}