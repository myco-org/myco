//! Crypto helper functions

// External dependencies
use ring::{digest, hkdf, hmac};
use crate::error::MycoError; 
use crate::utils::pad_message;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use rand::Rng;
use ed25519_dalek::{Keypair, SecretKey, PublicKey, Signature, Signer, Verifier, SIGNATURE_LENGTH};
use crate::constants::{NONCE_SIZE, SERVER_SIGNING_SEED, TAG_SIZE};
use lazy_static::lazy_static;

lazy_static! {
    /// The server's signing key pair, derived once from its seed.
    static ref SERVER_KEYPAIR: Keypair = {
        let secret = SecretKey::from_bytes(&SERVER_SIGNING_SEED).expect("Invalid server signing seed");
        let public: PublicKey = (&secret).into();
        Keypair { secret, public }
    };
}

/// A custom KeyType that tells Ring's HKDF to produce a 16-byte output.
struct Key16;

impl hkdf::KeyType for Key16 {
    fn len(&self) -> usize {
        16
    }
}

/// Key Derivation Function (KDF) that derives a 16-byte key from a 128-bit input key and a string.
///
/// Uses HKDF-SHA256 with a fixed salt to derive the key.
///
/// # Arguments
/// * `key` - The input key bytes to derive from (must be 16 bytes long)
/// * `input` - A string to mix into the derivation (serves as the HKDF "info")
///
/// # Returns
/// * `Ok(Vec<u8>)` - The derived 16-byte key
/// * `Err(MycoError)` - If HKDF expansion or fill fails, or if the input key length is invalid
pub fn kdf(key: &[u8], input: &str) -> Result<Vec<u8>, MycoError> {
    // Enforce that the input key is exactly 16 bytes (128 bits).
    if key.len() != 16 {
        return Err(MycoError::CryptoError("Invalid key length".to_string()));
    }

    // Compute a fixed salt (here, the SHA-256 digest of a constant string).
    let salt = digest::digest(&digest::SHA256, b"MC-OSAM-Salt");

    // Extract the pseudorandom key (PRK) using Ring's HKDF.
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt.as_ref()).extract(key);

    // Use the provided input (as bytes) as the HKDF "info" parameter.
    let info = [input.as_bytes()];

    // Expand to produce exactly 16 bytes of output.
    let okm = prk
        .expand(&info, Key16)
        .map_err(|_| MycoError::CryptoError("HKDF expansion failed".to_string()))?;

    let mut result = [0u8; 16];
    okm.fill(&mut result)
        .map_err(|_| MycoError::CryptoError("HKDF fill failed".to_string()))?;

    Ok(result.to_vec())
}

/// Alternative PRF using HMAC-SHA256 directly.
///
/// This version uses HMAC-SHA256 with the provided key (which can be 16 bytes)
/// to produce 16 bytes of pseudorandom output (by truncating the 32-byte tag).
///
/// # Arguments
/// * `key` - The input key bytes (can be 16 bytes or another acceptable length)
/// * `input` - Input bytes to mix into the PRF
///
/// # Returns
/// * `Ok(Vec<u8>)` - 16 bytes of pseudorandom output
/// * `Err(MycoError)` - In case of an error (though HMAC typically does not fail)
pub fn prf(key: &[u8], input: &[u8]) -> Result<Vec<u8>, MycoError> {
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&signing_key, input);
    // Truncate the 32-byte tag to 16 bytes.
    Ok(tag.as_ref()[..16].to_vec())
}

/// A wrapper around the PRF function that returns a fixed number of bytes.
///
/// This function calls the internal `_prf` function (which uses HMAC-SHA256 to produce a 16-byte output)
/// and returns the first `length` bytes of the output.
///
/// # Arguments
/// * `key` - The 128-bit key (16 bytes)
/// * `input` - Input bytes to mix into the PRF
/// * `length` - The number of bytes to return from the PRF output
///
/// # Returns
/// * `Ok(Vec<u8>)` - A byte array containing the first `length` bytes of the PRF output.
/// * `Err(MycoError)` - If the underlying PRF call fails.
///
pub fn prf_fixed_length(key: &[u8], input: &[u8], length: usize) -> Result<Vec<u8>, MycoError> {
    // Call the underlying PRF function to get 16 bytes (128 bits) of pseudorandom output.
    let prf_output = prf(key, input)?;
    
    // Return the first `length` bytes
    Ok(prf_output[..length].to_vec())
}

/// Encrypt a padded message using AES-GCM encryption.
///
/// # Arguments
/// * `key` - The encryption key
/// * `message` - The message to encrypt
/// * `padding_size` - The padding size for the message
///
/// # Returns
/// The encrypted message as a byte vector, or an error if encryption fails.
pub fn encrypt(key: &[u8], message: &[u8], padding_size: usize) -> Result<Vec<u8>, MycoError> {
    encrypt_with_aad(key, message, padding_size, b"")
}

/// Encrypts like [`encrypt`] and authenticates `aad` (associated data) with the ciphertext:
/// decryption succeeds only with the same `aad`. The client binds a message to the epoch it
/// is written in this way.
pub fn encrypt_with_aad(key: &[u8], message: &[u8], padding_size: usize, aad: &[u8]) -> Result<Vec<u8>, MycoError> {
    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|_| MycoError::CryptoError("Encryption failed".to_string()))?;
    let nonce_bytes = rand::thread_rng().gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut buffer = pad_message(message, padding_size);
    cipher
        .encrypt_in_place(nonce, aad, &mut buffer)
        .map_err(|_| MycoError::CryptoError("Encryption failed".to_string()))?;
    Ok([nonce.as_slice(), buffer.as_slice()].concat())
}

/// Decrypt a ciphertext encrypted with AES-GCM.
///
/// # Arguments
/// * `key` - The encryption key
/// * `ciphertext` - The encrypted message
///
/// # Returns
/// The decrypted message as a byte vector, or an error if decryption fails.
pub fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, MycoError> {
    decrypt_with_aad(key, ciphertext, b"")
}

/// Decrypts a ciphertext made by [`encrypt_with_aad`] with the same associated data.
pub fn decrypt_with_aad(key: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, MycoError> {
    if ciphertext.len() < 12 {
        return Err(MycoError::CryptoError("Decryption failed".to_string()));
    }
    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|_| MycoError::CryptoError("Decryption failed".to_string()))?;
    let (nonce, ciphertext) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce);
    let mut buffer = Vec::from(ciphertext);
    cipher
        .decrypt_in_place(nonce, aad, &mut buffer)
        .map_err(|_| MycoError::CryptoError("Decryption failed".to_string()))?;
    Ok(buffer)
}

/// Encrypts like [`encrypt`], but writes nonce, ciphertext and tag into `out` instead of
/// returning a new vector. `message` is not padded, so `out` must be exactly
/// `message.len() + NONCE_SIZE + TAG_SIZE` bytes long.
pub fn encrypt_into(key: &[u8], message: &[u8], out: &mut [u8]) -> Result<(), MycoError> {
    if out.len() != message.len() + NONCE_SIZE + TAG_SIZE {
        return Err(MycoError::CryptoError("Encryption failed".to_string()));
    }
    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|_| MycoError::CryptoError("Encryption failed".to_string()))?;
    let nonce_bytes = rand::thread_rng().gen::<[u8; NONCE_SIZE]>();
    let (nonce_out, rest) = out.split_at_mut(NONCE_SIZE);
    let (body, tag_out) = rest.split_at_mut(message.len());
    nonce_out.copy_from_slice(&nonce_bytes);
    body.copy_from_slice(message);
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), b"", body)
        .map_err(|_| MycoError::CryptoError("Encryption failed".to_string()))?;
    tag_out.copy_from_slice(&tag);
    Ok(())
}

/// Decrypts like [`decrypt`], but writes the plaintext into `out` instead of returning a new
/// vector. `out` must be exactly `ciphertext.len() - NONCE_SIZE - TAG_SIZE` bytes long.
pub fn decrypt_into(key: &[u8], ciphertext: &[u8], out: &mut [u8]) -> Result<(), MycoError> {
    if ciphertext.len() < NONCE_SIZE + TAG_SIZE || out.len() != ciphertext.len() - NONCE_SIZE - TAG_SIZE {
        return Err(MycoError::CryptoError("Decryption failed".to_string()));
    }
    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|_| MycoError::CryptoError("Decryption failed".to_string()))?;
    let (nonce, rest) = ciphertext.split_at(NONCE_SIZE);
    let (body, tag) = rest.split_at(out.len());
    out.copy_from_slice(body);
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(nonce), b"", out, aes_gcm::Tag::from_slice(tag))
        .map_err(|_| MycoError::CryptoError("Decryption failed".to_string()))
}

/// A decryption key set up once and used for many blocks.
pub struct BlockDecryptor(Aes128Gcm);

impl BlockDecryptor {
    /// Prepares `key` for decryption.
    pub fn new(key: &[u8]) -> Result<Self, MycoError> {
        Aes128Gcm::new_from_slice(key).map(BlockDecryptor).map_err(|_| MycoError::CryptoError("Decryption failed".to_string()))
    }

    /// Decrypts like [`decrypt_into`] with the prepared key.
    pub fn decrypt_into(&self, ciphertext: &[u8], out: &mut [u8]) -> Result<(), MycoError> {
        if ciphertext.len() < NONCE_SIZE + TAG_SIZE || out.len() != ciphertext.len() - NONCE_SIZE - TAG_SIZE {
            return Err(MycoError::CryptoError("Decryption failed".to_string()));
        }
        let (nonce, rest) = ciphertext.split_at(NONCE_SIZE);
        let (body, tag) = rest.split_at(out.len());
        out.copy_from_slice(body);
        self.0
            .decrypt_in_place_detached(Nonce::from_slice(nonce), b"", out, aes_gcm::Tag::from_slice(tag))
            .map_err(|_| MycoError::CryptoError("Decryption failed".to_string()))
    }
}

/// Signs `message` using the server's deterministic private key.
pub fn sign(message: &[u8]) -> Result<Vec<u8>, MycoError> {
    let signature: Signature = SERVER_KEYPAIR.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Verifies `signature` on `message` using the server's deterministic public key.
pub fn verify(message: &[u8], signature: &[u8]) -> Result<(), MycoError> {
    if signature.len() != SIGNATURE_LENGTH {
        return Err(MycoError::CryptoError("Invalid signature length".to_string()));
    }
    let sig = Signature::from_bytes(signature)
         .map_err(|e| MycoError::CryptoError(format!("Signature parse error: {}", e)))?;
    SERVER_KEYPAIR.public.verify(message, &sig)
        .map_err(|e| MycoError::CryptoError(format!("Signature verification failed: {}", e)))
}