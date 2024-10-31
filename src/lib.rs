#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_assignments)]
#![allow(unused_must_use)]
#![allow(dead_code)]
#![allow(unused_parens)]
#![allow(private_bounds)]

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use bincode::{deserialize, serialize};
use error::OramError;
use network::{Command, Local, ReadType, WriteType, Server1Access, Server2Access, LocalServer1Access, LocalServer2Access};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use ring::{digest, hkdf, pbkdf2};

use std::{
    collections::HashMap,
    num::NonZeroU32,
    sync::{Arc, Mutex},
};
use tree::BinaryTree;

// Add module declarations
pub mod constants;
pub mod dtypes;
pub mod error;
pub mod network;
pub mod server1;
pub mod server2;
pub mod tree;
pub mod tls_server;
pub mod client;

// Import constants and server modules
use constants::*;
use dtypes::*;
use server1::Server1;
use server2::Server2;

// Key Derivation Function (KDF)
pub fn kdf(key: &[u8], input: &str) -> Result<Vec<u8>, OramError> {
    let salt = digest::digest(&digest::SHA256, b"MC-OSAM-Salt");
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt.as_ref()).extract(key);
    let binding = [input.as_bytes()];
    let okm = prk
        .expand(&binding, hkdf::HKDF_SHA256)
        .map_err(|_| OramError::HkdfExpansionFailed)?;
    let mut result = vec![0u8; 32];
    okm.fill(&mut result)
        .map_err(|_| OramError::HkdfFillFailed)?;
    Ok(result[..16].to_vec())
}

// Pseudorandom Function (PRF)
// Make this an arbitrary-length PRF
pub fn prf(key: &[u8], input: &[u8]) -> Result<Vec<u8>, OramError> {
    // Fixed output length of 32 bytes
    let output_length = 32;

    // Using a fixed salt for HKDF
    let salt = digest::digest(&digest::SHA256, b"MC-OSAM-Salt");
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt.as_ref()).extract(key);

    // Use info directly as the context for HKDF expansion
    let binding = [input];
    let okm = prk
        .expand(&binding, hkdf::HKDF_SHA256)
        .map_err(|_| OramError::HkdfExpansionFailed)?;

    // Allocate output buffer with fixed length of 32 bytes
    let mut result = vec![0u8; output_length];
    okm.fill(&mut result).map_err(|_| OramError::HkdfFillFailed)?;
    Ok(result)
}

// Pad a message to the right with zeros
fn pad_message(message: &[u8], target_length: usize) -> Vec<u8> {
    let mut padded = message.to_vec();
    if padded.len() < target_length {
        padded.resize(target_length, 0);
    }
    padded
}

pub enum EncryptionType {
    Encrypt,
    DoubleEncrypt,
}

// Encrypt a padded message
pub fn encrypt(
    key: &[u8],
    message: &[u8],
    encryption_type: EncryptionType,
) -> Result<Vec<u8>, OramError> {
    #[cfg(feature = "no-enc")]
    {
        // In no-enc mode, just pad the message and return it
        return Ok(match encryption_type {
            EncryptionType::Encrypt => pad_message(message, BLOCK_SIZE),
            EncryptionType::DoubleEncrypt => pad_message(message, INNER_BLOCK_SIZE),
        });
    }

    #[cfg(not(feature = "no-enc"))]
    {
        let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| OramError::EncryptionFailed)?;
        let binding = rand::thread_rng().gen::<[u8; 12]>();
        let nonce = Nonce::from_slice(&binding);
        let mut buffer = match encryption_type {
            EncryptionType::Encrypt => pad_message(message, BLOCK_SIZE),
            EncryptionType::DoubleEncrypt => pad_message(message, INNER_BLOCK_SIZE),
        };

        cipher
            .encrypt_in_place(nonce, b"", &mut buffer)
            .map_err(|_| OramError::EncryptionFailed)?;

        Ok([nonce.as_slice(), buffer.as_slice()].concat())
    }
}

// Decrypt a ciphertext
pub fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, OramError> {
    #[cfg(feature = "no-enc")]
    {
        // In no-enc mode, just return the input
        return Ok(ciphertext.to_vec());
    }

    #[cfg(not(feature = "no-enc"))]
    {
        if ciphertext.len() < 12 {
            return Err(OramError::NoMessageFound);
        }

        let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| OramError::NoMessageFound)?;
        let (nonce, ciphertext) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce);
        let mut buffer = Vec::from(ciphertext);

        cipher
            .decrypt_in_place(nonce, b"", &mut buffer)
            .map_err(|_| OramError::NoMessageFound)?;

        Ok(buffer)
    }
}

pub fn trim_zeros(buffer: &[u8]) -> Vec<u8> {
    let buf: Vec<u8> = buffer
        .iter()
        .rev()
        .skip_while(|&&x| x == 0)
        .cloned()
        .collect();
    buf.into_iter().rev().collect()
}

/// Helper function to calculate the bucket usage of the server.
pub fn calculate_bucket_usage(
    server2_tree: &BinaryTree<Bucket>,
    metadata_tree: &BinaryTree<Metadata>,
    k_msg: &[u8],
) -> (usize, usize, f64, f64, f64) {
    let mut bucket_usage = Vec::new();
    let mut total_messages = 0;
    let mut max_usage = 0;
    let mut max_depth = 0;

    server2_tree
        .zip(metadata_tree)
        .into_iter()
        .for_each(|(bucket, metadata_bucket, path)| {
            if let (Some(bucket), Some(metadata_bucket)) = (bucket, metadata_bucket) {
                let messages_in_bucket = {
                    #[cfg(feature = "no-enc")]
                    {
                        // In no-enc mode, just count non-empty blocks
                        bucket.len()
                    }
                    #[cfg(not(feature = "no-enc"))]
                    {
                        // With encryption, check if messages are decryptable
                        let mut decryptable_messages = 0;
                        for b in 0..bucket.len() {
                            if let Some((_l, k_oram_t, _t_exp)) = metadata_bucket.get(b) {
                                if let Some(c_msg) = bucket.get(b) {
                                    if let Ok(ct) = decrypt(&k_oram_t.0, &c_msg.0) {
                                        if decrypt(k_msg, &ct).is_ok() {
                                            decryptable_messages += 1;
                                        }
                                    }
                                }
                            }
                        }
                        decryptable_messages
                    }
                };

                bucket_usage.push(messages_in_bucket);
                total_messages += messages_in_bucket;
                if messages_in_bucket > max_usage {
                    max_usage = messages_in_bucket;
                    max_depth = path.len();
                }
            }
        });

    let total_buckets = bucket_usage.len();
    let average_usage = total_messages as f64 / total_buckets as f64;

    // Calculate median
    bucket_usage.sort_unstable();
    let median_usage = if total_buckets % 2 == 0 {
        (bucket_usage[total_buckets / 2 - 1] + bucket_usage[total_buckets / 2]) as f64 / 2.0
    } else {
        bucket_usage[total_buckets / 2] as f64
    };

    // Calculate standard deviation
    let variance = bucket_usage
        .iter()
        .map(|&x| {
            let diff = x as f64 - average_usage;
            diff * diff
        })
        .sum::<f64>()
        / total_buckets as f64;
    let std_dev = variance.sqrt();
    println!(
        "Max usage: {}, Max depth: {}, Average usage: {:.2}, Median: {:.2}, Std dev: {:.2}",
        max_usage, max_depth, average_usage, median_usage, std_dev
    );
    (max_usage, max_depth, average_usage, median_usage, std_dev)
}