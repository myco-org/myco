//! Utility functions for the Myco protocol.

use crate::{
    dtypes::*,
    tree::BinaryTree,
    crypto::decrypt,
};

use std::{
    collections::HashSet,
    fs,
    path::Path as StdPath,
    process::Command,
};


/// Pads a message to a target length by appending zeros.
///
/// # Arguments
/// * `message` - The message bytes to pad
/// * `target_length` - The desired length after padding
///
/// # Returns
/// A new vector containing the padded message
pub fn pad_message(message: &[u8], target_length: usize) -> Vec<u8> {
    let mut padded = message.to_vec();
    if padded.len() < target_length {
        padded.resize(target_length, 0);
    }
    padded
}

/// Trims trailing zeros from a byte slice.
///
/// # Arguments
/// * `buffer` - The byte slice to trim
///
/// # Returns
/// A new vector with trailing zeros removed
pub fn trim_zeros(buffer: &[u8]) -> Vec<u8> {
    let buf: Vec<u8> = buffer
        .iter()
        .rev()
        .skip_while(|&&x| x == 0)
        .cloned()
        .collect();
    buf.into_iter().rev().collect()
}

/// Helper function to get the indices of the paths.
pub fn get_path_indices(paths: Vec<Path>) -> Vec<usize> {
    // Initialize empty set to store unique node indices, starting with root (index 1)
    let mut pathset: HashSet<usize> = HashSet::new();
    pathset.insert(1);

    // For each path, traverse from root to leaf and collect node indices
    paths.iter().for_each(|p| {
        p.clone().into_iter().fold(1, |acc, d| {
            // Calculate child index: left child is 2*parent, right child is 2*parent + 1
            let idx = 2 * acc + u8::from(d) as usize;
            pathset.insert(idx);
            idx
        });
    });

    // Convert set to vector and return
    pathset.into_iter().collect()
}

/// Helper function to calculate the bucket usage of the server.
pub fn calculate_bucket_usage(
    server2_tree: &BinaryTree<Bucket>,
    metadata_tree: &BinaryTree<Metadata>,
    k_msg: &[u8],
) -> (usize, usize, f64, f64, f64) {
    // Track bucket usage statistics
    let mut bucket_usage = Vec::new();
    let mut total_messages = 0;
    let mut max_usage = 0;
    let mut max_depth = 0;

    // Iterate through buckets and metadata to calculate usage
    server2_tree
        .zip(metadata_tree)
        .into_iter()
        .for_each(|(bucket, metadata_bucket, path)| {
            if let (Some(bucket), Some(metadata_bucket)) = (bucket, metadata_bucket) {
                // Count messages in this bucket based on encryption mode
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
                            if let Some((_l, k_oblv_t, _t_exp)) = metadata_bucket.get(b) {
                                if let Some(c_msg) = bucket.get(b) {
                                    // Try to decrypt with both keys to verify message
                                    if let Ok(ct) = decrypt(&k_oblv_t.0, &c_msg.0) {
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

                // Update statistics
                bucket_usage.push(messages_in_bucket);
                total_messages += messages_in_bucket;
                if messages_in_bucket > max_usage {
                    max_usage = messages_in_bucket;
                    max_depth = path.len();
                }
            }
        });

    // Calculate summary statistics
    let total_buckets = bucket_usage.len();
    let average_usage = total_messages as f64 / total_buckets as f64;

    // Calculate median usage
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

    // Print summary statistics
    println!(
        "Max usage: {}, Max depth: {}, Average usage: {:.2}, Median: {:.2}, Std dev: {:.2}",
        max_usage, max_depth, average_usage, median_usage, std_dev
    );

    // Return tuple of statistics
    (max_usage, max_depth, average_usage, median_usage, std_dev)
}

/// Generates self-signed TLS certificates for testing purposes.
/// Creates a certificate and private key in the 'certs' directory.
pub fn generate_test_certificates() -> Result<(), Box<dyn std::error::Error>> {
    // Use StdPath instead of Path
    if !StdPath::new("certs").exists() {
        fs::create_dir("certs")?;
    }
    if StdPath::new("certs/server-cert.pem").exists() && StdPath::new("certs/server-key.pem").exists() {
        // Clean up old certificates to ensure we have fresh ones
        fs::remove_file("certs/server-cert.pem")?;
        fs::remove_file("certs/server-key.pem")?;
    }

    // Create a config file for OpenSSL
    fs::write(
        "openssl.cnf",
        r#"
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = localhost

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
"#,
    )?;

    // Generate private key and self-signed certificate using OpenSSL
    Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:4096",
            "-keyout",
            "certs/server-key.pem",
            "-out",
            "certs/server-cert.pem",
            "-days",
            "365",
            "-nodes",
            "-config",
            "openssl.cnf",
            "-extensions",
            "v3_req",
        ])
        .output()?;

    // Convert the key to PKCS8 format which rustls expects
    Command::new("openssl")
        .args([
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in",
            "certs/server-key.pem",
            "-out",
            "certs/server-key.pem.tmp",
        ])
        .output()?;

    // Replace the original key with the PKCS8 version
    fs::rename("certs/server-key.pem.tmp", "certs/server-key.pem")?;

    // Clean up the config file
    fs::remove_file("openssl.cnf")?;

    Ok(())
}