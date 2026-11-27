//! Utility functions for the Myco protocol.
//! Utility functions for the Myco protocol.

use std::{
    collections::HashSet,
    error::Error,
    fs,
    path::Path as StdPath,
    process::Command,
};

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use tonic::transport::{Certificate, Channel, ClientTlsConfig};

use crate::{
    constants::{D, D_BYTES, MIN_PATHS_PER_BUCKET, NONCE_SIZE, NOTIF_LOC_BYTES, Q, TAG_SIZE},
    crypto::{encrypt, prf},
    dtypes::*,
    error::MycoError,
};


/// Number of levels at the top of the tree that readers skip: with the `short-reads` feature,
/// the levels that hold no messages; otherwise none.
///
/// Server1 writes a message to the deepest bucket of the epoch's path set on the message's
/// path, and a message only moves down afterwards. The path set is the union of `num_clients`
/// uniformly random root-to-leaf paths, so all of them miss a given bucket at depth `d` with
/// probability `(1 - 2^-d)^num_clients < exp(-num_clients / 2^d)`. Levels are skipped while
/// `num_clients / 2^d >= MIN_PATHS_PER_BUCKET` holds for the first level `d` that is still
/// read: a message then lies above that level with probability below `exp(-64) < 2^-92`.
pub fn read_skipped_levels(num_clients: usize) -> usize {
    if !cfg!(feature = "short-reads") {
        return 0;
    }
    let mut levels = 0;
    while levels < D && num_clients >> (levels + 1) >= MIN_PATHS_PER_BUCKET {
        levels += 1;
    }
    levels
}

/// Helper function to get the indices of the paths.
pub fn get_path_indices(paths: Vec<Path>) -> Vec<usize> {
    // Initialize empty set to store unique node indices, starting with root (index 1)
    let mut pathset: HashSet<usize> = HashSet::new();
    pathset.insert(1);

    // Use thread-safe collection for parallel processing
    let thread_safe_indices: HashSet<usize> = paths.par_iter()
        .flat_map(|p| {
            let mut indices = Vec::new();
            p.clone().into_iter().fold(1, |acc, d| {
                // Calculate child index: left child is 2*parent, right child is 2*parent + 1
                let idx = 2 * acc + u8::from(d) as usize;
                indices.push(idx);
                idx
            });
            indices
        })
        .collect();
    
    // Merge results into the pathset
    pathset.extend(thread_safe_indices);

    // Convert set to vector and return
    pathset.into_iter().collect()
}

/// Generates self-signed TLS certificates for testing purposes.
/// Creates a certificate and private key in the 'certs' directory.
pub fn generate_test_certificates() -> Result<(), MycoError> {
    // Ensure the "certs" directory exists.
    if !StdPath::new("certs").exists() {
        fs::create_dir("certs")?;
    }
    if StdPath::new("certs/server-cert.pem").exists() && StdPath::new("certs/server-key.pem").exists() {
        // Clean up old certificates to ensure we have fresh ones.
        fs::remove_file("certs/server-cert.pem")?;
        fs::remove_file("certs/server-key.pem")?;
    }

    // Create a temporary OpenSSL config file.
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

    // Generate private key and self-signed certificate using OpenSSL.
    let output = Command::new("openssl")
        .args(&[
            "req",
            "-x509",
            "-newkey", "rsa:4096",
            "-keyout", "certs/server-key.pem",
            "-out", "certs/server-cert.pem",
            "-days", "365",
            "-nodes",
            "-config", "openssl.cnf",
            "-extensions", "v3_req",
        ])
        .output()?;
    if !output.status.success() {
        return Err(MycoError::CryptoError(format!(
            "Failed to generate self-signed certificate: {:?}",
            output
        )));
    }

    // Convert the key to PKCS8 format which rustls expects.
    let output = Command::new("openssl")
        .args(&[
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in", "certs/server-key.pem",
            "-out", "certs/server-key.pem.tmp",
        ])
        .output()?;
    if !output.status.success() {
        return Err(MycoError::CryptoError(format!(
            "Failed to convert key to PKCS8 format: {:?}",
            output
        )));
    }

    // Replace the original key with the PKCS8 version.
    fs::rename("certs/server-key.pem.tmp", "certs/server-key.pem")?;
    // Clean up the config file.
    fs::remove_file("openssl.cnf")?;
    Ok(())
}

pub type Index = Vec<u8>;

pub(crate) fn l_to_u64(l: &Index, num_clients: usize) -> u64 {
    let mut bytes = [0u8; 8];
    let len = l.len().min(8);
    bytes[..len].copy_from_slice(&l[..len]);
    let result = u64::from_le_bytes(bytes);
    result % (Q * num_clients) as u64
}

/// Domain-separation tags: the tree pad and the notification pad of a sender are PRF values on
/// different inputs.
const TREE_PAD_TAG: u8 = 0;
const NOTIF_PAD_TAG: u8 = 1;

/// The tree location of a message: `l = f XOR PRF_k(0 || c_s)`, as D_BYTES bytes (the leaf is the
/// first D bits, see `leaf_from_bytes` in server1.rs). `k` is Server1's routing key of the epoch.
///
/// Server2 learns `k` after the epoch, so it can compute the pad of every sender; the location
/// still tells it nothing about the sender, because `f` is a secret uniformly random value known
/// only to the sender, the receiver and Server1 (a one-time pad). A sender chooses `f` but not the
/// pad, which is pseudorandom while `k` is secret, so it cannot steer its message.
pub fn tree_location(k: &[u8], f: &[u8], c_s: &[u8]) -> Result<Vec<u8>, MycoError> {
    if f.len() < D_BYTES {
        return Err(MycoError::CryptoError(format!("f is {} bytes, expected at least {}", f.len(), D_BYTES)));
    }
    let pad = prf(k, &[&[TREE_PAD_TAG][..], c_s].concat())?;
    Ok((0..D_BYTES).map(|i| f[i] ^ pad[i]).collect())
}

/// The notification location: `l_ntf = (f_ntf + PRF_k(1 || c_s)) mod (Q * num_clients)`, with
/// `f_ntf` and the pad each read as a 128-bit integer, encoded as NOTIF_LOC_BYTES little-endian
/// bytes (so `l_to_u64` returns it unchanged). Same argument as `tree_location`; reducing a
/// 128-bit value modulo Q * num_clients is within 2^-90 of uniform.
pub fn notification_location(k: &[u8], f_ntf: &[u8], c_s: &[u8], num_clients: usize) -> Result<Index, MycoError> {
    let f_ntf: [u8; 16] = f_ntf
        .try_into()
        .map_err(|_| MycoError::CryptoError(format!("f_ntf is {} bytes, expected 16", f_ntf.len())))?;
    let pad: [u8; 16] = prf(k, &[&[NOTIF_PAD_TAG][..], c_s].concat())?[..16]
        .try_into()
        .expect("the PRF returns 16 bytes");
    let m = (Q * num_clients) as u128;
    let l = (u128::from_le_bytes(f_ntf) % m + u128::from_le_bytes(pad) % m) % m;
    Ok(encode_notification_location(l))
}

/// A uniformly random notification location, encoded like a real one (padding and fake reads).
pub fn random_notification_location<R: RngCore>(rng: &mut R, num_clients: usize) -> Index {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    encode_notification_location(u128::from_le_bytes(bytes) % (Q * num_clients) as u128)
}

fn encode_notification_location(l: u128) -> Index {
    (l as u64).to_le_bytes()[..NOTIF_LOC_BYTES].to_vec()
}


/// Pads a message to a target length by appending zeros.
///
/// # Arguments
/// * `message` - The message bytes to pad
/// * `target_length` - The desired length after padding
///
/// # Returns
/// A new vector containing the padded message
pub(crate) fn pad_message(message: &[u8], target_length: usize) -> Vec<u8> {
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

/// Generates a dummy encrypted message of specified size with a random key
///
/// # Arguments
/// * `size` - The size of the dummy message to encrypt
///
/// # Returns
/// * `Ok(Vec<u8>)` - The encrypted dummy message
/// * `Err(MycoError)` - If encryption fails
pub fn generate_dummy_message(block_size: usize, rng: &mut ChaCha20Rng) -> Result<Vec<u8>, MycoError> {    
    // Generate random 16-byte key
    let mut key = vec![0u8; 16];
    rng.fill_bytes(&mut key);

    // Create zero vector of specified size
    let message = vec![0u8; block_size - NONCE_SIZE - TAG_SIZE];

    // Encrypt the zero vector
    let ciphertext = encrypt(&key, &message, block_size - NONCE_SIZE - TAG_SIZE)?;
    Ok(ciphertext)
}

/// Derive a per-bucket RNG by combining a global seed with the bucket index.
pub fn derive_rng(base_seed: [u8; 32], idx: usize) -> ChaCha20Rng {
    let mut new_seed = base_seed;
    new_seed[0] ^= idx as u8;
    ChaCha20Rng::from_seed(new_seed)
}

/// Constructs a TLS-enabled channel using the certificate in the `certs/` folder.
/// We load the server certificate (which, for self-signed setups, can act as the CA cert)
/// and configure TLS with the proper domain name.
pub async fn build_tls_channel(url: &str) -> Result<Channel, Box<dyn Error>> {
    // Check if the certificate file exists.
    if !std::path::Path::new("certs/server-cert.pem").exists() {
        println!("Certificate not found at 'certs/server-cert.pem'. Generating test certificates...");
        generate_test_certificates().map_err(|e| format!("Failed generating test certificates: {}", e))?;
    }

    // Load the server certificate (for self-signed setups, this certificate acts as the CA cert).
    let cert = fs::read("certs/server-cert.pem")?;
    let ca_cert = Certificate::from_pem(cert);

    let tls_config = ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        // The domain name here should match the certificate's CN or SAN.
        .domain_name("localhost");

    let channel = Channel::from_shared(url.to_string())?
        .tls_config(tls_config)?
        .connect()
        .await?;
    Ok(channel)
}