//! # Myco

//! "Myco" is a Rust library that enhances user anonymity in encrypted messaging by hiding metadata 
//! like communication timing and participant relationships. It uses an innovative data structure 
//! inspired by ORAM to achieve efficient read and write operations, while maintaining strong 
//! cryptographic guarantees. By separating message writing and reading across two servers, Myco 
//! significantly improves performance compared to existing systems.

// Add module declarations
pub mod constants;
pub mod dtypes;
pub mod utils;
pub mod network;
pub mod server1;
pub mod server2;
pub mod tree;
pub mod client;
pub mod logging;
pub mod proto;
pub mod crypto;
pub mod multisign;
pub mod error;
pub mod megaclient;