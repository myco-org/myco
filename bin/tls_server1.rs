use myco_rs::{
    client::Client,
    constants::{DELTA, NUM_CLIENTS},
    dtypes::Key,
    network::{Command, RemoteServer2Access},
    server1::Server1,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::error::Error;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr = "0.0.0.0:8420";
    let cert_path = "certs/server-cert.pem";
    let key_path = "certs/server-key.pem";
    
    println!("Server1 starting...");
    
    // Create a fixed key for simulation
    let mut rng = ChaCha20Rng::from_entropy();
    let simulation_key = Key::random(&mut rng);
    
    // Initialize simulation clients
    println!("Initializing {} simulation clients...", NUM_CLIENTS);
    
    // Start the server with simulation data
    println!("Starting TLS server...");
    Server1::run_server(
        addr, 
        cert_path, 
        key_path
    ).await.map_err(|e| e.into())
}
