use myco_rs::{
    constants::{DELTA, NUM_CLIENTS},
    dtypes::Key,
    server2::Server2,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client_addr = "0.0.0.0:8443";
    let s1_addr = "0.0.0.0:8444";
    let cert_path = "certs/server-cert.pem";
    let key_path = "certs/server-key.pem";
    
    println!("Server2 starting...");
    
    // Create the same fixed key as Server1
    let mut rng = ChaCha20Rng::from_entropy();
    let simulation_key = Key::random(&mut rng);
    
    println!("Starting TLS server...");
    Server2::run_server_with_simulation(
        client_addr,
        s1_addr,
        cert_path,
        key_path,
        simulation_key,
        move |epoch| {
            println!("Processed epoch {}/{}", epoch, DELTA);
        }
    ).await.map_err(|e| e.into())
}
