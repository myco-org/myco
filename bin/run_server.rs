use myco_rs::{
    client::Client,
    constants::{DELTA, NUM_CLIENTS},
    dtypes::Key,
    network::{Command, RemoteServer2Access},
    server1::Server1, server2::Server2,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::{error::Error, time::Duration};
use tokio::{self, time};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let s1_addr = "0.0.0.0:8420";
    let s2_client_addr = "0.0.0.0:8443"; 
    let s2_s1_addr = "0.0.0.0:8444";
    let cert_path = "certs/server-cert.pem";
    let key_path = "certs/server-key.pem";

    // Create fixed key for simulation
    let mut rng = ChaCha20Rng::from_entropy();
    let simulation_key = Key::random(&mut rng);

    println!("Starting Server1 and Server2...");

    // Spawn Server2 task 
    let s2_handle = tokio::spawn({
        let cert_path = cert_path.to_string();
        let key_path = key_path.to_string();
        async move {
            println!("Server2 starting...");
            Server2::run_server_with_simulation(
                s2_client_addr,
                s2_s1_addr, 
                &cert_path,
                &key_path,
                simulation_key.clone(),
            ).await
        }
    });

    time::sleep(Duration::from_secs(1)).await;

    let simulation_key = Key::random(&mut rng);


    // Spawn Server1 task
    let s1_handle = tokio::spawn({
        let cert_path = cert_path.to_string();
        let key_path = key_path.to_string();
        async move {
            println!("Server1 starting...");
            println!("Initializing {} simulation clients...", NUM_CLIENTS);
            Server1::run_server_with_simulation(
                s1_addr,
                &cert_path,
                &key_path,
                simulation_key.clone(),
            ).await
        }
    });


    // Wait for both servers
    let (s1_result, s2_result) = tokio::join!(s1_handle, s2_handle);
    s1_result.unwrap()?;
    s2_result.unwrap()?;

    println!("Server1 and Server2 finished");

    Ok(())
}
