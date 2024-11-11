#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_assignments)]
#![allow(unused_must_use)]
#![allow(dead_code)]
#![allow(unused_parens)]
#![allow(private_bounds)]

use myco_rs::{
    client::Client, constants::{BATCH_SIZE, DELTA, LATENCY_BENCH_COUNT, MESSAGE_SIZE, NUM_CLIENTS}, dtypes::Key, network::{RemoteServer1Access, RemoteServer2Access}
};
#[cfg(feature = "perf-logging")]
use myco_rs::logging::calculate_and_append_averages;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::error::Error;
use tokio::{self};
use futures::future::join_all;



#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let binding1 = "https://127.0.0.1:3001".to_string();
    let binding2 = "https://127.0.0.1:3003".to_string();
    let s1_addr = args.get(1).unwrap_or(&binding1);
    let s2_addr = args.get(2).unwrap_or(&binding2);

    let mut rng = ChaCha20Rng::from_entropy();

    // Generate BATCH_SIZE different random keys
    let mut simulation_keys = Vec::with_capacity(128);
    for _ in 0..128 {
        simulation_keys.push(Key::random(&mut rng));
    }

    // Initialize a single client instead of multiple
    let client_name = "SimClient_0".to_string();
    let s1_access = Box::new(RemoteServer1Access::new(s1_addr).await?);
    let s2_access = Box::new(RemoteServer2Access::new(s2_addr).await?);
    let mut simulation_client = Client::new(client_name, s1_access, s2_access);
    for key in simulation_keys.iter() {
        simulation_client.setup(key)?;
    }

    // Run the measurement iterations directly
    println!("\nStarting measurement phase...");
    for iteration in 0..LATENCY_BENCH_COUNT {
        println!("\nMeasurement iteration {}/{}", iteration + 1, LATENCY_BENCH_COUNT);
        
        {        
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)  // Only for development
                .pool_idle_timeout(Some(std::time::Duration::from_secs(300))) // Keep connections alive
                .tcp_keepalive(Some(std::time::Duration::from_secs(60)))      // Enable TCP keepalive
                .build()?;

            let request = myco_rs::rpc_types::BatchInitRequest {
                num_writes: NUM_CLIENTS,
            };
            let request_bytes = bincode::serialize(&request).unwrap();
            
            let response = client
                .post(format!("{}/batch_init", s1_addr))
                .header("Content-Type", "application/octet-stream")
                .body(request_bytes)
                .send()
                .await?;

            let response_bytes = response.bytes().await?;
            
            let response: myco_rs::rpc_types::BatchInitResponse =
                bincode::deserialize(&response_bytes).unwrap();
            assert!(response.success);

            // Process the single client
            let message = vec![1u8; 16];
            let random_index = rng.gen_range(0..128);
            if let Err(e) = simulation_client.async_write(&message, &simulation_keys[random_index]).await {
                eprintln!("Error in client write: {:?}", e);
            }

            let response = client
                .get(format!("{}/batch_write", s1_addr))
                .send()
                .await?;
            let response_bytes = response.bytes().await?;
            
            let response: myco_rs::rpc_types::BatchWriteResponse =
                bincode::deserialize(&response_bytes).unwrap();
            assert!(response.success);

            // Process the single client for reading
            let batch_sizes = vec![1, 16, 64, 128];
            
            for batch_size in batch_sizes {
                let simulation_keys_subset = simulation_keys[0..batch_size].to_vec();
                
                println!("Server1: Reading from client 0 with batch_size {}", batch_size);
                let res = simulation_client
                    .async_read(simulation_keys_subset, simulation_client.id.clone(), 0, batch_size)
                    .await;
                println!("Read messages: {:?}", res.unwrap());
            }
        }
    }

    // Add this section at the end of main, before calculate_and_append_averages
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    // Finalize Server1 benchmark
    let response = client
        .post(format!("{}/finalize_benchmark", s1_addr))
        .send()
        .await?;
    assert!(response.status().is_success());

    // Finalize Server2 benchmark
    let response = client
        .post(format!("{}/finalize_benchmark", s2_addr))
        .send()
        .await?;
    assert!(response.status().is_success());

    // Calculate client averages
    #[cfg(feature = "perf-logging")]
    calculate_and_append_averages("client_latency.csv", "client_bytes.csv");
    Ok(())
}
