use myco_rs::{
    client::Client,
    constants::{BATCH_SIZE, DELTA, NUM_CLIENTS},
    dtypes::Key,
    network::{RemoteServer1Access, RemoteServer2Access},
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::error::Error;
use tokio::{self};
use myco_rs::logging::{initialize_logging};
use futures::future::join_all;



#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let binding1 = "http://127.0.0.1:3001".to_string();
    let binding2 = "http://127.0.0.1:3002".to_string();
    let s1_addr = args.get(1).unwrap_or(&binding1);
    let s2_addr = args.get(2).unwrap_or(&binding2);

    let mut rng = ChaCha20Rng::from_entropy();

    // Generate BATCH_SIZE different random keys
    let mut simulation_keys = Vec::with_capacity(BATCH_SIZE);
    for _ in 0..BATCH_SIZE {
        simulation_keys.push(Key::random(&mut rng));
    }
    // Initialize a bunch of clients.
    let mut simulation_clients = Vec::new();
    for i in 0..NUM_CLIENTS {
        let client_name = format!("SimClient_{}", i);
        let s1_access = Box::new(RemoteServer1Access::new(s1_addr).await?);
        let s2_access = Box::new(RemoteServer2Access::new(s2_addr).await?);
        let mut client = Client::new(client_name, s1_access, s2_access);
        for key in simulation_keys.iter() {
            client.setup(key)?;
        }
        simulation_clients.push(client);
    }

    for i in 0..1000 {
        println!("Starting epoch: {}", i);
        let client = reqwest::Client::new();
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

        // Check that the batch init was successful
        let response_bytes = response.bytes().await?;
        let response: myco_rs::rpc_types::BatchInitResponse =
            bincode::deserialize(&response_bytes).unwrap();
        assert!(response.success);

        let mut clients = simulation_clients.iter_mut();
        let write_futures = clients.enumerate().map(|(i, client)| {
            let message = vec![1u8; 16];
            let simulation_keys_clone = simulation_keys.clone();
            let random_index = rng.gen_range(0..BATCH_SIZE);
            async move {
                println!("Server1: Writing from client {}", i);
                if let Err(e) = client.async_write(&message, &simulation_keys_clone[random_index]).await {
                    eprintln!("Error in client write: {:?}", e);
                }
            }
        });

        // Run all write operations in parallel
        join_all(write_futures).await;

        println!("Server1: Batch write to Server1");

        // Batch write to Server1
        let response = client
            .get(format!("{}/batch_write", s1_addr))
            .send()
            .await?;
        let response_bytes = response.bytes().await?;
        let response: myco_rs::rpc_types::BatchWriteResponse =
            bincode::deserialize(&response_bytes).unwrap();
        assert!(response.success);

        // // Client should be able to get the prf keys
        let mut clients = simulation_clients.iter_mut();
        for (i, client) in clients.enumerate() {
            println!("Server1: Reading from client {}", i);
            let res = client
                .async_read(simulation_keys.clone(), client.id.clone(), 0)
                .await;
            if let Ok(data) = res {
                println!("Server1: Client {} read: {:?}", i, data);
            } else {
                eprintln!("Error in client read: {:?}", res);
            }
        }
    }

    // Initialize logging for the final iteration
    initialize_logging("final_iteration_latency.csv", "final_iteration_bytes.csv");

    // Run one final iteration with logging enabled
    {        
        let client = reqwest::Client::new();

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

        let mut clients = simulation_clients.iter_mut();
        for (i, client) in clients.enumerate() {
            let message = vec![1u8; 16];
            // Choose a random index from 0 to batchsize and write to that client
            let random_index = rng.gen_range(0..BATCH_SIZE);
            if let Err(e) = client.async_write(&message, &simulation_keys[random_index]).await {
                eprintln!("Error in client write: {:?}", e);
            }
        }

        let response = client
            .get(format!("{}/batch_write", s1_addr))
            .send()
            .await?;
        let response_bytes = response.bytes().await?;
        
        let response: myco_rs::rpc_types::BatchWriteResponse =
            bincode::deserialize(&response_bytes).unwrap();
        assert!(response.success);

        let mut clients = simulation_clients.iter_mut();
        for (i, client) in clients.enumerate() {
            let simulation_keys_clone = simulation_keys.clone();

            println!("Server1: Reading from client {}", i);
            // Generate BATCH_SIZE different random keys
            let res = client
                .async_read(simulation_keys_clone, client.id.clone(), 0)
                .await;
            if let Ok(data) = res {
                println!("Server1: Client {} read: {:?}", i, data);
            } else {
                eprintln!("Error in client read: {:?}", res);
            }
        }
    }

    Ok(())
}
