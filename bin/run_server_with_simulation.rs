use myco_rs::{
    client::Client,
    constants::{DELTA, NUM_CLIENTS},
    dtypes::Key,
    network::{Command, RemoteServer1Access, RemoteServer2Access},
    server1::Server1,
    server2::Server2,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::{error::Error, time::Duration};
use tokio::{self, time};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let s1_addr = "http://127.0.0.1:3001";
    let s2_addr = "http://127.0.0.1:3002";

    let mut rng = ChaCha20Rng::from_entropy();
    let simulation_key = Key::random(&mut rng);
    // Initialize a bunch of clients.
    let mut simulation_clients = Vec::new();
    for i in 0..NUM_CLIENTS {
        let client_name = format!("SimClient_{}", i);
        let s1_access = Box::new(RemoteServer1Access::new(s1_addr).await?);
        let s2_access = Box::new(RemoteServer2Access::new(s2_addr).await?);
        let mut client = Client::new(client_name, s1_access, s2_access);
        client.setup(&simulation_key)?;
        simulation_clients.push(client);
    }

    for i in 0..DELTA {
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
        for (i, client) in clients.enumerate() {
            println!("Server1: Writing from client {}", i);
            let message = vec![1u8; 16];
            if let Err(e) = client.async_write(&message, &simulation_key).await {
                eprintln!("Error in client write: {:?}", e);
            }
        }

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

        // Client should be able to get the prf keys
        let mut clients = simulation_clients.iter_mut();
        for (i, client) in clients.enumerate() {
            println!("Server1: Reading from client {}", i);
            let res = client
                .async_read(&simulation_key, client.id.clone(), 0)
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
