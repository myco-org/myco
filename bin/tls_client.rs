use myco_rs::{
    client::Client,
    dtypes::Key,
    network::{RemoteServer1Access, RemoteServer2Access},
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::Instant;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting test client...");
    
    // Create connections
    let server2_conn = RemoteServer2Access::connect("localhost:8443", "certs/server-cert.pem").await?;
    let server1_conn = RemoteServer1Access::connect("localhost:8420", "certs/server-cert.pem").await?;

    // Create client
    let mut client = Client::new(
        "TestClient".to_string(),
        Box::new(server1_conn),
        Box::new(server2_conn),
    );

    let mut rng = ChaCha20Rng::from_entropy();
    let key = Key::random(&mut rng);
    
    println!("Setting up client...");
    client.setup(&key)?;

    // Prepare test message
    let test_message = vec![1, 2, 3, 4];

    println!("Beginning latency test...");
    
    // Measure write latency
    let write_start = Instant::now();
    client.write(&test_message, &key)?;
    let write_duration = write_start.elapsed();

    // Measure read latency
    let read_start = Instant::now();
    let read_result = client.read(&key, "TestClient".to_string(), 0)?;
    let read_duration = read_start.elapsed();

    println!("\nLatency Test Results:");
    println!("Write latency: {:?}", write_duration);
    println!("Read latency: {:?}", read_duration);
    println!("Total round-trip latency: {:?}", write_duration + read_duration);
    println!("Read result: {:?}", read_result);

    Ok(())
}