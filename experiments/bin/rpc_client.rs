use myco::constants::{LATENCY_BENCH_COUNT, MESSAGE_SIZE, Q, WARMUP_COUNT};
use myco::dtypes::Key;
use myco::logging::calculate_and_append_averages;
use myco::{
    client::Client,
    network::{server1::RemoteServer1Access, server2::RemoteServer2Access},
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::error::Error;
use tokio;
use myco::utils::build_tls_channel;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static ALLOCATOR: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let s1_addr = args.get(1)
        .map(|addr| if !addr.starts_with("https://") { format!("https://{}", addr) } else { addr.clone() })
        .unwrap_or("https://localhost:3002".to_string());
    let s2_addr = args.get(2)
        .map(|addr| if !addr.starts_with("https://") { format!("https://{}", addr) } else { addr.clone() })
        .unwrap_or("https://localhost:3004".to_string());

    println!("Connecting to Server1 at: {}", s1_addr);
    println!("Connecting to Server2 at: {}", s2_addr);

    let s1_channel = build_tls_channel(&s1_addr).await?;
    let s1_access = Box::new(RemoteServer1Access::from_channel(s1_channel));
    
    let s2_access = Box::new(RemoteServer2Access::new(&s2_addr).await?);

    let mut rng = ChaCha20Rng::from_entropy();

    let client_name = "SimClient_0".to_string();

    let mut simulation_client = Client::new(client_name.clone(), s1_access, s2_access, myco::constants::NUM_CLIENTS);

    let contact_list = (0..Q).map(|i| format!("SimClient_{}", i)).collect::<Vec<_>>();
    let key_list = (0..Q).map(|_| Key::random(&mut rng)).collect::<Vec<_>>();

    simulation_client.setup(key_list, contact_list)?;

    println!("\nStarting warm-up phase ({} iterations)...", WARMUP_COUNT);
    for iteration in 0..WARMUP_COUNT {
        println!("\nWarm-up iteration {}/{}", iteration + 1, WARMUP_COUNT);
        
        simulation_client.s1.batch_init().await?;
        let message = vec![1u8; MESSAGE_SIZE];
        simulation_client.async_write(&message, &client_name).await?;
        simulation_client.s1.batch_write().await?;
        let messages = simulation_client.async_read(Some(1)).await?;
        
        println!("Read messages: {:?}", messages);
    }

    println!("\nStarting measurement phase ({} iterations)...", LATENCY_BENCH_COUNT);
    let mut latencies = Vec::new();
    
    for iteration in 0..LATENCY_BENCH_COUNT {
        println!("\nMeasurement iteration {}/{}", iteration + 1, LATENCY_BENCH_COUNT);
        
        let start = std::time::Instant::now();

        let batch_init_start = std::time::Instant::now();
        simulation_client.s1.batch_init().await?;
        let batch_init_duration = batch_init_start.elapsed().as_secs_f64() * 1000.0;

        let write_start = std::time::Instant::now();
        let message = vec![1u8; MESSAGE_SIZE];
        simulation_client.async_write(&message, &client_name).await?;
        simulation_client.s1.batch_write().await?;
        let write_duration = write_start.elapsed().as_secs_f64() * 1000.0;

        let read_start = std::time::Instant::now();
        let messages = simulation_client.async_read(Some(1)).await?;
        let read_duration = read_start.elapsed().as_secs_f64() * 1000.0;
        
        let duration = start.elapsed().as_secs_f64() * 1000.0;
        latencies.push(duration);
        
        println!("Read messages: {:?}", messages);
        println!("Step durations:");
        println!("  Batch init: {:.2}ms", batch_init_duration);
        println!("  Write: {:.2}ms", write_duration);
        println!("  Read: {:.2}ms", read_duration);
        println!("Total iteration latency: {:.2}ms", duration);
    }

    if !latencies.is_empty() {
        let avg_latency = latencies.iter().sum::<f64>() / latencies.len() as f64;
        let min_latency = latencies.iter().fold(f64::INFINITY, |a, &b| a.min(b));
        let max_latency = latencies.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
        
        println!("\nLatency Statistics (ms):");
        println!("  Average: {:.2}", avg_latency);
        println!("  Min: {:.2}", min_latency);
        println!("  Max: {:.2}", max_latency);
        println!("  Total iterations: {}", latencies.len());
        calculate_and_append_averages("client_latency.csv", "client_bytes.csv");
    }
    Ok(())
}
