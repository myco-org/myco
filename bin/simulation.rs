#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_assignments)]
#![allow(unused_must_use)]
#![allow(dead_code)]
#![allow(unused_parens)]
#![allow(private_bounds)]

use myco_rs::{
    calculate_bucket_usage, constants::{DELTA, NUM_WRITES_PER_EPOCH}, dtypes::Key, server1::Server1, server2::Server2, Client
};
use rand::{Rng, SeedableRng};
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};
use std::{
    process::Command,
    sync::{Arc, Mutex},
};

fn run_multi_client_simulation(num_clients: usize, num_epochs: usize) {
    use rand_chacha::ChaCha20Rng;
    use std::time::Duration;

    let s2 = Arc::new(Mutex::new(Server2::new()));
    let s1 = Arc::new(Mutex::new(Server1::new(s2.clone())));

    let mut rng = ChaCha20Rng::from_entropy();
    let mut clients = Vec::new();

    let mut total_duration: Duration = Duration::new(0, 0);
    let mut successful_epochs = 0;
    let mut k_msg: Vec<u8> = Vec::new();
    let key = Key::random(&mut rng);
    for i in 0..num_clients {
        let client_name = format!("Client_{}", i);
        let mut client = Client::new(client_name, s1.clone(), s2.clone());

        client.setup(&key).expect("Setup failed");

        clients.push(client);
    }
    k_msg = clients[0].keys.get(&key).unwrap().0.clone();

    // Perform multiple epochs
    for epoch in 0..num_epochs {
        println!("Starting epoch: {}", epoch);

        // Measure batch_init latency
        let epoch_start_time = std::time::Instant::now();
        let batch_init_start_time = std::time::Instant::now();
        s1.lock().unwrap().batch_init(num_clients);
        let batch_init_duration = batch_init_start_time.elapsed();

        // Measure write latency
        let write_start_time = std::time::Instant::now();
        clients.iter_mut().for_each(|client| {
            let message: Vec<u8> = (0..16).map(|_| rng.clone().gen()).collect();
            #[cfg(feature = "no-enc")]
            client.fake_write().expect("Write failed");
            #[cfg(not(feature = "no-enc"))]
            client.write(&message, &key).expect("Write failed");
        });
        let write_duration = write_start_time.elapsed();

        // Measure batch_write latency
        let batch_write_start_time = std::time::Instant::now();
        s1.lock().unwrap().batch_write();
        let batch_write_duration = batch_write_start_time.elapsed();

        // Measure read latency for each client.
        let mut total_read_duration = Duration::new(0, 0);
        // Note: These operations are on the order of microseconds.
        for client in clients.iter() {
            let read_start_time = std::time::Instant::now();
            let read_result: Vec<u8> = client
                .read(&key, client.id.clone(), 0)
                .expect(&format!("Read failed in epoch {}", epoch));
            let client_read_duration = read_start_time.elapsed();
            total_read_duration += client_read_duration;
        }

        // Calculate average read duration across all clients in this epoch
        let average_read_duration = total_read_duration / num_clients as u32;

        // Measure total duration
        let epoch_duration = epoch_start_time.elapsed();
        total_duration += epoch_duration;
        successful_epochs += 1;

        // Print the duration of the current epoch and its phases
        println!(
            "Epoch {} completed in {:?} (batch_init: {:?}, write: {:?}, batch_write: {:?}, avg client read: {:?})",
            epoch, epoch_duration, batch_init_duration, write_duration, batch_write_duration, average_read_duration
        );

        // Calculate the average duration so far
        let average_duration = total_duration / successful_epochs as u32;

        // Print cumulative duration and average duration so far
        println!(
            "Total duration so far: {:?}, average duration so far: {:?}",
            total_duration, average_duration
        );
    }

    // After all epochs, print the total duration and final average duration
    let final_average_duration = total_duration / successful_epochs as u32;
    println!(
        "All epochs completed successfully. Total duration: {:?}, average duration: {:?}",
        total_duration, final_average_duration
    );
}

fn run_single_client_simulation(num_epochs: usize) {
    use rand_chacha::ChaCha20Rng;
    use std::time::Duration;

    let s2 = Arc::new(Mutex::new(Server2::new()));
    let s1 = Arc::new(Mutex::new(Server1::new(s2.clone())));

    let mut rng = ChaCha20Rng::from_entropy();
    let mut total_duration: Duration = Duration::new(0, 0);
    let mut successful_epochs = 0;

    // Setup single client
    let key = Key::random(&mut rng);
    let mut client = Client::new("Client_0".to_string(), s1.clone(), s2.clone());
    client.setup(&key).expect("Setup failed");

    // Track bucket usage statistics over time
    let check_interval = 100000 as usize;
    let mut usage_stats: Vec<(usize, usize, f64, f64, f64)> = Vec::new();
    let k_msg = client.keys.get(&key).unwrap().0.clone();

    // Perform multiple epochs
    for epoch in 0..num_epochs {
        println!("Starting epoch: {}", epoch);

        let epoch_start_time = std::time::Instant::now();
        
        // Single client batch_init
        let batch_init_start_time = std::time::Instant::now();
        s1.lock().unwrap().batch_init(1);
        let batch_init_duration = batch_init_start_time.elapsed();

        // Single write
        let write_start_time = std::time::Instant::now();
        let message: Vec<u8> = (0..16).map(|_| rng.clone().gen()).collect();
        #[cfg(feature = "no-enc")]
        client.fake_write().expect("Write failed");
        #[cfg(not(feature = "no-enc"))]
        client.write(&message, &key).expect("Write failed");
        let write_duration = write_start_time.elapsed();

        // Batch write
        let batch_write_start_time = std::time::Instant::now();
        s1.lock().unwrap().batch_write();
        let batch_write_duration = batch_write_start_time.elapsed();

        // Calculate durations
        let epoch_duration = epoch_start_time.elapsed();
        total_duration += epoch_duration;
        successful_epochs += 1;

        println!(
            "Epoch {} completed in {:?} (batch_init: {:?}, write: {:?}, batch_write: {:?})",
            epoch, epoch_duration, batch_init_duration, write_duration, batch_write_duration,
        );

        println!(
            "Total duration so far: {:?}, average duration: {:?}",
            total_duration,
            total_duration / successful_epochs as u32
        );

        // Calculate bucket usage at specified intervals
        if (epoch + 1) % check_interval == 0 {
            println!("Calculating bucket usage at epoch {}...", epoch);
            let stats = calculate_bucket_usage(
                &s2.lock().unwrap().tree,
                &s1.lock().unwrap().metadata,
                &k_msg
            );
            usage_stats.push(stats);
        }
    }

    println!(
        "All epochs completed successfully. Total duration: {:?}, average duration: {:?}",
        total_duration,
        total_duration / successful_epochs as u32
    );

    // Print all bucket usage statistics
    println!("\nBucket Usage Statistics Over Time:");
    println!("Epoch\tMax Usage\tMax Depth\tAvg Usage\tMedian Usage\tStd Dev");
    println!("---------------------------------------------------------------------");
    for (i, (max_usage, max_depth, avg_usage, median_usage, std_dev)) in usage_stats.iter().enumerate() {
        println!(
            "{}\t{}\t\t{}\t\t{:.2}\t\t{:.2}\t\t{:.2}",
            (i + 1) * check_interval,
            max_usage,
            max_depth,
            avg_usage,
            median_usage,
            std_dev
        );
    }
}

fn main() {
    #[cfg(feature = "no-enc")]
    println!("Running simulation in NO ENCRYPTION mode");
    
    #[cfg(not(feature = "no-enc"))]
    println!("Running simulation in STANDARD ENCRYPTION mode");

    let simulation_type = "single"; // or "multi"
    
    match simulation_type {
        "single" => run_single_client_simulation(100000000),
        "multi" => run_multi_client_simulation(NUM_WRITES_PER_EPOCH, DELTA),
        _ => panic!("Unknown simulation type"),
    }
}
