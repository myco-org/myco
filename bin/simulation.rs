#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_assignments)]
#![allow(unused_must_use)]
#![allow(dead_code)]
#![allow(unused_parens)]
#![allow(private_bounds)]

use myco_rs::{
    calculate_bucket_usage, constants::{DELTA, NUM_WRITES_PER_EPOCH, DB_SIZE}, dtypes::Key, server1::Server1, server2::Server2, Client
};
use rand::{Rng, SeedableRng};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator};
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
        println!("========== Starting epoch: {} ==========", epoch);

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

        // Read
        let read_start_time = std::time::Instant::now();
        let read_result: Vec<u8> = client
            .read(&key, client.id.clone(), 0)
            .expect(&format!("Read failed in epoch {}", epoch));
        let read_duration = read_start_time.elapsed();

        // Calculate durations
        let epoch_duration = epoch_start_time.elapsed();
        total_duration += epoch_duration;
        successful_epochs += 1;

        println!(
            "Epoch {} completed in {:?} (batch_init: {:?}, write: {:?}, batch_write: {:?}, read: {:?})",
            epoch, epoch_duration, batch_init_duration, write_duration, batch_write_duration, read_duration,
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

fn run_local_latency_benchmark() {
    use rand_chacha::ChaCha20Rng;
    use std::time::Duration;

    let s2 = Arc::new(Mutex::new(Server2::new()));
    let s1 = Arc::new(Mutex::new(Server1::new(s2.clone())));

    let mut rng = ChaCha20Rng::from_entropy();

    // Setup multiple clients
    let mut clients = Vec::new();
    let mut keys = Vec::new();
    for i in 0..NUM_WRITES_PER_EPOCH {
        let key = Key::random(&mut rng);
        let mut client = Client::new(format!("Client_{}", i), s1.clone(), s2.clone());
        client.setup(&key).expect("Setup failed");
        keys.push(key);
        clients.push(client);
    }

    println!("Starting benchmark: Performing {} epochs...", DELTA);

    // Perform DELTA epochs instead of DB_SIZE
    for epoch in 0..DELTA {
        println!("Epoch: {}/{}", epoch, DELTA);

        s1.lock().unwrap().batch_init(NUM_WRITES_PER_EPOCH);
        
        // Have each client perform a write
        clients.par_iter_mut()
            .zip_eq(keys.par_iter())
            .enumerate()
            .for_each(|(client_idx, (client, key))| {
                let message: Vec<u8> = (0..16).map(|_| rng.clone().gen()).collect();
                #[cfg(feature = "no-enc")]
                client.fake_write().expect("Write failed");
                #[cfg(not(feature = "no-enc"))]
                client.write(&message, key).expect("Write failed");
                
                if (epoch * NUM_WRITES_PER_EPOCH + client_idx) % 1000 == 0 {
                    println!("Progress: Write {} in epoch {}", client_idx, epoch);
                }
            });
        
        s1.lock().unwrap().batch_write();
    }

    // Track timings for each operation
    let mut batch_init_times = Vec::new();
    let mut write_times = Vec::new();
    let mut batch_write_times = Vec::new();
    let mut read_times = Vec::new();

    // Perform 10 complete sequences
    for i in 0..10 {
        println!("\nSequence {}/10:", i + 1);

        // Measure batch_init
        let start = std::time::Instant::now();
        s1.lock().unwrap().batch_init(NUM_WRITES_PER_EPOCH);
        batch_init_times.push(start.elapsed());

        // Measure write
        let start = std::time::Instant::now();
        let message: Vec<u8> = (0..16).map(|_| rng.clone().gen()).collect();
        #[cfg(feature = "no-enc")]
        client.fake_write().expect("Write failed");
        #[cfg(not(feature = "no-enc"))]
        clients[0].write(&message, &keys[0]).expect("Write failed");
        write_times.push(start.elapsed());

        // Measure batch_write
        let start = std::time::Instant::now();
        s1.lock().unwrap().batch_write();
        batch_write_times.push(start.elapsed());

        // Measure read
        let start = std::time::Instant::now();
        clients[0].read(&keys[0], clients[0].id.clone(), 0).expect("Read failed");
        read_times.push(start.elapsed());
    }

    // Calculate and print averages
    let avg_batch_init = batch_init_times.iter().sum::<Duration>() / 10;
    let avg_write = write_times.iter().sum::<Duration>() / 10;
    let avg_batch_write = batch_write_times.iter().sum::<Duration>() / 10;
    let avg_read = read_times.iter().sum::<Duration>() / 10;

    // Replace the println statements with file writing
    use std::fs::{create_dir_all, File};
    use std::io::Write;

    // Create directory if it doesn't exist
    create_dir_all("test_sims").expect("Failed to create directory");

    // Open file for writing
    let mut file = File::create("test_sims/latency")
        .expect("Failed to create latency file");

    // Write results to file
    writeln!(file, "Average timings over 10 sequences:").unwrap();
    writeln!(file, "Batch Init:  {:?}", avg_batch_init).unwrap();
    writeln!(file, "Write:       {:?}", avg_write).unwrap();
    writeln!(file, "Batch Write: {:?}", avg_batch_write).unwrap();
    writeln!(file, "Read:        {:?}", avg_read).unwrap();
    writeln!(file, "Total Avg:   {:?}", avg_batch_init + avg_write + avg_batch_write + avg_read).unwrap();

    // Optional: Keep a terminal output for confirmation
    println!("Benchmark results have been written to test_sims/latency");
}

fn main() {
    #[cfg(feature = "no-enc")]
    println!("Running simulation in NO ENCRYPTION mode");
    
    #[cfg(not(feature = "no-enc"))]
    println!("Running simulation in STANDARD ENCRYPTION mode");

    let args: Vec<String> = std::env::args().collect();

    let simulation_type = &args[1];
    
    match simulation_type.as_str() {
        "single" => run_single_client_simulation(262144),
        "multi" => run_multi_client_simulation(NUM_WRITES_PER_EPOCH, DELTA),
        "benchmark" => run_local_latency_benchmark(),
        _ => panic!("Unknown simulation type. Use: single, multi, or benchmark"),
    }
}
