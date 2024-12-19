#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_assignments)]
#![allow(unused_must_use)]
#![allow(dead_code)]
#![allow(unused_parens)]
#![allow(private_bounds)]

use myco_rs::{
    client::Client, constants::{DB_SIZE, DELTA, NUM_CLIENTS}, dtypes::{Key, ServerType}, error::MycoError, network::{LocalServer1Access, LocalServer2Access}, server1::Server1, server2::Server2, utils::calculate_bucket_usage
};
use rand::{Rng, SeedableRng};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use std::fs::create_dir_all;
use std::sync::RwLock;
use std::{
    process::Command,
    sync::{Arc, Mutex},
};
use std::io::Write;

fn run_multi_client_simulation(num_clients: usize, num_epochs: usize) {
    use rand_chacha::ChaCha20Rng;
    use std::time::Duration;

    let s2 = Arc::new(Mutex::new(Server2::new()));
    let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
    let s1 = Arc::new(RwLock::new(Server1::new(s2_access.clone(), ServerType::Sync)));
    let s1_access = Box::new(LocalServer1Access { server: s1.clone() });

    let mut rng = ChaCha20Rng::from_entropy();
    let mut clients = Vec::new();

    let mut total_duration: Duration = Duration::new(0, 0);
    let mut successful_epochs = 0;
    let mut k_msg: Vec<u8> = Vec::new();
    let key = Key::random(&mut rng);
    for i in 0..num_clients {
        let client_name = format!("Client_{}", i);
        let mut client = Client::new(client_name, s1_access.clone(), s2_access.clone());

        client.setup(&key).map_err(|e| MycoError::DatabaseError(format!("Setup failed: {}", e))).unwrap();

        clients.push(client);
    }
    k_msg = clients[0].keys.get(&key).unwrap().0.clone();

    // Perform multiple epochs
    for epoch in 0..num_epochs {
        println!("Starting epoch: {}", epoch);

        // Measure batch_init latency
        let epoch_start_time = std::time::Instant::now();
        let batch_init_start_time = std::time::Instant::now();
        s1.write().unwrap().batch_init(num_clients);
        let batch_init_duration = batch_init_start_time.elapsed();

        // Measure write latency
        let write_start_time = std::time::Instant::now();
        clients.par_iter_mut().for_each(|client| {
            let message: Vec<u8> = (0..16).map(|_| rng.clone().gen()).collect();
            #[cfg(feature = "no-enc")]
            client.fake_write().map_err(|e| MycoError::DatabaseError(format!("Write failed: {}", e))).unwrap();
            #[cfg(not(feature = "no-enc"))]
            client.write(&message, &key).map_err(|e| MycoError::DatabaseError(format!("Write failed: {}", e))).unwrap();
        });
        let write_duration = write_start_time.elapsed();

        // Measure batch_write latency
        let batch_write_start_time = std::time::Instant::now();
        s1.write().unwrap().batch_write();
        let batch_write_duration = batch_write_start_time.elapsed();

        // Measure read latency for each client.
        let mut total_read_duration = Duration::new(0, 0);
        // Note: These operations are on the order of microseconds.
        for client in clients.iter() {
            let read_start_time = std::time::Instant::now();
            let read_result: Vec<u8> = client
                .read(&key, client.id.clone(), 0)
                .map_err(|e| MycoError::DatabaseError(format!("Read failed: {}", e))).unwrap();
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

fn run_simulation(num_epochs: usize) {
    use rand_chacha::ChaCha20Rng;
    use std::time::Duration;

    let s2 = Arc::new(Mutex::new(Server2::new()));
    let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
    let s1 = Arc::new(RwLock::new(Server1::new(s2_access.clone(), ServerType::Sync)));
    let s1_access = Box::new(LocalServer1Access { server: s1.clone() });

    let mut rng = ChaCha20Rng::from_entropy();
    let mut total_duration: Duration = Duration::new(0, 0);
    let mut successful_epochs = 0;
    let key = Key::random(&mut rng);
    // Setup multiple clients
    let mut clients = Vec::new();
    for i in 0..NUM_CLIENTS {
        let mut client = Client::new(format!("Client_{}", i), s1_access.clone(), s2_access.clone());
        client.setup(&key).map_err(|e| MycoError::DatabaseError(format!("Setup failed: {}", e))).unwrap();
        clients.push(client);
    }

    // Track bucket usage statistics over time
    let check_interval = 1000 as usize;
    let usage_stats: Vec<(usize, usize, f64, f64, f64)> = Vec::new();
    let k_msg = clients[0].keys.get(&key).unwrap().0.clone();

    // Perform multiple epochs
    for epoch in 0..num_epochs {
        let epoch_start_time = std::time::Instant::now();

        // Multi-client batch_init
        let batch_init_start_time = std::time::Instant::now();
        s1.write().unwrap().batch_init(NUM_CLIENTS);
        let batch_init_duration = batch_init_start_time.elapsed();

        // Multiple writes
        let write_start_time = std::time::Instant::now();
        clients.par_iter_mut().for_each(|client| {
            let message: Vec<u8> = (0..16).map(|_| rng.clone().gen()).collect();
            #[cfg(feature = "no-enc")]
            client.fake_write().map_err(|e| MycoError::DatabaseError(format!("Write failed: {}", e))).unwrap();
            #[cfg(not(feature = "no-enc"))]
            client.write(&message, &key).map_err(|e| MycoError::DatabaseError(format!("Write failed: {}", e))).unwrap();
        });
        let write_duration = write_start_time.elapsed();

        // Batch write
        let batch_write_start_time = std::time::Instant::now();
        s1.write().unwrap().batch_write();
        let batch_write_duration = batch_write_start_time.elapsed();

        // Calculate durations
        let epoch_duration = epoch_start_time.elapsed();
        total_duration += epoch_duration;
        successful_epochs += 1;


        // // Calculate bucket usage at specified intervals
        // if (epoch + 1) % check_interval == 0 {
        //     println!("Calculating bucket usage at epoch {}...", epoch);
        //     let stats = calculate_bucket_usage(
        //         &s2.lock().unwrap().tree,
        //         &s1.read().unwrap().metadata,
        //         &k_msg,
        //     );
        //     usage_stats.push(stats);

        //     // Create directory if it doesn't exist
        //     create_dir_all("bucket_usage_sims").expect("Failed to create directory");

        //     // Open file in append mode
        //     let filename = format!("bucket_usage_sims/bucket_usage1_{}_{}", DELTA, NUM_CLIENTS);
        //     let mut file = std::fs::OpenOptions::new()
        //         .create(true)
        //         .append(true)
        //         .open(filename)
        //         .expect("Failed to open file");

        //     // Write the stats
        //     writeln!(
        //         file,
        //         "{}\t{}\t{}\t{:.2}\t{:.2}\t{:.2}",
        //         epoch + 1,
        //         stats.0,  // max_usage
        //         stats.1,  // max_depth
        //         stats.2,  // avg_usage
        //         stats.3,  // median_usage
        //         stats.4   // std_dev
        //     ).expect("Failed to write to file");
        // }
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
    for (i, (max_usage, max_depth, avg_usage, median_usage, std_dev)) in
        usage_stats.iter().enumerate()
    {
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
    let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
    let s1 = Arc::new(RwLock::new(Server1::new(s2_access.clone(), ServerType::Sync)));
    let s1_access = Box::new(LocalServer1Access { server: s1.clone() });

    let mut rng = ChaCha20Rng::from_entropy();

    // Setup multiple clients
    let mut clients = Vec::new();
    let mut keys = Vec::new();
    for i in 0..NUM_CLIENTS {
        let key = Key::random(&mut rng);
        let mut client = Client::new(
            format!("Client_{}", i),
            s1_access.clone(),
            s2_access.clone(),
        );
        client.setup(&key).map_err(|e| MycoError::DatabaseError(format!("Setup failed: {}", e))).unwrap();
        keys.push(key);
        clients.push(client);
    }

    println!("Starting benchmark: Performing {} epochs...", DELTA);

    // Perform DELTA epochs instead of DB_SIZE
    for epoch in 0..DELTA {
        println!("Epoch: {}/{}", epoch, DELTA);

        s1.write().unwrap().batch_init(NUM_CLIENTS);

        // Have each client perform a write
        clients
            .iter_mut()
            .zip(keys.iter())
            .enumerate()
            .for_each(|(client_idx, (client, key))| {
                let message: Vec<u8> = (0..16).map(|_| rng.clone().gen()).collect();
                #[cfg(feature = "no-enc")]
                client.fake_write().map_err(|e| MycoError::DatabaseError(format!("Write failed: {}", e))).unwrap();
                #[cfg(not(feature = "no-enc"))]
                client.write(&message, key).map_err(|e| MycoError::DatabaseError(format!("Write failed: {}", e))).unwrap();

                if (epoch * NUM_CLIENTS + client_idx) % 1000 == 0 {
                    println!("Progress: Write {} in epoch {}", client_idx, epoch);
                }
            });

        s1.write().unwrap().batch_write();
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
        s1.write().unwrap().batch_init(NUM_CLIENTS);
        batch_init_times.push(start.elapsed());

        // Measure write
        let start = std::time::Instant::now();
        let message: Vec<u8> = (0..16).map(|_| rng.clone().gen()).collect();
        #[cfg(feature = "no-enc")]
        clients[0].fake_write().map_err(|e| MycoError::DatabaseError(format!("Write failed: {}", e))).unwrap();
        #[cfg(not(feature = "no-enc"))]
        clients[0].write(&message, &keys[0]).map_err(|e| MycoError::DatabaseError(format!("Write failed: {}", e))).unwrap();
        write_times.push(start.elapsed());

        // Measure batch_write
        let start = std::time::Instant::now();
        s1.write().unwrap().batch_write();
        batch_write_times.push(start.elapsed());

        // Measure read
        let start = std::time::Instant::now();
        clients[0]
            .read(&keys[0], clients[0].id.clone(), 0)
            .map_err(|e| MycoError::DatabaseError(format!("Read failed: {}", e))).unwrap();
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
    create_dir_all("test_sims").map_err(|e| MycoError::DatabaseError(format!("Failed to create directory: {}", e))).unwrap();

    // Open file for writing
    let mut file = File::create("test_sims/latency").map_err(|e| MycoError::DatabaseError(format!("Failed to create latency file: {}", e))).unwrap();


    // Write results to file
    writeln!(file, "Average timings over 10 sequences:").unwrap();
    writeln!(file, "Batch Init:  {:?}", avg_batch_init).unwrap();
    writeln!(file, "Write:       {:?}", avg_write).unwrap();
    writeln!(file, "Batch Write: {:?}", avg_batch_write).unwrap();
    writeln!(file, "Read:        {:?}", avg_read).unwrap();
    writeln!(
        file,
        "Total Avg:   {:?}",
        avg_batch_init + avg_write + avg_batch_write + avg_read
    )
    .unwrap();

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
        "sim" => run_simulation(DELTA*DELTA*DELTA),
        "multi" => run_multi_client_simulation(NUM_CLIENTS, DELTA),
        "benchmark" => run_local_latency_benchmark(),
        _ => panic!("Unknown simulation type. Use: single, multi, or benchmark"),
    }
}
