use std::{process::Command, sync::{Arc, Mutex}};
use clap::Parser;
use myco_rs::{constants::{D, DELTA, NUM_WRITES_PER_EPOCH, Z}, dtypes::Key, server1::Server1, server2::Server2};
use rand::{Rng, SeedableRng};

use rand_chacha::ChaCha20Rng;
use rayon::iter::IntoParallelRefIterator;
use tree::{save_trees, DBStateParams};

use std::time::Duration;
use myco_rs::*;


#[derive(Debug, Clone, Parser)]
struct Args {
    #[clap(default_value_t = Z)]
    bucket_size: usize,
    #[clap(default_value_t = DELTA)]
    iters: usize,
    #[clap(default_value_t = D)]
    depth: usize,
    #[clap(default_value_t = NUM_WRITES_PER_EPOCH)]
    num_clients: usize,
}

impl Into<DBStateParams> for Args {
    fn into(self) -> DBStateParams {
        DBStateParams { bucket_size: self.bucket_size, num_iters: self.iters, depth: self.depth, num_clients: self.num_clients, timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() }
    }
}

/// Runs the Myco protocol simulation.
fn main() {

    // Arguments for parametetrizing the protocol.
    let simulation_args = Args::parse();

    let num_clients = simulation_args.num_clients;
    let num_epochs = simulation_args.iters;

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
        for client in clients.iter_mut() {
            let message: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
            if let Err(e) = client.write(&message, &key) {
                panic!("Write failed in epoch {}: {:?}", epoch, e);
            }
        }
        let write_duration = write_start_time.elapsed();

        // Measure batch_write latency
        let batch_write_start_time = std::time::Instant::now();
        s1.lock().unwrap().batch_write();
        let batch_write_duration = batch_write_start_time.elapsed();

        // Measure read latency for each client
        let mut total_read_duration = Duration::new(0, 0);
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

        calculate_bucket_usage(&s2.lock().unwrap().tree, &s1.lock().unwrap().metadata, &k_msg);
    }

    // After all epochs, print the total duration and final average duration
    let final_average_duration = total_duration / successful_epochs as u32;
    println!(
        "All epochs completed successfully. Total duration: {:?}, average duration: {:?}",
        total_duration, final_average_duration
    );

    save_trees(&s2.lock().unwrap().tree, &s1.lock().unwrap().metadata, &simulation_args.into());
}
