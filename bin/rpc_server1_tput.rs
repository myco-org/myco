use axum::body::Bytes;
use axum::{extract::State, http::StatusCode, routing::post, Router};
use axum_server::tls_rustls::RustlsConfig;
use myco_rs::{
    client::Client,
    constants::{BATCH_SIZE, NUM_CLIENTS},
    dtypes::Key,
    generate_test_certificates,
    network::{LocalServer1Access, RemoteServer2Access},
    server1::Server1,
};
use rand::{SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex as StdMutex},
    time::Instant,
};
use tokio::sync::{Mutex as TokioMutex, RwLock};
use tower::ServiceBuilder;
use futures::future::join_all;

const THROUGHPUT_ITERATIONS: usize = 10;

#[derive(Clone)]
struct AppState {
    server1: Arc<StdMutex<Server1>>,
    writer_clients: Arc<StdMutex<Vec<Client>>>,
    simulation_keys: Arc<Vec<Key>>,
    start_time: Arc<StdMutex<Option<Instant>>>,
    message_count: Arc<StdMutex<usize>>,
}

#[tokio::main]
async fn main() {
    // Setup logging
    tracing_subscriber::fmt::init();

    // Setup HTTPS certificates
    let cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("certs")
        .join("server-cert.pem");
    let key_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("certs")
        .join("server-key.pem");

    if !cert_path.exists() || !key_path.exists() {
        generate_test_certificates().expect("Failed to generate certificates");
    }

    let config = RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .unwrap();

    // Initialize Server2 connection
    let s2_addr = "https://127.0.0.1:3003";
    let s2_access = Box::new(RemoteServer2Access::new(s2_addr).await.unwrap());
    
    // Initialize Server1 and state
    let server1 = Server1::new(s2_access);
    let server1 = Arc::new(StdMutex::new(server1));

    // Generate simulation keys
    let mut rng = ChaCha20Rng::from_entropy();
    let mut simulation_keys = Vec::with_capacity(128);
    for _ in 0..128 {
        simulation_keys.push(Key::random(&mut rng));
    }
    let simulation_keys = Arc::new(simulation_keys);

    // Initialize writer clients
    let mut writer_clients = Vec::with_capacity(NUM_CLIENTS);
    for i in 0..NUM_CLIENTS {
        let client_name = format!("WriterClient_{}", i);
        let s1_access = Box::new(LocalServer1Access::new(server1.clone()));
        // We will never use this here, but it's required by the Client constructor.
        let s2_access = Box::new(RemoteServer2Access::new(s2_addr).await.unwrap());
        let mut client = Client::new(client_name, s1_access, s2_access);
        
        // Setup keys for this client
        for key in simulation_keys.iter() {
            client.setup(key).unwrap();
        }
        
        writer_clients.push(client);
    }

    println!("Writer clients initialized");

    let state = AppState {
        server1,
        writer_clients: Arc::new(StdMutex::new(writer_clients)),
        simulation_keys,
        start_time: Arc::new(StdMutex::new(None)),
        message_count: Arc::new(StdMutex::new(0)),
    };

    // Run experiment directly
    // Start timing
    *state.start_time.lock().unwrap() = Some(Instant::now());
    
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    for iteration in 0..THROUGHPUT_ITERATIONS {
        println!("\nThroughput iteration {}/{}", iteration + 1, THROUGHPUT_ITERATIONS);

        println!("Batch init about to start");
        // 1. Batch init
        // TODO: This should not need a Mutex/RwLock once Server1 is refactored to make the queue_write method threadsafe with DashMap.
        state
            .server1
            .lock()
            .unwrap()
            .async_batch_init(NUM_CLIENTS)
            .await;

        println!("Batch init finished");

        // 2. All clients write sequentially instead of in parallel
        let mut clients = state.writer_clients.lock().unwrap();
        let message = vec![1u8; 16];
        
        for client in clients.iter_mut() {
            let key = state.simulation_keys[0].clone();
            client.async_write(&message, &key).await.unwrap();
        }

        println!("All clients wrote");

        // 3. Batch write
        state
            .server1
            .lock()
            .unwrap()
            .async_batch_write()
            .await
            .expect("Failed to batch write");

        println!("Batch write finished");
        
        // Update message count
        let mut count = state.message_count.lock().unwrap();
        *count += NUM_CLIENTS;
    }

    // Calculate throughput
    let elapsed = state.start_time.lock().unwrap().unwrap().elapsed();
    let total_messages = *state.message_count.lock().unwrap();
    let seconds = elapsed.as_secs_f64();
    let throughput = total_messages as f64 / seconds;

    println!("\nThroughput Results:");
    println!("Total messages: {}", total_messages);
    println!("Total time: {:.2} seconds", seconds);
    println!("Throughput: {:.2} messages/second", throughput);

    // Save results
    std::fs::write(
        "throughput_results.txt",
        format!(
            "Total messages: {}\nTotal time: {:.2} seconds\nThroughput: {:.2} messages/second",
            total_messages, seconds, throughput
        ),
    )
    .unwrap();
}