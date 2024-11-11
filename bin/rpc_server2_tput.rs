#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_assignments)]
#![allow(unused_must_use)]
#![allow(dead_code)]
#![allow(unused_parens)]
#![allow(private_bounds)]

use axum::body::Bytes;
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use myco_rs::client::Client;
use myco_rs::constants::{BATCH_SIZE, FIXED_SEED_TPUT_RNG, NUM_CLIENTS, THROUGHPUT_ITERATIONS};
use myco_rs::dtypes::{Key, Path};
use myco_rs::error::MycoError;
use myco_rs::rpc_types::EpochNumberResponse;
use myco_rs::tree::SparseBinaryTree;
use myco_rs::{decrypt, get_path_indices, kdf, prf, trim_zeros};
use myco_rs::{
    generate_test_certificates,
    rpc_types::{
        ChunkReadPathsRequest, ChunkReadPathsResponse, ChunkWriteRequest, ChunkWriteResponse,
        FinalizeEpochRequest, FinalizeEpochResponse, ReadPathsRequest, ReadPathsResponse,
        StorePathIndicesRequest, StorePathIndicesResponse,
    },
    server2::Server2,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::RwLock;
use tower::ServiceBuilder;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct AppState {
    server2: Arc<RwLock<Server2>>,
    write_count: Arc<Mutex<usize>>,
    simulation_keys: Arc<Vec<Key>>,
    simulation_k_msg: Arc<Vec<Vec<u8>>>,
    simulation_k_oblv: Arc<Vec<Vec<u8>>>,
    simulation_k_prf: Arc<Vec<Vec<u8>>>,
}

#[tokio::main]
async fn main() {

    // Get bind address from command line args
    let args: Vec<String> = std::env::args().collect();
    let bind_addr = args
        .get(1)
        .map(|s| s.parse().unwrap())
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 3003)));

    println!("Server2 binding to: {}", bind_addr);

    // configure certificate and private key used by https
    let cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("certs")
        .join("server-cert.pem");
    let key_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("certs")
        .join("server-key.pem");

    // Generate certificates if they don't exist
    if !cert_path.exists() || !key_path.exists() {
        generate_test_certificates().map_err(|e| MycoError::CertificateError(e.to_string())).unwrap();
    }

    let config = RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .unwrap();

    let server2 = Server2::new();

    // Generate simulation keys used for the tput benchmarks.
    let mut rng = ChaCha20Rng::from_seed(FIXED_SEED_TPUT_RNG);
    let mut simulation_keys = Vec::with_capacity(BATCH_SIZE);
    for _ in 0..BATCH_SIZE {
        simulation_keys.push(Key::random(&mut rng));
    }

    // Pre-compute derived keys
    let mut simulation_k_msg = Vec::with_capacity(BATCH_SIZE);
    let mut simulation_k_oblv = Vec::with_capacity(BATCH_SIZE);
    let mut simulation_k_prf = Vec::with_capacity(BATCH_SIZE);
    
    for k in &simulation_keys {
        simulation_k_msg.push(kdf(&k.0, "MSG").unwrap());
        simulation_k_oblv.push(kdf(&k.0, "ORAM").unwrap());
        simulation_k_prf.push(kdf(&k.0, "PRF").unwrap());
    }

    let state = AppState {
        server2: Arc::new(RwLock::new(server2)),
        write_count: Arc::new(Mutex::new(0)),
        simulation_keys: Arc::new(simulation_keys),
        simulation_k_msg: Arc::new(simulation_k_msg),
        simulation_k_oblv: Arc::new(simulation_k_oblv),
        simulation_k_prf: Arc::new(simulation_k_prf),
    };

    let app = Router::new()
        .route("/chunk_write", post(handle_chunk_write))
        .route("/chunk_read_paths", post(handle_chunk_read_paths))
        .route("/store_path_indices", post(handle_store_path_indices))
        .route("/finalize_epoch", post(handle_finalize_epoch))
        .layer(
            ServiceBuilder::new().layer(axum::extract::DefaultBodyLimit::max(
                1024 * 1024 * 1024 * 1024,
            )),
        )
        .with_state(state);

    // run tcp server with provided bind address
    tracing::debug!("listening on {}", bind_addr);
    let listener = std::net::TcpListener::bind(bind_addr).unwrap();
    axum_server::from_tcp_rustls(listener, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn handle_store_path_indices(
    State(state): State<AppState>,
    bytes: Bytes,
) -> Result<Bytes, StatusCode> {
    let request: StorePathIndicesRequest =
        bincode::deserialize(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    state
        .server2
        .write()
        .await
        .store_path_indices(request.pathset);

    bincode::serialize(&StorePathIndicesResponse { success: true })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn handle_chunk_read_paths(
    State(state): State<AppState>,
    bytes: Bytes,
) -> Result<Bytes, StatusCode> {
    {
        let mut count = state.write_count.lock().unwrap();
        *count += 1;
    }

    let request: ChunkReadPathsRequest =
        bincode::deserialize(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    let buckets = state
        .server2
        .read()
        .await
        .read_pathset_chunk(request.chunk_idx)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    bincode::serialize(&ChunkReadPathsResponse { buckets })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn handle_chunk_write(
    State(state): State<AppState>,
    bytes: Bytes,
) -> Result<Bytes, StatusCode> {
    let request: ChunkWriteRequest =
        bincode::deserialize(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    state
        .server2
        .write()
        .await
        .chunk_write(request.buckets, request.chunk_idx);

    bincode::serialize(&ChunkWriteResponse { success: true })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// This finalizes the epoch AND simulates the client reading from S2.
async fn handle_finalize_epoch(
    State(state): State<AppState>,
    bytes: Bytes,
) -> Result<Bytes, StatusCode> {
    let request: FinalizeEpochRequest =
        bincode::deserialize(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    println!("Finalizing epoch");
    state.server2.write().await.finalize_epoch(&request.prf_key);

    // Now, let's read with all of the simulated clients.
    // New: Perform reads after each batch write
    let epoch = state.server2.read().await.epoch as usize;
    let simulation_keys = state.simulation_keys.clone().to_vec();

    // Get PRF keys from server2
    let server_keys = state
        .server2
        .read()
        .await
        .get_prf_keys()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    println!("Starting to perform the client reads");
    let futures = (0..NUM_CLIENTS).map(|i| {
        let client_name = format!("WriterClient_{}", i);
        read_without_client(
            state.server2.clone(),
            epoch,
            state.simulation_k_msg.clone(),
            state.simulation_k_oblv.clone(),
            state.simulation_k_prf.clone(),
            client_name,
            server_keys.clone(),
        )
    });
    futures::future::try_join_all(futures)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    println!("Client reads finished");

    // Increment write count at the end of finalize_epoch
    let mut write_count = state.write_count.lock().unwrap();
    *write_count += 1;

    // Calculate averages when all epochs are complete
    if *write_count == THROUGHPUT_ITERATIONS {
        println!("All epochs complete, calculating averages");
        myco_rs::logging::calculate_and_append_averages("server2_latency.csv", "server2_bytes.csv");
    }

    bincode::serialize(&FinalizeEpochResponse { success: true })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn read_without_client(
    server2: Arc<RwLock<Server2>>,
    current_epoch: usize,
    simulation_k_msg: Arc<Vec<Vec<u8>>>,
    simulation_k_oblv: Arc<Vec<Vec<u8>>>,
    simulation_k_prf: Arc<Vec<Vec<u8>>>,
    cs: String,
    current_prf_keys: Vec<Key>,
) -> Result<(), MycoError> {
    let epoch = current_epoch - 1;
    let cs: Vec<u8> = cs.into_bytes();
    let k_s1_t = current_prf_keys.get(current_prf_keys.len() - 1).unwrap();

    let mut paths = Vec::new();
    let mut key_data = Vec::new();

    for i in 0..simulation_k_msg.len() {
        let k_oblv_t = kdf(&simulation_k_oblv[i], &epoch.to_string())
            .map_err(|_| MycoError::NoMessageFound)?;
        let f = prf(&simulation_k_prf[i], &epoch.to_be_bytes())?;

        let l = prf(k_s1_t.0.as_slice(), &[&f[..], &cs[..]].concat())?;
        let l_path = Path::from(l);
        paths.push(l_path);
        key_data.push((simulation_k_msg[i].clone(), k_oblv_t));
    }

    // Get path indices and read paths
    let indices = get_path_indices(paths.clone());

    server2
        .read()
        .await
        .read_paths_client(indices.clone())
        .map_err(|_| MycoError::NoMessageFound)?;

    Ok(())
}
