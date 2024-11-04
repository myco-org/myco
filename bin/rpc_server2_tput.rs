use axum::body::Bytes;
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use myco_rs::client::Client;
use myco_rs::constants::{FIXED_SEED_TPUT_RNG, NUM_CLIENTS};
use myco_rs::dtypes::{Key, Path};
use myco_rs::error::OramError;
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
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // configure certificate and private key used by https
    let cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("certs")
        .join("server-cert.pem");
    let key_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("certs")
        .join("server-key.pem");

    // Generate certificates if they don't exist
    if !cert_path.exists() || !key_path.exists() {
        generate_test_certificates().expect("Failed to generate certificates");
    }

    let config = RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .unwrap();

    let server2 = Server2::new();

    // Generate simulation keys used for the tput benchmarks.
    let mut rng = ChaCha20Rng::from_seed(FIXED_SEED_TPUT_RNG);
    let mut simulation_keys = Vec::with_capacity(128);
    for _ in 0..128 {
        simulation_keys.push(Key::random(&mut rng));
    }

    let state = AppState {
        server2: Arc::new(RwLock::new(server2)),
        write_count: Arc::new(Mutex::new(0)),
        simulation_keys: Arc::new(simulation_keys),
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

    // run tcp server
    let addr = SocketAddr::from(([0, 0, 0, 0], 3003));
    tracing::debug!("listening on {}", addr);
    let listener = std::net::TcpListener::bind(addr).unwrap();
    axum_server::from_tcp_rustls(listener, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn handle_store_path_indices(
    State(state): State<AppState>,
    bytes: Bytes,
) -> Result<Bytes, StatusCode> {
    println!("Store path indices received");
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
    println!("Chunk read paths received");
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
    println!("Chunk write received");
    let request: ChunkWriteRequest =
        bincode::deserialize(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    println!("Chunk write deserialized");

    state
        .server2
        .write()
        .await
        .chunk_write(request.buckets, request.chunk_idx);

    bincode::serialize(&ChunkWriteResponse { success: true })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn handle_finalize_epoch(
    State(state): State<AppState>,
    bytes: Bytes,
) -> Result<Bytes, StatusCode> {
    println!("Finalize epoch received");
    let request: FinalizeEpochRequest =
        bincode::deserialize(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

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

    for i in 0..NUM_CLIENTS {
        let client_name = format!("WriterClient_{}", i);
        read_without_client(
            state.server2.clone(),
            epoch,
            simulation_keys.clone(),
            client_name,
            server_keys.clone(),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    bincode::serialize(&FinalizeEpochResponse { success: true })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn read_without_client(
    server2: Arc<RwLock<Server2>>,
    current_epoch: usize,
    simulation_keys: Vec<Key>,
    cs: String,
    current_prf_keys: Vec<Key>,
) -> Result<(), OramError> {
    // current_epoch is the epoch of server2
    let epoch = current_epoch - 1;
    let cs: Vec<u8> = cs.into_bytes();

    let k_s1_t = current_prf_keys.get(current_prf_keys.len() - 1).unwrap();

    // Calculate paths for all keys
    let mut paths = Vec::new();
    let mut key_data = Vec::new();

    for k in simulation_keys {
        let k_msg = kdf(&k.0, "MSG")?;
        let k_oram = kdf(&k.0, "ORAM")?;
        let k_prf = kdf(&k.0, "PRF")?;
        let k_oram_t = kdf(&k_oram, &epoch.to_string()).map_err(|_| OramError::NoMessageFound)?;
        let f = prf(&k_prf, &epoch.to_be_bytes())?;

        let l = prf(k_s1_t.0.as_slice(), &[&f[..], &cs[..]].concat())?;
        let l_path = Path::from(l);
        paths.push(l_path);
        key_data.push((k_msg.clone(), k_oram_t));
    }

    // Get path indices and read paths
    let indices = get_path_indices(paths.clone());

    let buckets = server2
        .read()
        .await
        .read_paths_client(indices.clone())
        .map_err(|_| OramError::NoMessageFound)?;

    Ok(())
}
