//! Run with
//!
//! ```not_rust
//! cargo run -p example-tls-rustls
//! ```

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
    handler::HandlerWithoutStateExt,
    http::{StatusCode, Uri},
    response::Redirect,
    routing::{get, post},
    BoxError, Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use myco_rs::constants::DELTA;
use myco_rs::constants::LATENCY_BENCH_COUNT;
use myco_rs::generate_test_certificates;
use myco_rs::rpc_types::{
    ChunkReadPathsClientRequest, ChunkReadPathsClientResponse, ChunkReadPathsRequest, ChunkReadPathsResponse, ChunkWriteRequest, ChunkWriteResponse, FinalizeEpochRequest, FinalizeEpochResponse, ReadPathsClientRequest, StorePathIndicesRequest, StorePathIndicesResponse
};
use myco_rs::{
    dtypes::{Bucket, Key, Path},
    network::RemoteServer2Access,
    rpc_types::{
        GetPrfKeysResponse, ReadPathsRequest, ReadPathsResponse, ReadRequest, ReadResponse,
        WriteRequest, WriteResponse,
    },
    server1::Server1,
    server2::Server2,
};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path as StdPath, process::Command};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::RwLock;
use tower::ServiceBuilder;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[allow(dead_code)]
#[derive(Clone, Copy)]
struct Ports {
    http: u16,
    https: u16,
}

#[derive(Clone)]
struct AppState {
    server2: Arc<RwLock<Server2>>,
    write_count: Arc<Mutex<usize>>,
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

    let ports = Ports {
        http: 3004,
        https: 3003,
    };

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
    let state = AppState {
        server2: Arc::new(RwLock::new(server2)),
        write_count: Arc::new(Mutex::new(0)),
    };

    let app = Router::new()
        .route("/read_paths", post(handle_read_paths))
        .route("/read_paths_client", post(handle_read_paths_client))
        .route("/chunk_read_paths_client", post(handle_chunk_read_paths_client))
        .route("/write", post(handle_write))
        .route("/chunk_write", post(handle_chunk_write))
        .route("/chunk_read_paths", post(handle_chunk_read_paths))
        .route("/store_path_indices", post(handle_store_path_indices))
        .route("/finalize_epoch", post(handle_finalize_epoch))
        .route("/get_prf_keys", get(handle_get_prf_keys))
        .route("/finalize_benchmark", post(handle_finalize_benchmark))
        .layer(
            ServiceBuilder::new().layer(axum::extract::DefaultBodyLimit::max(
                1024 * 1024 * 1024 * 1024,
            )),
        ) // Set the max request body size.
        .with_state(state);

    // run tcp server
    let addr = SocketAddr::from(([0, 0, 0, 0], ports.https));
    tracing::debug!("listening on {}", addr);
    let listener = std::net::TcpListener::bind(addr).unwrap();
    axum_server::from_tcp_rustls(listener, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn handle_read_paths(
    State(state): State<AppState>,
    bytes: Bytes,
) -> Result<Bytes, StatusCode> {
    println!("Received request: /read_paths");
    // TODO: Optimize the request to be smaller by sending the list of paths rather than the indices, and computing it client side. (E.g. just send leaves)
    let request: ReadPathsRequest =
        bincode::deserialize(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    let buckets = state
        .server2
        .write()
        .await
        .read_and_store_path_indices(request.indices)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    bincode::serialize(&ReadPathsResponse { buckets })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Store the pathset indices.
async fn handle_store_path_indices(
    State(state): State<AppState>,
    bytes: Bytes,
) -> Result<Bytes, StatusCode> {
    println!("Received request: /store_path_indices");
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

/// Read a chunk of buckets from the server.
async fn handle_chunk_read_paths(
    State(state): State<AppState>,
    bytes: Bytes,
) -> Result<Bytes, StatusCode> {
    // println!("Received request: /chunk_read_paths");
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

async fn handle_read_paths_client(
    State(state): State<AppState>,
    bytes: Bytes,
) -> Result<Bytes, StatusCode> {
    println!("Received request: /read_paths_client");
    let request: ReadPathsClientRequest =
        bincode::deserialize(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    let buckets = state
        .server2
        .read()
        .await
        .read_paths_client(request.indices)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    bincode::serialize(&ReadPathsResponse { buckets })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn handle_chunk_read_paths_client(
    State(state): State<AppState>,
    bytes: Bytes,
) -> Result<Bytes, StatusCode> {
    println!("Received request: /chunk_read_paths_client");
    let request: ChunkReadPathsClientRequest =
        bincode::deserialize(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    let buckets = state
        .server2
        .read()
        .await
        .read_paths_client_chunk(request.chunk_idx, request.indices)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    bincode::serialize(&ChunkReadPathsClientResponse { buckets })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}


async fn handle_chunk_write(
    State(state): State<AppState>,
    bytes: Bytes,
) -> Result<Bytes, StatusCode> {
    // println!("Received request: /chunk_write");
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

async fn handle_finalize_epoch(
    State(state): State<AppState>,
    bytes: Bytes,
) -> Result<Bytes, StatusCode> {
    println!("Received request: /finalize_epoch");
    let request: FinalizeEpochRequest =
        bincode::deserialize(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    state.server2.write().await.finalize_epoch(&request.prf_key);

    bincode::serialize(&FinalizeEpochResponse { success: true })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn handle_write(State(state): State<AppState>, bytes: Bytes) -> Result<Bytes, StatusCode> {
    let request: WriteRequest =
        bincode::deserialize(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    state.server2.write().await.write(request.buckets);
    state.server2.write().await.add_prf_key(&request.prf_key);

    bincode::serialize(&WriteResponse { success: true })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn handle_get_prf_keys(State(state): State<AppState>) -> Result<Bytes, StatusCode> {
    println!("Received request: /get_prf_keys");
    
    let keys = state
        .server2
        .read()
        .await
        .get_prf_keys()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    bincode::serialize(&GetPrfKeysResponse { keys })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn handle_finalize_benchmark(State(state): State<AppState>) -> Result<Bytes, StatusCode> {
    println!("Received request: /finalize_benchmark");
    myco_rs::logging::calculate_and_append_averages(
        "server2_latency.csv",
        "server2_bytes.csv",
    );
    Ok(Bytes::from("Benchmark finalized"))
}
