use axum::body::Bytes;
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use myco_rs::{
    generate_test_certificates,
    rpc_types::{
        ChunkReadPathsRequest, ChunkReadPathsResponse, ChunkWriteRequest, ChunkWriteResponse,
        FinalizeEpochRequest, FinalizeEpochResponse, ReadPathsRequest, ReadPathsResponse,
        StorePathIndicesRequest, StorePathIndicesResponse,
    },
    server2::Server2,
};
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
    let state = AppState {
        server2: Arc::new(RwLock::new(server2)),
        write_count: Arc::new(Mutex::new(0)),
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

    bincode::serialize(&FinalizeEpochResponse { success: true })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}