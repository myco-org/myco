//! Run with
//!
//! ```not_rust
//! cargo run -p example-tls-rustls
//! ```

#![allow(unused_imports)]

use axum::{
    body::Bytes,
    extract::State,
    handler::HandlerWithoutStateExt,
    http::{StatusCode, Uri},
    response::Redirect,
    routing::{get, post},
    BoxError, Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use myco_rs::{generate_test_certificates, rpc_types::{
    BatchInitRequest, BatchInitResponse, BatchWriteResponse, QueueWriteRequest, QueueWriteResponse,
}};
use myco_rs::{dtypes::Key, network::RemoteServer2Access, server1::Server1};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;
use tower::ServiceBuilder;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::{fs, process::Command, path::Path};

#[allow(dead_code)]
#[derive(Clone, Copy)]
struct Ports {
    http: u16,
    https: u16,
}

#[derive(Clone)]
struct AppState {
    server1: Arc<Mutex<Server1>>,
    batch_write_count: Arc<Mutex<usize>>,
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

    let args: Vec<String> = std::env::args().collect();
    let http_port = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(3001);
    let https_port = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(7878);
    let s2_addr = args.get(3)
        .map(|s| s.to_string())
        .unwrap_or_else(|| "http://127.0.0.1:3002".to_string());

    let ports = Ports {
        http: http_port,
        https: https_port,
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

    // Initialize Server1 with Server2 access using the provided or default address
    let s2_access = Box::new(
        RemoteServer2Access::new(&s2_addr)
            .await
            .unwrap(),
    );
    let server1 = Server1::new(s2_access);
    let state = AppState {
        server1: Arc::new(Mutex::new(server1)),
        batch_write_count: Arc::new(Mutex::new(0)),
    };

    let app = Router::new()
        .route("/queue_write", post(queue_write))
        .route("/batch_write", get(batch_write))
        .route("/batch_init", post(batch_init))
        .layer(ServiceBuilder::new().layer(axum::extract::DefaultBodyLimit::max(1024 * 1024 * 64))) // Set the max request body size.
        .with_state(state);

    // run tcp server
    let addr = SocketAddr::from(([0, 0, 0, 0], ports.http));
    tracing::debug!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Queue a write onto Server1. Uses the shared app state for Server1 to queue the write.
async fn queue_write(State(state): State<AppState>, bytes: Bytes) -> Result<Bytes, StatusCode> {
    let request: QueueWriteRequest =
        bincode::deserialize(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    // TODO: This should not need a Mutex/RwLock once Server1 is refactored to make the queue_write method threadsafe with DashMap.
    state
        .server1
        .lock()
        .await
        .queue_write(request.ct, request.f, request.k_oram_t, request.cs)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    bincode::serialize(&QueueWriteResponse { success: true })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Queue a write onto Server1. Uses the shared app state for Server1 to queue the write.
async fn batch_write(State(state): State<AppState>) -> Result<Bytes, StatusCode> {
    // Increment counter and check if we should start logging
    {
        let mut count = state.batch_write_count.lock().await;
        *count += 1;
        
        if *count == myco_rs::constants::DELTA {
            myco_rs::logging::initialize_logging(
                "server1_latency.csv",
                "server1_bytes.csv"
            );
        }
    }

    state
        .server1
        .lock()
        .await
        .async_batch_write()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    bincode::serialize(&BatchWriteResponse { success: true })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Queue a write onto Server1. Uses the shared app state for Server1 to queue the write.
async fn batch_init(State(state): State<AppState>, bytes: Bytes) -> Result<Bytes, StatusCode> {
    let request: BatchInitRequest =
        bincode::deserialize(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    // TODO: This should not need a Mutex/RwLock once Server1 is refactored to make the queue_write method threadsafe with DashMap.
    state
        .server1
        .lock()
        .await
        .async_batch_init(request.num_writes)
        .await;

    bincode::serialize(&BatchInitResponse { success: true })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn cleanup_servers() {
    // Kill any existing server processes
    Command::new("pkill")
        .args(["-f", "tls_server"])
        .output()
        .ok();

    // Give OS time to free up the ports
    std::thread::sleep(std::time::Duration::from_secs(1));
}