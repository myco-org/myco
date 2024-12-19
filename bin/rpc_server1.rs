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
use myco_rs::{
    constants::{DELTA, LATENCY_BENCH_COUNT},
    dtypes::{Key, ServerType},
    error::MycoError,
    network::RemoteServer2Access,
    rpc_types::{
        BatchInitRequest, BatchInitResponse, BatchWriteResponse, QueueWriteRequest,
        QueueWriteResponse,
    },
    server1::Server1,
    utils::generate_test_certificates,
};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, process::Command};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, RwLock};
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
    server1: Arc<RwLock<Server1>>,
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
    let s2_addr = args
        .get(1)
        .map(|s| s.to_string())
        .unwrap_or_else(|| "https://127.0.0.1:3003".to_string());

    println!("s2_addr: {}", s2_addr);
    let ports = Ports {
        http: 3002,
        https: 3001,
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
        generate_test_certificates()
            .map_err(|e| MycoError::CertificateError(e.to_string()))
            .unwrap();
    }

    let config = RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .unwrap();

    // Initialize Server1 with Server2 access using the provided or default address
    let s2_access = Box::new(RemoteServer2Access::new(&s2_addr).await.unwrap());
    let server1 = Server1::new(s2_access, ServerType::Async);
    let state = AppState {
        server1: Arc::new(RwLock::new(server1)),
        batch_write_count: Arc::new(Mutex::new(0)),
    };

    let app = Router::new()
        .route("/queue_write", post(queue_write))
        .route("/batch_write", get(batch_write))
        .route("/batch_init", post(batch_init))
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

/// Queue a write onto Server1. Uses the shared app state for Server1 to queue the write.
async fn queue_write(State(state): State<AppState>, bytes: Bytes) -> Result<Bytes, StatusCode> {
    println!("Received request: /queue_write");
    let request: QueueWriteRequest =
        bincode::deserialize(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    // TODO: This should not need a Mutex/RwLock once Server1 is refactored to make the queue_write method threadsafe with DashMap.
    state
        .server1
        .write()
        .await
        .queue_write(request.ct, request.f, request.k_oblv_t, request.cs)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    bincode::serialize(&QueueWriteResponse { success: true })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Queue a write onto Server1. Uses the shared app state for Server1 to queue the write.
async fn batch_write(State(state): State<AppState>) -> Result<Bytes, StatusCode> {
    println!("Received request: /batch_write");

    state
        .server1
        .write()
        .await
        .batch_write()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    bincode::serialize(&BatchWriteResponse { success: true })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Queue a write onto Server1. Uses the shared app state for Server1 to queue the write.
async fn batch_init(State(state): State<AppState>, bytes: Bytes) -> Result<Bytes, StatusCode> {
    println!("Received request: /batch_init");
    let request: BatchInitRequest =
        bincode::deserialize(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    // TODO: This should not need a Mutex/RwLock once Server1 is refactored to make the queue_write method threadsafe with DashMap.
    state
        .server1
        .write()
        .await
        .batch_init(request.num_writes)
        .unwrap();

    bincode::serialize(&BatchInitResponse { success: true })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

// Add this new endpoint handler
async fn handle_finalize_benchmark(State(state): State<AppState>) -> Result<Bytes, StatusCode> {
    println!("Received request: /finalize_benchmark");
    #[cfg(feature = "perf-logging")]
    myco_rs::logging::calculate_and_append_averages("server1_latency.csv", "server1_bytes.csv");
    Ok(Bytes::from("Benchmark finalized"))
}
