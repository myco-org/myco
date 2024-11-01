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
use myco_rs::rpc_types::{
    BatchInitRequest, BatchInitResponse, BatchWriteResponse, QueueWriteRequest, QueueWriteResponse,
};
use myco_rs::{dtypes::Key, network::RemoteServer2Access, server1::Server1};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;
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
    server1: Arc<Mutex<Server1>>,
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
        http: 3001,
        https: 7878,
    };

    // configure certificate and private key used by https
    let config = RustlsConfig::from_pem_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("server-cert.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("server-key.pem"),
    )
    .await
    .unwrap();

    // Initialize Server1 with Server2 access
    let s2_access = Box::new(
        RemoteServer2Access::new("http://127.0.0.1:3002")
            .await
            .unwrap(),
    );
    let server1 = Server1::new(s2_access);
    let state = AppState {
        server1: Arc::new(Mutex::new(server1)),
    };

    let app = Router::new()
        .route("/queue_write", post(queue_write))
        .route("/batch_write", get(batch_write))
        .route("/batch_init", post(batch_init))
        .layer(ServiceBuilder::new().layer(axum::extract::DefaultBodyLimit::max(1024 * 1024 * 64))) // Set the max request body size.
        .with_state(state);

    // run tcp server
    let addr = SocketAddr::from(([127, 0, 0, 1], ports.http));
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
    // TODO: This should not need a Mutex/RwLock once Server1 is refactored to make the queue_write method threadsafe with DashMap.
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
