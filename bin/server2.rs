//! Run with
//!
//! ```not_rust
//! cargo run -p example-tls-rustls
//! ```

#![allow(unused_imports)]

use axum::{
    extract::State,
    handler::HandlerWithoutStateExt,
    http::{StatusCode, Uri},
    response::Redirect,
    routing::{get, post},
    BoxError, Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
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
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::RwLock;
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
        http: 3002,
        https: 3001,
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

    let server2 = Server2::new();
    let state = AppState {
        server2: Arc::new(RwLock::new(server2)),
    };
    let app = Router::new()
        .route("/read_paths", post(handle_read_paths))
        .route("/read", post(handle_read))
        .route("/write", post(handle_write))
        .route("/get_prf_keys", get(handle_get_prf_keys))
        .with_state(state);

    // run tcp server
    let addr = SocketAddr::from(([127, 0, 0, 1], ports.http));
    tracing::debug!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handle_read_paths(
    State(state): State<AppState>,
    Json(request): Json<ReadPathsRequest>,
) -> Json<ReadPathsResponse> {
    let buckets = state
        .server2
        .write()
        .await
        .read_paths(request.indices)
        .unwrap();
    Json(ReadPathsResponse { buckets })
}

async fn handle_read(
    State(state): State<AppState>,
    Json(request): Json<ReadRequest>,
) -> Json<ReadResponse> {
    let buckets = state.server2.read().await.read(&request.path).unwrap();
    Json(ReadResponse { buckets })
}

async fn handle_write(
    State(state): State<AppState>,
    Json(request): Json<WriteRequest>,
) -> Json<WriteResponse> {
    println!("Server2: Writing to Server2");
    state.server2.write().await.write(request.buckets);
    state.server2.write().await.add_prf_key(&request.prf_key);
    Json(WriteResponse { success: true })
}

async fn handle_get_prf_keys(State(state): State<AppState>) -> Json<GetPrfKeysResponse> {
    println!("Server2: Getting PRF keys");
    let keys = state.server2.read().await.get_prf_keys().unwrap();
    Json(GetPrfKeysResponse { keys })
}
