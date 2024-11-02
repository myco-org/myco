//! Run with
//!
//! ```not_rust
//! cargo run -p example-tls-rustls
//! ```

#![allow(unused_imports)]

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
use myco_rs::generate_test_certificates;
use myco_rs::rpc_types::ReadPathsClientRequest;
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
use tower::ServiceBuilder;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::{fs, process::Command, path::Path as StdPath};

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
        .route("/write", post(handle_write))
        .route("/get_prf_keys", get(handle_get_prf_keys))
        .layer(ServiceBuilder::new().layer(axum::extract::DefaultBodyLimit::max(1024 * 1024 * 256))) // Set the max request body size.
        .with_state(state);

    // run tcp server
    let addr = SocketAddr::from(([127, 0, 0, 1], ports.http));
    tracing::debug!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}


async fn handle_read_paths(
    State(state): State<AppState>,
    bytes: Bytes,
) -> Result<Bytes, StatusCode> {
    let request: ReadPathsRequest =
        bincode::deserialize(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    let buckets = state
        .server2
        .write()
        .await
        .read_paths(request.indices)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    bincode::serialize(&ReadPathsResponse { buckets })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn handle_read_paths_client(State(state): State<AppState>, bytes: Bytes) -> Result<Bytes, StatusCode> {
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

async fn handle_write(State(state): State<AppState>, bytes: Bytes) -> Result<Bytes, StatusCode> {
    println!("Server2: Writing to Server2");
    
    // Increment counter and check if we should start logging
    {
        let mut count = state.write_count.lock().unwrap();
        *count += 1;
        
        if *count == myco_rs::constants::DELTA {
            myco_rs::logging::initialize_logging(
                "server2_latency.csv",
                "server2_bytes.csv"
            );
        }
    }

    let request: WriteRequest =
        bincode::deserialize(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;

    state.server2.write().await.write(request.buckets);
    state.server2.write().await.add_prf_key(&request.prf_key);

    bincode::serialize(&WriteResponse { success: true })
        .map(Bytes::from)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn handle_get_prf_keys(State(state): State<AppState>) -> Result<Bytes, StatusCode> {
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
