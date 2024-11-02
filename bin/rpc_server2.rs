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

pub fn generate_test_certificates() -> Result<(), Box<dyn std::error::Error>> {
    // Skip if certificates already exist
    if !StdPath::new("certs").exists() {
        fs::create_dir("certs")?;
    }
    if StdPath::new("certs/server-cert.pem").exists() && StdPath::new("certs/server-key.pem").exists() {
        // Clean up old certificates to ensure we have fresh ones
        fs::remove_file("certs/server-cert.pem")?;
        fs::remove_file("certs/server-key.pem")?;
    }

    // Create a config file for OpenSSL
    fs::write(
        "openssl.cnf",
        r#"
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = localhost

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
"#,
    )?;

    // Generate private key and self-signed certificate using OpenSSL
    Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:4096",
            "-keyout",
            "certs/server-key.pem",
            "-out",
            "certs/server-cert.pem",
            "-days",
            "365",
            "-nodes",
            "-config",
            "openssl.cnf",
            "-extensions",
            "v3_req",
        ])
        .output()?;

    // Convert the key to PKCS8 format which rustls expects
    Command::new("openssl")
        .args([
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in",
            "certs/server-key.pem",
            "-out",
            "certs/server-key.pem.tmp",
        ])
        .output()?;

    // Replace the original key with the PKCS8 version
    fs::rename("certs/server-key.pem.tmp", "certs/server-key.pem")?;

    // Clean up the config file
    fs::remove_file("openssl.cnf")?;

    Ok(())
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