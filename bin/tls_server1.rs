use myco_rs::server1::Server1;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr = "0.0.0.0:8420";
    let cert_path = "certs/server-cert.pem";
    let key_path = "certs/server-key.pem";
    
    Server1::run_server(addr, cert_path, key_path).await.map_err(|e| e.into())
}
