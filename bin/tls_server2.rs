use myco_rs::server2::Server2;
use std::error::Error;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr = "0.0.0.0:8444";
    let cert_path = "server-cert.pem";
    let key_path = "server-key.pem";
    
    Server2::run_server(addr, cert_path, key_path).await.map_err(|e| e.into())
}