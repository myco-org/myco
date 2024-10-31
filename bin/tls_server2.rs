use myco_rs::server2::Server2;
use std::error::Error;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client_addr = "0.0.0.0:8443";
    let s1_addr = "0.0.0.0:8444";
    let cert_path = "certs/server-cert.pem";
    let key_path = "certs/server-key.pem";
    
    Server2::run_server(client_addr, s1_addr, cert_path, key_path).await.map_err(|e| e.into())
}
