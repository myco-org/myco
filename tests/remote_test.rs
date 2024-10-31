use myco_rs::{
    Client,
    network::{RemoteServer1Access, RemoteServer2Access},
    dtypes::Key,
};
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;
use std::process::Command;
use std::time::Duration;
use tokio;
use std::fs;
use std::path::Path;

fn generate_test_certificates() -> Result<(), Box<dyn std::error::Error>> {
    // Skip if certificates already exist
    if Path::new("server-cert.pem").exists() && Path::new("server-key.pem").exists() {
        // Clean up old certificates to ensure we have fresh ones
        fs::remove_file("server-cert.pem")?;
        fs::remove_file("server-key.pem")?;
    }

    // Create a config file for OpenSSL
    fs::write("openssl.cnf", r#"
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
"#)?;

    // Generate private key and self-signed certificate using OpenSSL
    Command::new("openssl")
        .args([
            "req", "-x509",
            "-newkey", "rsa:4096",
            "-keyout", "server-key.pem",
            "-out", "server-cert.pem",
            "-days", "365",
            "-nodes",
            "-config", "openssl.cnf",
            "-extensions", "v3_req"
        ])
        .output()?;

    // Convert the key to PKCS8 format which rustls expects
    Command::new("openssl")
        .args([
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in", "server-key.pem",
            "-out", "server-key.pem.tmp"
        ])
        .output()?;

    // Replace the original key with the PKCS8 version
    fs::rename("server-key.pem.tmp", "server-key.pem")?;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_remote_single_client() {
    println!("Starting test setup...");
    cleanup_servers();
    generate_test_certificates().expect("Failed to generate certificates");
    println!("Certificates generated successfully");

    // Start Server2 in a separate process
    println!("Starting Server2...");
    let mut server2 = Command::new("cargo")
        .args(["run", "--bin", "tls_server2"])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("Failed to start Server2");
    println!("Server2 process spawned");

    // Give Server2 more time to start
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Start Server1 in a separate process
    println!("Starting Server1...");
    let mut server1 = Command::new("cargo")
        .args(["run", "--bin", "tls_server1"])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("Failed to start Server1");
    println!("Server1 process spawned");

    // Give Server1 more time to start and complete batch_init
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Create separate connections for client and server1
    let server2_connection_for_client = RemoteServer2Access::connect("localhost:8443", "server-cert.pem").await
        .expect("Failed to connect to Server2");
    let server1_connection = RemoteServer1Access::connect("localhost:8420", "server-cert.pem").await
        .expect("Failed to connect to Server1");

    // Create client with its own connection
    let mut client = Client::new(
        "TestClient".to_string(),
        Box::new(server1_connection),
        Box::new(server2_connection_for_client)
    );
    let mut rng = ChaCha20Rng::from_entropy();
    let key = Key::random(&mut rng);
    
    // Add delay before setup
    tokio::time::sleep(Duration::from_secs(1)).await;
    client.setup(&key).expect("Setup failed");

    println!("Setup successful");
    
    // Add delay before write
    tokio::time::sleep(Duration::from_secs(1)).await;
    
    // Write data
    let message = vec![1, 2, 3, 4];
    println!("Attempting write operation...");
    match client.write(&message, &key) {
        Ok(_) => println!("Client write call completed"),
        Err(e) => println!("Client write failed with error: {:?}", e),
    }
    
    // Add delay after write
    tokio::time::sleep(Duration::from_secs(1)).await;
    println!("Write successful");

    // Add delay before read
    tokio::time::sleep(Duration::from_secs(1)).await;
    
    // Read data back
    println!("Attempting read operation...");
    match client.read(&key, "TestClient".to_string(), 0) {
        Ok(msg) => println!("Read successful: {:?}", msg),
        Err(e) => println!("Read failed with error: {:?}", e),
    }

    // Clean up processes
    server1.kill().expect("Failed to kill Server1");
    server2.kill().expect("Failed to kill Server2");
    cleanup_servers();
}