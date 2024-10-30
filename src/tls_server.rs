use std::sync::Arc;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener};
use tokio_rustls::TlsAcceptor;
use rustls::{Certificate, Connection, PrivateKey, ServerConfig};
use std::io::{Read, Write};

use crate::error::OramError;

pub struct TlsServer {
    acceptor: TlsAcceptor,
    listener: TcpListener,
}

impl TlsServer {
    pub async fn new(
        addr: &str,
        cert_path: &str,
        key_path: &str
    ) -> Result<Self, OramError> {
        // Load certificate and private key
        let cert_file = std::fs::File::open(cert_path)?;
        let key_file = std::fs::File::open(key_path)?;
        let mut cert_reader = std::io::BufReader::new(cert_file);
        let mut key_reader = std::io::BufReader::new(key_file);

        let certs: Vec<Certificate> = rustls_pemfile::certs(&mut cert_reader)?
            .into_iter()
            .map(Certificate)
            .collect();
        
        let keys: Vec<PrivateKey> = rustls_pemfile::pkcs8_private_keys(&mut key_reader)?
            .into_iter()
            .map(PrivateKey)
            .collect();

        // Configure TLS
        let config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, keys[0].clone())?;

        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(addr).await?;

        Ok(Self {
            acceptor,
            listener,
        })
    }

    pub async fn run<F>(&self, handler: F) -> Result<(), OramError> 
    where
        F: Fn(&[u8]) -> Result<Vec<u8>, OramError> + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        
        loop {
            let (stream, _) = self.listener.accept().await?;
            let acceptor = self.acceptor.clone();
            let handler = handler.clone();

            tokio::spawn(async move {
                let result: Result<(), OramError> = async move {
                    let mut stream = acceptor.accept(stream).await?;
                    
                    loop {
                        let mut len_bytes = [0u8; 4];
                        println!("TLS Server: Reading command length...");
                        
                        match stream.read_exact(&mut len_bytes).await {
                            Ok(0) => {
                                println!("TLS Server: Client disconnected naturally");
                                break;
                            }
                            Ok(_) => {
                                let len = u32::from_be_bytes(len_bytes);
                                println!("TLS Server: Command length is {}", len);
                                
                                let mut command = vec![0u8; len as usize];
                                stream.read_exact(&mut command).await?;
                                println!("TLS Server: Command received");

                                println!("TLS Server: Processing command...");
                                let response = handler(&command)?;
                                println!("TLS Server: Command processed, response length: {}", response.len());
                                
                                let len = response.len() as u32;
                                println!("TLS Server: Sending response length...");
                                stream.write_all(&len.to_be_bytes()).await?;
                                println!("TLS Server: Sending response...");
                                stream.write_all(&response).await?;
                                println!("TLS Server: Response sent");
                                
                                // Remove the shutdown() call that was here
                                // Just flush to ensure data is sent
                                stream.flush().await?;
                                println!("TLS Server: Ready for next command");
                            }
                            Err(e) => {
                                println!("TLS Server: Error reading command length: {:?}", e);
                                break;
                            }
                        }
                    }
                    Ok(())
                }.await;
                
                if let Err(e) = result {
                    eprintln!("Connection error: {:?}", e);
                }
            });
        }
    }
} 