// Import clap for command line argument parsing
use clap::Parser;
// Import Quinn QUIC library components
use quinn::{crypto, Endpoint, ServerConfig, VarInt};

// Import logging macros
use log::{debug, error, info};
// Import serde for configuration deserialization
use serde::Deserialize;
// Import standard library collections and utilities
use std::collections::HashMap;
use std::error::Error;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::{net::SocketAddr, sync::Arc};
// Import tokio async file operations
use tokio::fs::read_to_string;
// Import tokio async I/O traits
use tokio::io::{AsyncReadExt, AsyncWriteExt};
// Import tokio TCP stream for SSH connections
use tokio::net::TcpStream;

// Define command line options structure for the server
#[derive(Parser, Debug)]
#[clap(name = "server")]
pub struct Opt {
    // Socket address to bind the QUIC server to (default: 0.0.0.0:4433)
    #[clap(long = "listen", short = 'l', default_value = "0.0.0.0:4433")]
    listen: SocketAddr,
    // Optional default SSH server address to proxy connections to
    #[clap(long = "proxy-to", short = 'p')]
    proxy_to: Option<SocketAddr>,
    // Optional path to TOML configuration file
    #[clap(long = "conf", short = 'F')]
    conf_path: Option<PathBuf>,
}

// Configure QUIC server with self-signed certificate and transport settings
// Returns server configuration and certificate data
fn configure_server() -> Result<(ServerConfig, Vec<u8>), Box<dyn Error>> {
    // Generate self-signed certificate for localhost
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    
    // Serialize certificate to DER format
    let cert_der = cert.serialize_der().unwrap();
    
    // Extract and wrap private key
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::PrivateKey(priv_key);
    
    // Create certificate chain with single self-signed certificate
    let cert_chain = vec![rustls::Certificate(cert_der.clone())];

    // Create Quinn server configuration with TLS certificate
    let mut server_config = ServerConfig::with_single_cert(cert_chain, priv_key)?;
    
    // Configure transport layer settings
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    
    // Disable unidirectional streams (only bidirectional streams allowed)
    transport_config.max_concurrent_uni_streams(0_u8.into());
    
    // Set maximum idle timeout to 60 seconds
    transport_config.max_idle_timeout(Some(VarInt::from_u32(60_000).into()));
    
    // Send keep-alive packets every 1 second
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(1)));
    
    // Enable MTU discovery on supported platforms
    #[cfg(any(windows, os = "linux"))]
    transport_config.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));

    Ok((server_config, cert_der))
}

// Create a QUIC server endpoint bound to the specified address
// Returns the endpoint and certificate data
#[allow(unused)]
pub fn make_server_endpoint(bind_addr: SocketAddr) -> Result<(Endpoint, Vec<u8>), Box<dyn Error>> {
    // Get server configuration and certificate
    let (server_config, server_cert) = configure_server()?;
    
    // Create server endpoint bound to the specified address
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    
    Ok((endpoint, server_cert))
}

// Configuration structure for server proxy mappings
#[derive(Deserialize, Debug)]
struct ServerConf {
    // Map of SNI hostnames to SSH server addresses
    proxy: HashMap<String, SocketAddr>,
}

impl ServerConf {
    // Create new empty server configuration
    fn new() -> Self {
        ServerConf {
            proxy: HashMap::<String, SocketAddr>::new(),
        }
    }
}

// Main async function to run the QUIC server
#[tokio::main]
pub async fn run(options: Opt) -> Result<(), Box<dyn Error>> {
    // Load server configuration from file or create empty config
    let conf: ServerConf = match options.conf_path {
        Some(path) => {
            info!("[server] importing conf file: {}", path.display());
            // Read and parse TOML configuration file
            toml::from_str(&(read_to_string(path).await?))?
        }
        // Use empty configuration if no file provided
        None => ServerConf::new(),
    };

    // Determine default SSH server to proxy to
    let default_proxy = match conf.proxy.get("default") {
        // Use "default" entry from config if available
        Some(sock) => sock.clone(),
        // Fall back to command line option or localhost:22
        None => options
            .proxy_to
            .unwrap_or(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 22)),
    };
    info!("[server] default proxy aim: {}", default_proxy);

    // Create and start QUIC server endpoint
    let (endpoint, _) = make_server_endpoint(options.listen).unwrap();
    info!("[server] listening on: {}", options.listen);
    
    // Main server loop - accept and handle connections
    loop {
        // Wait for incoming connection
        let incoming_conn = match endpoint.accept().await {
            Some(conn) => conn,
            None => {
                continue;  // No connection, keep waiting
            }
        };
        
        // Complete the connection handshake
        let conn = match incoming_conn.await {
            Ok(conn) => conn,
            Err(e) => {
                error!("[server] accept connection error: {}", e);
                continue;  // Skip failed connections
            }
        };

        // Extract SNI (Server Name Indication) from TLS handshake
        let sni = conn
            .handshake_data()
            .unwrap()
            .downcast::<crypto::rustls::HandshakeData>()
            .unwrap()
            .server_name
            .unwrap_or(conn.remote_address().ip().to_string());  // Fall back to IP if no SNI
        
        // Determine which SSH server to proxy to based on SNI
        let proxy_to = conf.proxy.get(&sni).unwrap_or(&default_proxy).clone();
        
        // Log connection details
        info!(
            "[server] connection accepted: ({}, {}) -> {}",
            conn.remote_address(),
            sni,
            proxy_to
        );
        
        // Spawn async task to handle this connection
        tokio::spawn(async move {
            handle_connection(proxy_to, conn).await;
        });
        
        // Connection handling continues in background
        // Server loop continues to accept new connections
    }
}

// Handle a single QUIC connection by proxying data to/from SSH server
async fn handle_connection(proxy_for: SocketAddr, connection: quinn::Connection) {
    // Establish TCP connection to SSH server
    let ssh_stream = TcpStream::connect(proxy_for).await;
    let ssh_conn = match ssh_stream {
        Ok(conn) => conn,
        Err(e) => {
            error!("[server] connect to ssh error: {}", e);
            return;  // Exit if SSH connection fails
        }
    };

    info!("[server] ssh connection established");

    // Accept bidirectional stream from QUIC client
    let (mut quinn_send, mut quinn_recv) = match connection.accept_bi().await {
        Ok(stream) => stream,
        Err(e) => {
            error!("[server] open quic stream error: {}", e);
            return;  // Exit if QUIC stream fails
        }
    };

    // Split SSH connection into read and write halves
    let (mut ssh_recv, mut ssh_write) = tokio::io::split(ssh_conn);

    // Task to read from SSH server and send to QUIC client
    let recv_thread = async move {
        // Buffer for SSH server data (2KB)
        let mut buf = [0; 2048];
        
        // Continuous loop to proxy data from SSH to QUIC
        loop {
            match ssh_recv.read(&mut buf).await {
                Ok(n) => {
                    // Skip empty reads
                    if n == 0 {
                        continue;
                    }
                    debug!("[server] recv data from ssh server {} bytes", n);
                    
                    // Forward data to QUIC client
                    match quinn_send.write_all(&buf[..n]).await {
                        Ok(_) => (),
                        Err(e) => {
                            error!("[server] writing to quic stream error: {}", e);
                            return;  // Exit thread on write error
                        }
                    }
                }
                Err(e) => {
                    error!("[server] reading from ssh server error: {}", e);
                    return;  // Exit thread on read error
                }
            }
        }
    };

    // Task to read from QUIC client and send to SSH server
    let write_thread = async move {
        // Buffer for QUIC client data (2KB)
        let mut buf = [0; 2048];
        
        // Continuous loop to proxy data from QUIC to SSH
        loop {
            match quinn_recv.read(&mut buf).await {
                // No data available, continue waiting
                Ok(None) => {
                    continue;
                }
                // Data received successfully
                Ok(Some(n)) => {
                    debug!("[server] recv data from quic stream {} bytes", n);
                    
                    // Skip empty reads
                    if n == 0 {
                        continue;
                    }
                    
                    // Forward data to SSH server
                    match ssh_write.write_all(&buf[..n]).await {
                        Ok(_) => (),
                        Err(e) => {
                            error!("[server] writing to ssh server error: {}", e);
                            return;  // Exit thread on write error
                        }
                    }
                }
                // Error reading from QUIC client
                Err(e) => {
                    error!("[server] reading from quic client error: {}", e);
                    return;  // Exit thread on read error
                }
            }
        }
    };

    // Run both proxy threads concurrently, exit when either completes
    tokio::select! {
        _ = recv_thread => (),   // Exit if SSH->QUIC thread terminates
        _ = write_thread => (),  // Exit if QUIC->SSH thread terminates
    }

    // Log connection termination
    info!("[server] exit client");

    // Connection cleanup is handled automatically by tokio
}
