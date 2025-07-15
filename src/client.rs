// Optional feature flag for rustls TLS library
// #![cfg(feature = "rustls")]

// Import clap for command line argument parsing
use clap::Parser;
// Import Quinn QUIC library components
use quinn::{ClientConfig, Endpoint, VarInt};
// Import standard library error handling and networking
use std::{error::Error, net::SocketAddr, sync::Arc};
// Import tokio async I/O traits
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Import Unix signal handling for non-Windows systems
#[cfg(not(windows))]
use tokio::signal::unix::{signal, SignalKind};
// Import Windows signal handling for Windows systems
#[cfg(windows)]
use tokio::signal::windows::ctrl_c;
// Import URL parsing functionality
use url::Url;

// Import logging macros (some may be unused)
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn, Level};

// Define command line options structure for the client
#[derive(Parser, Debug)]
#[clap(name = "client")]
pub struct Opt {
    // URL of the QUIC server to connect to
    url: Url,
    // Optional local address to bind the client to
    #[clap(long = "bind", short = 'b')]
    bind_addr: Option<SocketAddr>,
}

// Enable MTU Discovery (MTUD) for non-Windows/Linux systems
// Returns default transport config since MTUD is not supported
#[cfg(not(any(windows, os = "linux")))]
pub fn enable_mtud_if_supported() -> quinn::TransportConfig {
    quinn::TransportConfig::default()
}

// Enable MTU Discovery (MTUD) for Windows and Linux systems
// Configures transport to use MTU discovery for optimal packet sizing
#[cfg(any(windows, os = "linux"))]
pub fn enable_mtud_if_supported() -> quinn::TransportConfig {
    // Create default transport configuration
    let mut transport_config = quinn::TransportConfig::default();
    // Enable MTU discovery with default settings
    transport_config.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));
    transport_config
}

// Custom certificate verifier that skips server certificate validation
// WARNING: This is insecure and should only be used for testing
struct SkipServerVerification;

impl SkipServerVerification {
    // Create a new instance wrapped in Arc for thread safety
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

// Implementation of rustls ServerCertVerifier trait
impl rustls::client::ServerCertVerifier for SkipServerVerification {
    // Always accept any server certificate without verification
    // All parameters are ignored (hence the underscore prefix)
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,        // Server's certificate
        _intermediates: &[rustls::Certificate],   // Intermediate certificates
        _server_name: &rustls::ServerName,        // Expected server name
        _scts: &mut dyn Iterator<Item = &[u8]>,   // Certificate transparency logs
        _ocsp_response: &[u8],                    // OCSP response
        _now: std::time::SystemTime,              // Current time
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        // Always return success without any verification
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

// Configure the QUIC client with TLS and transport settings
fn configure_client() -> Result<ClientConfig, Box<dyn Error>> {
    // Build rustls client configuration with insecure certificate verification
    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()                                           // Use safe default cryptographic settings
        .with_custom_certificate_verifier(SkipServerVerification::new()) // Skip certificate verification (insecure)
        .with_no_client_auth();                                         // No client certificate authentication

    // Create Quinn client configuration with the rustls config
    let mut client_config = ClientConfig::new(Arc::new(crypto));
    
    // Configure transport layer settings
    let mut transport_config = enable_mtud_if_supported();
    
    // Set maximum idle timeout to 60 seconds before connection is closed
    transport_config.max_idle_timeout(Some(VarInt::from_u32(60_000).into()));
    
    // Send keep-alive packets every 1 second to maintain connection
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(1)));
    
    // Apply transport configuration to client config
    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}

// Create a QUIC endpoint configured for client-only operation
// 
// Arguments:
// - bind_addr: Local socket address to bind the client endpoint to
// 
// Returns: Configured QUIC endpoint ready for outbound connections
#[allow(unused)]
pub fn make_client_endpoint(bind_addr: SocketAddr) -> Result<Endpoint, Box<dyn Error>> {
    // Get the configured client settings
    let client_cfg = configure_client()?;
    
    // Create a client-only endpoint bound to the specified address
    let mut endpoint = Endpoint::client(bind_addr)?;
    
    // Set the default client configuration for all connections
    endpoint.set_default_client_config(client_cfg);
    
    Ok(endpoint)
}

// Main async function to run the QUIC client
#[tokio::main]
pub async fn run(options: Opt) -> Result<(), Box<dyn Error>> {
    // Extract URL from command line options
    let url = options.url;
    
    // Validate that URL scheme is "quic"
    if url.scheme() != "quic" {
        return Err("URL scheme must be quic".into());
    }

    // Resolve URL to socket addresses with default port 4433
    // NOTE: url crate doesn't recognize "quic" scheme, so we provide default port
    // In future, if QUIC gets an official port (like 80/443), this may need updates
    let sock_list = url
        .socket_addrs(|| Some(4433))  // Default QUIC port
        .map_err(|_| "Couldn't resolve to any address")?;

    // Use first resolved address (TODO: implement fallback to other addresses)
    let remote = sock_list[0];
    
    // Extract hostname for SNI (Server Name Indication)
    let sni = url.host_str().unwrap_or("THIS_HOSTNAME_SHOULD_NOT_BE_USED");

    // Clean up IPv6 address format by removing brackets
    let sni = sni.trim_start_matches('[').trim_end_matches(']');

    // Log connection attempt
    info!("[client] Connecting to: {} <- {}", remote, sni);

    // Create QUIC endpoint with appropriate bind address
    let endpoint = make_client_endpoint(match options.bind_addr {
        // Use user-specified bind address if provided
        Some(local) => local,
        // Auto-select bind address based on remote address type
        None => {
            use std::net::{IpAddr::*, Ipv4Addr, Ipv6Addr};
            if remote.is_ipv6() {
                // Bind to IPv6 unspecified address (::) on any port
                SocketAddr::new(V6(Ipv6Addr::UNSPECIFIED), 0)
            } else {
                // Bind to IPv4 unspecified address (0.0.0.0) on any port
                SocketAddr::new(V4(Ipv4Addr::UNSPECIFIED), 0)
            }
        }
    })?;
    
    // Establish QUIC connection to the server
    let connection = endpoint.connect(remote, sni).unwrap().await.unwrap();
    
    // Log successful connection
    info!(
        "[client] Connected to: {} <- {}",
        connection.remote_address(),
        sni
    );

    // Open bidirectional stream for communication
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| format!("failed to open stream: {}", e))?;

    // Task to handle receiving data from QUIC server and writing to stdout
    let recv_thread = async move {
        // Buffer for incoming data (2KB)
        let mut buf = vec![0; 2048];
        // Buffered writer for stdout to improve performance
        let mut writer = tokio::io::BufWriter::new(tokio::io::stdout());

        // Continuous loop to receive data
        loop {
            match recv.read(&mut buf).await {
                // No data received, continue waiting
                Ok(None) => {
                    continue;
                }
                // Data received successfully
                Ok(Some(n)) => {
                    debug!("[client] recv data from quic server {} bytes", n);
                    // Write received data to stdout
                    match writer.write_all(&buf[..n]).await {
                        Ok(_) => (),
                        Err(e) => {
                            error!("[client] write to stdout error: {}", e);
                            return;  // Exit thread on write error
                        }
                    }
                }
                // Error receiving data
                Err(err) => {
                    error!("[client] recv data from quic server error: {}", err);
                    return;  // Exit thread on read error
                }
            }
            // Flush buffered output to ensure data is displayed
            if writer.flush().await.is_err() {
                error!("[client] recv data flush stdout error");
            }
        }
    };

    // Task to handle reading data from stdin and sending to QUIC server
    let write_thread = async move {
        // Buffer for stdin data (2KB)
        let mut buf = [0; 2048];
        // Buffered reader for stdin to improve performance
        let mut reader = tokio::io::BufReader::new(tokio::io::stdin());

        // Continuous loop to read from stdin
        loop {
            match reader.read(&mut buf).await {
                // Data read successfully
                Ok(n) => {
                    // Skip empty reads
                    if n == 0 {
                        continue;
                    }
                    debug!("[client] recv data from stdin {} bytes", n);
                    
                    // Send data to QUIC server
                    if send.write_all(&buf[..n]).await.is_err() {
                        info!("[client] send data to quic server error");
                        return;  // Exit thread on send error
                    }
                }
                // Error reading from stdin
                Err(err) => {
                    info!("[client] recv data from stdin error: {}", err);
                    return;  // Exit thread on read error
                }
            }
        }
    };

    // Create signal handling thread for graceful shutdown
    let signal_thread = create_signal_thread();

    // Run all threads concurrently, exit when any completes
    tokio::select! {
        _ = recv_thread => (),     // Exit if recv thread terminates
        _ = write_thread => (),    // Exit if write thread terminates  
        _ = signal_thread => connection.close(0u32.into(), b"signal HUP"), // Exit on signal
    }

    // Log client shutdown
    info!("[client] exit client");

    Ok(())
}

// Windows-specific signal handler for Ctrl-C
#[cfg(windows)]
fn create_signal_thread() -> impl core::future::Future<Output = ()> {
    async move {
        // Create Ctrl-C signal stream
        let mut stream = match ctrl_c() {
            Ok(s) => s,
            Err(e) => {
                error!("[client] create signal stream error: {}", e);
                return;
            }
        };

        // Wait for Ctrl-C signal
        stream.recv().await;
        info!("[client] got signal Ctrl-C");
    }
}
// Unix-specific signal handler for SIGHUP
#[cfg(not(windows))]
fn create_signal_thread() -> impl core::future::Future<Output = ()> {
    async move {
        // Create SIGHUP signal stream
        let mut stream = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                error!("[client] create signal stream error: {}", e);
                return;
            }
        };

        // Wait for SIGHUP signal
        stream.recv().await;
        info!("[client] got signal HUP");
    }
}
