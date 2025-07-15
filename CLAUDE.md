# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**quicssh-rs** is a QUIC proxy that allows SSH connections over QUIC protocol without patching client or server. It provides a Rust implementation of quicssh with connection migration and weak network optimization.

## Architecture

The codebase is organized into three main modules:

- **main.rs** - CLI entry point with logging configuration and command routing
- **client.rs** - QUIC client that connects to server, handles stdin/stdout bridging  
- **server.rs** - QUIC server that accepts connections and proxies to SSH server

### Key Components

**Client Flow**: SSH client → quicssh-rs client → QUIC → quicssh-rs server → SSH server
- Client reads from stdin, writes to QUIC stream
- Receives from QUIC stream, writes to stdout
- Handles signal interruption (HUP on Unix, Ctrl-C on Windows)

**Server Flow**: Accepts QUIC connections and proxies to SSH server
- Supports SNI-based routing via configuration file
- Bidirectional data streaming between QUIC and TCP
- Self-signed certificate generation for QUIC encryption

## Common Commands

### Building
```bash
cargo build --release
```

### Running
```bash
# Start server (default: listen on 0.0.0.0:4433, proxy to 127.0.0.1:22)
cargo run -- server

# Start server with custom options
cargo run -- server --listen 0.0.0.0:8443 --proxy-to 192.168.1.100:22

# Start client
cargo run -- client quic://hostname:4433

# With logging
cargo run -- --log /tmp/quicssh.log --log-level info server
```

### Testing
```bash
# Build and test basic functionality
cargo build --release
./target/release/quicssh-rs server &
./target/release/quicssh-rs client quic://localhost:4433
```

## Configuration

### Server Configuration
Optional TOML configuration file for SNI-based routing:
```toml
[proxy]
default = "127.0.0.1:22"
"hostname1" = "192.168.1.100:22"
"hostname2" = "192.168.1.101:22"
```

### SSH Client Configuration
```
Host myhost
    HostName myhost.example.com
    User myuser
    Port 4433
    ProxyCommand /path/to/quicssh-rs client quic://%h:%p
```

## Development Notes

- Uses Quinn for QUIC implementation with rustls for TLS
- Client skips certificate verification for simplicity
- MTU discovery enabled on Windows and Linux
- Tokio async runtime for all I/O operations
- Self-signed certificates generated at runtime for server
- Connection migration and keep-alive configured for stability