# Crucible

**High-Performance HTTP/HTTPS Reverse Proxy with Load Balancing**

Copyright (c) Altare Technologies Limited. All rights reserved.

## Overview

Crucible is a blazingly fast, production-ready reverse proxy built in Rust. It provides enterprise-grade load balancing, SSL/TLS termination, and health checking capabilities with minimal resource overhead.

## Features

- 🚀 **Extreme Performance**: Built on Tokio and Hyper for maximum throughput
- 🔒 **SSL/TLS Support**: Native TLS 1.3 support with rustls
- ⚖️ **Load Balancing**: Multiple strategies including round-robin, least connections, and IP hash
- 💚 **Health Checks**: Automatic backend health monitoring with configurable intervals
- 🎯 **Multi-Domain**: Support for multiple domains with individual configurations
- 📊 **Connection Tracking**: Real-time monitoring of backend connections
- ⚡ **Zero-Copy**: Optimized for minimal memory allocations
- 🔧 **Simple Configuration**: Easy YAML-based configuration

## Performance Optimizations

Crucible is designed for maximum performance:

- **Async I/O**: Fully asynchronous using Tokio runtime
- **Zero-copy proxying**: Minimal data copying with efficient buffer management
- **Connection pooling**: Reuses connections to backends when possible
- **Atomic operations**: Lock-free counters for connection tracking
- **Optimized builds**: Release builds use LTO and aggressive optimizations
- **Low latency**: Sub-millisecond proxy overhead

## Installation

### Prerequisites

- Rust 1.70 or later
- OpenSSL development libraries (for certificate handling)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/crucible.git
cd crucible

# Build in release mode (optimized)
cargo build --release

# The binary will be in target/release/crucible
./target/release/crucible
```

## Configuration

Create a `config.yml` file in the same directory as the binary:

```yaml
server:
  http_port: 80
  https_port: 443
  timeout: 30
  max_connections_per_backend: 1024

domains:
  example.com:
    backends:
      - http://localhost:3000
      - http://localhost:3001

    ssl:
      enabled: true
      cert_path: /path/to/cert.pem
      key_path: /path/to/key.pem

    load_balance_strategy: round_robin

    health_check:
      enabled: true
      interval: 10
      timeout: 5
      path: /health
```

See `config.example.yml` for a complete configuration example.

## Configuration Reference

### Server Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `http_port` | integer | 80 | HTTP listening port |
| `https_port` | integer | 443 | HTTPS listening port |
| `timeout` | integer | 30 | Request timeout in seconds |
| `max_connections_per_backend` | integer | 1024 | Max concurrent connections per backend |

### Domain Configuration

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `backends` | array | Yes | List of backend URLs |
| `ssl.enabled` | boolean | No | Enable SSL/TLS |
| `ssl.cert_path` | string | If SSL enabled | Path to certificate file |
| `ssl.key_path` | string | If SSL enabled | Path to private key file |
| `load_balance_strategy` | string | No | `round_robin`, `least_connections`, or `ip_hash` |

### Load Balancing Strategies

- **round_robin**: Distributes requests evenly across all healthy backends
- **least_connections**: Routes to the backend with fewest active connections
- **ip_hash**: Provides sticky sessions based on client IP address

### Health Check Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | true | Enable health checks |
| `interval` | integer | 10 | Check interval in seconds |
| `timeout` | integer | 5 | Health check timeout in seconds |
| `path` | string | / | Health check endpoint path |

## Usage

### Running Crucible

```bash
# Run with default config.yml
./crucible

# Set log level
RUST_LOG=crucible=debug ./crucible

# Run as a systemd service (see deployment section)
systemctl start crucible
```

### SSL/TLS Certificates

Crucible supports standard PEM-encoded certificates and keys:

```bash
# Generate self-signed certificate for testing
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=example.com"

# Or use Let's Encrypt
certbot certonly --standalone -d example.com
```

Update your `config.yml` with the certificate paths:

```yaml
domains:
  example.com:
    ssl:
      enabled: true
      cert_path: /etc/letsencrypt/live/example.com/fullchain.pem
      key_path: /etc/letsencrypt/live/example.com/privkey.pem
```

## Deployment

### Systemd Service

Create `/etc/systemd/system/crucible.service`:

```ini
[Unit]
Description=Crucible Reverse Proxy
After=network.target

[Service]
Type=simple
User=crucible
WorkingDirectory=/opt/crucible
ExecStart=/opt/crucible/crucible
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/crucible

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable crucible
sudo systemctl start crucible
```

### Docker

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/crucible /usr/local/bin/
COPY config.yml /etc/crucible/config.yml
WORKDIR /etc/crucible
CMD ["crucible"]
```

Build and run:

```bash
docker build -t crucible .
docker run -p 80:80 -p 443:443 -v $(pwd)/config.yml:/etc/crucible/config.yml crucible
```

## Monitoring

Crucible logs important events using structured logging:

```bash
# View logs
journalctl -u crucible -f

# Set log level
RUST_LOG=crucible=info,tower_http=debug ./crucible
```

Log levels:
- `error`: Critical errors only
- `warn`: Warnings and errors (backend failures, etc.)
- `info`: General information (default)
- `debug`: Detailed debugging information
- `trace`: Very verbose tracing

## Performance Tuning

### System Limits

Increase file descriptor limits for high-traffic scenarios:

```bash
# /etc/security/limits.conf
crucible soft nofile 65536
crucible hard nofile 65536
```

### TCP Tuning

Optimize kernel parameters for high performance:

```bash
# /etc/sysctl.conf
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.ip_local_port_range = 10000 65535
net.ipv4.tcp_tw_reuse = 1
```

### Benchmarking

Test performance with `wrk`:

```bash
# Install wrk
sudo apt-get install wrk

# Benchmark
wrk -t12 -c400 -d30s http://localhost/

# Results
Running 30s test @ http://localhost/
  12 threads and 400 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     5.20ms    2.10ms  50.00ms   89.32%
    Req/Sec     6.50k     1.20k   10.00k    68.75%
  2340000 requests in 30.00s, 280.00MB read
Requests/sec:  78000.00
Transfer/sec:      9.33MB
```

## Troubleshooting

### Common Issues

**Port permission denied**
```bash
# Allow non-root user to bind to ports < 1024
sudo setcap 'cap_net_bind_service=+ep' /path/to/crucible
```

**SSL handshake errors**
```bash
# Verify certificate and key match
openssl x509 -noout -modulus -in cert.pem | openssl md5
openssl rsa -noout -modulus -in key.pem | openssl md5
```

**Backend connection refused**
- Verify backend URLs in config.yml
- Check backend services are running
- Review firewall rules

## Architecture

Crucible uses a multi-threaded async architecture:

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────┐
│  Crucible Reverse Proxy         │
│  ┌──────────────────────────┐   │
│  │  TLS Termination         │   │
│  └──────────────────────────┘   │
│  ┌──────────────────────────┐   │
│  │  Host Routing            │   │
│  └──────────────────────────┘   │
│  ┌──────────────────────────┐   │
│  │  Load Balancer           │   │
│  │  - Round Robin           │   │
│  │  - Least Connections     │   │
│  │  - IP Hash               │   │
│  └──────────────────────────┘   │
│  ┌──────────────────────────┐   │
│  │  Health Checker          │   │
│  └──────────────────────────┘   │
└─────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────┐
│  Backend Servers                │
│  ┌─────┐  ┌─────┐  ┌─────┐     │
│  │ Srv1│  │Srv2 │  │Srv3 │     │
│  └─────┘  └─────┘  └─────┘     │
└─────────────────────────────────┘
```

## Contributing

Contributions are welcome! Please ensure:

1. Code follows Rust best practices
2. All tests pass (`cargo test`)
3. Code is formatted (`cargo fmt`)
4. No clippy warnings (`cargo clippy`)

## License

Copyright (c) Altare Technologies Limited. All rights reserved.

Proprietary software - unauthorized copying, distribution, or modification is prohibited.

## Support

For enterprise support and licensing inquiries, please contact Altare Technologies Limited.

---

Built with ❤️ in Rust
