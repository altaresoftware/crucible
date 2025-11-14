# Crucible Configuration Guide

This document describes all configuration options for Crucible and how to supply them.

Crucible supports two configuration modes:

- Single file: pass a YAML file with `--config /path/to/config.yml`.
- Nginx-style sites directory: enable multiple site files under a base folder that contains `sites_available` and `sites_enabled`.
  - Default base dir: `/etc/crucible`
  - You can change it with `--sites-dir /custom/path`
  - Crucible reads and merges all `*.yml`/`*.yaml` files found in `<base>/sites_enabled` (alphabetical order). The last file wins on conflicts.
  - On startup, Crucible will create `<base>/sites_available` and `<base>/sites_enabled` if they do not exist.

## CLI flags

- `--config <FILE>`: Load configuration from a single YAML file. If present, this overrides `--sites-dir`.
- `--sites-dir <DIR>`: Base directory for `sites_available` and `sites_enabled`. Default: `/etc/crucible`.

## Top-level structure

```yaml
server:
  http_port: 80
  https_port: 443
  workers: 4                # optional, default: CPU count
  timeout: 30               # seconds
  max_connections_per_backend: 1024
  security:                 # Altare Flux security
    enabled: true
    block_tor: true
    block_bots: true
    rate_limit:
      default_rps: 50
      api_rps: 100
      window_seconds: 1
    request_limits:
      max_header_size: 16384
      max_body_size: 10485760
      max_url_length: 2048
    slow_request_protection:
      min_header_rate: 1024
      min_body_rate: 10240
      timeout_seconds: 30
    tls_anomaly_detection:
      max_failed_handshakes: 5
      window_seconds: 60

domains:
  example.com:
    backends:
      - http://127.0.0.1:3000
      - http://127.0.0.1:3001
    ssl:
      enabled: true
      cert_path: /etc/ssl/example.com/fullchain.pem
      key_path: /etc/ssl/example.com/privkey.pem
    load_balance_strategy: round_robin   # round_robin | least_connections | ip_hash
    health_check:
      enabled: true
      interval: 10
      timeout: 5
      path: /health
    static_files:
      enabled: true
      root: /var/www/example.com
      try_files: ["$uri", "/index.php"]
      autoindex: false
    php_fpm:
      enabled: false
      socket: /run/php/php-fpm.sock
      timeout: 300
    headers:
      - name: X-Frame-Options
        value: SAMEORIGIN
      - name: Referrer-Policy
        value: no-referrer
    redirect_to_https: false
```

Notes:
- You must configure at least one of `backends`, `static_files.enabled: true`, or `php_fpm.enabled: true` per domain.
- When `ssl.enabled: true`, both `cert_path` and `key_path` are required.

## Sites directory mode

Place per-site files in `<base>/sites_enabled` (e.g., `/etc/crucible/sites_enabled/example.yml`). Each file may either:
- be a full config document containing `server` and `domains`, or
- only contain a `domains:` map. Files are merged in alphabetical order. Later files override earlier entries.

Example `example.yml` (domains-only):
```yaml
domains:
  example.com:
    backends: ["http://127.0.0.1:3000"]
    ssl:
      enabled: true
      cert_path: /etc/ssl/example.com/fullchain.pem
      key_path: /etc/ssl/example.com/privkey.pem
    static_files:
      enabled: true
      root: /var/www/example.com
      autoindex: true
```

## Static files

- `enabled`: serve files from `root` directly.
- `root`: document root directory.
- `try_files`: array of resolution patterns, e.g. `"$uri"`, `"/index.php"`.
- `autoindex`: when true and no index file is present in a directory, Crucible renders a directory listing styled like the error pages.

## PHP-FPM

- `enabled`: enable PHP handling.
- `socket`: path to FPM UNIX socket.
- `timeout`: script timeout in seconds.

## SSL/TLS (SNI)

Crucible supports multiple certificates via SNI. Configure `ssl.enabled`, `cert_path`, and `key_path` per domain. The correct certificate is selected during TLS handshake based on the requested server name.

## Health checks

- `enabled`: enable health checking for backends.
- `interval`: seconds between checks.
- `timeout`: per-check timeout in seconds.
- `path`: path to GET on each backend.

## Load balancing

- `load_balance_strategy` per domain:
  - `round_robin`
  - `least_connections`
  - `ip_hash` (client-IP affinity)

## Custom headers

Add any response headers via the `headers` list for a domain.

## Logging

Use `RUST_LOG` to set verbosity, e.g.: `RUST_LOG=crucible=debug`.
