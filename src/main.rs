// Copyright (c) Altare Technologies Limited. All rights reserved.

mod config;
mod error_pages;
mod health;
mod load_balancer;
mod proxy;
mod security;
mod ssl;

use crate::config::Config;
use crate::health::initialize_health_checks;
use crate::load_balancer::{LoadBalancer, LoadBalancerManager};
use crate::proxy::{handle_connection, ProxyHandler};
use crate::security::AltareFlux;
use crate::ssl::SslManager;
use hyper::service::service_fn;
use anyhow::{Context, Result};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "crucible=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Crucible - High Performance Reverse Proxy");
    info!("Copyright (c) Altare Technologies Limited");

    // Load configuration
    let config = Config::from_file("config.yml")
        .context("Failed to load configuration from config.yml")?;

    info!("Configuration loaded successfully");
    info!("HTTP Port: {}", config.server.http_port);
    info!("HTTPS Port: {}", config.server.https_port);
    info!("Configured domains: {}", config.domains.len());

    // Initialize load balancer manager
    let lb_manager = Arc::new(LoadBalancerManager::new());

    // Initialize SSL manager
    let mut ssl_manager = SslManager::new();
    let mut ssl_domains = Vec::new();

    // Configure domains
    for (domain, domain_config) in &config.domains {
        info!("Configuring domain: {}", domain);
        info!("  Backends: {:?}", domain_config.backends);
        info!(
            "  Load balancing: {:?}",
            domain_config.load_balance_strategy
        );

        // Create load balancer for this domain
        let load_balancer = Arc::new(LoadBalancer::new(
            domain_config,
            config.server.max_connections_per_backend,
        ));

        lb_manager
            .add_domain(domain.clone(), load_balancer)
            .await;

        // Configure SSL if enabled
        if domain_config.ssl.enabled {
            let cert_path = domain_config
                .ssl
                .cert_path
                .as_ref()
                .expect("SSL cert_path required when SSL is enabled");
            let key_path = domain_config
                .ssl
                .key_path
                .as_ref()
                .expect("SSL key_path required when SSL is enabled");

            info!("  SSL enabled for {}", domain);
            ssl_manager
                .add_domain(domain.clone(), cert_path, key_path)
                .context(format!("Failed to configure SSL for domain: {}", domain))?;

            ssl_domains.push(domain.clone());
        }
    }

    // Initialize health checks
    info!("Initializing health checks...");
    initialize_health_checks(lb_manager.clone()).await;

    // Initialize Altare Flux security system
    info!("Initializing Altare Flux security system...");
    let security_config = config.server.security.clone().into();
    let security = Arc::new(AltareFlux::new(security_config));

    if let Err(e) = security.initialize().await {
        warn!("Failed to fully initialize security system: {}", e);
        info!("Security system will continue with degraded functionality");
    }

    // Create proxy handler
    let proxy_handler = Arc::new(ProxyHandler::new(
        lb_manager.clone(),
        security.clone(),
        config.server.timeout,
    ));

    // Start HTTP server
    let http_proxy = proxy_handler.clone();
    let http_port = config.server.http_port;
    tokio::spawn(async move {
        if let Err(e) = start_http_server(http_port, http_proxy).await {
            error!("HTTP server error: {}", e);
        }
    });

    // Start HTTPS server if SSL is configured
    if ssl_manager.has_ssl_domains() {
        let https_port = config.server.https_port;
        let ssl_manager = Arc::new(ssl_manager);

        info!("Starting HTTPS server on port {}", https_port);
        info!("SSL configured for domains: {:?}", ssl_domains);

        if let Err(e) = start_https_server(https_port, proxy_handler, ssl_manager, security).await {
            error!("HTTPS server error: {}", e);
        }
    } else {
        info!("No SSL domains configured, HTTPS server not started");

        // Keep the process running
        tokio::signal::ctrl_c()
            .await
            .context("Failed to listen for ctrl-c")?;

        info!("Shutdown signal received");
    }

    Ok(())
}

/// Start HTTP server
async fn start_http_server(port: u16, proxy_handler: Arc<ProxyHandler>) -> Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr)
        .await
        .context(format!("Failed to bind HTTP server to {}", addr))?;

    info!("HTTP server listening on {}", addr);

    loop {
        let (stream, client_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                continue;
            }
        };

        let io = TokioIo::new(stream);
        let proxy_handler = proxy_handler.clone();

        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                let proxy_handler = proxy_handler.clone();
                async move {
                    handle_connection(proxy_handler, client_addr, req).await
                }
            });

            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                error!("Error serving connection from {}: {:?}", client_addr, err);
            }
        });
    }
}

/// Start HTTPS server
async fn start_https_server(
    port: u16,
    proxy_handler: Arc<ProxyHandler>,
    ssl_manager: Arc<SslManager>,
    security: Arc<AltareFlux>,
) -> Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr)
        .await
        .context(format!("Failed to bind HTTPS server to {}", addr))?;

    info!("HTTPS server listening on {}", addr);

    loop {
        let (stream, client_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                continue;
            }
        };

        let proxy_handler = proxy_handler.clone();
        let ssl_manager = ssl_manager.clone();
        let security = security.clone();

        tokio::task::spawn(async move {
            // For simplicity, we'll use the first available acceptor
            // In a production system, you'd want SNI-based selection
            let acceptor = ssl_manager
                .get_first_acceptor()
                .expect("No SSL acceptor available");

            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("TLS handshake failed from {}: {}", client_addr, e);
                    // Record failed TLS handshake for security monitoring
                    security.record_failed_tls_handshake(client_addr.ip()).await;
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let service = service_fn(move |req| {
                let proxy_handler = proxy_handler.clone();
                async move {
                    handle_connection(proxy_handler, client_addr, req).await
                }
            });

            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                error!("Error serving HTTPS connection from {}: {:?}", client_addr, err);
            }
        });
    }
}
