// Copyright (c) Altare Technologies Limited. All rights reserved.

use crate::load_balancer::{ConnectionGuard, LoadBalancerManager};
use anyhow::Result;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::http1;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, error, warn};

/// Main proxy handler
pub struct ProxyHandler {
    lb_manager: Arc<LoadBalancerManager>,
    timeout: Duration,
}

impl ProxyHandler {
    pub fn new(lb_manager: Arc<LoadBalancerManager>, timeout_secs: u64) -> Self {
        Self {
            lb_manager,
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// Handle an incoming HTTP request and proxy it to a backend
    pub async fn handle_request(
        &self,
        req: Request<Incoming>,
        client_addr: SocketAddr,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let host = extract_host(&req);

        if host.is_none() {
            warn!("Request without Host header from {}", client_addr);
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Missing Host header",
            ));
        }

        let host = host.unwrap();
        debug!("Handling request for host: {} from {}", host, client_addr);

        // Get load balancer for this domain
        let lb = match self.lb_manager.get_balancer(&host).await {
            Some(lb) => lb,
            None => {
                warn!("No backend configured for host: {}", host);
                return Ok(error_response(StatusCode::BAD_GATEWAY, "No backend available"));
            }
        };

        // Select a backend
        let client_ip = client_addr.ip().to_string();
        let backend = match lb.select_backend(Some(&client_ip)) {
            Some(b) => b,
            None => {
                error!("No healthy backend available for host: {}", host);
                return Ok(error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "No healthy backend available",
                ));
            }
        };

        debug!("Selected backend: {} for host: {}", backend.url, host);

        // Create connection guard to track active connections
        let _guard = ConnectionGuard::new(backend.clone());

        // Proxy the request
        match self.proxy_request(req, &backend.url).await {
            Ok(response) => Ok(response),
            Err(e) => {
                error!("Proxy error for backend {}: {}", backend.url, e);
                backend.set_healthy(false);
                Ok(error_response(
                    StatusCode::BAD_GATEWAY,
                    "Backend connection failed",
                ))
            }
        }
    }

    /// Proxy a request to the backend
    async fn proxy_request(
        &self,
        mut req: Request<Incoming>,
        backend_url: &str,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        // Parse backend URL
        let backend_uri: Uri = backend_url.parse()?;
        let backend_host = backend_uri.host().unwrap_or("localhost");
        let backend_port = backend_uri.port_u16().unwrap_or(80);

        // Build new URI with backend information
        let path = req.uri().path();
        let query = req.uri().query().map(|q| format!("?{}", q)).unwrap_or_default();
        let new_uri = format!(
            "{}://{}:{}{}{}",
            backend_uri.scheme_str().unwrap_or("http"),
            backend_host,
            backend_port,
            path,
            query
        )
        .parse::<Uri>()?;

        *req.uri_mut() = new_uri;

        // Update headers
        req.headers_mut()
            .insert("X-Forwarded-For", "client".parse()?);
        req.headers_mut()
            .insert("X-Real-IP", "client".parse()?);

        // Connect to backend with timeout
        let backend_addr = format!("{}:{}", backend_host, backend_port);
        let stream = timeout(self.timeout, TcpStream::connect(&backend_addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))?
            .map_err(|e| anyhow::anyhow!("Connection failed: {}", e))?;

        let io = TokioIo::new(stream);

        // Create HTTP client connection
        let (mut sender, conn) = http1::handshake(io).await?;

        // Spawn connection task
        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                error!("Connection error: {:?}", err);
            }
        });

        // Send request with timeout
        let response = timeout(self.timeout, sender.send_request(req))
            .await
            .map_err(|_| anyhow::anyhow!("Request timeout"))??;

        // Convert response body
        let (parts, body) = response.into_parts();
        let body = body.boxed();
        Ok(Response::from_parts(parts, body))
    }
}

/// Extract host from request
fn extract_host(req: &Request<Incoming>) -> Option<String> {
    req.headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(|h| {
            // Remove port if present
            h.split(':').next().unwrap_or(h).to_string()
        })
        .or_else(|| {
            req.uri()
                .host()
                .map(|h| h.to_string())
        })
}

/// Create an error response
fn error_response(status: StatusCode, message: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .body(
            Full::new(Bytes::from(message.to_string()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

/// Create a service function for hyper
pub async fn handle_connection(
    proxy_handler: Arc<ProxyHandler>,
    client_addr: SocketAddr,
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    proxy_handler
        .handle_request(req, client_addr)
        .await
        .or_else(|e| {
            error!("Handler error: {}", e);
            Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error",
            ))
        })
}

/// Health check handler
pub async fn health_check_backend(backend_url: &str, path: &str, timeout_secs: u64) -> bool {
    let check_url = format!("{}{}", backend_url, path);
    let uri: Result<Uri> = check_url.parse().map_err(|e| anyhow::anyhow!("{}", e));

    if uri.is_err() {
        return false;
    }

    let uri = uri.unwrap();
    let host = uri.host().unwrap_or("localhost");
    let port = uri.port_u16().unwrap_or(80);

    let backend_addr = format!("{}:{}", host, port);
    let stream_result = timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(&backend_addr),
    )
    .await;

    match stream_result {
        Ok(Ok(stream)) => {
            let io = TokioIo::new(stream);
            let (mut sender, conn) = match http1::handshake(io).await {
                Ok(v) => v,
                Err(_) => return false,
            };

            tokio::task::spawn(async move {
                let _ = conn.await;
            });

            let req = Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Empty::<Bytes>::new())
                .unwrap();

            match timeout(Duration::from_secs(timeout_secs), sender.send_request(req)).await {
                Ok(Ok(response)) => response.status().is_success(),
                _ => false,
            }
        }
        _ => false,
    }
}
