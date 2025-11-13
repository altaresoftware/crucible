// Copyright (c) Altare Technologies Limited. All rights reserved.

use crate::config::DomainConfig;
use crate::error_pages::{generate_html_error, generate_json_error, is_api_request};
use crate::load_balancer::{ConnectionGuard, LoadBalancerManager};
use crate::php_fpm::PhpFpm;
use crate::security::AltareFlux;
use crate::static_files::{add_security_headers, StaticFileServer};
use anyhow::Result;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::http1;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, error, warn};

/// Main proxy handler
pub struct ProxyHandler {
    lb_manager: Arc<LoadBalancerManager>,
    security: Arc<AltareFlux>,
    timeout: Duration,
    domain_configs: Arc<HashMap<String, DomainConfig>>,
    static_servers: Arc<HashMap<String, StaticFileServer>>,
    php_handlers: Arc<HashMap<String, PhpFpm>>,
}

impl ProxyHandler {
    pub fn new(
        lb_manager: Arc<LoadBalancerManager>,
        security: Arc<AltareFlux>,
        timeout_secs: u64,
        domain_configs: HashMap<String, DomainConfig>,
    ) -> Self {
        // Build static servers and PHP handlers
        let mut static_servers = HashMap::new();
        let mut php_handlers = HashMap::new();

        for (domain, config) in &domain_configs {
            if let Some(static_config) = &config.static_files {
                if static_config.enabled {
                    static_servers.insert(
                        domain.clone(),
                        StaticFileServer::new(&static_config.root),
                    );
                }
            }

            if let Some(php_config) = &config.php_fpm {
                if php_config.enabled {
                    let doc_root = config
                        .static_files
                        .as_ref()
                        .map(|s| s.root.clone())
                        .unwrap_or_else(|| "/var/www".to_string());
                    php_handlers.insert(
                        domain.clone(),
                        PhpFpm::new(php_config.socket.clone(), doc_root),
                    );
                }
            }
        }

        Self {
            lb_manager,
            security,
            timeout: Duration::from_secs(timeout_secs),
            domain_configs: Arc::new(domain_configs),
            static_servers: Arc::new(static_servers),
            php_handlers: Arc::new(php_handlers),
        }
    }

    /// Handle an incoming HTTP request and proxy it to a backend
    pub async fn handle_request(
        &self,
        req: Request<Incoming>,
        client_addr: SocketAddr,
        is_https: bool,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let client_ip = client_addr.ip();
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("").to_string();
        let method = req.method().clone();
        let is_api = is_api_request(&path);

        // Get host and domain config
        let host = match extract_host(&req) {
            Some(h) => h,
            None => {
                warn!("Request without Host header from {}", client_addr);
                return Ok(create_error_response(
                    StatusCode::BAD_REQUEST,
                    "Missing Host header",
                    &path,
                ));
            }
        };

        let domain_config = self.domain_configs.get(&host);

        // Handle HTTP to HTTPS redirect
        if !is_https && domain_config.map(|c| c.redirect_to_https).unwrap_or(false) {
            let location = format!(
                "https://{}{}",
                host,
                req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/")
            );
            return Ok(Response::builder()
                .status(StatusCode::MOVED_PERMANENTLY)
                .header("Location", location)
                .body(
                    Empty::<Bytes>::new()
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap());
        }

        // Security checks
        if let Err(security_error) = self.security.check_ip(client_ip).await {
            warn!("Security: Blocked IP {}: {}", client_ip, security_error);
            return Ok(create_error_response(
                security_error.status_code(),
                security_error.message(),
                &path,
            ));
        }

        if let Err(security_error) = self.security.check_rate_limit(client_ip, is_api).await {
            warn!("Security: Rate limit exceeded for IP {}", client_ip);
            return Ok(create_error_response(
                security_error.status_code(),
                security_error.message(),
                &path,
            ));
        }

        if let Err(security_error) = self.security.check_tls_anomaly(client_ip).await {
            warn!("Security: TLS anomaly detected for IP {}", client_ip);
            return Ok(create_error_response(
                security_error.status_code(),
                security_error.message(),
                &path,
            ));
        }

        let url_length = req.uri().to_string().len();
        let header_size = estimate_header_size(&req);
        if let Err(security_error) = self
            .security
            .validate_request_size(url_length, header_size, 0)
        {
            warn!("Security: Request size limit exceeded for IP {}", client_ip);
            return Ok(create_error_response(
                security_error.status_code(),
                security_error.message(),
                &path,
            ));
        }

        debug!("Handling request for host: {} from {}", host, client_addr);

        // Try static file serving first
        if let Some(static_server) = self.static_servers.get(&host) {
            // Check if it's a PHP file
            if static_server.is_php_file(&path).await {
                if let Some(php_handler) = self.php_handlers.get(&host) {
                    return self
                        .handle_php_request(req, php_handler, &path, &query, domain_config)
                        .await;
                }
            }

            // Try serving static file
            if let Some(mut response) = static_server.serve(&path, &method).await {
                // Add custom headers
                if let Some(config) = domain_config {
                    let headers_vec: Vec<(String, String)> = config
                        .headers
                        .iter()
                        .map(|h| (h.name.clone(), h.value.clone()))
                        .collect();
                    add_security_headers(response.headers_mut(), &headers_vec);
                }
                return Ok(response);
            }
        }

        // Fall back to backend proxying
        self.handle_backend_proxy(req, &host, &path, client_addr, domain_config)
            .await
    }

    async fn handle_php_request(
        &self,
        req: Request<Incoming>,
        php_handler: &PhpFpm,
        path: &str,
        query: &str,
        domain_config: Option<&DomainConfig>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        debug!("Handling PHP request: {}", path);

        let method_str = req.method().as_str().to_string();
        let headers = req.headers().clone();
        let method = req.method().clone();

        // Collect body if present
        let body_bytes = if method == Method::POST || method == Method::PUT {
            Some(req.collect().await?.to_bytes().to_vec())
        } else {
            None
        };

        // Resolve script path
        let script_path = std::path::PathBuf::from(path.trim_start_matches('/'));

        match php_handler
            .execute(&script_path, path, query, &method_str, &headers, body_bytes)
            .await
        {
            Ok(mut response) => {
                // Add custom headers
                if let Some(config) = domain_config {
                    let headers_vec: Vec<(String, String)> = config
                        .headers
                        .iter()
                        .map(|h| (h.name.clone(), h.value.clone()))
                        .collect();
                    add_security_headers(response.headers_mut(), &headers_vec);
                }
                Ok(response)
            }
            Err(e) => {
                error!("PHP execution error: {}", e);
                Ok(create_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "PHP execution failed",
                    path,
                ))
            }
        }
    }

    async fn handle_backend_proxy(
        &self,
        req: Request<Incoming>,
        host: &str,
        path: &str,
        client_addr: SocketAddr,
        domain_config: Option<&DomainConfig>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        // Get load balancer for this domain
        let lb = match self.lb_manager.get_balancer(host).await {
            Some(lb) => lb,
            None => {
                warn!("No backend configured for host: {}", host);
                return Ok(create_error_response(
                    StatusCode::BAD_GATEWAY,
                    "No backend available",
                    path,
                ));
            }
        };

        // Select a backend
        let client_ip_str = client_addr.ip().to_string();
        let backend = match lb.select_backend(Some(&client_ip_str)) {
            Some(b) => b,
            None => {
                error!("No healthy backend available for host: {}", host);
                return Ok(create_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "No healthy backend available",
                    path,
                ));
            }
        };

        debug!("Selected backend: {} for host: {}", backend.url, host);

        // Create connection guard to track active connections
        let _guard = ConnectionGuard::new(backend.clone());

        // Proxy the request
        match self.proxy_request(req, &backend.url).await {
            Ok(mut response) => {
                // Add custom headers
                if let Some(config) = domain_config {
                    let headers_vec: Vec<(String, String)> = config
                        .headers
                        .iter()
                        .map(|h| (h.name.clone(), h.value.clone()))
                        .collect();
                    add_security_headers(response.headers_mut(), &headers_vec);
                }
                Ok(response)
            }
            Err(e) => {
                error!("Proxy error for backend {}: {}", backend.url, e);
                backend.set_healthy(false);
                Ok(create_error_response(
                    StatusCode::BAD_GATEWAY,
                    "Backend connection failed",
                    path,
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

/// Estimate header size for security checks
fn estimate_header_size(req: &Request<Incoming>) -> usize {
    let mut size = 0;
    for (name, value) in req.headers().iter() {
        size += name.as_str().len() + value.len() + 4; // +4 for ": \r\n"
    }
    size
}

/// Create an error response with fancy HTML or JSON
fn create_error_response(
    status: StatusCode,
    message: &str,
    path: &str,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    if is_api_request(path) {
        // Return JSON for API requests
        let json = generate_json_error(status, message);
        Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(
                Full::new(Bytes::from(json))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    } else {
        // Return HTML for regular requests
        let html = generate_html_error(status, message);
        Response::builder()
            .status(status)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(
                Full::new(Bytes::from(html))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }
}

/// Create a simple error response (deprecated - use create_error_response)
#[allow(dead_code)]
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
    is_https: bool,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let path = req.uri().path().to_string();
    proxy_handler
        .handle_request(req, client_addr, is_https)
        .await
        .or_else(|e| {
            error!("Handler error: {}", e);
            Ok(create_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error",
                &path,
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
