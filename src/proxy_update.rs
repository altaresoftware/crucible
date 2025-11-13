    /// Handle an incoming HTTP request and proxy it to a backend
    pub async fn handle_request(
        &self,
        req: Request<Incoming>,
        client_addr: SocketAddr,
        is_https: bool,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let client_ip = client_addr.ip();
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("");
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
            let location = format!("https://{}{}", host, req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/"));
            return Ok(Response::builder()
                .status(StatusCode::MOVED_PERMANENTLY)
                .header("Location", location)
                .body(Empty::<Bytes>::new().map_err(|never| match never {}).boxed())
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
                    return self.handle_php_request(req, php_handler, &path, query, domain_config).await;
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
        self.handle_backend_proxy(req, &host, &path, client_addr, domain_config).await
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

        let method_str = req.method().as_str();
        let headers = req.headers().clone();

        // Collect body if present
        let body_bytes = if req.method() == Method::POST || req.method() == Method::PUT {
            Some(req.collect().await?.to_bytes().to_vec())
        } else {
            None
        };

        // Resolve script path
        let script_path = std::path::PathBuf::from(path.trim_start_matches('/'));

        match php_handler
            .execute(&script_path, path, query, method_str, &headers, body_bytes)
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
