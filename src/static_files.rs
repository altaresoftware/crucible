// Copyright (c) Altare Technologies Limited. All rights reserved.

use anyhow::Result;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Bytes;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, warn};

/// Static file server
pub struct StaticFileServer {
    root: PathBuf,
    index_files: Vec<String>,
}

impl StaticFileServer {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            index_files: vec!["index.html".to_string(), "index.php".to_string()],
        }
    }

    /// Serve a static file if it exists
    pub async fn serve(
        &self,
        path: &str,
        method: &Method,
    ) -> Option<Response<BoxBody<Bytes, hyper::Error>>> {
        // Only handle GET and HEAD requests
        if method != Method::GET && method != Method::HEAD {
            return None;
        }

        // Sanitize path and prevent directory traversal
        let file_path = self.resolve_path(path)?;

        // Check if file exists
        let metadata = match fs::metadata(&file_path).await {
            Ok(m) => m,
            Err(_) => return None,
        };

        // If directory, try index files
        if metadata.is_dir() {
            for index_file in &self.index_files {
                let index_path = file_path.join(index_file);
                if index_path.exists() {
                    return self.serve_file(&index_path, method).await;
                }
            }
            return None;
        }

        // Serve the file
        self.serve_file(&file_path, method).await
    }

    /// Resolve and sanitize path
    fn resolve_path(&self, uri_path: &str) -> Option<PathBuf> {
        // Remove query string
        let path = uri_path.split('?').next().unwrap_or(uri_path);

        // Decode percent-encoded path
        let decoded_path = match urlencoding::decode(path) {
            Ok(p) => p,
            Err(_) => return None,
        };

        // Remove leading slash
        let clean_path = decoded_path.trim_start_matches('/');

        // Build full path
        let mut full_path = self.root.clone();
        full_path.push(clean_path);

        // Canonicalize to prevent directory traversal
        let canonical = match full_path.canonicalize() {
            Ok(p) => p,
            Err(_) => return None,
        };

        // Ensure the canonical path is within root
        if !canonical.starts_with(&self.root) {
            warn!("Directory traversal attempt: {:?}", canonical);
            return None;
        }

        Some(canonical)
    }

    /// Serve a file
    async fn serve_file(
        &self,
        path: &Path,
        method: &Method,
    ) -> Option<Response<BoxBody<Bytes, hyper::Error>>> {
        // Check if it's a PHP file - should be handled by PHP-FPM
        if path.extension().and_then(|e| e.to_str()) == Some("php") {
            return None;
        }

        debug!("Serving static file: {:?}", path);

        // Read file content
        let content = match fs::read(path).await {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to read file {:?}: {}", path, e);
                return None;
            }
        };

        // Determine content type
        let content_type = get_content_type(path);

        // For HEAD requests, return empty body
        let body = if method == Method::HEAD {
            Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed()
        } else {
            Full::new(Bytes::from(content))
                .map_err(|never| match never {})
                .boxed()
        };

        let response = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", content_type)
            .header("Cache-Control", "public, max-age=3600")
            .body(body)
            .unwrap();

        Some(response)
    }

    /// Check if a path would be handled as a PHP file
    pub async fn is_php_file(&self, path: &str) -> bool {
        if let Some(file_path) = self.resolve_path(path) {
            if let Ok(metadata) = fs::metadata(&file_path).await {
                if metadata.is_file() {
                    return file_path.extension().and_then(|e| e.to_str()) == Some("php");
                }
            }
        }
        false
    }

    /// Try files in order (like nginx try_files)
    pub async fn try_files(&self, path: &str, try_patterns: &[String]) -> Option<PathBuf> {
        for pattern in try_patterns {
            let test_path = pattern
                .replace("$uri", path)
                .replace("$query_string", ""); // Simplified for now

            if test_path == "/index.php" || test_path.ends_with("/index.php") {
                // Return path to index.php for PHP processing
                return self.resolve_path(&test_path);
            }

            if let Some(resolved) = self.resolve_path(&test_path) {
                if resolved.exists() {
                    return Some(resolved);
                }
            }
        }
        None
    }
}

/// Determine content type from file extension
fn get_content_type(path: &Path) -> &'static str {
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    match extension {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "eot" => "application/vnd.ms-fontobject",
        "pdf" => "application/pdf",
        "txt" => "text/plain; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "zip" => "application/zip",
        "tar" => "application/x-tar",
        "gz" => "application/gzip",
        _ => "application/octet-stream",
    }
}

/// Add security headers to response
pub fn add_security_headers(headers: &mut HeaderMap, custom_headers: &[(String, String)]) {
    // Add custom headers first
    for (name, value) in custom_headers {
        if let (Ok(header_name), Ok(header_value)) = (
            hyper::header::HeaderName::from_bytes(name.as_bytes()),
            hyper::header::HeaderValue::from_str(value),
        ) {
            headers.insert(header_name, header_value);
        }
    }
}
