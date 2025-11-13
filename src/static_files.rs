// Copyright (c) Altare Technologies Limited. All rights reserved.
//
// Static file server implementation

use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Bytes;
use hyper::{HeaderMap, Method, Response, StatusCode};
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
        req_headers: &HeaderMap,
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
                    return self.serve_file(&index_path, method, req_headers).await;
                }
            }
            return None;
        }

        // Serve the file
        self.serve_file(&file_path, method, req_headers).await
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
        req_headers: &HeaderMap,
    ) -> Option<Response<BoxBody<Bytes, hyper::Error>>> {
        // Check if it's a PHP file - should be handled by PHP-FPM
        if path.extension().and_then(|e| e.to_str()) == Some("php") {
            return None;
        }

        debug!("Serving static file: {:?}", path);

        // Determine if we can serve precompressed
        let accept_enc = req_headers
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let wants_br = accept_enc.contains("br");
        let wants_gzip = accept_enc.contains("gzip");

        let mut served_path = path.to_path_buf();
        let mut content_encoding: Option<&'static str> = None;
        if wants_br {
            if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
                let candidate = path.with_file_name(format!("{}.br", fname));
                if candidate.exists() {
                    served_path = candidate;
                    content_encoding = Some("br");
                }
            }
        }
        if content_encoding.is_none() && wants_gzip {
            if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
                let candidate = path.with_file_name(format!("{}.gz", fname));
                if candidate.exists() {
                    served_path = candidate;
                    content_encoding = Some("gzip");
                }
            }
        }

        // Stat for caching headers (based on served file)
        let metadata = match fs::metadata(&served_path).await {
            Ok(m) => m,
            Err(e) => {
                warn!("Failed to stat file {:?}: {}", path, e);
                return None;
            }
        };
        let len = metadata.len();
        #[allow(deprecated)]
        let mtime = metadata.modified().ok();
        let (etag_value, last_modified_value) = if let Some(mtime) = mtime {
            let secs = mtime
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let etag = format!("\"{}-{}\"", len, secs);
            let last_mod = httpdate::fmt_http_date(mtime);
            (Some(etag), Some(last_mod))
        } else {
            (None, None)
        };

        // Conditional requests: If-None-Match / If-Modified-Since
        if method == Method::GET || method == Method::HEAD {
            if let Some(etag) = &etag_value {
                if let Some(inm) = req_headers.get("if-none-match").and_then(|v| v.to_str().ok()) {
                    if inm.split(',').any(|t| t.trim() == etag) {
                        let mut resp = Response::builder()
                            .status(StatusCode::NOT_MODIFIED)
                            .body(
                                Empty::<Bytes>::new()
                                    .map_err(|never| match never {})
                                    .boxed(),
                            )
                            .unwrap();
                        resp.headers_mut().insert(
                            "ETag",
                            hyper::header::HeaderValue::from_str(etag).ok()?,
                        );
                        if let Some(lm) = &last_modified_value {
                            resp.headers_mut().insert(
                                "Last-Modified",
                                hyper::header::HeaderValue::from_str(lm).ok()?,
                            );
                        }
                        return Some(resp);
                    }
                }
            }
            if let Some(lm) = &last_modified_value {
                if let Some(ims) = req_headers.get("if-modified-since").and_then(|v| v.to_str().ok()) {
                    if let Ok(ims_time) = httpdate::parse_http_date(ims) {
                        if let Some(mtime) = metadata.modified().ok() {
                            if mtime <= ims_time {
                                let mut resp = Response::builder()
                                    .status(StatusCode::NOT_MODIFIED)
                                    .body(
                                        Empty::<Bytes>::new()
                                            .map_err(|never| match never {})
                                            .boxed(),
                                    )
                                    .unwrap();
                                resp.headers_mut().insert(
                                    "Last-Modified",
                                    hyper::header::HeaderValue::from_str(lm).ok()?,
                                );
                                if let Some(et) = &etag_value {
                                    resp.headers_mut().insert(
                                        "ETag",
                                        hyper::header::HeaderValue::from_str(et).ok()?,
                                    );
                                }
                                return Some(resp);
                            }
                        }
                    }
                }
            }
        }

        // Determine content type from original path (not compressed extension)
        let content_type = get_content_type(path);

        // Read file content
        let content = if method == Method::HEAD {
            Vec::new()
        } else {
            match fs::read(&served_path).await {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to read file {:?}: {}", served_path, e);
                    return None;
                }
            }
        };

        // Build body
        let body = if method == Method::HEAD {
            Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed()
        } else {
            Full::new(Bytes::from(content))
                .map_err(|never| match never {})
                .boxed()
        };

        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", content_type)
            .header("Cache-Control", "public, max-age=3600")
            .body(body)
            .unwrap();
        if let Some(enc) = content_encoding {
            response
                .headers_mut()
                .insert("Content-Encoding", hyper::header::HeaderValue::from_static(enc));
            response
                .headers_mut()
                .insert("Vary", hyper::header::HeaderValue::from_static("Accept-Encoding"));
        }
        if let Some(et) = etag_value {
            response.headers_mut().insert(
                "ETag",
                hyper::header::HeaderValue::from_str(&et).unwrap_or(hyper::header::HeaderValue::from_static("")),
            );
        }
        if let Some(lm) = last_modified_value {
            response.headers_mut().insert(
                "Last-Modified",
                hyper::header::HeaderValue::from_str(&lm).unwrap_or(hyper::header::HeaderValue::from_static("")),
            );
        }

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
                if let Ok(metadata) = fs::metadata(&resolved).await {
                    if metadata.is_file() {
                        return Some(resolved);
                    }
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
