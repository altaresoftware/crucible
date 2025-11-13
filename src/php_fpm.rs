// Copyright (c) Altare Technologies Limited. All rights reserved.
//
// PHP-FPM FastCGI implementation

use anyhow::{Context, Result};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Response, StatusCode};
use std::collections::HashMap;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
const FCGI_END_REQUEST: u8 = 3;

const FCGI_RESPONDER: u16 = 1;
const FCGI_VERSION_1: u8 = 1;

/// PHP-FPM FastCGI client
pub struct PhpFpm {
    socket_path: String,
    script_filename_prefix: String,
}

impl PhpFpm {
    pub fn new(socket_path: String, document_root: String) -> Self {
        Self {
            socket_path,
            script_filename_prefix: document_root,
        }
    }

    /// Execute PHP script via PHP-FPM
    pub async fn execute(
        &self,
        script_path: &Path,
        request_uri: &str,
        query_string: &str,
        method: &str,
        headers: &hyper::HeaderMap,
        client_ip: &str,
        is_https: bool,
        body: Option<Vec<u8>>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        // Connect to PHP-FPM
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .context("Failed to connect to PHP-FPM")?;

        let script_filename_str = script_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid script path"))?;
        let script_path_obj = Path::new(script_filename_str);
        let script_filename_owned = if script_path_obj.is_absolute() {
            script_filename_str.to_string()
        } else {
            let mut combined = std::path::PathBuf::from(&self.script_filename_prefix);
            combined.push(script_filename_str);
            combined.to_string_lossy().to_string()
        };

        // Build FastCGI parameters
        // We need to store owned Strings for dynamic values
        let content_length_str;
        let server_port_str;
        let x_forwarded_port_str;
        let host_header_owned;
        let server_name_owned;
        let x_forwarded_proto_owned;
        let request_scheme_owned;

        let mut params = HashMap::new();
        params.insert("GATEWAY_INTERFACE", "CGI/1.1");
        params.insert("SERVER_SOFTWARE", "Crucible/1.0.0");
        params.insert("QUERY_STRING", query_string);
        params.insert("REQUEST_METHOD", method);
        params.insert("SCRIPT_FILENAME", &script_filename_owned);
        let script_name = if script_filename_owned.ends_with("index.php") {
            "/index.php"
        } else {
            request_uri
        };
        params.insert("SCRIPT_NAME", script_name);
        let request_uri_full_owned = if query_string.is_empty() {
            request_uri.to_string()
        } else {
            let mut s = String::with_capacity(request_uri.len() + 1 + query_string.len());
            s.push_str(request_uri);
            s.push('?');
            s.push_str(query_string);
            s
        };
        params.insert("REQUEST_URI", &request_uri_full_owned);
        params.insert("DOCUMENT_URI", request_uri);
        params.insert("PHP_SELF", script_name);
        params.insert("DOCUMENT_ROOT", self.script_filename_prefix.as_str());
        params.insert("SERVER_PROTOCOL", "HTTP/1.1");
        params.insert("REDIRECT_STATUS", "200");

        // Derive host and ports
        let host_header = headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        host_header_owned = host_header.to_string();
        let (server_name, server_port_from_host) = if let Some((h, p)) = host_header_owned.split_once(':') {
            (h.to_string(), p.to_string())
        } else {
            (host_header_owned.clone(), String::new())
        };
        server_name_owned = server_name;
        let default_port = if is_https { 443 } else { 80 };
        server_port_str = if !server_port_from_host.is_empty() {
            server_port_from_host.clone()
        } else {
            default_port.to_string()
        };

        // Standard CGI/server params
        if !server_name_owned.is_empty() {
            params.insert("SERVER_NAME", &server_name_owned);
        }
        params.insert("SERVER_PORT", &server_port_str);
        params.insert("REMOTE_ADDR", client_ip);
        if is_https {
            params.insert("HTTPS", "on");
            params.insert("HTTP_X_FORWARDED_SSL", "on");
        }
        request_scheme_owned = if is_https { "https".to_string() } else { "http".to_string() };
        params.insert("REQUEST_SCHEME", &request_scheme_owned);

        // Forwarded headers for framework awareness
        x_forwarded_proto_owned = if is_https { "https".to_string() } else { "http".to_string() };
        x_forwarded_port_str = server_port_str.clone();
        if !host_header_owned.is_empty() {
            params.insert("HTTP_HOST", &host_header_owned);
            params.insert("HTTP_X_FORWARDED_HOST", &host_header_owned);
        }
        params.insert("HTTP_X_FORWARDED_PROTO", &x_forwarded_proto_owned);
        params.insert("HTTP_X_FORWARDED_PORT", &x_forwarded_port_str);
        params.insert("HTTP_X_FORWARDED_FOR", client_ip);

        // Cookies and common HTTP headers
        if let Some(cookie) = headers.get("cookie") {
            if let Ok(c) = cookie.to_str() {
                params.insert("HTTP_COOKIE", c);
            }
        }
        if let Some(ua) = headers.get("user-agent") {
            if let Ok(v) = ua.to_str() {
                params.insert("HTTP_USER_AGENT", v);
            }
        }
        if let Some(accept) = headers.get("accept") {
            if let Ok(v) = accept.to_str() {
                params.insert("HTTP_ACCEPT", v);
            }
        }
        if let Some(accept_lang) = headers.get("accept-language") {
            if let Ok(v) = accept_lang.to_str() {
                params.insert("HTTP_ACCEPT_LANGUAGE", v);
            }
        }
        if let Some(accept_enc) = headers.get("accept-encoding") {
            if let Ok(v) = accept_enc.to_str() {
                params.insert("HTTP_ACCEPT_ENCODING", v);
            }
        }
        if let Some(referer) = headers.get("referer") {
            if let Ok(v) = referer.to_str() {
                params.insert("HTTP_REFERER", v);
            }
        }
        if let Some(origin) = headers.get("origin") {
            if let Ok(v) = origin.to_str() {
                params.insert("HTTP_ORIGIN", v);
            }
        }

        if let Some(h) = headers.get("x-csrf-token") {
            if let Ok(v) = h.to_str() {
                params.insert("HTTP_X_CSRF_TOKEN", v);
            }
        }
        if let Some(h) = headers.get("x-xsrf-token") {
            if let Ok(v) = h.to_str() {
                params.insert("HTTP_X_XSRF_TOKEN", v);
            }
        }
        if let Some(h) = headers.get("x-requested-with") {
            if let Ok(v) = h.to_str() {
                params.insert("HTTP_X_REQUESTED_WITH", v);
            }
        }

        

        // Add headers as CGI variables
        if let Some(content_type) = headers.get("content-type") {
            if let Ok(ct) = content_type.to_str() {
                params.insert("CONTENT_TYPE", ct);
            }
        }

        if let Some(content_length) = headers.get("content-length") {
            if let Ok(cl) = content_length.to_str() {
                params.insert("CONTENT_LENGTH", cl);
            }
        } else if let Some(ref body_data) = body {
            content_length_str = body_data.len().to_string();
            params.insert("CONTENT_LENGTH", &content_length_str);
        }

        let request_id: u16 = 1;

        // Send BEGIN_REQUEST
        let begin_request_body = build_begin_request(FCGI_RESPONDER);
        write_record(&mut stream, FCGI_BEGIN_REQUEST, request_id, &begin_request_body).await?;

        // Send PARAMS
        let params_data = build_params(&params);
        write_record(&mut stream, FCGI_PARAMS, request_id, &params_data).await?;
        write_record(&mut stream, FCGI_PARAMS, request_id, &[]).await?; // Empty params = end

        // Send STDIN (request body)
        if let Some(body_data) = body {
            write_record(&mut stream, FCGI_STDIN, request_id, &body_data).await?;
        }
        write_record(&mut stream, FCGI_STDIN, request_id, &[]).await?; // Empty stdin = end

        // Read response
        let mut response_data = Vec::new();

        loop {
            let header = read_record_header(&mut stream).await?;

            if header.request_id != request_id {
                continue;
            }

            let mut content = vec![0u8; header.content_length as usize];
            stream.read_exact(&mut content).await?;

            // Skip padding
            if header.padding_length > 0 {
                let mut padding = vec![0u8; header.padding_length as usize];
                stream.read_exact(&mut padding).await?;
            }

            match header.record_type {
                FCGI_STDOUT => {
                    if !content.is_empty() {
                        response_data.extend_from_slice(&content);
                    }
                }
                FCGI_END_REQUEST => {
                    break;
                }
                _ => {}
            }
        }

        // Parse CGI response
        parse_cgi_response(&response_data)
    }
}

#[derive(Debug)]
struct RecordHeader {
    record_type: u8,
    request_id: u16,
    content_length: u16,
    padding_length: u8,
}

async fn read_record_header(stream: &mut UnixStream) -> Result<RecordHeader> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).await?;

    Ok(RecordHeader {
        record_type: header[1],
        request_id: u16::from_be_bytes([header[2], header[3]]),
        content_length: u16::from_be_bytes([header[4], header[5]]),
        padding_length: header[6],
    })
}

async fn write_record(
    stream: &mut UnixStream,
    record_type: u8,
    request_id: u16,
    content: &[u8],
) -> Result<()> {
    let content_length = content.len() as u16;
    let padding_length = ((8 - (content_length % 8)) % 8) as u8;

    let header = [
        FCGI_VERSION_1,
        record_type,
        (request_id >> 8) as u8,
        (request_id & 0xff) as u8,
        (content_length >> 8) as u8,
        (content_length & 0xff) as u8,
        padding_length,
        0, // reserved
    ];

    stream.write_all(&header).await?;
    stream.write_all(content).await?;

    if padding_length > 0 {
        let padding = vec![0u8; padding_length as usize];
        stream.write_all(&padding).await?;
    }

    Ok(())
}

fn build_begin_request(role: u16) -> Vec<u8> {
    vec![
        (role >> 8) as u8,
        (role & 0xff) as u8,
        0, // flags
        0,
        0,
        0,
        0,
        0,
    ]
}

fn build_params(params: &HashMap<&str, &str>) -> Vec<u8> {
    let mut data = Vec::new();

    for (key, value) in params {
        let key_bytes = key.as_bytes();
        let value_bytes = value.as_bytes();

        // Write key length
        write_length(&mut data, key_bytes.len());
        // Write value length
        write_length(&mut data, value_bytes.len());
        // Write key
        data.extend_from_slice(key_bytes);
        // Write value
        data.extend_from_slice(value_bytes);
    }

    data
}

fn write_length(data: &mut Vec<u8>, length: usize) {
    if length < 128 {
        data.push(length as u8);
    } else {
        data.push(((length >> 24) | 0x80) as u8);
        data.push((length >> 16) as u8);
        data.push((length >> 8) as u8);
        data.push(length as u8);
    }
}

fn parse_cgi_response(data: &[u8]) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    // Find the end of headers (double CRLF)
    let header_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(0);

    if header_end == 0 {
        // No headers, just body
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=UTF-8")
            .body(
                Full::new(Bytes::from(data.to_vec()))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap());
    }

    let headers_data = &data[..header_end];
    let body_data = &data[header_end + 4..];

    // Parse headers
    let headers_str = String::from_utf8_lossy(headers_data);
    let mut response_builder = Response::builder();
    let mut status = StatusCode::OK;

    for line in headers_str.lines() {
        if line.is_empty() {
            continue;
        }

        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();

            if name.eq_ignore_ascii_case("Status") {
                // Parse status code
                if let Some(code_str) = value.split_whitespace().next() {
                    if let Ok(code) = code_str.parse::<u16>() {
                        if let Ok(status_code) = StatusCode::from_u16(code) {
                            status = status_code;
                        }
                    }
                }
            } else {
                response_builder = response_builder.header(name, value);
            }
        }
    }

    Ok(response_builder
        .status(status)
        .body(
            Full::new(Bytes::from(body_data.to_vec()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap())
}
