// Copyright (c) Altare Technologies Limited. All rights reserved.

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Seek};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// Load SSL certificates and keys for multiple domains
pub struct SslManager {
    acceptors: HashMap<String, TlsAcceptor>,
}

impl SslManager {
    pub fn new() -> Self {
        Self {
            acceptors: HashMap::new(),
        }
    }

    /// Add a domain with SSL configuration
    pub fn add_domain(
        &mut self,
        domain: String,
        cert_path: &str,
        key_path: &str,
    ) -> Result<()> {
        let config = load_ssl_config(cert_path, key_path)
            .context(format!("Failed to load SSL config for domain: {}", domain))?;

        let acceptor = TlsAcceptor::from(Arc::new(config));
        self.acceptors.insert(domain, acceptor);

        Ok(())
    }

    /// Get the TLS acceptor for a specific domain (for future SNI support)
    #[allow(dead_code)]
    pub fn get_acceptor(&self, domain: &str) -> Option<&TlsAcceptor> {
        self.acceptors.get(domain)
    }

    /// Get the first available TLS acceptor
    pub fn get_first_acceptor(&self) -> Option<&TlsAcceptor> {
        self.acceptors.values().next()
    }

    /// Check if any domains have SSL configured
    pub fn has_ssl_domains(&self) -> bool {
        !self.acceptors.is_empty()
    }
}

impl Default for SslManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Load SSL configuration from certificate and key files
fn load_ssl_config(cert_path: &str, key_path: &str) -> Result<ServerConfig> {
    // Load certificates
    let cert_file = File::open(cert_path)
        .context(format!("Failed to open certificate file: {}", cert_path))?;
    let mut cert_reader = BufReader::new(cert_file);

    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificate file")?;

    if certs.is_empty() {
        anyhow::bail!("No certificates found in {}", cert_path);
    }

    // Load private key
    let key_file = File::open(key_path)
        .context(format!("Failed to open private key file: {}", key_path))?;
    let mut key_reader = BufReader::new(key_file);

    let key = load_private_key(&mut key_reader)
        .context("Failed to load private key")?;

    // Build TLS configuration
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build TLS configuration")?;

    Ok(config)
}

/// Load private key from PEM file
fn load_private_key(reader: &mut BufReader<File>) -> Result<PrivateKeyDer<'static>> {
    // Try to read as PKCS8 first
    let keys: Result<Vec<_>, _> = rustls_pemfile::pkcs8_private_keys(reader).collect();

    if let Ok(mut keys) = keys {
        if !keys.is_empty() {
            return Ok(PrivateKeyDer::Pkcs8(keys.remove(0)));
        }
    }

    // Reset reader
    reader.seek(std::io::SeekFrom::Start(0))?;

    // Try RSA private key format
    let keys: Result<Vec<_>, _> = rustls_pemfile::rsa_private_keys(reader).collect();

    if let Ok(mut keys) = keys {
        if !keys.is_empty() {
            return Ok(PrivateKeyDer::Pkcs1(keys.remove(0)));
        }
    }

    anyhow::bail!("No private key found in PEM file")
}
