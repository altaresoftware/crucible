// Copyright (c) Altare Technologies Limited. All rights reserved.

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCertUsingSni;
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use rustls::crypto::ring;
use std::fs::File;
use std::io::{BufReader, Seek};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// Load SSL certificates and keys for multiple domains
pub struct SslManager {
    domains: Vec<(String, Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    acceptor: Option<TlsAcceptor>,
}

impl SslManager {
    pub fn new() -> Self {
        Self {
            domains: Vec::new(),
            acceptor: None,
        }
    }

    /// Add a domain with SSL configuration
    pub fn add_domain(
        &mut self,
        domain: String,
        cert_path: &str,
        key_path: &str,
    ) -> Result<()> {
        // Load certs and key and store for later SNI resolver build
        let (certs, key) = load_certs_and_key(cert_path, key_path)
            .context(format!("Failed to load SSL materials for domain: {}", domain))?;
        self.domains.push((domain, certs, key));
        Ok(())
    }

    /// Build a single TLS acceptor that selects certificates via SNI
    pub fn build_acceptor(&mut self) -> Result<()> {
        let mut resolver = ResolvesServerCertUsingSni::new();

        for (domain, certs, key) in &self.domains {
            let signing_key = ring::sign::any_supported_type(key)
                .context("Unsupported or invalid private key type")?;
            let certified_key = CertifiedKey::new(certs.clone(), signing_key);
            resolver
                .add(domain.as_str(), certified_key)
                .context(format!("Failed adding certificate for domain {}", domain))?;
        }

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));

        self.acceptor = Some(TlsAcceptor::from(Arc::new(config)));
        Ok(())
    }

    /// Check if any domains have SSL configured
    pub fn has_ssl_domains(&self) -> bool {
        !self.domains.is_empty()
    }

    /// Get the unified TLS acceptor (after build_acceptor)
    pub fn get_acceptor(&self) -> Option<&TlsAcceptor> {
        self.acceptor.as_ref()
    }
}

impl Default for SslManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Load certificate chain and private key from files
fn load_certs_and_key(cert_path: &str, key_path: &str) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
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

    let key = load_private_key(&mut key_reader).context("Failed to load private key")?;

    Ok((certs, key))
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
