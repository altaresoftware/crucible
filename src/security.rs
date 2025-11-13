// Copyright (c) Altare Technologies Limited. All rights reserved.

use anyhow::{Context, Result};
use hyper::StatusCode;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

const TOR_LIST_URL: &str = "https://www.dan.me.uk/torlist/?full";
const BOT_LIST_URL: &str = "https://raw.githubusercontent.com/antoinevastel/avastel-bot-ips-lists/refs/heads/master/avastel-proxy-bot-ips-blocklist-5days.txt";

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Enable Altare Flux security system
    pub enabled: bool,

    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,

    /// Request size limits
    pub request_limits: RequestLimits,

    /// Slow request protection
    pub slow_request_protection: SlowRequestConfig,

    /// TLS handshake anomaly detection
    pub tls_anomaly_detection: TlsAnomalyConfig,

    /// Block Tor exit nodes
    pub block_tor: bool,

    /// Block known bot/proxy IPs
    pub block_bots: bool,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Default requests per second per IP
    pub default_rps: u32,

    /// API requests per second per IP
    pub api_rps: u32,

    /// Time window for rate limiting (seconds)
    pub window_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct RequestLimits {
    /// Maximum header size in bytes
    pub max_header_size: usize,

    /// Maximum body size in bytes
    pub max_body_size: usize,

    /// Maximum URL length
    pub max_url_length: usize,
}

#[derive(Debug, Clone)]
pub struct SlowRequestConfig {
    /// Minimum bytes per second for headers
    pub min_header_rate: usize,

    /// Minimum bytes per second for body
    pub min_body_rate: usize,

    /// Timeout for slow requests (seconds)
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct TlsAnomalyConfig {
    /// Maximum failed handshakes per IP before blocking
    pub max_failed_handshakes: u32,

    /// Time window for tracking handshakes (seconds)
    pub window_seconds: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rate_limit: RateLimitConfig {
                default_rps: 20,
                api_rps: 100,
                window_seconds: 1,
            },
            request_limits: RequestLimits {
                max_header_size: 16384,      // 16KB
                max_body_size: 10485760,     // 10MB
                max_url_length: 2048,
            },
            slow_request_protection: SlowRequestConfig {
                min_header_rate: 1024,       // 1KB/s
                min_body_rate: 10240,        // 10KB/s
                timeout_seconds: 30,
            },
            tls_anomaly_detection: TlsAnomalyConfig {
                max_failed_handshakes: 5,
                window_seconds: 60,
            },
            block_tor: true,
            block_bots: true,
        }
    }
}

/// Rate limiter entry for tracking requests
#[derive(Debug)]
struct RateLimitEntry {
    requests: Vec<Instant>,
}

impl RateLimitEntry {
    fn new() -> Self {
        Self {
            requests: Vec::new(),
        }
    }

    fn add_request(&mut self, now: Instant) {
        self.requests.push(now);
    }

    fn clean_old_requests(&mut self, now: Instant, window: Duration) {
        self.requests.retain(|&time| now.duration_since(time) < window);
    }

    fn request_count(&self) -> usize {
        self.requests.len()
    }
}

/// TLS handshake tracking entry
#[derive(Debug)]
struct TlsHandshakeEntry {
    failed_count: u32,
    last_failure: Instant,
}

/// Altare Flux Security System
pub struct AltareFlux {
    config: SecurityConfig,
    rate_limiters: Arc<RwLock<HashMap<IpAddr, RateLimitEntry>>>,
    tls_handshakes: Arc<RwLock<HashMap<IpAddr, TlsHandshakeEntry>>>,
    tor_ips: Arc<RwLock<HashSet<IpAddr>>>,
    bot_ips: Arc<RwLock<HashSet<IpAddr>>>,
    bot_cidrs: Arc<RwLock<Vec<ipnetwork::IpNetwork>>>,
}

impl AltareFlux {
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            config,
            rate_limiters: Arc::new(RwLock::new(HashMap::new())),
            tls_handshakes: Arc::new(RwLock::new(HashMap::new())),
            tor_ips: Arc::new(RwLock::new(HashSet::new())),
            bot_ips: Arc::new(RwLock::new(HashSet::new())),
            bot_cidrs: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Initialize security system (load blacklists)
    pub async fn initialize(&self) -> Result<()> {
        if !self.config.enabled {
            info!("Altare Flux security system is disabled");
            return Ok(());
        }

        info!("Initializing Altare Flux security system...");

        // Load Tor exit nodes
        if self.config.block_tor {
            match self.load_tor_nodes().await {
                Ok(count) => info!("Loaded {} Tor exit nodes", count),
                Err(e) => warn!("Failed to load Tor exit nodes: {}", e),
            }
        }

        // Load bot IPs
        if self.config.block_bots {
            match self.load_bot_ips().await {
                Ok(count) => info!("Loaded {} bot/proxy IPs and networks", count),
                Err(e) => warn!("Failed to load bot IPs: {}", e),
            }
        }

        info!("Altare Flux security system initialized");
        Ok(())
    }

    /// Load Tor exit node list
    async fn load_tor_nodes(&self) -> Result<usize> {
        let response = reqwest::get(TOR_LIST_URL)
            .await
            .context("Failed to fetch Tor list")?;

        let text = response.text().await.context("Failed to read Tor list")?;

        let mut tor_ips = self.tor_ips.write().await;
        tor_ips.clear();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Ok(ip) = line.parse::<IpAddr>() {
                tor_ips.insert(ip);
            }
        }

        Ok(tor_ips.len())
    }

    /// Load bot/proxy IP list
    async fn load_bot_ips(&self) -> Result<usize> {
        let response = reqwest::get(BOT_LIST_URL)
            .await
            .context("Failed to fetch bot list")?;

        let text = response.text().await.context("Failed to read bot list")?;

        let mut bot_ips = self.bot_ips.write().await;
        let mut bot_cidrs = self.bot_cidrs.write().await;
        bot_ips.clear();
        bot_cidrs.clear();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Format: ip_address;autonomous_system;confidence
            let parts: Vec<&str> = line.split(';').collect();
            if parts.is_empty() {
                continue;
            }

            let ip_or_cidr = parts[0];

            // Try to parse as CIDR first
            if let Ok(network) = ip_or_cidr.parse::<ipnetwork::IpNetwork>() {
                bot_cidrs.push(network);
            } else if let Ok(ip) = ip_or_cidr.parse::<IpAddr>() {
                bot_ips.insert(ip);
            }
        }

        Ok(bot_ips.len() + bot_cidrs.len())
    }

    /// Check if an IP is blocked
    pub async fn check_ip(&self, ip: IpAddr) -> Result<(), SecurityError> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check Tor
        if self.config.block_tor {
            let tor_ips = self.tor_ips.read().await;
            if tor_ips.contains(&ip) {
                debug!("Blocked Tor exit node: {}", ip);
                return Err(SecurityError::TorNodeBlocked);
            }
        }

        // Check bot IPs
        if self.config.block_bots {
            let bot_ips = self.bot_ips.read().await;
            if bot_ips.contains(&ip) {
                debug!("Blocked bot IP: {}", ip);
                return Err(SecurityError::BotBlocked);
            }

            // Check CIDR ranges
            let bot_cidrs = self.bot_cidrs.read().await;
            for network in bot_cidrs.iter() {
                if network.contains(ip) {
                    debug!("Blocked bot IP in CIDR range: {}", ip);
                    return Err(SecurityError::BotBlocked);
                }
            }
        }

        Ok(())
    }

    /// Check rate limit for an IP
    pub async fn check_rate_limit(&self, ip: IpAddr, is_api: bool) -> Result<(), SecurityError> {
        if !self.config.enabled {
            return Ok(());
        }

        // Skip rate limiting for loopback during local development
        if ip.is_loopback() {
            return Ok(());
        }

        let now = Instant::now();
        let window = Duration::from_secs(self.config.rate_limit.window_seconds);
        let limit = if is_api {
            self.config.rate_limit.api_rps
        } else {
            self.config.rate_limit.default_rps
        };

        let mut rate_limiters = self.rate_limiters.write().await;
        let entry = rate_limiters.entry(ip).or_insert_with(RateLimitEntry::new);

        entry.clean_old_requests(now, window);

        if entry.request_count() >= limit as usize {
            debug!("Rate limit exceeded for IP: {}", ip);
            return Err(SecurityError::RateLimitExceeded);
        }

        entry.add_request(now);
        Ok(())
    }

    /// Record a failed TLS handshake
    pub async fn record_failed_tls_handshake(&self, ip: IpAddr) {
        if !self.config.enabled {
            return;
        }

        let now = Instant::now();
        let window = Duration::from_secs(self.config.tls_anomaly_detection.window_seconds);

        let mut handshakes = self.tls_handshakes.write().await;
        let entry = handshakes.entry(ip).or_insert(TlsHandshakeEntry {
            failed_count: 0,
            last_failure: now,
        });

        // Reset if outside window
        if now.duration_since(entry.last_failure) > window {
            entry.failed_count = 0;
        }

        entry.failed_count += 1;
        entry.last_failure = now;

        if entry.failed_count >= self.config.tls_anomaly_detection.max_failed_handshakes {
            warn!("TLS anomaly detected for IP: {} ({} failed handshakes)", ip, entry.failed_count);
        }
    }

    /// Check if IP has TLS anomalies
    pub async fn check_tls_anomaly(&self, ip: IpAddr) -> Result<(), SecurityError> {
        if !self.config.enabled {
            return Ok(());
        }

        let now = Instant::now();
        let window = Duration::from_secs(self.config.tls_anomaly_detection.window_seconds);

        let handshakes = self.tls_handshakes.read().await;
        if let Some(entry) = handshakes.get(&ip) {
            if now.duration_since(entry.last_failure) <= window
                && entry.failed_count >= self.config.tls_anomaly_detection.max_failed_handshakes
            {
                debug!("Blocked IP with TLS anomalies: {}", ip);
                return Err(SecurityError::TlsAnomalyDetected);
            }
        }

        Ok(())
    }

    /// Validate request size limits
    pub fn validate_request_size(
        &self,
        url_length: usize,
        header_size: usize,
        body_size: usize,
    ) -> Result<(), SecurityError> {
        if !self.config.enabled {
            return Ok(());
        }

        if url_length > self.config.request_limits.max_url_length {
            return Err(SecurityError::UrlTooLong);
        }

        if header_size > self.config.request_limits.max_header_size {
            return Err(SecurityError::HeadersTooLarge);
        }

        if body_size > self.config.request_limits.max_body_size {
            return Err(SecurityError::BodyTooLarge);
        }

        Ok(())
    }

    /// Get configuration
    pub fn config(&self) -> &SecurityConfig {
        &self.config
    }
}

/// Security check errors
#[derive(Debug)]
pub enum SecurityError {
    TorNodeBlocked,
    BotBlocked,
    RateLimitExceeded,
    TlsAnomalyDetected,
    UrlTooLong,
    HeadersTooLarge,
    BodyTooLarge,
    SlowRequest,
}

impl SecurityError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            SecurityError::TorNodeBlocked => StatusCode::FORBIDDEN,
            SecurityError::BotBlocked => StatusCode::FORBIDDEN,
            SecurityError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            SecurityError::TlsAnomalyDetected => StatusCode::FORBIDDEN,
            SecurityError::UrlTooLong => StatusCode::URI_TOO_LONG,
            SecurityError::HeadersTooLarge => StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            SecurityError::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            SecurityError::SlowRequest => StatusCode::REQUEST_TIMEOUT,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            SecurityError::TorNodeBlocked => "Access denied: Tor exit nodes are not allowed",
            SecurityError::BotBlocked => "Access denied: Your IP has been identified as a bot or proxy",
            SecurityError::RateLimitExceeded => "Rate limit exceeded: Please slow down your requests",
            SecurityError::TlsAnomalyDetected => "Access denied: TLS handshake anomaly detected",
            SecurityError::UrlTooLong => "Request URL is too long",
            SecurityError::HeadersTooLarge => "Request headers are too large",
            SecurityError::BodyTooLarge => "Request body is too large",
            SecurityError::SlowRequest => "Request timeout: Connection too slow",
        }
    }
}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for SecurityError {}
