// Copyright (c) Altare Technologies Limited. All rights reserved.

use anyhow::{Context, Result};
use crate::security::{
    RateLimitConfig, RequestLimits, SecurityConfig, SlowRequestConfig, TlsAnomalyConfig,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Global server configuration
    #[serde(default)]
    pub server: ServerConfig,

    /// Domain configurations
    pub domains: HashMap<String, DomainConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    /// HTTP port (default: 80)
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// HTTPS port (default: 443)
    #[serde(default = "default_https_port")]
    pub https_port: u16,

    /// Number of worker threads (default: CPU count)
    #[serde(default)]
    pub workers: Option<usize>,

    /// Connection timeout in seconds (default: 30)
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// Maximum concurrent connections per backend (default: 1024)
    #[serde(default = "default_max_connections")]
    pub max_connections_per_backend: usize,

    /// Altare Flux security configuration
    #[serde(default)]
    pub security: SecurityConfigWrapper,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DomainConfig {
    /// Backend hosts to load balance between (optional if using static/PHP)
    #[serde(default)]
    pub backends: Vec<String>,

    /// SSL/TLS configuration
    #[serde(default)]
    pub ssl: SslConfig,

    /// Load balancing strategy (default: round_robin)
    #[serde(default)]
    pub load_balance_strategy: LoadBalanceStrategy,

    /// Health check configuration
    #[serde(default)]
    pub health_check: HealthCheckConfig,

    /// Static file serving configuration
    #[serde(default)]
    pub static_files: Option<StaticFilesConfig>,

    /// PHP-FPM configuration
    #[serde(default)]
    pub php_fpm: Option<PhpFpmConfig>,

    /// HTTP to HTTPS redirect
    #[serde(default)]
    pub redirect_to_https: bool,

    /// Custom headers to add to responses
    #[serde(default)]
    pub headers: Vec<HeaderConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StaticFilesConfig {
    /// Enable static file serving
    #[serde(default)]
    pub enabled: bool,

    /// Document root directory
    pub root: String,

    /// Try files pattern (like nginx try_files)
    #[serde(default)]
    pub try_files: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PhpFpmConfig {
    /// Enable PHP-FPM
    #[serde(default)]
    pub enabled: bool,

    /// PHP-FPM socket path
    pub socket: String,

    /// Script timeout in seconds
    #[serde(default = "default_php_timeout")]
    pub timeout: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HeaderConfig {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SslConfig {
    /// Enable SSL/TLS
    #[serde(default)]
    pub enabled: bool,

    /// Path to certificate file
    pub cert_path: Option<String>,

    /// Path to private key file
    pub key_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    RoundRobin,
    LeastConnections,
    IpHash,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthCheckConfig {
    /// Enable health checks
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Health check interval in seconds
    #[serde(default = "default_health_check_interval")]
    pub interval: u64,

    /// Health check timeout in seconds
    #[serde(default = "default_health_check_timeout")]
    pub timeout: u64,

    /// Health check path
    #[serde(default = "default_health_check_path")]
    pub path: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_port: default_http_port(),
            https_port: default_https_port(),
            workers: None,
            timeout: default_timeout(),
            max_connections_per_backend: default_max_connections(),
            security: SecurityConfigWrapper::default(),
        }
    }
}

impl Default for SslConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: None,
            key_path: None,
        }
    }
}

impl Default for LoadBalanceStrategy {
    fn default() -> Self {
        Self::RoundRobin
    }
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            interval: default_health_check_interval(),
            timeout: default_health_check_timeout(),
            path: default_health_check_path(),
        }
    }
}

fn default_http_port() -> u16 {
    80
}

fn default_https_port() -> u16 {
    443
}

fn default_timeout() -> u64 {
    30
}

fn default_max_connections() -> usize {
    1024
}

fn default_true() -> bool {
    true
}

fn default_health_check_interval() -> u64 {
    10
}

fn default_health_check_timeout() -> u64 {
    5
}

fn default_health_check_path() -> String {
    "/".to_string()
}

/// Wrapper for SecurityConfig to allow YAML deserialization
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfigWrapper {
    /// Enable Altare Flux security system
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: RateLimitConfigWrapper,

    /// Request size limits
    #[serde(default)]
    pub request_limits: RequestLimitsWrapper,

    /// Slow request protection
    #[serde(default)]
    pub slow_request_protection: SlowRequestConfigWrapper,

    /// TLS handshake anomaly detection
    #[serde(default)]
    pub tls_anomaly_detection: TlsAnomalyConfigWrapper,

    /// Block Tor exit nodes
    #[serde(default = "default_true")]
    pub block_tor: bool,

    /// Block known bot/proxy IPs
    #[serde(default = "default_true")]
    pub block_bots: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfigWrapper {
    #[serde(default = "default_rate_limit_rps")]
    pub default_rps: u32,

    #[serde(default = "default_api_rate_limit_rps")]
    pub api_rps: u32,

    #[serde(default = "default_rate_limit_window")]
    pub window_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequestLimitsWrapper {
    #[serde(default = "default_max_header_size")]
    pub max_header_size: usize,

    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    #[serde(default = "default_max_url_length")]
    pub max_url_length: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SlowRequestConfigWrapper {
    #[serde(default = "default_min_header_rate")]
    pub min_header_rate: usize,

    #[serde(default = "default_min_body_rate")]
    pub min_body_rate: usize,

    #[serde(default = "default_slow_timeout")]
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsAnomalyConfigWrapper {
    #[serde(default = "default_max_failed_handshakes")]
    pub max_failed_handshakes: u32,

    #[serde(default = "default_tls_window")]
    pub window_seconds: u64,
}

impl Default for SecurityConfigWrapper {
    fn default() -> Self {
        Self {
            enabled: true,
            rate_limit: RateLimitConfigWrapper::default(),
            request_limits: RequestLimitsWrapper::default(),
            slow_request_protection: SlowRequestConfigWrapper::default(),
            tls_anomaly_detection: TlsAnomalyConfigWrapper::default(),
            block_tor: true,
            block_bots: true,
        }
    }
}

impl Default for RateLimitConfigWrapper {
    fn default() -> Self {
        Self {
            default_rps: default_rate_limit_rps(),
            api_rps: default_api_rate_limit_rps(),
            window_seconds: default_rate_limit_window(),
        }
    }
}

impl Default for RequestLimitsWrapper {
    fn default() -> Self {
        Self {
            max_header_size: default_max_header_size(),
            max_body_size: default_max_body_size(),
            max_url_length: default_max_url_length(),
        }
    }
}

impl Default for SlowRequestConfigWrapper {
    fn default() -> Self {
        Self {
            min_header_rate: default_min_header_rate(),
            min_body_rate: default_min_body_rate(),
            timeout_seconds: default_slow_timeout(),
        }
    }
}

impl Default for TlsAnomalyConfigWrapper {
    fn default() -> Self {
        Self {
            max_failed_handshakes: default_max_failed_handshakes(),
            window_seconds: default_tls_window(),
        }
    }
}

impl From<SecurityConfigWrapper> for SecurityConfig {
    fn from(wrapper: SecurityConfigWrapper) -> Self {
        Self {
            enabled: wrapper.enabled,
            rate_limit: RateLimitConfig {
                default_rps: wrapper.rate_limit.default_rps,
                api_rps: wrapper.rate_limit.api_rps,
                window_seconds: wrapper.rate_limit.window_seconds,
            },
            request_limits: RequestLimits {
                max_header_size: wrapper.request_limits.max_header_size,
                max_body_size: wrapper.request_limits.max_body_size,
                max_url_length: wrapper.request_limits.max_url_length,
            },
            slow_request_protection: SlowRequestConfig {
                min_header_rate: wrapper.slow_request_protection.min_header_rate,
                min_body_rate: wrapper.slow_request_protection.min_body_rate,
                timeout_seconds: wrapper.slow_request_protection.timeout_seconds,
            },
            tls_anomaly_detection: TlsAnomalyConfig {
                max_failed_handshakes: wrapper.tls_anomaly_detection.max_failed_handshakes,
                window_seconds: wrapper.tls_anomaly_detection.window_seconds,
            },
            block_tor: wrapper.block_tor,
            block_bots: wrapper.block_bots,
        }
    }
}

fn default_rate_limit_rps() -> u32 {
    20
}

fn default_api_rate_limit_rps() -> u32 {
    100
}

fn default_rate_limit_window() -> u64 {
    1
}

fn default_max_header_size() -> usize {
    16384 // 16KB
}

fn default_max_body_size() -> usize {
    10485760 // 10MB
}

fn default_max_url_length() -> usize {
    2048
}

fn default_min_header_rate() -> usize {
    1024 // 1KB/s
}

fn default_min_body_rate() -> usize {
    10240 // 10KB/s
}

fn default_slow_timeout() -> u64 {
    30
}

fn default_max_failed_handshakes() -> u32 {
    5
}

fn default_tls_window() -> u64 {
    60
}

fn default_php_timeout() -> u64 {
    300 // 5 minutes
}

impl Config {
    /// Load configuration from a YAML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .context("Failed to read config file")?;

        let config: Config = serde_yaml::from_str(&content)
            .context("Failed to parse config file")?;

        config.validate()?;

        Ok(config)
    }

    /// Validate the configuration
    fn validate(&self) -> Result<()> {
        for (domain, domain_config) in &self.domains {
            let has_static = domain_config.static_files.as_ref().map(|s| s.enabled).unwrap_or(false);
            let has_php = domain_config.php_fpm.as_ref().map(|p| p.enabled).unwrap_or(false);
            let has_backends = !domain_config.backends.is_empty();

            // Must have at least one: backends, static files, or PHP
            if !has_backends && !has_static && !has_php {
                anyhow::bail!("Domain '{}' must have backends, static files, or PHP-FPM configured", domain);
            }

            if domain_config.ssl.enabled {
                if domain_config.ssl.cert_path.is_none() {
                    anyhow::bail!("Domain '{}' has SSL enabled but no cert_path specified", domain);
                }
                if domain_config.ssl.key_path.is_none() {
                    anyhow::bail!("Domain '{}' has SSL enabled but no key_path specified", domain);
                }
            }

            // Validate backend URLs
            for backend in &domain_config.backends {
                if !backend.starts_with("http://") && !backend.starts_with("https://") {
                    anyhow::bail!("Backend '{}' for domain '{}' must start with http:// or https://", backend, domain);
                }
            }

            // Validate static files config
            if let Some(static_config) = &domain_config.static_files {
                if static_config.enabled && static_config.root.is_empty() {
                    anyhow::bail!("Domain '{}' has static files enabled but no root specified", domain);
                }
            }

            // Validate PHP-FPM config
            if let Some(php_config) = &domain_config.php_fpm {
                if php_config.enabled && php_config.socket.is_empty() {
                    anyhow::bail!("Domain '{}' has PHP-FPM enabled but no socket specified", domain);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_parsing() {
        let yaml = r#"
server:
  http_port: 8080
  https_port: 8443

domains:
  example.com:
    backends:
      - http://localhost:3000
      - http://localhost:3001
    ssl:
      enabled: true
      cert_path: /path/to/cert.pem
      key_path: /path/to/key.pem
"#;

        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.server.http_port, 8080);
        assert_eq!(config.domains.len(), 1);
    }
}
