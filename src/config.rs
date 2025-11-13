// Copyright (c) Altare Technologies Limited. All rights reserved.

use anyhow::{Context, Result};
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
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DomainConfig {
    /// Backend hosts to load balance between
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
            if domain_config.backends.is_empty() {
                anyhow::bail!("Domain '{}' has no backend hosts configured", domain);
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
