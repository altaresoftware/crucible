// Copyright (c) Altare Technologies Limited. All rights reserved.

use crate::config::{DomainConfig, LoadBalanceStrategy};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct Backend {
    pub url: String,
    pub healthy: Arc<AtomicBool>,
    pub active_connections: Arc<AtomicUsize>,
}

impl Backend {
    pub fn new(url: String) -> Self {
        Self {
            url,
            healthy: Arc::new(AtomicBool::new(true)),
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    pub fn set_healthy(&self, healthy: bool) {
        self.healthy.store(healthy, Ordering::Relaxed);
    }

    pub fn increment_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get_active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }
}

pub struct LoadBalancer {
    backends: Vec<Backend>,
    strategy: LoadBalanceStrategy,
    round_robin_counter: AtomicUsize,
    #[allow(dead_code)]
    connection_limits: usize,
}

impl LoadBalancer {
    pub fn new(config: &DomainConfig, max_connections: usize) -> Self {
        let backends = config
            .backends
            .iter()
            .map(|url| Backend::new(url.clone()))
            .collect();

        Self {
            backends,
            strategy: config.load_balance_strategy.clone(),
            round_robin_counter: AtomicUsize::new(0),
            connection_limits: max_connections,
        }
    }

    /// Select the next backend based on the configured strategy
    pub fn select_backend(&self, client_ip: Option<&str>) -> Option<Backend> {
        let healthy_backends: Vec<&Backend> = self
            .backends
            .iter()
            .filter(|b| b.is_healthy())
            .collect();

        if healthy_backends.is_empty() {
            return None;
        }

        match self.strategy {
            LoadBalanceStrategy::RoundRobin => self.select_round_robin(&healthy_backends),
            LoadBalanceStrategy::LeastConnections => self.select_least_connections(&healthy_backends),
            LoadBalanceStrategy::IpHash => self.select_ip_hash(&healthy_backends, client_ip),
        }
    }

    fn select_round_robin(&self, backends: &[&Backend]) -> Option<Backend> {
        let index = self.round_robin_counter.fetch_add(1, Ordering::Relaxed) % backends.len();
        backends.get(index).map(|b| (*b).clone())
    }

    fn select_least_connections(&self, backends: &[&Backend]) -> Option<Backend> {
        backends
            .iter()
            .min_by_key(|b| b.get_active_connections())
            .map(|b| (*b).clone())
    }

    fn select_ip_hash(&self, backends: &[&Backend], client_ip: Option<&str>) -> Option<Backend> {
        if let Some(ip) = client_ip {
            // Simple hash function for IP-based selection
            let hash = ip
                .bytes()
                .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
            let index = (hash as usize) % backends.len();
            backends.get(index).map(|b| (*b).clone())
        } else {
            // Fallback to round-robin if no IP available
            self.select_round_robin(backends)
        }
    }

    pub fn get_backends(&self) -> &[Backend] {
        &self.backends
    }
}

/// Global load balancer manager for all domains
pub struct LoadBalancerManager {
    balancers: Arc<RwLock<HashMap<String, Arc<LoadBalancer>>>>,
}

impl LoadBalancerManager {
    pub fn new() -> Self {
        Self {
            balancers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_domain(&self, domain: String, load_balancer: Arc<LoadBalancer>) {
        let mut balancers = self.balancers.write().await;
        balancers.insert(domain, load_balancer);
    }

    pub async fn get_balancer(&self, domain: &str) -> Option<Arc<LoadBalancer>> {
        let balancers = self.balancers.read().await;
        balancers.get(domain).cloned()
    }

    pub async fn get_all_balancers(&self) -> HashMap<String, Arc<LoadBalancer>> {
        let balancers = self.balancers.read().await;
        balancers.clone()
    }
}

impl Default for LoadBalancerManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Connection guard that automatically decrements connection count on drop
pub struct ConnectionGuard {
    backend: Backend,
}

impl ConnectionGuard {
    pub fn new(backend: Backend) -> Self {
        backend.increment_connections();
        Self { backend }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.backend.decrement_connections();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_robin() {
        let config = DomainConfig {
            backends: vec![
                "http://localhost:3000".to_string(),
                "http://localhost:3001".to_string(),
            ],
            ssl: Default::default(),
            load_balance_strategy: LoadBalanceStrategy::RoundRobin,
            health_check: Default::default(),
        };

        let lb = LoadBalancer::new(&config, 100);

        let backend1 = lb.select_backend(None).unwrap();
        let backend2 = lb.select_backend(None).unwrap();

        assert_ne!(backend1.url, backend2.url);
    }

    #[test]
    fn test_least_connections() {
        let config = DomainConfig {
            backends: vec![
                "http://localhost:3000".to_string(),
                "http://localhost:3001".to_string(),
            ],
            ssl: Default::default(),
            load_balance_strategy: LoadBalanceStrategy::LeastConnections,
            health_check: Default::default(),
        };

        let lb = LoadBalancer::new(&config, 100);

        // First backend should be selected (least connections)
        let backend = lb.select_backend(None).unwrap();
        backend.increment_connections();

        // Second backend should be selected now
        let backend2 = lb.select_backend(None).unwrap();
        assert_ne!(backend.url, backend2.url);
    }
}
