// Copyright (c) Altare Technologies Limited. All rights reserved.

use crate::config::HealthCheckConfig;
use crate::load_balancer::{Backend, LoadBalancerManager};
use crate::proxy::health_check_backend;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, info, warn};

/// Health checker for monitoring backend health
pub struct HealthChecker {
    lb_manager: Arc<LoadBalancerManager>,
}

impl HealthChecker {
    pub fn new(lb_manager: Arc<LoadBalancerManager>) -> Self {
        Self { lb_manager }
    }

    /// Start health checking for all domains
    pub async fn start(self: Arc<Self>) {
        let balancers = self.lb_manager.get_all_balancers().await;

        for (domain, lb) in balancers {
            for backend in lb.get_backends() {
                let backend = backend.clone();
                let domain = domain.clone();
                let checker = self.clone();

                tokio::spawn(async move {
                    // Default health check config
                    let config = HealthCheckConfig::default();
                    checker.check_backend_loop(domain, backend, config).await;
                });
            }
        }

        info!("Health checker started");
    }

    /// Continuously check a single backend
    async fn check_backend_loop(
        &self,
        domain: String,
        backend: Backend,
        config: HealthCheckConfig,
    ) {
        if !config.enabled {
            return;
        }

        let mut check_interval = interval(Duration::from_secs(config.interval));

        loop {
            check_interval.tick().await;

            let is_healthy =
                health_check_backend(&backend.url, &config.path, config.timeout).await;

            let was_healthy = backend.is_healthy();

            if is_healthy != was_healthy {
                if is_healthy {
                    info!(
                        "Backend {} for domain {} is now healthy",
                        backend.url, domain
                    );
                } else {
                    warn!(
                        "Backend {} for domain {} is now unhealthy",
                        backend.url, domain
                    );
                }
                backend.set_healthy(is_healthy);
            } else {
                debug!(
                    "Backend {} for domain {} health status: {}",
                    backend.url,
                    domain,
                    if is_healthy { "healthy" } else { "unhealthy" }
                );
            }
        }
    }
}

/// Initialize health checking for all configured domains
pub async fn initialize_health_checks(lb_manager: Arc<LoadBalancerManager>) {
    let health_checker = Arc::new(HealthChecker::new(lb_manager));
    health_checker.start().await;
}
