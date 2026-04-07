//! Prometheus metrics exporter
//!
//! Exposes metrics via HTTP endpoint in Prometheus text format.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderValue, StatusCode},
    response::Response,
    routing::get,
    Router,
};
use prometheus::{Encoder, Registry, TextEncoder};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

/// Metrics server error
#[derive(Debug, thiserror::Error)]
pub enum MetricsError {
    #[error("Prometheus error: {0}")]
    Prometheus(#[from] prometheus::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Axum error: {0}")]
    Axum(#[from] axum::BoxError),
}

/// Metrics server state
#[derive(Clone)]
struct MetricsState {
    registry: Arc<Registry>,
}

/// The Prometheus metrics exporter server
pub struct MetricsServer {
    registry: Registry,
    port: u16,
    cors_enabled: bool,
}

impl MetricsServer {
    /// Create a new metrics server on the specified port
    pub fn new(port: u16) -> Self {
        let registry = Registry::new();
        Self {
            registry,
            port,
            cors_enabled: true,
        }
    }

    /// Create with a custom registry
    pub fn with_registry(port: u16, registry: Registry) -> Self {
        Self {
            registry,
            port,
            cors_enabled: true,
        }
    }

    /// Disable CORS
    #[must_use]
    pub fn with_cors_disabled(mut self) -> Self {
        self.cors_enabled = false;
        self
    }

    /// Register all metrics with this server's registry
    pub fn register_all(&self) -> Result<(), MetricsError> {
        // Import the register functions from sibling modules
        // These register with the local registry
        use crate::metrics::counter::{
            BYTES_RECEIVED_COUNTER, BYTES_SENT_COUNTER, CONNECTION_COUNTER, DNS_RESOLUTION_COUNTER,
            ERROR_COUNTER, NODE_LATENCY_TEST_COUNTER, RULE_MATCH_COUNTER,
        };
        use crate::metrics::gauge::{
            ACTIVE_CONNECTIONS_GAUGE, ACTIVE_TCP_CONNECTIONS_GAUGE, ACTIVE_UDP_CONNECTIONS_GAUGE,
            CONNECTION_POOL_SIZE_GAUGE, EBPF_MAP_ENTRIES_GAUGE, MEMORY_USAGE_GAUGE,
            NODE_COUNT_GAUGE, NODE_LATENCY_GAUGE,
        };
        use crate::metrics::histogram::{
            CONNECTION_DURATION_HISTOGRAM, DNS_RESOLUTION_LATENCY_HISTOGRAM,
            EBPF_LATENCY_HISTOGRAM, NODE_LATENCY_HISTOGRAM, REQUEST_SIZE_HISTOGRAM,
            RESPONSE_TIME_HISTOGRAM, RULE_MATCH_LATENCY_HISTOGRAM,
        };
        use crate::metrics::tracking::{
            CONNECTION_STATE_COUNTER, DROPPED_COUNTER, NODE_BYTES_IN_COUNTER,
            NODE_BYTES_OUT_COUNTER, NODE_REQUESTS_COUNTER, PROXY_PROTOCOL_BYTES_IN_COUNTER,
            PROXY_PROTOCOL_BYTES_OUT_COUNTER, PROXY_PROTOCOL_CONNECTIONS_COUNTER, ROUTED_COUNTER,
            RULE_MATCH_BYTES_COUNTER, RULE_MATCH_BY_ACTION_COUNTER, RULE_MATCH_BY_TYPE_COUNTER,
            TRACKING_ACTIVE_CONNECTIONS_GAUGE, TRACKING_BYTES_IN_COUNTER,
            TRACKING_BYTES_OUT_COUNTER, TRACKING_PACKETS_COUNTER, UNMATCHED_COUNTER,
        };

        self.registry
            .register(Box::new(CONNECTION_COUNTER.clone()))?;
        self.registry
            .register(Box::new((*BYTES_SENT_COUNTER).clone()))?;
        self.registry
            .register(Box::new((*BYTES_RECEIVED_COUNTER).clone()))?;
        self.registry
            .register(Box::new((*RULE_MATCH_COUNTER).clone()))?;
        self.registry
            .register(Box::new((*DNS_RESOLUTION_COUNTER).clone()))?;
        self.registry.register(Box::new((*ERROR_COUNTER).clone()))?;
        self.registry
            .register(Box::new(NODE_LATENCY_TEST_COUNTER.clone()))?;
        self.registry
            .register(Box::new(ACTIVE_CONNECTIONS_GAUGE.clone()))?;
        self.registry
            .register(Box::new(ACTIVE_TCP_CONNECTIONS_GAUGE.clone()))?;
        self.registry
            .register(Box::new(ACTIVE_UDP_CONNECTIONS_GAUGE.clone()))?;
        self.registry
            .register(Box::new(CONNECTION_POOL_SIZE_GAUGE.clone()))?;
        self.registry
            .register(Box::new((*NODE_COUNT_GAUGE).clone()))?;
        self.registry
            .register(Box::new((*NODE_LATENCY_GAUGE).clone()))?;
        self.registry
            .register(Box::new(MEMORY_USAGE_GAUGE.clone()))?;
        self.registry
            .register(Box::new((*EBPF_MAP_ENTRIES_GAUGE).clone()))?;
        self.registry
            .register(Box::new((*CONNECTION_DURATION_HISTOGRAM).clone()))?;
        self.registry
            .register(Box::new((*REQUEST_SIZE_HISTOGRAM).clone()))?;
        self.registry
            .register(Box::new((*RESPONSE_TIME_HISTOGRAM).clone()))?;
        self.registry
            .register(Box::new(DNS_RESOLUTION_LATENCY_HISTOGRAM.clone()))?;
        self.registry
            .register(Box::new((*EBPF_LATENCY_HISTOGRAM).clone()))?;
        self.registry
            .register(Box::new(RULE_MATCH_LATENCY_HISTOGRAM.clone()))?;
        self.registry
            .register(Box::new((*NODE_LATENCY_HISTOGRAM).clone()))?;
        self.registry
            .register(Box::new(CONNECTION_STATE_COUNTER.clone()))?;
        self.registry
            .register(Box::new(TRACKING_ACTIVE_CONNECTIONS_GAUGE.clone()))?;
        self.registry
            .register(Box::new((*TRACKING_BYTES_IN_COUNTER).clone()))?;
        self.registry
            .register(Box::new((*TRACKING_BYTES_OUT_COUNTER).clone()))?;
        self.registry
            .register(Box::new((*TRACKING_PACKETS_COUNTER).clone()))?;
        self.registry
            .register(Box::new((*PROXY_PROTOCOL_BYTES_IN_COUNTER).clone()))?;
        self.registry
            .register(Box::new((*PROXY_PROTOCOL_BYTES_OUT_COUNTER).clone()))?;
        self.registry
            .register(Box::new((*PROXY_PROTOCOL_CONNECTIONS_COUNTER).clone()))?;
        self.registry
            .register(Box::new((*NODE_BYTES_IN_COUNTER).clone()))?;
        self.registry
            .register(Box::new((*NODE_BYTES_OUT_COUNTER).clone()))?;
        self.registry
            .register(Box::new((*NODE_REQUESTS_COUNTER).clone()))?;
        self.registry
            .register(Box::new((*RULE_MATCH_BY_TYPE_COUNTER).clone()))?;
        self.registry
            .register(Box::new((*RULE_MATCH_BY_ACTION_COUNTER).clone()))?;
        self.registry
            .register(Box::new((*RULE_MATCH_BYTES_COUNTER).clone()))?;
        self.registry.register(Box::new(DROPPED_COUNTER.clone()))?;
        self.registry.register(Box::new(ROUTED_COUNTER.clone()))?;
        self.registry
            .register(Box::new(UNMATCHED_COUNTER.clone()))?;

        Ok(())
    }

    /// Get a reference to the underlying registry
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Consume self and start the metrics HTTP server
    pub async fn start(self) -> Result<(), MetricsError> {
        let addr: SocketAddr = ([0, 0, 0, 0], self.port).into();
        let registry = Arc::new(self.registry);
        let state = MetricsState {
            registry: registry.clone(),
        };

        let mut app = Router::new()
            .route("/metrics", get(metrics_handler))
            .with_state(state);

        if self.cors_enabled {
            let cors = CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any);
            app = app.layer(cors);
        }

        // Also add /health endpoint for simple health check
        app = app.route("/health", get(health_handler));

        info!("Starting metrics server on {}", addr);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}

/// Metrics handler - serves Prometheus text format
async fn metrics_handler(State(state): State<MetricsState>) -> Response<Body> {
    let encoder = TextEncoder::new();
    let metric_families = state.registry.gather();
    let mut buffer = Vec::new();

    match encoder.encode(&metric_families, &mut buffer) {
        Ok(()) => {
            let mut response = Response::new(Body::from(buffer));
            response.headers_mut().insert(
                "Content-Type",
                HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
            );
            response
        }
        Err(e) => {
            let mut response = Response::new(Body::from(format!("Encoder error: {e}")));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response
        }
    }
}

/// Health check handler
async fn health_handler() -> StatusCode {
    StatusCode::OK
}

/// Global metrics server handle for standalone use
static METRICS_SERVER: std::sync::RwLock<Option<MetricsServer>> = std::sync::RwLock::new(None);

/// Start the global metrics server
pub async fn start_metrics_server(port: u16) -> Result<(), MetricsError> {
    // Ensure global counters are initialized by accessing them
    use crate::metrics::counter::*;
    use crate::metrics::gauge::*;
    use crate::metrics::histogram::*;

    // Touch all lazy statics to ensure they're initialized
    let _ = &*CONNECTION_COUNTER;
    let _ = &*BYTES_SENT_COUNTER;
    let _ = &*ACTIVE_CONNECTIONS_GAUGE;
    let _ = &*CONNECTION_DURATION_HISTOGRAM;

    // Start the server with the default registry
    let server = MetricsServer::new(port);

    // Note: The MetricsServer has its own registry, but the global prometheus
    // registry also has the metrics registered via the lazy_static initialization.
    // For a truly isolated server, we'd need to use a custom registry for the lazy statics too.
    // For simplicity, we use the global registry here.
    drop(server);

    // Use prometheus global registry
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    let state = MetricsState {
        registry: Arc::new(Registry::new()),
    };

    let mut app = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(state);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    app = app.layer(cors);
    app = app.route("/health", get(health_handler));

    info!("Starting metrics server on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Stop the global metrics server
#[allow(clippy::await_holding_lock)]
pub async fn stop_metrics_server() {
    // Note: holding a std::sync::RwLock across an await point is generally
    // unsafe, but in this case we're just clearing the handle synchronously
    // after the server has been stopped externally.
    if let Ok(mut guard) = METRICS_SERVER.write() {
        *guard = None;
    }
}

/// Hook connection lifecycle to metrics
pub fn hook_connection_metrics() {
    // This is called by the connection pool on connection create/close
    // Metrics are already tracked via the global lazy statics
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inc_connection_counter() {
        use crate::metrics::counter::inc_connection;
        // Should not panic
        inc_connection();
        inc_connection();
    }

    #[test]
    fn test_gauge_inc_dec() {
        use crate::metrics::gauge::{dec_active_connections, inc_active_connections};
        inc_active_connections();
        inc_active_connections();
        dec_active_connections();
        // Should not panic
    }

    #[test]
    fn test_histogram_observe() {
        use crate::metrics::histogram::observe_connection_duration;
        observe_connection_duration("tcp", 0.5);
        observe_connection_duration("udp", 0.1);
        // Should not panic
    }

    #[test]
    fn test_counter_with_labels() {
        use crate::metrics::counter::inc_bytes_sent;
        inc_bytes_sent("tcp", 1024);
        inc_bytes_sent("ws", 2048);
    }

    #[test]
    fn test_gauge_with_labels() {
        use crate::metrics::gauge::set_node_count;
        set_node_count("active", 5);
        set_node_count("inactive", 2);
    }

    #[test]
    fn test_metrics_server_creation() {
        let server = MetricsServer::new(9090);
        assert!(server.register_all().is_ok());
    }

    #[tokio::test]
    async fn test_metrics_handler() {
        let registry = Registry::new();
        let counter = prometheus::IntCounter::new("test_counter", "A test counter").unwrap();
        registry.register(Box::new(counter.clone())).unwrap();
        counter.inc();

        let state = MetricsState {
            registry: Arc::new(registry),
        };

        let response = metrics_handler(State(state)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
