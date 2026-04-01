//! REST API server using Axum
//!
//! This module provides the HTTP API server for managing nodes, rules, and configuration

use axum::{
    Router,
    routing::{get, post, put},
    http::StatusCode,
    Json,
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{CorsLayer, Any};
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::api::routes::{nodes, rules, config, stats};
use crate::api::models::{NodeResponse, NodeStatus, RuleResponse, ConfigResponse, StatsResponse, ErrorResponse};

/// Application state shared across route handlers
#[derive(Debug, Clone)]
pub struct AppState {
    /// List of proxy nodes
    pub nodes: Vec<NodeResponse>,
    /// List of routing rules
    pub rules: Vec<RuleResponse>,
    /// Current configuration
    pub config: ConfigResponse,
    /// Statistics
    pub stats: StatsResponse,
    /// Whether the proxy is running
    pub running: bool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            nodes: vec![
                NodeResponse {
                    id: "node-1".to_string(),
                    name: "US Server".to_string(),
                    protocol: "shadowsocks".to_string(),
                    latency_ms: Some(120),
                    status: NodeStatus::Online,
                },
                NodeResponse {
                    id: "node-2".to_string(),
                    name: "Japan Server".to_string(),
                    protocol: "vless".to_string(),
                    latency_ms: Some(85),
                    status: NodeStatus::Online,
                },
                NodeResponse {
                    id: "node-3".to_string(),
                    name: "Singapore Server".to_string(),
                    protocol: "trojan".to_string(),
                    latency_ms: None,
                    status: NodeStatus::Unknown,
                },
            ],
            rules: vec![
                RuleResponse {
                    id: "rule-1".to_string(),
                    name: "Proxy domestic traffic".to_string(),
                    action: "accept".to_string(),
                    priority: 100,
                },
                RuleResponse {
                    id: "rule-2".to_string(),
                    name: "Block ads".to_string(),
                    action: "reject".to_string(),
                    priority: 50,
                },
                RuleResponse {
                    id: "rule-3".to_string(),
                    name: "Proxy international traffic".to_string(),
                    action: "proxy".to_string(),
                    priority: 200,
                },
            ],
            config: ConfigResponse {
                socks5_listen: Some("127.0.0.1:1080".to_string()),
                http_listen: Some("127.0.0.1:8080".to_string()),
                ebpf_interface: "eth0".to_string(),
                ebpf_enabled: true,
                node_count: 3,
                rules_config: Some("/etc/dae/rules.toml".to_string()),
            },
            stats: StatsResponse {
                total_connections: 1234,
                active_connections: 42,
                bytes_sent: 1024000000,
                bytes_received: 2048000000,
                uptime_secs: 86400,
            },
            running: true,
        }
    }
}

/// API server instance
pub struct ApiServer {
    app: Router<Arc<RwLock<AppState>>>,
    port: u16,
}

impl ApiServer {
    /// Create a new API server
    pub async fn new(port: u16) -> Self {
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        let app = Router::new()
            .route("/api/nodes", get(nodes::list_nodes))
            .route("/api/nodes/:id", get(nodes::get_node))
            .route("/api/nodes/:id/test", post(nodes::test_node))
            .route("/api/rules", get(rules::list_rules))
            .route("/api/rules/summary", get(rules::rules_summary))
            .route("/api/config", get(config::get_config))
            .route("/api/config", put(config::update_config))
            .route("/api/stats", get(stats::get_stats))
            .route("/api/health", get(stats::health_check))
            .layer(cors)
            .layer(TraceLayer::new_for_http())
            .with_state(Arc::new(RwLock::new(AppState::default())));

        Self { app, port }
    }

    /// Create API server with custom state
    pub async fn with_state(port: u16, state: AppState) -> Self {
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        let app = Router::new()
            .route("/api/nodes", get(nodes::list_nodes))
            .route("/api/nodes/:id", get(nodes::get_node))
            .route("/api/nodes/:id/test", post(nodes::test_node))
            .route("/api/rules", get(rules::list_rules))
            .route("/api/rules/summary", get(rules::rules_summary))
            .route("/api/config", get(config::get_config))
            .route("/api/config", put(config::update_config))
            .route("/api/stats", get(stats::get_stats))
            .route("/api/health", get(stats::health_check))
            .layer(cors)
            .layer(TraceLayer::new_for_http())
            .with_state(Arc::new(RwLock::new(state)));

        Self { app, port }
    }

    /// Start the API server
    pub async fn start(self) -> Result<(), ApiError> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        info!("Starting REST API server on http://{}", addr);
        
        let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| ApiError::ServerError(e.to_string()))?;
        axum::serve(listener, self.app)
            .await
            .map_err(|e| ApiError::ServerError(e.to_string()))?;
        
        Ok(())
    }
}

/// API server errors
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Server error: {0}")]
    ServerError(String),
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_response) = match &self {
            ApiError::ServerError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorResponse::new("server_error", msg),
            ),
            ApiError::InvalidRequest(msg) => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::new("invalid_request", msg),
            ),
            ApiError::NotFound(msg) => (
                StatusCode::NOT_FOUND,
                ErrorResponse::new("not_found", msg),
            ),
        };

        (status, Json(error_response)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_list_nodes() {
        let server = ApiServer::new(0).await;
        let response = server.app
            .oneshot(Request::builder().uri("/api/nodes").body(()).unwrap())
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_node_not_found() {
        let server = ApiServer::new(0).await;
        let response = server.app
            .oneshot(Request::builder().uri("/api/nodes/nonexistent").body(()).unwrap())
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_health() {
        let server = ApiServer::new(0).await;
        let response = server.app
            .oneshot(Request::builder().uri("/api/health").body(()).unwrap())
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::OK);
    }
}
