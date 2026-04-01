//! Node management routes
//!
//! Endpoints for listing and managing proxy nodes

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::api::models::NodeResponse;
use crate::api::AppState;

/// List all nodes
///
/// GET /api/nodes
pub async fn list_nodes(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<Vec<NodeResponse>> {
    let state = state.read().await;
    Json(state.nodes.clone())
}

/// Get a specific node by ID
///
/// GET /api/nodes/:id
pub async fn get_node(
    State(state): State<Arc<RwLock<AppState>>>,
    Path(id): Path<String>,
) -> Result<Json<NodeResponse>, StatusCode> {
    let state = state.read().await;
    state
        .nodes
        .iter()
        .find(|n| n.id == id)
        .map(|n| Json(n.clone()))
        .ok_or(StatusCode::NOT_FOUND)
}

/// Test latency for a specific node
///
/// POST /api/nodes/:id/test
pub async fn test_node(
    State(state): State<Arc<RwLock<AppState>>>,
    Path(id): Path<String>,
) -> Result<Json<NodeResponse>, StatusCode> {
    let mut state = state.write().await;
    
    if let Some(node) = state.nodes.iter_mut().find(|n| n.id == id) {
        // Simulate latency test - in real implementation this would ping the node
        let latency = Some(42);
        node.latency_ms = latency;
        Ok(Json(node.clone()))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
