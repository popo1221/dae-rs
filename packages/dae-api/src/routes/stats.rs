//! Statistics routes
//!
//! Endpoints for viewing proxy statistics and health

use axum::{
    extract::State,
    Json,
};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::{HealthResponse, StatsResponse};
use crate::AppState;

/// Get proxy statistics
///
/// GET /api/stats
pub async fn get_stats(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<StatsResponse> {
    let state = state.read().await;
    Json(state.stats.clone())
}

/// Get health status
///
/// GET /api/health
pub async fn health_check(
    State(state): State<Arc<RwLock<AppState>>>,
) -> Json<HealthResponse> {
    let state = state.read().await;
    Json(HealthResponse {
        status: if state.running { "healthy".to_string() } else { "stopped".to_string() },
        uptime_secs: state.stats.uptime_secs,
        version: "0.1.0".to_string(),
    })
}
