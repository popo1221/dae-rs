//! Configuration routes
//!
//! Endpoints for viewing and updating proxy configuration

use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::{ConfigResponse, ErrorResponse};
use crate::AppState;

/// Get current configuration
///
/// GET /api/config
pub async fn get_config(State(state): State<Arc<RwLock<AppState>>>) -> Json<ConfigResponse> {
    let state = state.read().await;
    Json(state.config.clone())
}

/// Update configuration
///
/// PUT /api/config
///
/// Note: This is a simplified implementation. In production,
/// you'd want to validate the config and possibly restart
/// affected services.
pub async fn update_config(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(input): Json<ConfigUpdate>,
) -> Result<Json<ConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut state = state.write().await;

    // Update config fields if provided
    if let Some(socks5) = input.socks5_listen {
        state.config.socks5_listen = Some(socks5);
    }
    if let Some(http) = input.http_listen {
        state.config.http_listen = Some(http);
    }
    if let Some(ebpf) = input.ebpf_enabled {
        state.config.ebpf_enabled = ebpf;
    }

    Ok(Json(state.config.clone()))
}

#[derive(Debug, serde::Deserialize)]
pub struct ConfigUpdate {
    socks5_listen: Option<String>,
    http_listen: Option<String>,
    ebpf_enabled: Option<bool>,
}
