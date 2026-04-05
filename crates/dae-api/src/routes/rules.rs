//! Rules management routes
//!
//! Endpoints for listing and managing routing rules

use axum::{extract::State, Json};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::RuleResponse;
use crate::AppState;

/// List all rules
///
/// GET /api/rules
pub async fn list_rules(State(state): State<Arc<RwLock<AppState>>>) -> Json<Vec<RuleResponse>> {
    let state = state.read().await;
    Json(state.rules.clone())
}

/// Get rules summary
///
/// GET /api/rules/summary
pub async fn rules_summary(State(state): State<Arc<RwLock<AppState>>>) -> Json<RulesSummary> {
    let state = state.read().await;
    let total = state.rules.len();
    let proxy_rules = state.rules.iter().filter(|r| r.action == "proxy").count();
    let accept_rules = state.rules.iter().filter(|r| r.action == "accept").count();
    let reject_rules = state.rules.iter().filter(|r| r.action == "reject").count();

    Json(RulesSummary {
        total,
        proxy_rules,
        accept_rules,
        reject_rules,
    })
}

#[derive(Debug, serde::Serialize)]
pub struct RulesSummary {
    total: usize,
    proxy_rules: usize,
    accept_rules: usize,
    reject_rules: usize,
}
