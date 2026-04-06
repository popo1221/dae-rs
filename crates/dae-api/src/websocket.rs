//! WebSocket API for real-time dashboard updates
//!
//! This module provides WebSocket-based API for real-time dashboard monitoring.
//! It streams connection updates, statistics, and node status to connected clients.

use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::Response,
    routing::get,
    Router,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;
use tokio::sync::{broadcast, RwLock};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};

use super::models::{NodeStatus as ApiNodeStatus, StatsResponse as ApiStatsResponse};

/// Dashboard update types sent to WebSocket clients
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum DashboardUpdate {
    /// New connection established
    ConnectionNew { id: String, info: ConnectionInfo },
    /// Connection closed
    ConnectionClose { id: String },
    /// Statistics update
    StatsUpdate { stats: ApiStatsResponse },
    /// Node status change
    NodeUpdate {
        node_id: String,
        status: ApiNodeStatus,
    },
}

/// Information about a single connection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionInfo {
    pub id: String,
    pub protocol: String,
    pub source_addr: String,
    pub dest_addr: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub start_time: u64,
    pub state: String,
}

/// WebSocket dashboard state shared across connections
pub struct DashboardState {
    /// Broadcast channel for sending updates to all connected clients
    tx: broadcast::Sender<DashboardUpdate>,
    /// Connection registry
    connections: RwLock<HashMap<String, ConnectionInfo>>,
    /// Statistics
    stats: RwLock<ApiStatsResponse>,
    /// Node statuses
    nodes: RwLock<HashMap<String, ApiNodeStatus>>,
}

impl DashboardState {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1000);
        Self {
            tx,
            connections: RwLock::new(HashMap::new()),
            stats: RwLock::new(ApiStatsResponse {
                total_connections: 0,
                active_connections: 0,
                bytes_sent: 0,
                bytes_received: 0,
                uptime_secs: 0,
            }),
            nodes: RwLock::new(HashMap::new()),
        }
    }

    /// Subscribe to dashboard updates
    pub fn subscribe(&self) -> broadcast::Receiver<DashboardUpdate> {
        self.tx.subscribe()
    }

    /// Broadcast an update to all connected clients
    async fn broadcast(&self, update: DashboardUpdate) {
        if self.tx.send(update).is_err() {
            warn!("No active WebSocket connections to broadcast to");
        }
    }

    /// Register a new connection
    pub async fn register_connection(&self, info: ConnectionInfo) {
        let id = info.id.clone();
        self.connections
            .write()
            .await
            .insert(id.clone(), info.clone());

        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_connections += 1;
        stats.active_connections += 1;

        // Broadcast to all subscribers
        self.broadcast(DashboardUpdate::ConnectionNew { id, info })
            .await;
    }

    /// Unregister a connection
    pub async fn unregister_connection(&self, id: &str) {
        if self.connections.write().await.remove(id).is_some() {
            let mut stats = self.stats.write().await;
            stats.active_connections = stats.active_connections.saturating_sub(1);

            self.broadcast(DashboardUpdate::ConnectionClose { id: id.to_string() })
                .await;
        }
    }

    /// Update statistics
    pub async fn update_stats(&self, stats: ApiStatsResponse) {
        *self.stats.write().await = stats.clone();
        self.broadcast(DashboardUpdate::StatsUpdate { stats }).await;
    }

    /// Update node status
    pub async fn update_node_status(&self, node_id: String, status: ApiNodeStatus) {
        *self
            .nodes
            .write()
            .await
            .entry(node_id.clone())
            .or_insert(status.clone()) = status.clone();
        self.broadcast(DashboardUpdate::NodeUpdate { node_id, status })
            .await;
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> ApiStatsResponse {
        self.stats.read().await.clone()
    }

    /// Get all active connections
    pub async fn get_connections(&self) -> Vec<ConnectionInfo> {
        self.connections.read().await.values().cloned().collect()
    }
}

impl Default for DashboardState {
    fn default() -> Self {
        Self::new()
    }
}

/// Global dashboard state instance
static DASHBOARD_STATE: OnceLock<DashboardState> = OnceLock::new();

/// Get a clone of the global dashboard state
pub fn get_dashboard_state() -> &'static DashboardState {
    DASHBOARD_STATE.get_or_init(DashboardState::new)
}

/// Create a shared reference to dashboard state
pub fn shared_dashboard_state() -> Arc<DashboardState> {
    Arc::new(DashboardState::new())
}

/// WebSocket upgrade handler for dashboard
pub async fn dashboard_handler(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(dashboard_socket)
}

/// Handle WebSocket connection for dashboard
async fn dashboard_socket(socket: WebSocket) {
    let (mut sender, mut receiver) = socket.split();
    let state = get_dashboard_state();
    let mut rx = state.subscribe();

    info!("New dashboard WebSocket connection established");

    // Send initial state
    let initial_stats = state.get_stats().await;
    let initial_connections = state.get_connections().await;

    // Send initial stats
    if sender
        .send(Message::Text(
            serde_json::to_string(&DashboardUpdate::StatsUpdate {
                stats: initial_stats,
            })
            .unwrap_or_default(),
        ))
        .await
        .is_err()
    {
        error!("Failed to send initial stats to dashboard client");
        return;
    }

    // Send initial connections
    for conn in initial_connections {
        if sender
            .send(Message::Text(
                serde_json::to_string(&DashboardUpdate::ConnectionNew {
                    id: conn.id.clone(),
                    info: conn,
                })
                .unwrap_or_default(),
            ))
            .await
            .is_err()
        {
            break;
        }
    }

    // Forward updates to the client
    loop {
        tokio::select! {
            // Receive update from broadcast channel and send to client
            update = rx.recv() => {
                match update {
                    Ok(update) => {
                        let msg = serde_json::to_string(&update).unwrap_or_default();
                        if sender.send(Message::Text(msg)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Dashboard update lagged by {} messages", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
            // Handle messages from client
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        // Handle client commands
                        if let Err(e) = handle_client_message(&text).await {
                            error!("Error handling client message: {}", e);
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    info!("Dashboard WebSocket connection closed");
}

/// Handle incoming messages from dashboard clients
async fn handle_client_message(msg: &str) -> Result<(), String> {
    // Parse client command
    #[derive(Deserialize)]
    #[serde(tag = "cmd", rename_all = "camelCase")]
    enum ClientCommand {
        Ping,
        GetConnections,
        GetStats,
        GetNodes,
    }

    match serde_json::from_str::<ClientCommand>(msg) {
        Ok(cmd) => {
            match cmd {
                ClientCommand::Ping => {
                    // Pong is implicit - just don't close the connection
                }
                ClientCommand::GetConnections => {
                    let state = get_dashboard_state();
                    let connections = state.get_connections().await;
                    info!("Client requested connections: {} active", connections.len());
                }
                ClientCommand::GetStats => {
                    let state = get_dashboard_state();
                    let _stats = state.get_stats().await;
                }
                ClientCommand::GetNodes => {
                    // Return node list
                }
            }
            Ok(())
        }
        Err(e) => Err(format!("Invalid command: {}", e)),
    }
}

/// Subscribe to connection updates for broadcasting to WebSocket clients
pub async fn subscribe_connection_updates() -> broadcast::Receiver<DashboardUpdate> {
    get_dashboard_state().subscribe()
}

/// Create the dashboard router with WebSocket endpoint
pub fn create_dashboard_router() -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/ws", get(dashboard_handler))
        .layer(cors)
}

/// Start the dashboard HTTP server
pub async fn start_dashboard_server(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let app = create_dashboard_router();

    info!("Starting dashboard WebSocket server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Dashboard state management functions for integration with proxy
pub mod state {
    use super::*;

    /// Called when a new connection is established
    pub async fn on_connection_open(info: ConnectionInfo) {
        get_dashboard_state().register_connection(info).await;
    }

    /// Called when a connection is closed
    pub async fn on_connection_close(id: &str) {
        get_dashboard_state().unregister_connection(id).await;
    }

    /// Called when statistics are updated
    pub async fn on_stats_update(stats: ApiStatsResponse) {
        get_dashboard_state().update_stats(stats).await;
    }

    /// Called when a node's status changes
    pub async fn on_node_status_change(node_id: String, status: ApiNodeStatus) {
        get_dashboard_state()
            .update_node_status(node_id, status)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dashboard_state_creation() {
        let state = DashboardState::new();
        let stats = state.get_stats().await;

        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.active_connections, 0);
    }

    #[tokio::test]
    async fn test_register_connection() {
        let state = DashboardState::new();

        let info = ConnectionInfo {
            id: "conn-1".to_string(),
            protocol: "tcp".to_string(),
            source_addr: "127.0.0.1:12345".to_string(),
            dest_addr: "127.0.0.1:8080".to_string(),
            bytes_in: 0,
            bytes_out: 0,
            start_time: 0,
            state: "active".to_string(),
        };

        state.register_connection(info.clone()).await;

        let connections = state.get_connections().await;
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].id, "conn-1");

        let stats = state.get_stats().await;
        assert_eq!(stats.active_connections, 1);
    }

    #[tokio::test]
    async fn test_unregister_connection() {
        let state = DashboardState::new();

        let info = ConnectionInfo {
            id: "conn-1".to_string(),
            protocol: "tcp".to_string(),
            source_addr: "127.0.0.1:12345".to_string(),
            dest_addr: "127.0.0.1:8080".to_string(),
            bytes_in: 0,
            bytes_out: 0,
            start_time: 0,
            state: "active".to_string(),
        };

        state.register_connection(info.clone()).await;
        state.unregister_connection("conn-1").await;

        let connections = state.get_connections().await;
        assert_eq!(connections.len(), 0);
    }

    #[tokio::test]
    async fn test_subscribe_and_broadcast() {
        let state = DashboardState::new();
        let mut rx = state.subscribe();

        let update = DashboardUpdate::StatsUpdate {
            stats: ApiStatsResponse {
                total_connections: 1,
                active_connections: 1,
                bytes_sent: 100,
                bytes_received: 200,
                uptime_secs: 60,
            },
        };

        state.broadcast(update.clone()).await;

        let received = rx.recv().await;
        assert!(received.is_ok());
    }

    #[tokio::test]
    async fn test_node_status_update() {
        let state = DashboardState::new();

        state
            .update_node_status("node-1".to_string(), ApiNodeStatus::Online)
            .await;

        state
            .update_node_status("node-1".to_string(), ApiNodeStatus::Offline)
            .await;
    }

    #[test]
    fn test_dashboard_update_serialization() {
        let update = DashboardUpdate::ConnectionNew {
            id: "test-conn".to_string(),
            info: ConnectionInfo {
                id: "test-conn".to_string(),
                protocol: "tcp".to_string(),
                source_addr: "127.0.0.1:12345".to_string(),
                dest_addr: "127.0.0.1:8080".to_string(),
                bytes_in: 100,
                bytes_out: 200,
                start_time: 1234567890,
                state: "active".to_string(),
            },
        };

        let json = serde_json::to_string(&update).unwrap();
        assert!(json.contains("connectionNew"));
        assert!(json.contains("test-conn"));
    }
}
