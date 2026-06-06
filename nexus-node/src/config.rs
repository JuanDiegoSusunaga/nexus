//! Node configuration

use serde::{Deserialize, Serialize};
use crate::NodeRole;

/// Node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node role
    pub role: String,
    /// Network listen address
    pub listen_addr: String,
    /// RPC server address
    pub rpc_addr: String,
    /// Data directory
    pub data_dir: String,
    /// Log level
    pub log_level: String,
    /// Bootstrap peers
    pub bootstrap_peers: Vec<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            role: "full".into(),
            listen_addr: "0.0.0.0:9000".into(),
            rpc_addr: "127.0.0.1:8545".into(),
            data_dir: "./data".into(),
            log_level: "info".into(),
            bootstrap_peers: Vec::new(),
        }
    }
}

impl NodeConfig {
    pub fn node_role(&self) -> NodeRole {
        match self.role.as_str() {
            "validator" => NodeRole::Validator,
            "sequencer" => NodeRole::Sequencer,
            "light" => NodeRole::LightClient,
            _ => NodeRole::FullNode,
        }
    }
}
