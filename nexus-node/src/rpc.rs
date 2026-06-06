//! RPC server (placeholder)

/// RPC server configuration
pub struct RpcConfig {
    pub addr: String,
    pub max_connections: usize,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:8545".into(),
            max_connections: 100,
        }
    }
}
