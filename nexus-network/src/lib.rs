//! # NEXUS Network
//!
//! P2P networking layer for the NEXUS blockchain.
//! Built on libp2p for robust peer-to-peer communication.

use nexus_core::{Block, Hash256, NexusError, SignedTransaction};
use serde::{Deserialize, Serialize};

pub mod peer;
pub mod protocol;

/// Network message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// New block announcement
    NewBlock(Block),
    /// New transaction
    NewTransaction(SignedTransaction),
    /// Block request
    GetBlock(Hash256),
    /// Block response
    Block(Option<Block>),
    /// Peer discovery
    Ping,
    /// Peer response
    Pong,
    /// Consensus message
    Consensus(Vec<u8>),
}

/// Peer identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub String);

impl PeerId {
    pub fn new(id: String) -> Self {
        Self(id)
    }
}

/// Network configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub listen_addr: String,
    pub bootstrap_peers: Vec<String>,
    pub max_peers: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/tcp/9000".into(),
            bootstrap_peers: Vec::new(),
            max_peers: 50,
        }
    }
}
