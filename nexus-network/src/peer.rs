//! Peer management

use crate::PeerId;
use nexus_core::Timestamp;
use std::collections::HashMap;

/// Peer information
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub id: PeerId,
    pub address: String,
    pub connected_at: Timestamp,
    pub last_seen: Timestamp,
    pub reputation: i32,
}

/// Peer manager
pub struct PeerManager {
    peers: HashMap<PeerId, PeerInfo>,
    max_peers: usize,
}

impl PeerManager {
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: HashMap::new(),
            max_peers,
        }
    }

    pub fn add_peer(&mut self, info: PeerInfo) -> bool {
        if self.peers.len() >= self.max_peers {
            return false;
        }
        self.peers.insert(info.id.clone(), info);
        true
    }

    pub fn remove_peer(&mut self, id: &PeerId) -> Option<PeerInfo> {
        self.peers.remove(id)
    }

    pub fn get_peer(&self, id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(id)
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn all_peers(&self) -> Vec<&PeerInfo> {
        self.peers.values().collect()
    }
}
