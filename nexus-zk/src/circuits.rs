//! ZK Circuit definitions

use nexus_core::Hash256;

/// Placeholder for state transition circuit
/// In production, this would use ark-relations to define R1CS constraints
pub struct StateTransitionCircuit {
    pub pre_state: [u8; 32],
    pub post_state: [u8; 32],
    pub tx_root: [u8; 32],
}

impl StateTransitionCircuit {
    pub fn new(pre_state: Hash256, post_state: Hash256, tx_root: Hash256) -> Self {
        Self {
            pre_state: pre_state.0,
            post_state: post_state.0,
            tx_root: tx_root.0,
        }
    }
}

/// Merkle inclusion circuit
pub struct MerkleInclusionCircuit {
    pub leaf: [u8; 32],
    pub root: [u8; 32],
    pub path: Vec<[u8; 32]>,
    pub indices: Vec<bool>,
}

/// Balance range proof circuit
pub struct BalanceProofCircuit {
    pub balance: u128,
    pub minimum: u128,
    pub blinding: [u8; 32],
}
