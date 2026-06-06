//! # NEXUS Node
//!
//! Full node implementation for the NEXUS dual-chain blockchain.
//! Integrates all components into a cohesive node.

use nexus_anchor::AnchorChain;
use nexus_active::ActiveChain;
use nexus_core::{BlockHeight, Hash256, NexusError, SignedTransaction};
use nexus_crypto::DilithiumKeypair;
use nexus_sentinel::SecurityMonitor;
use std::sync::Arc;

pub mod config;
pub mod rpc;

/// Node role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole {
    /// Full validator node (L1 + L2)
    Validator,
    /// L2 Sequencer
    Sequencer,
    /// Full node (no validation)
    FullNode,
    /// Light client
    LightClient,
}

/// NEXUS Node
pub struct NexusNode {
    /// Node role
    pub role: NodeRole,
    /// Anchor chain (L1)
    pub anchor: Option<Arc<AnchorChain>>,
    /// Active chain (L2)
    pub active: Option<Arc<ActiveChain>>,
    /// Security monitor
    pub security: Arc<SecurityMonitor>,
    /// Node keypair
    keypair: Arc<DilithiumKeypair>,
}

impl NexusNode {
    /// Create a new full node
    pub fn new(role: NodeRole, keypair: DilithiumKeypair) -> Self {
        let keypair = Arc::new(keypair);

        let anchor = match role {
            NodeRole::Validator | NodeRole::FullNode => {
                Some(Arc::new(AnchorChain::new(
                    nexus_anchor::AnchorChainConfig::default(),
                    (*keypair).clone(),
                )))
            }
            _ => None,
        };

        let active = match role {
            NodeRole::Validator | NodeRole::Sequencer | NodeRole::FullNode => {
                Some(Arc::new(ActiveChain::new(
                    nexus_active::ActiveChainConfig::default(),
                    (*keypair).clone(),
                )))
            }
            _ => None,
        };

        Self {
            role,
            anchor,
            active,
            security: Arc::new(SecurityMonitor::new()),
            keypair,
        }
    }

    /// Start the node
    pub async fn start(&self) -> Result<(), NexusError> {
        tracing::info!("Starting NEXUS node as {:?}", self.role);
        Ok(())
    }

    /// Stop the node
    pub async fn stop(&self) -> Result<(), NexusError> {
        tracing::info!("Stopping NEXUS node");
        Ok(())
    }

    /// Submit transaction to L2
    pub fn submit_transaction(&self, tx: SignedTransaction) -> Result<Hash256, NexusError> {
        self.active
            .as_ref()
            .ok_or(NexusError::NotImplemented("L2 not available".into()))?
            .submit_transaction(tx)
    }

    /// Get L1 height
    pub fn l1_height(&self) -> Option<BlockHeight> {
        self.anchor.as_ref().map(|a| a.height())
    }

    /// Get L2 height
    pub fn l2_height(&self) -> Option<BlockHeight> {
        self.active.as_ref().map(|a| a.height())
    }

    /// Get node info
    pub fn info(&self) -> NodeInfo {
        NodeInfo {
            role: self.role,
            l1_height: self.l1_height(),
            l2_height: self.l2_height(),
            address: self.keypair.address(),
        }
    }
}

/// Node information
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub role: NodeRole,
    pub l1_height: Option<BlockHeight>,
    pub l2_height: Option<BlockHeight>,
    pub address: nexus_core::Address,
}
