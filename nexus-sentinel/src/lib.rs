//! # NEXUS Sentinel
//!
//! Security monitoring system for the NEXUS blockchain.
//! Re-exports entropy monitoring from nexus-crypto and provides
//! additional security features.

pub use nexus_crypto::entropy::{
    EntropyMonitor, EntropyAnalysis, EntropyQuality,
    SentinelSeed, SentinelConfig, RotationReason, RotationResult,
    MIN_ENTROPY_BITS, MAX_ENTROPY_BITS,
};

use nexus_core::{Address, Hash256, NexusError, Timestamp};
use std::collections::HashMap;

/// Security event types
#[derive(Debug, Clone)]
pub enum SecurityEvent {
    /// Low entropy detected
    LowEntropy { level: f64, threshold: f64 },
    /// Key rotation triggered
    KeyRotation { old_epoch: u64, new_epoch: u64 },
    /// Suspicious activity detected
    SuspiciousActivity { address: Address, reason: String },
    /// Signature verification failure
    SignatureFailure { address: Address },
}

/// Security monitor for tracking security events
pub struct SecurityMonitor {
    events: Vec<(Timestamp, SecurityEvent)>,
    max_events: usize,
}

impl SecurityMonitor {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            max_events: 10000,
        }
    }

    pub fn record_event(&mut self, event: SecurityEvent) {
        if self.events.len() >= self.max_events {
            self.events.remove(0);
        }
        self.events.push((Timestamp::now(), event));
    }

    pub fn recent_events(&self, count: usize) -> &[(Timestamp, SecurityEvent)] {
        let start = self.events.len().saturating_sub(count);
        &self.events[start..]
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl Default for SecurityMonitor {
    fn default() -> Self {
        Self::new()
    }
}
