//! Public, immutable emergency authorities. A request grants only a permanent L2 freeze.
use crate::{DilithiumKeypair, DilithiumPublicKey, DilithiumSignature};
use nexus_core::{Address, ChainId, Hash256, NexusError, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryAuthority {
    pub identity: Address,
    pub public_key: DilithiumPublicKey,
}

/// Constructed and deserialized through validation; no mutable authority API.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(try_from = "RecoveryPolicyData")]
pub struct RecoveryPolicy {
    domain: Hash256,
    authorities: Vec<RecoveryAuthority>,
}

#[derive(Deserialize)]
struct RecoveryPolicyData {
    domain: Hash256,
    authorities: Vec<RecoveryAuthority>,
}

impl TryFrom<RecoveryPolicyData> for RecoveryPolicy {
    type Error = NexusError;
    fn try_from(data: RecoveryPolicyData) -> Result<Self, Self::Error> {
        Self::new(data.domain, data.authorities)
    }
}

impl RecoveryPolicy {
    pub fn new(domain: Hash256, authorities: Vec<RecoveryAuthority>) -> Result<Self, NexusError> {
        if !authorities.is_empty() && domain == Hash256::ZERO {
            return Err(NexusError::ConfigError("Emergency recovery requires a nonzero deployment domain".into()));
        }
        let mut identities = HashSet::new();
        for authority in &authorities {
            DilithiumPublicKey::from_bytes(authority.public_key.as_bytes().to_vec(), authority.public_key.scheme())?;
            if !identities.insert(authority.identity) || authority.identity == authority.public_key.to_address() {
                return Err(NexusError::ConfigError("Duplicate identity or operational key used as recovery authority".into()));
            }
        }
        if authorities.iter().any(|key| identities.contains(&key.public_key.to_address())) {
            return Err(NexusError::ConfigError("Recovery and protected operational keys must be distinct".into()));
        }
        Ok(Self { domain, authorities })
    }

    pub fn domain(&self) -> Hash256 { self.domain }
    pub fn authorities(&self) -> &[RecoveryAuthority] { &self.authorities }

    pub fn is_recovery_key(&self, public_key: &[u8]) -> bool {
        self.authorities.iter().any(|authority| authority.public_key.as_bytes() == public_key)
    }

    /// Authority is selected from trusted configuration, never from the request.
    pub fn verify_freeze(&self, request: &EmergencyFreezeRequest, chain_id: ChainId, at: Timestamp)
        -> Result<(), NexusError> {
        let body = &request.body;
        if body.version != 1 || body.chain_id != chain_id || body.deployment != self.domain
            || self.domain == Hash256::ZERO || body.issued_at > at || at > body.expires_at
            || body.issued_at >= body.expires_at {
            return Err(NexusError::SecurityViolation("Invalid emergency request context or validity interval".into()));
        }
        let authority = self.authorities.iter().find(|authority| authority.identity == body.identity)
            .ok_or_else(|| NexusError::SecurityViolation("No emergency authority for this identity".into()))?;
        if !authority.public_key.verify(&body.signing_bytes()?, &request.signature)? {
            return Err(NexusError::SignatureVerificationFailed(body.identity));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyFreezeBody {
    pub version: u16,
    pub chain_id: ChainId,
    pub deployment: Hash256,
    pub identity: Address,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
}

impl EmergencyFreezeBody {
    fn signing_bytes(&self) -> Result<Vec<u8>, NexusError> {
        let mut bytes = b"NEXUS_L2_EMERGENCY_FREEZE_V1".to_vec();
        bytes.extend(bincode::serialize(self)?);
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyFreezeRequest {
    pub body: EmergencyFreezeBody,
    pub signature: DilithiumSignature,
}

impl EmergencyFreezeRequest {
    pub fn sign(chain_id: ChainId, deployment: Hash256, identity: Address,
        issued_at: Timestamp, expires_at: Timestamp, authority: &DilithiumKeypair) -> Result<Self, NexusError> {
        if deployment == Hash256::ZERO || issued_at >= expires_at {
            return Err(NexusError::ConfigError("Emergency request needs a deployment and a positive validity interval".into()));
        }
        let body = EmergencyFreezeBody { version: 1, chain_id, deployment, identity, issued_at, expires_at };
        let signature = authority.sign(&body.signing_bytes()?)?;
        Ok(Self { body, signature })
    }
}

/// The local acceptance time is checkpoint metadata, not a certified external timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyFreezeReceipt {
    pub request: EmergencyFreezeRequest,
    pub accepted_at: Timestamp,
}
