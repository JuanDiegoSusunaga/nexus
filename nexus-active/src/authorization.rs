//! Shared local key and emergency policy. Archives contain public authenticated records only.
use nexus_core::{checkpoint, Address, ChainId, Hash256, NexusError, SignedTransaction, Timestamp};
use nexus_crypto::{KeyRegistry, RegistryCheckpoint, RecoveryPolicy, EmergencyFreezeRequest,
    EmergencyFreezeReceipt, registry::{RegistryEvent, RotationRecord}};
use parking_lot::RwLock;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::sync::Arc;

pub(crate) type SharedAuthorization = Arc<RwLock<AuthorizationState>>;

#[derive(Clone)]
pub(crate) struct AuthorizationState {
    pub(crate) registry: KeyRegistry,
    chain_id: ChainId,
    recovery: RecoveryPolicy,
    freezes: Vec<EmergencyFreezeReceipt>,
}

impl AuthorizationState {
    pub(crate) fn new(chain_id: ChainId, registry: KeyRegistry, recovery: RecoveryPolicy) -> Result<Self, NexusError> {
        let state = Self { registry, chain_id, recovery, freezes: Vec::new() };
        state.check_key_separation()?;
        Ok(state)
    }

    pub(crate) fn empty(chain_id: ChainId, recovery: RecoveryPolicy) -> Self {
        Self { registry: KeyRegistry::new(), chain_id, recovery, freezes: Vec::new() }
    }

    fn check_key_separation(&self) -> Result<(), NexusError> {
        for record in self.registry.records() {
            let conflict = match &record.body.event {
                RegistryEvent::Enrollment { key, .. } => self.recovery.is_recovery_key(key.public_key.as_bytes()),
                RegistryEvent::Rotation { replacements, .. } => replacements.iter()
                    .any(|(_, key)| self.recovery.is_recovery_key(key.as_bytes())),
                RegistryEvent::Retirement { .. } => false,
            };
            if conflict {
                return Err(NexusError::SecurityViolation("Recovery keys cannot be operational signing keys".into()));
            }
        }
        Ok(())
    }

    pub(crate) fn matches_context(&self, chain_id: ChainId, recovery: &RecoveryPolicy) -> Result<bool, NexusError> {
        Ok(self.chain_id == chain_id && checkpoint::encode(&self.recovery)? == checkpoint::encode(recovery)?)
    }

    pub(crate) fn verify_transaction_at(&self, tx: &SignedTransaction, at: Timestamp) -> Result<bool, NexusError> {
        if tx.transaction.chain_id != self.chain_id { return Err(NexusError::InvalidChainId); }
        if self.freeze_status(&tx.sender).is_some() || self.recovery.is_recovery_key(&tx.public_key) {
            return Ok(false);
        }
        nexus_crypto::signer::verify_registered_transaction_at(tx, &self.registry, at)
    }

    pub(crate) fn apply_key_record(&mut self, record: RotationRecord) -> Result<(), NexusError> {
        let mut next = self.clone();
        next.registry.apply_record(record)?;
        next.check_key_separation()?;
        *self = next;
        Ok(())
    }

    pub(crate) fn freeze_status(&self, identity: &Address) -> Option<&EmergencyFreezeReceipt> {
        self.freezes.iter().find(|receipt| receipt.request.body.identity == *identity)
    }

    pub(crate) fn apply_emergency_freeze_at(&mut self, request: EmergencyFreezeRequest, at: Timestamp)
        -> Result<EmergencyFreezeReceipt, NexusError> {
        self.recovery.verify_freeze(&request, self.chain_id, at)?;
        if self.freeze_status(&request.body.identity).is_some() {
            return Err(NexusError::SecurityViolation("Identity already frozen; repeated emergency request".into()));
        }
        let receipt = EmergencyFreezeReceipt { request, accepted_at: at };
        self.freezes.push(receipt.clone());
        Ok(receipt)
    }
}

#[derive(Serialize, Deserialize)]
struct AuthorizationArchive {
    version: u16,
    chain_id: ChainId,
    recovery: RecoveryPolicy,
    registry: Vec<u8>,
    freezes: Vec<EmergencyFreezeReceipt>,
}

pub(crate) fn serialize<S: Serializer>(state: &SharedAuthorization, serializer: S) -> Result<S::Ok, S::Error> {
    let state = state.read();
    AuthorizationArchive { version: 1, chain_id: state.chain_id, recovery: state.recovery.clone(),
        registry: state.registry.to_bytes().map_err(serde::ser::Error::custom)?, freezes: state.freezes.clone() }
        .serialize(serializer)
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SharedAuthorization, D::Error> {
    let archive = AuthorizationArchive::deserialize(deserializer)?;
    let restore = || -> Result<AuthorizationState, NexusError> {
        if archive.version != 1 { return Err(NexusError::StateError("Unknown authorization archive version".into())); }
        let registry = KeyRegistry::from_bytes(&archive.registry, RegistryCheckpoint { records: 0, head: Hash256::ZERO })?;
        let mut state = AuthorizationState::new(archive.chain_id, registry, archive.recovery)?;
        for receipt in archive.freezes {
            // Accepted freezes remain effective after their request's submission window expires.
            state.apply_emergency_freeze_at(receipt.request, receipt.accepted_at)?;
        }
        Ok(state)
    };
    Ok(Arc::new(RwLock::new(restore().map_err(serde::de::Error::custom)?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::SignatureScheme;
    use nexus_crypto::{DilithiumKeypair, RecoveryAuthority};

    #[derive(Deserialize)]
    struct Restored { #[serde(with = "super")] state: SharedAuthorization }

    fn archive() -> AuthorizationArchive {
        let operational = DilithiumKeypair::from_seed(&[1; 32], SignatureScheme::Dilithium3).unwrap();
        let guardian = DilithiumKeypair::from_seed(&[2; 32], SignatureScheme::Dilithium3).unwrap();
        let domain = Hash256::hash(b"archive-test");
        let recovery = RecoveryPolicy::new(domain, vec![RecoveryAuthority {
            identity: operational.address(), public_key: guardian.public_key().clone() }]).unwrap();
        let request = EmergencyFreezeRequest::sign(ChainId::LOCAL, domain, operational.address(),
            Timestamp(100), Timestamp(200), &guardian).unwrap();
        AuthorizationArchive { version: 1, chain_id: ChainId::LOCAL, recovery,
            registry: KeyRegistry::new().to_bytes().unwrap(),
            freezes: vec![EmergencyFreezeReceipt { request, accepted_at: Timestamp(150) }] }
    }

    #[test]
    fn archived_freeze_remains_effective_after_submission_window_expires() {
        let archive = archive(); let identity = archive.freezes[0].request.body.identity;
        assert!(Timestamp::now() > archive.freezes[0].request.body.expires_at);
        let restored: Restored = checkpoint::decode(&checkpoint::encode(&archive).unwrap()).unwrap();
        assert!(restored.state.read().freeze_status(&identity).is_some());
    }

    #[test]
    fn forged_duplicate_or_invalid_time_receipts_are_rejected_on_restore() {
        for variant in 0..6 {
            let mut archive = archive();
            match variant {
                0 => archive.freezes[0].request.body.identity = Address::ZERO,
                1 => archive.freezes.push(archive.freezes[0].clone()),
                2 => archive.freezes[0].accepted_at = Timestamp(201),
                3 => archive.recovery = RecoveryPolicy::default(),
                4 => archive.chain_id = ChainId::TESTNET,
                _ => archive.version = 2,
            }
            assert!(checkpoint::decode::<Restored>(&checkpoint::encode(&archive).unwrap()).is_err());
        }
    }
}
