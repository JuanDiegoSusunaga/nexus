//! Key Management for NEXUS Blockchain
//!
//! Provides unified key management including:
//! - Key generation and storage
//! - Key rotation with epoch tracking
//! - Multi-scheme support (Dilithium variants)

use crate::{
    dilithium::{DilithiumKeypair, DilithiumPublicKey, DilithiumSignature},
    entropy::{SentinelSeed, SourceStatus},
    registry::{operation_bytes, EpochSignature, KeyRegistry, PublicKeyMaterial,
        PublicKeyVersion, RecordAuthorization, RegistryCheckpoint, RegistryEvent, RotationRecord},
};
use nexus_core::{Address, Hash256, NexusError, SignatureScheme, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Unified NEXUS keypair supporting multiple derivation methods
pub struct NexusKeypair {
    /// The underlying Dilithium keypair
    keypair: DilithiumKeypair,
    /// Key metadata
    metadata: KeyMetadata,
    /// Derivation info (how the key was created)
    derivation: KeyDerivation,
}

/// Metadata about a key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key identifier (hash of public key)
    pub id: Hash256,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Key epoch (for rotation tracking)
    pub epoch: u64,
    /// Signature scheme
    pub scheme: SignatureScheme,
    /// Optional label
    pub label: Option<String>,
}

/// How a key was derived
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyDerivation {
    /// Randomly generated
    Random,
    /// Derived from seed
    FromSeed { seed_hash: Hash256 },
    /// Derived from mnemonic phrase
    FromMnemonic { path: String },
    /// Imported from external source
    Imported,
}

impl NexusKeypair {
    /// Generate a new random keypair
    pub fn generate(scheme: SignatureScheme) -> Result<Self, NexusError> {
        let keypair = DilithiumKeypair::generate(scheme)?;
        let id = Hash256::hash(keypair.public_key().as_bytes());

        Ok(Self {
            keypair,
            metadata: KeyMetadata {
                id,
                created_at: Timestamp::now(),
                epoch: 0,
                scheme,
                label: None,
            },
            derivation: KeyDerivation::Random,
        })
    }

    /// Generate keypair from Sentinel-Seed
    pub fn from_sentinel_seed(
        seed: &mut SentinelSeed,
        scheme: SignatureScheme,
        context: &[u8],
    ) -> Result<Self, NexusError> {
        // El contenedor borra el derivado también al propagar un error.
        let derived_seed = Zeroizing::new(seed.derive_key(context)?);
        let keypair = DilithiumKeypair::from_seed(&derived_seed, scheme)?;
        let id = Hash256::hash(keypair.public_key().as_bytes());

        Ok(Self {
            keypair,
            metadata: KeyMetadata {
                id,
                created_at: Timestamp::now(),
                epoch: seed.epoch(),
                scheme,
                label: None,
            },
            derivation: KeyDerivation::FromSeed {
                seed_hash: seed.seed_hash(),
            },
        })
    }

    /// Get public key
    pub fn public_key(&self) -> &DilithiumPublicKey {
        self.keypair.public_key()
    }

    /// Get address
    pub fn address(&self) -> Address {
        self.keypair.address()
    }

    /// Get key ID
    pub fn id(&self) -> Hash256 {
        self.metadata.id
    }

    /// Get metadata
    pub fn metadata(&self) -> &KeyMetadata {
        &self.metadata
    }

    /// Set label
    pub fn set_label(&mut self, label: String) {
        self.metadata.label = Some(label);
    }

    /// Sign message
    pub fn sign(&self, message: &[u8]) -> Result<DilithiumSignature, NexusError> {
        self.keypair.sign(message)
    }

    /// Sign hash
    pub fn sign_hash(&self, hash: &Hash256) -> Result<DilithiumSignature, NexusError> {
        self.keypair.sign_hash(hash)
    }

    /// Verify signature
    pub fn verify(&self, message: &[u8], signature: &DilithiumSignature) -> Result<bool, NexusError> {
        self.keypair.verify(message, signature)
    }

    /// Get signature scheme
    pub fn scheme(&self) -> SignatureScheme {
        self.metadata.scheme
    }

    /// Get key epoch
    pub fn epoch(&self) -> u64 {
        self.metadata.epoch
    }

    /// Export public key bytes
    pub fn export_public_key(&self) -> Vec<u8> {
        self.keypair.public_key().as_bytes().to_vec()
    }
}

impl std::fmt::Debug for NexusKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NexusKeypair")
            .field("address", &self.address())
            .field("metadata", &self.metadata)
            .field("derivation", &self.derivation)
            .finish()
    }
}

/// Gestor de identidades estables; las claves privadas nunca salen del gestor.
pub struct KeyManager {
    /// La dirección del alta identifica la cuenta, incluso después de rotar.
    keys: HashMap<Address, NexusKeypair>,
    default_key: Option<Address>,
    sentinel: Option<SentinelSeed>,
    registry: KeyRegistry,
}

impl KeyManager {
    /// Create a new empty key manager
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            default_key: None,
            sentinel: None,
            registry: KeyRegistry::new(),
        }
    }

    /// Create with Sentinel-Seed for key derivation
    pub fn with_sentinel(sentinel: SentinelSeed) -> Self {
        Self {
            keys: HashMap::new(),
            default_key: None,
            sentinel: Some(sentinel),
            registry: KeyRegistry::new(),
        }
    }

    /// Generate and add a new key
    pub fn generate_key(&mut self, scheme: SignatureScheme) -> Result<Address, NexusError> {
        let mut staged_seed = self.sentinel.clone();
        let keypair = if let Some(ref mut sentinel) = staged_seed {
            let context = format!("NEXUS_ACCOUNT_{}", self.registry.records().len()).into_bytes();
            NexusKeypair::from_sentinel_seed(sentinel, scheme, &context)?
        } else {
            NexusKeypair::generate(scheme)?
        };

        let address = self.add_key(keypair)?;
        self.sentinel = staged_seed;
        Ok(address)
    }

    /// El alta exige pertenecer a la semilla vigente cuando el gestor usa Sentinel.
    pub fn add_key(&mut self, keypair: NexusKeypair) -> Result<Address, NexusError> {
        self.ensure_signing_allowed()?;
        let seed_hash = match keypair.derivation {
            KeyDerivation::FromSeed { seed_hash } => Some(seed_hash),
            _ => None,
        };
        if let Some(seed) = &self.sentinel {
            if seed_hash != Some(seed.seed_hash()) || keypair.epoch() != seed.epoch() {
                return Err(NexusError::SecurityViolation("Clave ajena a la época del gestor".into()));
            }
        }
        let address = keypair.address();
        let body = self.registry.prepare(RegistryEvent::Enrollment {
            identity: address,
            key: PublicKeyMaterial { epoch: keypair.epoch(), public_key: keypair.public_key().clone(), seed_hash },
        });
        let signature = keypair.sign(&body.signing_bytes()?)?;
        self.registry.append(RotationRecord { body, authorizations: vec![RecordAuthorization {
            identity: address, previous: None, next: Some(signature),
        }] })?;
        self.keys.insert(address, keypair);
        if self.default_key.is_none() {
            self.default_key = Some(address);
        }
        Ok(address)
    }

    /// Vista pública; impide eludir la política obteniendo un firmador privado.
    pub fn get_key(&self, address: &Address) -> Option<&PublicKeyVersion> {
        self.registry.current(address)
    }

    pub fn default_key(&self) -> Option<&PublicKeyVersion> {
        self.default_key.and_then(|addr| self.get_key(&addr))
    }

    pub fn registry(&self) -> &KeyRegistry { &self.registry }

    /// Metadatos de la clave operativa, sin capacidad de firma ni material secreto.
    pub fn key_metadata(&self, address: &Address) -> Option<&KeyMetadata> {
        self.keys.get(address).map(NexusKeypair::metadata)
    }

    fn ensure_signing_allowed(&self) -> Result<(), NexusError> {
        if self.needs_rotation() { Err(NexusError::KeyRotationRequired) } else { Ok(()) }
    }

    /// Set default key
    pub fn set_default(&mut self, address: Address) -> Result<(), NexusError> {
        if !self.keys.contains_key(&address) {
            return Err(NexusError::AccountNotFound(address));
        }
        self.default_key = Some(address);
        Ok(())
    }

    /// Sign with specific key
    pub fn sign(
        &self,
        address: &Address,
        message: &[u8],
    ) -> Result<EpochSignature, NexusError> {
        self.ensure_signing_allowed()?;
        let key = self.keys
            .get(address)
            .ok_or(NexusError::AccountNotFound(*address))?;
        let signature = key.sign(&operation_bytes(*address, key.epoch(), message))?;
        // La edad puede vencer durante ML-DSA: no entregar una firma ya vencida.
        self.ensure_signing_allowed()?;
        Ok(EpochSignature { identity: *address, epoch: key.epoch(), signature })
    }

    /// Sign with default key
    pub fn sign_default(&self, message: &[u8]) -> Result<EpochSignature, NexusError> {
        let address = self.default_key.ok_or_else(|| NexusError::ConfigError("No hay clave predeterminada".into()))?;
        self.sign(&address, message)
    }

    /// List all addresses
    pub fn addresses(&self) -> Vec<Address> {
        self.keys.keys().copied().collect()
    }

    /// Get number of keys
    pub fn count(&self) -> usize {
        self.keys.len()
    }

    /// Retiro autorizado de custodia y vigencia; conserva el historial público.
    pub fn remove_key(&mut self, address: &Address) -> Result<(), NexusError> {
        let key = self.keys.get(address).ok_or(NexusError::AccountNotFound(*address))?;
        let body = self.registry.prepare(RegistryEvent::Retirement { identity: *address });
        let signature = key.sign(&body.signing_bytes()?)?;
        self.registry.append(RotationRecord { body, authorizations: vec![RecordAuthorization {
            identity: *address, previous: Some(signature), next: None,
        }] })?;
        if self.default_key == Some(*address) {
            self.default_key = None;
        }
        self.keys.remove(address);
        Ok(())
    }

    /// Check if rotation is needed (via Sentinel)
    pub fn needs_rotation(&self) -> bool {
        self.sentinel.as_ref().map(|s| s.needs_rotation()).unwrap_or(false)
    }

    /// Entrega muestras al monitor asociado; no modifica las claves almacenadas.
    pub fn ingest_source(&mut self, samples: &[u8]) -> Result<SourceStatus, NexusError> {
        let sentinel = self.sentinel.as_mut().ok_or_else(||
            NexusError::ConfigError("El gestor no tiene Sentinel configurado".into()))?;
        sentinel.ingest_source(samples);
        Ok(sentinel.source_status())
    }

    /// Inicia una reevaluación explícita manteniendo bloqueadas las derivaciones.
    pub fn begin_source_recovery(&mut self) -> Result<(), NexusError> {
        self.sentinel.as_mut().ok_or_else(||
            NexusError::ConfigError("El gestor no tiene Sentinel configurado".into()))?
            .begin_source_recovery()
    }

    /// Consulta el estado sin exponer la semilla ni las muestras.
    pub fn source_status(&self) -> Option<SourceStatus> {
        self.sentinel.as_ref().map(SentinelSeed::source_status)
    }

    /// Prepara semilla, claves y evento; instala el conjunto solo si todo resulta válido.
    /// Las firmas de transición y retiro son controles de recuperación, no operaciones.
    pub fn rotate_sentinel(&mut self) -> Result<RegistryCheckpoint, NexusError> {
        self.rotate_with_deriver(NexusKeypair::from_sentinel_seed)
    }

    fn rotate_with_deriver<F>(&mut self, mut derive: F) -> Result<RegistryCheckpoint, NexusError>
    where F: FnMut(&mut SentinelSeed, SignatureScheme, &[u8]) -> Result<NexusKeypair, NexusError> {
        let mut staged_seed = self.sentinel.clone().ok_or_else(||
            NexusError::ConfigError("El gestor no tiene Sentinel configurado".into()))?;
        if self.keys.is_empty() {
            return Err(NexusError::ConfigError("No hay identidades para rotar".into()));
        }
        let old_seed_hash = staged_seed.seed_hash();
        let result = staged_seed.rotate()?;
        let mut identities = self.addresses();
        identities.sort_by_key(|identity| *identity.as_bytes());
        let mut staged_keys = HashMap::new();
        let mut replacements = Vec::new();
        for identity in &identities {
            let old = self.keys.get(identity).ok_or(NexusError::AccountNotFound(*identity))?;
            let mut context = b"NEXUS_ROTATED_ACCOUNT_V1".to_vec();
            context.extend(identity.as_bytes());
            let mut key = derive(&mut staged_seed, old.scheme(), &context)?;
            key.metadata.label = old.metadata.label.clone();
            replacements.push((*identity, key.public_key().clone()));
            staged_keys.insert(*identity, key);
        }
        // No instalar una época que agotó su cupo derivando el propio conjunto.
        if staged_seed.needs_rotation() { return Err(NexusError::KeyRotationRequired); }
        let body = self.registry.prepare(RegistryEvent::Rotation {
            old_epoch: result.old_epoch, new_epoch: result.new_epoch,
            old_seed_hash, new_seed_hash: staged_seed.seed_hash(),
            reason: result.reason.unwrap_or(crate::entropy::RotationReason::Manual), replacements,
        });
        let bytes = body.signing_bytes()?;
        let mut authorizations = Vec::new();
        for identity in &identities {
            let previous = self.keys.get(identity).ok_or(NexusError::AccountNotFound(*identity))?;
            let next = staged_keys.get(identity).ok_or(NexusError::AccountNotFound(*identity))?;
            authorizations.push(RecordAuthorization { identity: *identity,
                previous: Some(previous.sign(&bytes)?), next: Some(next.sign(&bytes)?),
            });
        }
        if staged_seed.needs_rotation() { return Err(NexusError::KeyRotationRequired); }
        self.registry.append(RotationRecord { body, authorizations })?;
        self.keys = staged_keys;
        self.sentinel = Some(staged_seed);
        Ok(self.registry.checkpoint())
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_manager(config: crate::entropy::SentinelConfig) -> KeyManager {
        use rand::{RngCore, SeedableRng};
        let mut samples = vec![0u8; crate::entropy::SOURCE_ASSESSMENT_SAMPLES];
        rand_chacha::ChaCha20Rng::from_seed([7u8; 32]).fill_bytes(&mut samples);
        let mut manager = KeyManager::with_sentinel(SentinelSeed::with_config(config));
        assert_eq!(manager.ingest_source(&samples).unwrap(), SourceStatus::Healthy);
        manager
    }

    #[test]
    fn rotation_changes_all_keys_preserves_identity_default_and_history() {
        let mut manager = healthy_manager(Default::default());
        let first = manager.generate_key(SignatureScheme::Dilithium3).unwrap();
        let second = manager.generate_key(SignatureScheme::Dilithium2).unwrap();
        manager.set_default(second).unwrap();
        let old_signature = manager.sign(&first, b"operacion").unwrap();
        let old_public = manager.get_key(&first).unwrap().material.public_key.as_bytes().to_vec();
        let accepted_at = manager.registry().checkpoint().records - 1;
        let checkpoint = manager.rotate_sentinel().unwrap();
        assert_eq!(checkpoint.records, 3);
        assert_eq!(manager.count(), 2);
        assert_eq!(manager.default_key, Some(second));
        for identity in [first, second] {
            assert_eq!(manager.get_key(&identity).unwrap().material.epoch, 1);
            assert_eq!(manager.keys[&identity].epoch(), 1);
        }
        assert_ne!(old_public, manager.get_key(&first).unwrap().material.public_key.as_bytes());
        assert!(!manager.registry().verify_current(b"operacion", &old_signature).unwrap());
        assert!(manager.registry().verify_historical(b"operacion", &old_signature).unwrap());
        assert!(manager.registry().verify_at_record(b"operacion", &old_signature, accepted_at).unwrap());
        assert!(!manager.registry().verify_at_record(b"operacion", &old_signature, 2).unwrap());
        assert!(!manager.registry().verify_at_record(b"operacion", &old_signature, u64::MAX).unwrap());
        let current = manager.sign_default(b"operacion").unwrap();
        assert_eq!(current.identity, second);
        assert!(manager.registry().verify_current(b"operacion", &current).unwrap());
    }

    #[test]
    fn operation_signature_binds_epoch_identity_and_payload() {
        let mut manager = healthy_manager(Default::default());
        let first = manager.generate_key(SignatureScheme::Dilithium3).unwrap();
        let second = manager.generate_key(SignatureScheme::Dilithium3).unwrap();
        let signed = manager.sign(&first, b"mensaje").unwrap();
        assert!(!manager.registry().verify_current(b"otro", &signed).unwrap());
        let mut forged = signed.clone();
        forged.identity = second;
        assert!(!manager.registry().verify_current(b"mensaje", &forged).unwrap());
        manager.rotate_sentinel().unwrap();
        forged = signed;
        forged.epoch = 1;
        assert!(!manager.registry().verify_current(b"mensaje", &forged).unwrap());
    }

    #[test]
    fn health_failure_blocks_all_operation_signing_until_recovery_and_rotation() {
        let mut manager = healthy_manager(Default::default());
        let address = manager.generate_key(SignatureScheme::Dilithium3).unwrap();
        let checkpoint = manager.registry().checkpoint();
        manager.ingest_source(&[0; 4]).unwrap();
        assert!(manager.sign(&address, b"mensaje").is_err());
        assert!(manager.sign_default(b"mensaje").is_err());
        assert!(manager.rotate_sentinel().is_err());
        assert_eq!(checkpoint, manager.registry().checkpoint());
        manager.begin_source_recovery().unwrap();
        assert!(manager.sign_default(b"mensaje").is_err());
        use rand::{RngCore, SeedableRng};
        let mut samples = vec![0; crate::entropy::SOURCE_ASSESSMENT_SAMPLES];
        rand_chacha::ChaCha20Rng::from_seed([7; 32]).fill_bytes(&mut samples);
        manager.ingest_source(&samples).unwrap();
        assert!(manager.sign_default(b"mensaje").is_err());
        manager.rotate_sentinel().unwrap();
        assert!(manager.sign_default(b"mensaje").is_ok());
        assert!(matches!(manager.registry().records().last().unwrap().body.event,
            RegistryEvent::Rotation { reason: crate::entropy::RotationReason::SourceRecovered, .. }));
    }

    #[test]
    fn age_expiration_blocks_signing() {
        let mut manager = healthy_manager(crate::entropy::SentinelConfig {
            max_age_ms: 2_000, ..Default::default()
        });
        let address = manager.generate_key(SignatureScheme::Dilithium3).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2_050));
        assert!(manager.sign(&address, b"mensaje").is_err());
        manager.rotate_sentinel().unwrap();
        assert!(manager.sign_default(b"mensaje").is_ok());
    }

    #[test]
    fn exhausted_derivation_budget_requires_capacity_for_rotation() {
        let mut manager = healthy_manager(crate::entropy::SentinelConfig {
            max_uses: 2, ..Default::default()
        });
        let first = manager.generate_key(SignatureScheme::Dilithium3).unwrap();
        let second = manager.generate_key(SignatureScheme::Dilithium3).unwrap();
        let checkpoint = manager.registry().checkpoint();
        assert!(manager.sign(&first, b"mensaje").is_err());
        assert!(manager.rotate_sentinel().is_err());
        assert_eq!(checkpoint, manager.registry().checkpoint());
        assert_eq!(manager.sentinel.as_ref().unwrap().epoch(), 0);
        manager.remove_key(&second).unwrap();
        manager.rotate_sentinel().unwrap();
        assert!(manager.sign_default(b"mensaje").is_ok());
    }

    #[test]
    fn failure_after_first_derived_key_leaves_entire_state_unchanged() {
        let mut manager = healthy_manager(Default::default());
        let first = manager.generate_key(SignatureScheme::Dilithium3).unwrap();
        let second = manager.generate_key(SignatureScheme::Dilithium3).unwrap();
        let checkpoint = manager.registry().checkpoint();
        let seed_hash = manager.sentinel.as_ref().unwrap().seed_hash();
        let uses = manager.sentinel.as_ref().unwrap().use_count();
        let public_keys: Vec<_> = [first, second].iter().map(|id|
            manager.get_key(id).unwrap().material.public_key.as_bytes().to_vec()).collect();
        let mut calls = 0;
        let result = manager.rotate_with_deriver(|seed, scheme, context| {
            calls += 1;
            if calls == 2 { return Err(NexusError::CryptoError("Fallo inyectado".into())); }
            NexusKeypair::from_sentinel_seed(seed, scheme, context)
        });
        assert!(result.is_err());
        assert_eq!(calls, 2);
        assert_eq!(checkpoint, manager.registry().checkpoint());
        assert_eq!(seed_hash, manager.sentinel.as_ref().unwrap().seed_hash());
        assert_eq!(uses, manager.sentinel.as_ref().unwrap().use_count());
        for (identity, public_key) in [first, second].iter().zip(public_keys) {
            assert_eq!(public_key, manager.get_key(identity).unwrap().material.public_key.as_bytes());
        }
        assert!(manager.sign_default(b"mensaje").is_ok());
    }

    #[test]
    fn retirement_rejects_new_signatures_but_preserves_historical_verification() {
        let mut manager = healthy_manager(Default::default());
        let identity = manager.generate_key(SignatureScheme::Dilithium3).unwrap();
        let signed = manager.sign_default(b"mensaje").unwrap();
        manager.ingest_source(&[0; 4]).unwrap();
        manager.remove_key(&identity).unwrap();
        assert_eq!(manager.count(), 0);
        assert_eq!(manager.registry().active_count(), 0);
        assert!(manager.get_key(&identity).is_none());
        assert!(manager.sign_default(b"mensaje").is_err());
        assert!(!manager.registry().verify_current(b"mensaje", &signed).unwrap());
        assert!(manager.registry().verify_historical(b"mensaje", &signed).unwrap());
        assert_eq!(manager.registry().at_epoch(&identity, 0).unwrap().valid_until, Some(1));
    }

    #[test]
    fn invalid_import_and_empty_rotation_do_not_change_registry() {
        let mut manager = healthy_manager(Default::default());
        assert!(manager.rotate_sentinel().is_err());
        assert!(manager.add_key(NexusKeypair::generate(SignatureScheme::Dilithium3).unwrap()).is_err());
        assert_eq!(manager.registry().checkpoint().records, 0);
        assert!(KeyManager::new().rotate_sentinel().is_err());
    }

    #[test]
    fn failed_registry_validation_does_not_install_staged_keys() {
        let mut manager = healthy_manager(Default::default());
        let identity = manager.generate_key(SignatureScheme::Dilithium3).unwrap();
        let checkpoint = manager.registry().checkpoint();
        let old_id = manager.key_metadata(&identity).unwrap().id;
        let old_seed = manager.sentinel.as_ref().unwrap().seed_hash();
        let result = manager.rotate_with_deriver(|seed, _, context|
            NexusKeypair::from_sentinel_seed(seed, SignatureScheme::Dilithium2, context));
        assert!(result.is_err());
        assert_eq!(manager.registry().checkpoint(), checkpoint);
        assert_eq!(manager.key_metadata(&identity).unwrap().id, old_id);
        assert_eq!(manager.sentinel.as_ref().unwrap().seed_hash(), old_seed);
        assert!(manager.sign_default(b"mensaje").is_ok());
    }

    #[test]
    fn enrollment_after_rotation_and_repeated_rotations_remain_verifiable() {
        let mut manager = healthy_manager(Default::default());
        let first = manager.generate_key(SignatureScheme::Dilithium3).unwrap();
        manager.rotate_sentinel().unwrap();
        let second = manager.generate_key(SignatureScheme::Dilithium5).unwrap();
        manager.rotate_sentinel().unwrap();
        let registry = KeyRegistry::from_bytes(&manager.registry().to_bytes().unwrap(),
            manager.registry().checkpoint()).unwrap();
        assert!(registry.at_epoch(&second, 0).is_none());
        for identity in [first, second] {
            assert_eq!(registry.current(&identity).unwrap().material.epoch, 2);
            assert!(registry.verify_current(b"mensaje", &manager.sign(&identity, b"mensaje").unwrap()).unwrap());
        }
    }

    #[test]
    fn test_key_manager_respects_source_evaluation_and_recovery() {
        use rand::{RngCore, SeedableRng};
        let mut samples = vec![0u8; crate::entropy::SOURCE_ASSESSMENT_SAMPLES];
        rand_chacha::ChaCha20Rng::from_seed([7u8; 32]).fill_bytes(&mut samples);
        let mut manager = KeyManager::with_sentinel(SentinelSeed::new());
        assert!(manager.generate_key(SignatureScheme::Dilithium3).is_err());
        assert_eq!(manager.count(), 0);
        assert_eq!(manager.ingest_source(&samples).unwrap(), SourceStatus::Healthy);
        assert!(manager.generate_key(SignatureScheme::Dilithium3).is_ok());
        manager.ingest_source(&[0; 4]).unwrap();
        assert!(manager.generate_key(SignatureScheme::Dilithium3).is_err());
        assert!(manager.rotate_sentinel().is_err());
        manager.begin_source_recovery().unwrap();
        assert_eq!(manager.source_status(), Some(SourceStatus::Recovering));
        manager.ingest_source(&samples).unwrap();
        assert!(manager.generate_key(SignatureScheme::Dilithium3).is_err());
        manager.rotate_sentinel().unwrap();
        assert!(manager.generate_key(SignatureScheme::Dilithium3).is_ok());
        // La identidad previa se conserva con una clave de la nueva época.
        assert_eq!(manager.count(), 2);
    }

    #[test]
    fn test_keypair_generation() {
        let keypair = NexusKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        assert!(!keypair.address().as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_keypair_from_sentinel() {
        let mut sentinel = SentinelSeed::new();
        // Datos sintéticos reproducibles para preparar el monitor del caso existente.
        use rand::{RngCore, SeedableRng};
        let mut samples = vec![0u8; crate::entropy::SOURCE_ASSESSMENT_SAMPLES];
        rand_chacha::ChaCha20Rng::from_seed([7u8; 32]).fill_bytes(&mut samples);
        sentinel.ingest_source(&samples);
        let keypair = NexusKeypair::from_sentinel_seed(
            &mut sentinel,
            SignatureScheme::Dilithium3,
            b"test_context",
        ).unwrap();

        assert_eq!(keypair.epoch(), sentinel.epoch());
    }

    #[test]
    fn test_key_manager() {
        let mut manager = KeyManager::new();

        let addr1 = manager.generate_key(SignatureScheme::Dilithium3).unwrap();
        let addr2 = manager.generate_key(SignatureScheme::Dilithium3).unwrap();

        assert_ne!(addr1, addr2);
        assert_eq!(manager.count(), 2);
        assert_eq!(manager.default_key().unwrap().material.public_key.to_address(), addr1);
    }

    #[test]
    fn test_key_manager_sign() {
        let mut manager = KeyManager::new();
        let addr = manager.generate_key(SignatureScheme::Dilithium3).unwrap();

        let message = b"Test message";
        let sig = manager.sign(&addr, message).unwrap();

        assert!(manager.registry().verify_current(message, &sig).unwrap());
    }
}
