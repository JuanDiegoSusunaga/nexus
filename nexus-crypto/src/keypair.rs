//! Key Management for NEXUS Blockchain
//!
//! Provides unified key management including:
//! - Key generation and storage
//! - Key rotation with epoch tracking
//! - Multi-scheme support (Dilithium variants)

use crate::{
    dilithium::{DilithiumKeypair, DilithiumPublicKey, DilithiumSignature},
    entropy::SentinelSeed,
};
use nexus_core::{Address, Hash256, NexusError, SignatureScheme, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;

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
        let derived_seed = seed.derive_key(context)?;
        let mut seed_32 = [0u8; 32];
        seed_32.copy_from_slice(&derived_seed);

        let keypair = DilithiumKeypair::from_seed(&seed_32, scheme)?;
        let id = Hash256::hash(keypair.public_key().as_bytes());

        // Zeroize derived seed
        let mut derived_seed = derived_seed;
        derived_seed.zeroize();

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

/// Key Manager for handling multiple keys
pub struct KeyManager {
    /// Active keys by address
    keys: HashMap<Address, NexusKeypair>,
    /// Key metadata by ID
    metadata: HashMap<Hash256, KeyMetadata>,
    /// Default key address (if set)
    default_key: Option<Address>,
    /// Sentinel seed for key derivation
    sentinel: Option<SentinelSeed>,
}

impl KeyManager {
    /// Create a new empty key manager
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            metadata: HashMap::new(),
            default_key: None,
            sentinel: None,
        }
    }

    /// Create with Sentinel-Seed for key derivation
    pub fn with_sentinel(sentinel: SentinelSeed) -> Self {
        Self {
            keys: HashMap::new(),
            metadata: HashMap::new(),
            default_key: None,
            sentinel: Some(sentinel),
        }
    }

    /// Generate and add a new key
    pub fn generate_key(&mut self, scheme: SignatureScheme) -> Result<Address, NexusError> {
        let keypair = if let Some(ref mut sentinel) = self.sentinel {
            let context = format!("key_{}", self.keys.len()).into_bytes();
            NexusKeypair::from_sentinel_seed(sentinel, scheme, &context)?
        } else {
            NexusKeypair::generate(scheme)?
        };

        let address = keypair.address();
        let metadata = keypair.metadata().clone();

        self.metadata.insert(keypair.id(), metadata);
        self.keys.insert(address, keypair);

        if self.default_key.is_none() {
            self.default_key = Some(address);
        }

        Ok(address)
    }

    /// Add an existing keypair
    pub fn add_key(&mut self, keypair: NexusKeypair) -> Address {
        let address = keypair.address();
        let metadata = keypair.metadata().clone();

        self.metadata.insert(keypair.id(), metadata);
        self.keys.insert(address, keypair);

        if self.default_key.is_none() {
            self.default_key = Some(address);
        }

        address
    }

    /// Get key by address
    pub fn get_key(&self, address: &Address) -> Option<&NexusKeypair> {
        self.keys.get(address)
    }

    /// Get default key
    pub fn default_key(&self) -> Option<&NexusKeypair> {
        self.default_key.and_then(|addr| self.keys.get(&addr))
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
    ) -> Result<DilithiumSignature, NexusError> {
        self.keys
            .get(address)
            .ok_or(NexusError::AccountNotFound(*address))?
            .sign(message)
    }

    /// Sign with default key
    pub fn sign_default(&self, message: &[u8]) -> Result<DilithiumSignature, NexusError> {
        self.default_key()
            .ok_or(NexusError::Internal("No default key set".into()))?
            .sign(message)
    }

    /// List all addresses
    pub fn addresses(&self) -> Vec<Address> {
        self.keys.keys().copied().collect()
    }

    /// Get number of keys
    pub fn count(&self) -> usize {
        self.keys.len()
    }

    /// Remove a key
    pub fn remove_key(&mut self, address: &Address) -> Option<NexusKeypair> {
        if self.default_key == Some(*address) {
            self.default_key = None;
        }
        let keypair = self.keys.remove(address)?;
        self.metadata.remove(&keypair.id());
        Some(keypair)
    }

    /// Check if rotation is needed (via Sentinel)
    pub fn needs_rotation(&self) -> bool {
        self.sentinel.as_ref().map(|s| s.needs_rotation()).unwrap_or(false)
    }

    /// Rotate Sentinel seed and regenerate keys
    pub fn rotate_sentinel(&mut self) -> Result<(), NexusError> {
        if let Some(ref mut sentinel) = self.sentinel {
            sentinel.rotate();
            // Note: In production, you'd want to re-derive keys here
            // and handle the transition properly
            Ok(())
        } else {
            Err(NexusError::Internal("No Sentinel seed configured".into()))
        }
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

    #[test]
    fn test_keypair_generation() {
        let keypair = NexusKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        assert!(!keypair.address().as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_keypair_from_sentinel() {
        let mut sentinel = SentinelSeed::new();
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
        assert_eq!(manager.default_key().unwrap().address(), addr1);
    }

    #[test]
    fn test_key_manager_sign() {
        let mut manager = KeyManager::new();
        let addr = manager.generate_key(SignatureScheme::Dilithium3).unwrap();

        let message = b"Test message";
        let sig = manager.sign(&addr, message).unwrap();

        let keypair = manager.get_key(&addr).unwrap();
        assert!(keypair.verify(message, &sig).unwrap());
    }
}
