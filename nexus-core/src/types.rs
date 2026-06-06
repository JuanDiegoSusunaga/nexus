//! Core types for NEXUS blockchain
//!
//! Defines fundamental types like Hash, Address, and cryptographic primitives
//! that are used throughout the NEXUS protocol.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;
use zeroize::Zeroize;

/// 256-bit hash used for block hashes, transaction hashes, and state roots
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn new(data: [u8; 32]) -> Self {
        Self(data)
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(slice);
        Some(Self(arr))
    }

    /// Compute SHA3-256 hash of data
    pub fn hash(data: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        Self(arr)
    }

    /// Compute BLAKE3 hash (faster, used for internal operations)
    pub fn hash_blake3(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Self(*hash.as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex::decode(s).ok()?;
        Self::from_slice(&bytes)
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Post-Quantum address derived from Dilithium public key
/// Uses first 32 bytes of SHA3-256(public_key)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Address(pub [u8; 32]);

impl Address {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn new(data: [u8; 32]) -> Self {
        Self(data)
    }

    /// Derive address from public key bytes
    pub fn from_public_key(pk_bytes: &[u8]) -> Self {
        let hash = Hash256::hash(pk_bytes);
        Self(hash.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex::decode(s).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(Self(arr))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({}...)", &self.to_hex()[..12])
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "nx{}", self.to_hex())
    }
}

/// Post-Quantum signature (Dilithium)
/// Variable size depending on security level (2420 bytes for Dilithium3)
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PQSignature {
    /// Raw signature bytes
    pub bytes: Vec<u8>,
    /// Signature scheme identifier
    pub scheme: SignatureScheme,
}

impl PQSignature {
    pub fn new(bytes: Vec<u8>, scheme: SignatureScheme) -> Self {
        Self { bytes, scheme }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for PQSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PQSignature({:?}, {} bytes)", self.scheme, self.bytes.len())
    }
}

impl Zeroize for PQSignature {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

/// Supported post-quantum signature schemes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureScheme {
    /// CRYSTALS-Dilithium Level 2 (128-bit security)
    Dilithium2,
    /// CRYSTALS-Dilithium Level 3 (192-bit security) - RECOMMENDED
    Dilithium3,
    /// CRYSTALS-Dilithium Level 5 (256-bit security)
    Dilithium5,
}

impl Default for SignatureScheme {
    fn default() -> Self {
        Self::Dilithium3
    }
}

/// Represents a balance amount (in smallest unit)
/// Uses u128 to support large values without overflow
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct Amount(pub u128);

impl Amount {
    pub const ZERO: Self = Self(0);
    pub const MAX: Self = Self(u128::MAX);

    /// Create amount from whole units (1 unit = 10^18 smallest units)
    pub fn from_units(units: u64) -> Self {
        Self(units as u128 * 1_000_000_000_000_000_000)
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }

    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }

    pub fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    pub fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0 / 1_000_000_000_000_000_000;
        let frac = self.0 % 1_000_000_000_000_000_000;
        if frac == 0 {
            write!(f, "{} NXS", whole)
        } else {
            write!(f, "{}.{:018} NXS", whole, frac)
        }
    }
}

/// Timestamp in milliseconds since UNIX epoch
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub fn now() -> Self {
        Self(chrono::Utc::now().timestamp_millis() as u64)
    }

    pub fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    pub fn as_millis(&self) -> u64 {
        self.0
    }

    pub fn elapsed_since(&self, earlier: Timestamp) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self::now()
    }
}

/// Block height (number)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct BlockHeight(pub u64);

impl BlockHeight {
    pub const GENESIS: Self = Self(0);

    pub fn new(height: u64) -> Self {
        Self(height)
    }

    pub fn next(&self) -> Self {
        Self(self.0 + 1)
    }

    pub fn prev(&self) -> Option<Self> {
        if self.0 == 0 {
            None
        } else {
            Some(Self(self.0 - 1))
        }
    }
}

impl fmt::Display for BlockHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// Nonce for transaction ordering and replay protection
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct Nonce(pub u64);

impl Nonce {
    pub fn new(n: u64) -> Self {
        Self(n)
    }

    pub fn increment(&mut self) {
        self.0 += 1;
    }
}

/// Chain identifier to prevent cross-chain replay attacks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainId(pub u64);

impl ChainId {
    /// NEXUS Mainnet
    pub const MAINNET: Self = Self(1);
    /// NEXUS Testnet
    pub const TESTNET: Self = Self(2);
    /// Local development
    pub const LOCAL: Self = Self(31337);
}

impl Default for ChainId {
    fn default() -> Self {
        Self::LOCAL
    }
}

/// Layer identifier in dual-chain architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Layer {
    /// Anchor Layer (L1) - Consensus and Data Availability
    Anchor,
    /// Active Layer (L2) - Execution and Computation
    Active,
}

impl Default for Layer {
    fn default() -> Self {
        Self::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash256() {
        let data = b"NEXUS Post-Quantum Blockchain";
        let hash = Hash256::hash(data);
        assert_ne!(hash, Hash256::ZERO);

        let hex = hash.to_hex();
        let recovered = Hash256::from_hex(&hex).unwrap();
        assert_eq!(hash, recovered);
    }

    #[test]
    fn test_address_from_pk() {
        let fake_pk = vec![1u8; 1952]; // Dilithium3 public key size
        let addr = Address::from_public_key(&fake_pk);
        assert_ne!(addr, Address::ZERO);
    }

    #[test]
    fn test_amount_arithmetic() {
        let a = Amount::from_units(100);
        let b = Amount::from_units(50);

        assert_eq!(a.checked_sub(b), Some(Amount::from_units(50)));
        assert_eq!(b.checked_sub(a), None);
    }
}
