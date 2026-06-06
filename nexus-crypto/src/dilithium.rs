//! CRYSTALS-Dilithium (ML-DSA, NIST FIPS 204) Post-Quantum Digital Signatures
//!
//! Backed by the pure-Rust, constant-time `fips204` crate, which implements the
//! standardized ML-DSA scheme and — crucially for NEXUS Objective 2 — exposes a
//! **deterministic seed-based KeyGen** (`keygen_from_seed`).
//!
//! ## Security Levels
//!
//! - Dilithium2 / ML-DSA-44: NIST Level 2
//! - Dilithium3 / ML-DSA-65: NIST Level 3 [RECOMMENDED]
//! - Dilithium5 / ML-DSA-87: NIST Level 5
//!
//! ## Key Sizes (Dilithium3 / ML-DSA-65, FIPS 204)
//!
//! - Public Key: 1,952 bytes
//! - Secret Key: 4,032 bytes
//! - Signature: 3,309 bytes

use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use nexus_core::{Address, Hash256, NexusError, PQSignature, SignatureScheme};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Backend dispatch (the three ML-DSA parameter sets are distinct types in
// `fips204`; the wrapper stores keys/signatures as bytes and dispatches here).
// ---------------------------------------------------------------------------

/// (public key, secret key, signature) byte lengths for a scheme.
fn scheme_sizes(scheme: SignatureScheme) -> (usize, usize, usize) {
    match scheme {
        SignatureScheme::Dilithium2 => (ml_dsa_44::PK_LEN, ml_dsa_44::SK_LEN, ml_dsa_44::SIG_LEN),
        SignatureScheme::Dilithium3 => (ml_dsa_65::PK_LEN, ml_dsa_65::SK_LEN, ml_dsa_65::SIG_LEN),
        SignatureScheme::Dilithium5 => (ml_dsa_87::PK_LEN, ml_dsa_87::SK_LEN, ml_dsa_87::SIG_LEN),
    }
}

/// Random key generation (OS entropy).
fn gen_random(scheme: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), NexusError> {
    match scheme {
        SignatureScheme::Dilithium2 => {
            let (pk, sk) = ml_dsa_44::KG::try_keygen().map_err(|e| NexusError::Internal(e.into()))?;
            Ok((pk.into_bytes().to_vec(), sk.into_bytes().to_vec()))
        }
        SignatureScheme::Dilithium3 => {
            let (pk, sk) = ml_dsa_65::KG::try_keygen().map_err(|e| NexusError::Internal(e.into()))?;
            Ok((pk.into_bytes().to_vec(), sk.into_bytes().to_vec()))
        }
        SignatureScheme::Dilithium5 => {
            let (pk, sk) = ml_dsa_87::KG::try_keygen().map_err(|e| NexusError::Internal(e.into()))?;
            Ok((pk.into_bytes().to_vec(), sk.into_bytes().to_vec()))
        }
    }
}

/// Deterministic key generation from a 32-byte seed (FIPS 204 ML-DSA.KeyGen).
fn gen_from_seed(scheme: SignatureScheme, seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    match scheme {
        SignatureScheme::Dilithium2 => {
            let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(seed);
            (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
        }
        SignatureScheme::Dilithium3 => {
            let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(seed);
            (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
        }
        SignatureScheme::Dilithium5 => {
            let (pk, sk) = ml_dsa_87::KG::keygen_from_seed(seed);
            (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
        }
    }
}

/// Sign `message` with the secret-key bytes of `scheme`.
fn sign_bytes(scheme: SignatureScheme, sk_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, NexusError> {
    match scheme {
        SignatureScheme::Dilithium2 => {
            let arr: [u8; ml_dsa_44::SK_LEN] =
                sk_bytes.try_into().map_err(|_| NexusError::InvalidPrivateKey)?;
            let sk = ml_dsa_44::PrivateKey::try_from_bytes(arr)
                .map_err(|_| NexusError::InvalidPrivateKey)?;
            let sig = sk
                .try_sign(message, b"")
                .map_err(|e| NexusError::InvalidSignature(e.into()))?;
            Ok(sig.to_vec())
        }
        SignatureScheme::Dilithium3 => {
            let arr: [u8; ml_dsa_65::SK_LEN] =
                sk_bytes.try_into().map_err(|_| NexusError::InvalidPrivateKey)?;
            let sk = ml_dsa_65::PrivateKey::try_from_bytes(arr)
                .map_err(|_| NexusError::InvalidPrivateKey)?;
            let sig = sk
                .try_sign(message, b"")
                .map_err(|e| NexusError::InvalidSignature(e.into()))?;
            Ok(sig.to_vec())
        }
        SignatureScheme::Dilithium5 => {
            let arr: [u8; ml_dsa_87::SK_LEN] =
                sk_bytes.try_into().map_err(|_| NexusError::InvalidPrivateKey)?;
            let sk = ml_dsa_87::PrivateKey::try_from_bytes(arr)
                .map_err(|_| NexusError::InvalidPrivateKey)?;
            let sig = sk
                .try_sign(message, b"")
                .map_err(|e| NexusError::InvalidSignature(e.into()))?;
            Ok(sig.to_vec())
        }
    }
}

/// Verify `signature` over `message` against the public-key bytes of `scheme`.
fn verify_bytes(
    scheme: SignatureScheme,
    pk_bytes: &[u8],
    message: &[u8],
    sig_bytes: &[u8],
) -> Result<bool, NexusError> {
    match scheme {
        SignatureScheme::Dilithium2 => {
            let pk_arr: [u8; ml_dsa_44::PK_LEN] = pk_bytes
                .try_into()
                .map_err(|_| NexusError::InvalidPublicKey("Invalid public key size".into()))?;
            let pk = ml_dsa_44::PublicKey::try_from_bytes(pk_arr)
                .map_err(|_| NexusError::InvalidPublicKey("Invalid public key".into()))?;
            let sig_arr: [u8; ml_dsa_44::SIG_LEN] = sig_bytes
                .try_into()
                .map_err(|_| NexusError::InvalidSignature("Invalid signature size".into()))?;
            Ok(pk.verify(message, &sig_arr, b""))
        }
        SignatureScheme::Dilithium3 => {
            let pk_arr: [u8; ml_dsa_65::PK_LEN] = pk_bytes
                .try_into()
                .map_err(|_| NexusError::InvalidPublicKey("Invalid public key size".into()))?;
            let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_arr)
                .map_err(|_| NexusError::InvalidPublicKey("Invalid public key".into()))?;
            let sig_arr: [u8; ml_dsa_65::SIG_LEN] = sig_bytes
                .try_into()
                .map_err(|_| NexusError::InvalidSignature("Invalid signature size".into()))?;
            Ok(pk.verify(message, &sig_arr, b""))
        }
        SignatureScheme::Dilithium5 => {
            let pk_arr: [u8; ml_dsa_87::PK_LEN] = pk_bytes
                .try_into()
                .map_err(|_| NexusError::InvalidPublicKey("Invalid public key size".into()))?;
            let pk = ml_dsa_87::PublicKey::try_from_bytes(pk_arr)
                .map_err(|_| NexusError::InvalidPublicKey("Invalid public key".into()))?;
            let sig_arr: [u8; ml_dsa_87::SIG_LEN] = sig_bytes
                .try_into()
                .map_err(|_| NexusError::InvalidSignature("Invalid signature size".into()))?;
            Ok(pk.verify(message, &sig_arr, b""))
        }
    }
}

// ---------------------------------------------------------------------------
// Public wrappers (byte-based, scheme-tagged) — interface unchanged.
// ---------------------------------------------------------------------------

/// Dilithium public key wrapper
#[derive(Clone, Serialize, Deserialize)]
pub struct DilithiumPublicKey {
    bytes: Vec<u8>,
    scheme: SignatureScheme,
}

impl DilithiumPublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: Vec<u8>, scheme: SignatureScheme) -> Result<Self, NexusError> {
        let (expected_size, _, _) = scheme_sizes(scheme);
        if bytes.len() != expected_size {
            return Err(NexusError::InvalidPublicKey(format!(
                "Expected {} bytes, got {}",
                expected_size,
                bytes.len()
            )));
        }
        Ok(Self { bytes, scheme })
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get signature scheme
    pub fn scheme(&self) -> SignatureScheme {
        self.scheme
    }

    /// Derive address from this public key
    pub fn to_address(&self) -> Address {
        Address::from_public_key(&self.bytes)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &DilithiumSignature) -> Result<bool, NexusError> {
        if self.scheme != signature.scheme {
            return Err(NexusError::InvalidSignature(
                "Scheme mismatch between key and signature".into(),
            ));
        }
        verify_bytes(self.scheme, &self.bytes, message, &signature.bytes)
    }
}

impl std::fmt::Debug for DilithiumPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DilithiumPublicKey({:?}, {} bytes)", self.scheme, self.bytes.len())
    }
}

/// Dilithium secret key wrapper (zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DilithiumSecretKey {
    bytes: Vec<u8>,
    #[zeroize(skip)]
    scheme: SignatureScheme,
}

impl DilithiumSecretKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: Vec<u8>, scheme: SignatureScheme) -> Result<Self, NexusError> {
        let (_, expected_size, _) = scheme_sizes(scheme);
        if bytes.len() != expected_size {
            return Err(NexusError::InvalidPrivateKey);
        }
        Ok(Self { bytes, scheme })
    }

    /// Get signature scheme
    pub fn scheme(&self) -> SignatureScheme {
        self.scheme
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<DilithiumSignature, NexusError> {
        let sig_bytes = sign_bytes(self.scheme, &self.bytes, message)?;
        Ok(DilithiumSignature {
            bytes: sig_bytes,
            scheme: self.scheme,
        })
    }

    /// Get raw bytes (use with caution)
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for DilithiumSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DilithiumSecretKey({:?}, [REDACTED])", self.scheme)
    }
}

/// Dilithium signature wrapper
#[derive(Clone, Serialize, Deserialize)]
pub struct DilithiumSignature {
    bytes: Vec<u8>,
    scheme: SignatureScheme,
}

impl DilithiumSignature {
    /// Create from raw bytes
    pub fn from_bytes(bytes: Vec<u8>, scheme: SignatureScheme) -> Result<Self, NexusError> {
        let (_, _, expected_size) = scheme_sizes(scheme);
        if bytes.len() != expected_size {
            return Err(NexusError::InvalidSignature(format!(
                "Expected {} bytes, got {}",
                expected_size,
                bytes.len()
            )));
        }
        Ok(Self { bytes, scheme })
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get signature scheme
    pub fn scheme(&self) -> SignatureScheme {
        self.scheme
    }

    /// Convert to PQSignature (for use in transactions)
    pub fn to_pq_signature(&self) -> PQSignature {
        PQSignature::new(self.bytes.clone(), self.scheme)
    }
}

impl std::fmt::Debug for DilithiumSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DilithiumSignature({:?}, {} bytes)", self.scheme, self.bytes.len())
    }
}

/// Complete Dilithium keypair
#[derive(Clone)]
pub struct DilithiumKeypair {
    pub public_key: DilithiumPublicKey,
    secret_key: DilithiumSecretKey,
}

impl DilithiumKeypair {
    /// Generate a new random keypair (OS entropy).
    pub fn generate(scheme: SignatureScheme) -> Result<Self, NexusError> {
        let (pk_bytes, sk_bytes) = gen_random(scheme)?;
        Ok(Self::from_parts(pk_bytes, sk_bytes, scheme))
    }

    /// Generate a keypair using the provided RNG.
    ///
    /// The RNG seeds a 32-byte value that drives the **deterministic** FIPS 204
    /// `keygen_from_seed`, so the keypair is reproducible for a given RNG state.
    pub fn generate_with_rng<R: RngCore>(
        scheme: SignatureScheme,
        rng: &mut R,
    ) -> Result<Self, NexusError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let kp = Self::from_seed(&seed, scheme);
        seed.zeroize();
        kp
    }

    /// Derive a keypair **deterministically** from a 32-byte seed (FIPS 204
    /// ML-DSA.KeyGen). The same seed always yields the same keypair; the
    /// key-management KDF that produces this seed lives in `entropy::SentinelSeed`.
    pub fn from_seed(seed: &[u8; 32], scheme: SignatureScheme) -> Result<Self, NexusError> {
        let (pk_bytes, sk_bytes) = gen_from_seed(scheme, seed);
        Ok(Self::from_parts(pk_bytes, sk_bytes, scheme))
    }

    fn from_parts(pk_bytes: Vec<u8>, sk_bytes: Vec<u8>, scheme: SignatureScheme) -> Self {
        Self {
            public_key: DilithiumPublicKey { bytes: pk_bytes, scheme },
            secret_key: DilithiumSecretKey { bytes: sk_bytes, scheme },
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> &DilithiumPublicKey {
        &self.public_key
    }

    /// Get the address
    pub fn address(&self) -> Address {
        self.public_key.to_address()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<DilithiumSignature, NexusError> {
        self.secret_key.sign(message)
    }

    /// Sign a hash
    pub fn sign_hash(&self, hash: &Hash256) -> Result<DilithiumSignature, NexusError> {
        self.sign(hash.as_bytes())
    }

    /// Verify a signature (convenience method)
    pub fn verify(&self, message: &[u8], signature: &DilithiumSignature) -> Result<bool, NexusError> {
        self.public_key.verify(message, signature)
    }

    /// Get signature scheme
    pub fn scheme(&self) -> SignatureScheme {
        self.public_key.scheme
    }

    /// Serialize keypair (encrypted in production)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.public_key.scheme as u8);
        bytes.extend_from_slice(&(self.public_key.bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.public_key.bytes);
        bytes.extend_from_slice(&(self.secret_key.bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.secret_key.bytes);
        bytes
    }

    /// Deserialize keypair
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NexusError> {
        if bytes.len() < 9 {
            return Err(NexusError::InvalidPrivateKey);
        }
        let scheme = match bytes[0] {
            0 => SignatureScheme::Dilithium2,
            1 => SignatureScheme::Dilithium3,
            2 => SignatureScheme::Dilithium5,
            _ => return Err(NexusError::InvalidPrivateKey),
        };
        let pk_len = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        if bytes.len() < 5 + pk_len + 4 {
            return Err(NexusError::InvalidPrivateKey);
        }
        let pk_bytes = bytes[5..5 + pk_len].to_vec();
        let sk_len_start = 5 + pk_len;
        let sk_len = u32::from_le_bytes([
            bytes[sk_len_start],
            bytes[sk_len_start + 1],
            bytes[sk_len_start + 2],
            bytes[sk_len_start + 3],
        ]) as usize;
        if bytes.len() < sk_len_start + 4 + sk_len {
            return Err(NexusError::InvalidPrivateKey);
        }
        let sk_bytes = bytes[sk_len_start + 4..sk_len_start + 4 + sk_len].to_vec();
        Ok(Self {
            public_key: DilithiumPublicKey::from_bytes(pk_bytes, scheme)?,
            secret_key: DilithiumSecretKey::from_bytes(sk_bytes, scheme)?,
        })
    }
}

impl std::fmt::Debug for DilithiumKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DilithiumKeypair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"[REDACTED]")
            .field("address", &self.address())
            .finish()
    }
}

/// Get key sizes (public key, secret key, signature) for a given scheme.
pub fn key_sizes(scheme: SignatureScheme) -> (usize, usize, usize) {
    scheme_sizes(scheme)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        assert_eq!(keypair.scheme(), SignatureScheme::Dilithium3);
        let (pk_size, _, _) = key_sizes(SignatureScheme::Dilithium3);
        assert_eq!(keypair.public_key.as_bytes().len(), pk_size);
    }

    #[test]
    fn test_sign_verify() {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let message = b"NEXUS Post-Quantum Test Message";
        let signature = keypair.sign(message).unwrap();
        assert!(keypair.verify(message, &signature).unwrap());
        let invalid = keypair.verify(b"Wrong message", &signature).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_deterministic_from_seed() {
        // FIPS 204 seed-based KeyGen is reproducible: same seed -> same keypair.
        let seed = [42u8; 32];
        let kp1 = DilithiumKeypair::from_seed(&seed, SignatureScheme::Dilithium3).unwrap();
        let kp2 = DilithiumKeypair::from_seed(&seed, SignatureScheme::Dilithium3).unwrap();
        assert_eq!(kp1.public_key().as_bytes(), kp2.public_key().as_bytes());
        // A different seed yields a different key.
        let kp3 = DilithiumKeypair::from_seed(&[7u8; 32], SignatureScheme::Dilithium3).unwrap();
        assert_ne!(kp1.public_key().as_bytes(), kp3.public_key().as_bytes());
        // Cross-usable: kp2's public key (same as kp1) verifies kp1's signature.
        let msg = b"seed-derived keypair";
        let sig = kp1.sign(msg).unwrap();
        assert!(kp2.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_serialization() {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let bytes = keypair.to_bytes();
        let recovered = DilithiumKeypair::from_bytes(&bytes).unwrap();
        assert_eq!(keypair.public_key.as_bytes(), recovered.public_key.as_bytes());
        // Recovered keypair can still sign/verify.
        let msg = b"roundtrip";
        let sig = recovered.sign(msg).unwrap();
        assert!(keypair.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_address_derivation() {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let address = keypair.address();
        let address2 = Address::from_public_key(keypair.public_key.as_bytes());
        assert_eq!(address, address2);
    }

    #[test]
    fn test_all_schemes() {
        for scheme in [
            SignatureScheme::Dilithium2,
            SignatureScheme::Dilithium3,
            SignatureScheme::Dilithium5,
        ] {
            let keypair = DilithiumKeypair::generate(scheme).unwrap();
            let message = b"Test";
            let sig = keypair.sign(message).unwrap();
            assert!(keypair.verify(message, &sig).unwrap());
        }
    }
}
