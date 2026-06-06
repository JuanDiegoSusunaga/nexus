//! Signer and Verifier traits for NEXUS
//!
//! Provides high-level signing and verification interfaces
//! that abstract over the underlying cryptographic primitives.

use crate::dilithium::{DilithiumKeypair, DilithiumPublicKey, DilithiumSignature};
use nexus_core::{
    Address, Hash256, NexusError, PQSignature, SignatureScheme,
    SignedTransaction, Transaction,
};

/// Trait for signing operations
pub trait Signer {
    /// Sign a raw message
    fn sign(&self, message: &[u8]) -> Result<DilithiumSignature, NexusError>;

    /// Sign a hash
    fn sign_hash(&self, hash: &Hash256) -> Result<DilithiumSignature, NexusError> {
        self.sign(hash.as_bytes())
    }

    /// Sign a transaction
    fn sign_transaction(&self, tx: Transaction) -> Result<SignedTransaction, NexusError>;

    /// Get the signer's address
    fn address(&self) -> Address;

    /// Get the signer's public key bytes
    fn public_key_bytes(&self) -> Vec<u8>;

    /// Get the signature scheme
    fn scheme(&self) -> SignatureScheme;
}

/// Trait for verification operations
pub trait Verifier {
    /// Verify a signature on a message
    fn verify(&self, message: &[u8], signature: &DilithiumSignature) -> Result<bool, NexusError>;

    /// Verify a signature on a hash
    fn verify_hash(&self, hash: &Hash256, signature: &DilithiumSignature) -> Result<bool, NexusError> {
        self.verify(hash.as_bytes(), signature)
    }

    /// Get the verifier's address
    fn address(&self) -> Address;
}

impl Signer for DilithiumKeypair {
    fn sign(&self, message: &[u8]) -> Result<DilithiumSignature, NexusError> {
        DilithiumKeypair::sign(self, message)
    }

    fn sign_transaction(&self, tx: Transaction) -> Result<SignedTransaction, NexusError> {
        let signing_hash = tx.signing_hash();
        let signature = self.sign_hash(&signing_hash)?;

        Ok(SignedTransaction::new(
            tx,
            self.address(),
            signature.to_pq_signature(),
            self.public_key().as_bytes().to_vec(),
        ))
    }

    fn address(&self) -> Address {
        DilithiumKeypair::address(self)
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key().as_bytes().to_vec()
    }

    fn scheme(&self) -> SignatureScheme {
        DilithiumKeypair::scheme(self)
    }
}

impl Verifier for DilithiumKeypair {
    fn verify(&self, message: &[u8], signature: &DilithiumSignature) -> Result<bool, NexusError> {
        DilithiumKeypair::verify(self, message, signature)
    }

    fn address(&self) -> Address {
        DilithiumKeypair::address(self)
    }
}

impl Verifier for DilithiumPublicKey {
    fn verify(&self, message: &[u8], signature: &DilithiumSignature) -> Result<bool, NexusError> {
        DilithiumPublicKey::verify(self, message, signature)
    }

    fn address(&self) -> Address {
        self.to_address()
    }
}

/// Verify a signed transaction
pub fn verify_signed_transaction(tx: &SignedTransaction) -> Result<bool, NexusError> {
    // Validate structure first
    tx.validate_structure()?;

    // Recreate signing hash
    let signing_hash = tx.transaction.signing_hash();

    // Reconstruct signature
    let signature = DilithiumSignature::from_bytes(
        tx.signature.bytes.clone(),
        tx.signature.scheme,
    )?;

    // Reconstruct public key
    let public_key = DilithiumPublicKey::from_bytes(
        tx.public_key.clone(),
        tx.signature.scheme,
    )?;

    // Verify
    public_key.verify(signing_hash.as_bytes(), &signature)
}

/// Batch verify multiple signatures (for block validation)
/// Returns indices of invalid signatures
pub fn batch_verify(
    messages: &[&[u8]],
    signatures: &[&DilithiumSignature],
    public_keys: &[&DilithiumPublicKey],
) -> Result<Vec<usize>, NexusError> {
    if messages.len() != signatures.len() || messages.len() != public_keys.len() {
        return Err(NexusError::InvalidSignature(
            "Mismatched array lengths".into(),
        ));
    }

    let mut invalid_indices = Vec::new();

    // Note: In production, use parallel verification for performance
    for (i, ((message, signature), public_key)) in messages
        .iter()
        .zip(signatures.iter())
        .zip(public_keys.iter())
        .enumerate()
    {
        match public_key.verify(message, signature) {
            Ok(true) => {}
            Ok(false) => invalid_indices.push(i),
            Err(_) => invalid_indices.push(i),
        }
    }

    Ok(invalid_indices)
}

/// Signature aggregation helper (for future use with aggregate signatures)
pub struct SignatureAggregator {
    signatures: Vec<DilithiumSignature>,
    messages: Vec<Vec<u8>>,
    public_keys: Vec<DilithiumPublicKey>,
}

impl SignatureAggregator {
    pub fn new() -> Self {
        Self {
            signatures: Vec::new(),
            messages: Vec::new(),
            public_keys: Vec::new(),
        }
    }

    pub fn add(
        &mut self,
        message: Vec<u8>,
        signature: DilithiumSignature,
        public_key: DilithiumPublicKey,
    ) {
        self.messages.push(message);
        self.signatures.push(signature);
        self.public_keys.push(public_key);
    }

    pub fn count(&self) -> usize {
        self.signatures.len()
    }

    /// Verify all signatures
    pub fn verify_all(&self) -> Result<bool, NexusError> {
        let messages: Vec<&[u8]> = self.messages.iter().map(|m| m.as_slice()).collect();
        let signatures: Vec<&DilithiumSignature> = self.signatures.iter().collect();
        let public_keys: Vec<&DilithiumPublicKey> = self.public_keys.iter().collect();

        let invalid = batch_verify(&messages, &signatures, &public_keys)?;
        Ok(invalid.is_empty())
    }

    /// Get indices of invalid signatures
    pub fn get_invalid(&self) -> Result<Vec<usize>, NexusError> {
        let messages: Vec<&[u8]> = self.messages.iter().map(|m| m.as_slice()).collect();
        let signatures: Vec<&DilithiumSignature> = self.signatures.iter().collect();
        let public_keys: Vec<&DilithiumPublicKey> = self.public_keys.iter().collect();

        batch_verify(&messages, &signatures, &public_keys)
    }
}

impl Default for SignatureAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::{Amount, ChainId, Nonce};

    #[test]
    fn test_signer_trait() {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let message = b"Test message";

        let sig = Signer::sign(&keypair, message).unwrap();
        assert!(Verifier::verify(&keypair, message, &sig).unwrap());
    }

    #[test]
    fn test_sign_transaction() {
        let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();

        let tx = Transaction::transfer(
            ChainId::LOCAL,
            Nonce::new(0),
            Address::ZERO,
            Amount::from_units(100),
            21000,
            Amount(1000000000),
        );

        let signed = keypair.sign_transaction(tx).unwrap();
        assert!(verify_signed_transaction(&signed).unwrap());
    }

    #[test]
    fn test_batch_verify() {
        let keypair1 = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let keypair2 = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();

        let msg1 = b"Message 1";
        let msg2 = b"Message 2";

        let sig1 = keypair1.sign(msg1).unwrap();
        let sig2 = keypair2.sign(msg2).unwrap();

        let messages: Vec<&[u8]> = vec![msg1, msg2];
        let signatures: Vec<&DilithiumSignature> = vec![&sig1, &sig2];
        let public_keys: Vec<&DilithiumPublicKey> = vec![keypair1.public_key(), keypair2.public_key()];

        let invalid = batch_verify(&messages, &signatures, &public_keys).unwrap();
        assert!(invalid.is_empty());
    }

    #[test]
    fn test_batch_verify_with_invalid() {
        let keypair1 = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let keypair2 = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();

        let msg1 = b"Message 1";
        let msg2 = b"Message 2";
        let wrong_msg = b"Wrong message";

        let sig1 = keypair1.sign(msg1).unwrap();
        let sig2 = keypair2.sign(wrong_msg).unwrap(); // Wrong message

        let messages: Vec<&[u8]> = vec![msg1, msg2];
        let signatures: Vec<&DilithiumSignature> = vec![&sig1, &sig2];
        let public_keys: Vec<&DilithiumPublicKey> = vec![keypair1.public_key(), keypair2.public_key()];

        let invalid = batch_verify(&messages, &signatures, &public_keys).unwrap();
        assert_eq!(invalid, vec![1]); // Index 1 is invalid
    }

    #[test]
    fn test_signature_aggregator() {
        let keypair1 = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let keypair2 = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();

        let mut aggregator = SignatureAggregator::new();

        let msg1 = b"Message 1".to_vec();
        let sig1 = keypair1.sign(&msg1).unwrap();
        aggregator.add(msg1, sig1, keypair1.public_key().clone());

        let msg2 = b"Message 2".to_vec();
        let sig2 = keypair2.sign(&msg2).unwrap();
        aggregator.add(msg2, sig2, keypair2.public_key().clone());

        assert_eq!(aggregator.count(), 2);
        assert!(aggregator.verify_all().unwrap());
    }
}
