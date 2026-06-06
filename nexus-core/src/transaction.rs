//! Transaction structures for NEXUS blockchain
//!
//! Supports multiple transaction types including transfers, smart contract
//! interactions, and L2 batch submissions.

use crate::{
    Address, Amount, ChainId, Hash256, Nonce, PQSignature, SignatureScheme,
    Timestamp, NexusError, Hashable, Encodable,
};
use serde::{Deserialize, Serialize};

/// Transaction types supported by NEXUS
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionType {
    /// Simple value transfer
    Transfer {
        to: Address,
        amount: Amount,
    },
    /// Smart contract deployment
    Deploy {
        code: Vec<u8>,
        init_data: Vec<u8>,
    },
    /// Smart contract call
    Call {
        contract: Address,
        method: String,
        args: Vec<u8>,
        value: Amount,
    },
    /// L2 batch submission (only on L1)
    BatchSubmit {
        batch_root: Hash256,
        batch_size: u32,
        compressed_data: Vec<u8>,
    },
    /// Validator registration
    ValidatorRegister {
        public_key: Vec<u8>,
        stake: Amount,
    },
    /// Validator exit
    ValidatorExit,
    /// Key rotation announcement
    KeyRotation {
        new_public_key: Vec<u8>,
        proof: Vec<u8>,
    },
    /// Cross-layer message (L1 <-> L2)
    CrossLayerMessage {
        target_layer: crate::Layer,
        payload: Vec<u8>,
    },
}

/// Unsigned transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Chain ID for replay protection
    pub chain_id: ChainId,
    /// Sender's nonce
    pub nonce: Nonce,
    /// Maximum gas willing to pay
    pub gas_limit: u64,
    /// Gas price (in smallest unit)
    pub gas_price: Amount,
    /// Transaction type and payload
    pub tx_type: TransactionType,
    /// Transaction creation timestamp
    pub timestamp: Timestamp,
    /// Expiration timestamp (optional)
    pub expires_at: Option<Timestamp>,
}

impl Transaction {
    /// Create a new transfer transaction
    pub fn transfer(
        chain_id: ChainId,
        nonce: Nonce,
        to: Address,
        amount: Amount,
        gas_limit: u64,
        gas_price: Amount,
    ) -> Self {
        Self {
            chain_id,
            nonce,
            gas_limit,
            gas_price,
            tx_type: TransactionType::Transfer { to, amount },
            timestamp: Timestamp::now(),
            expires_at: None,
        }
    }

    /// Create a contract call transaction
    pub fn call(
        chain_id: ChainId,
        nonce: Nonce,
        contract: Address,
        method: String,
        args: Vec<u8>,
        value: Amount,
        gas_limit: u64,
        gas_price: Amount,
    ) -> Self {
        Self {
            chain_id,
            nonce,
            gas_limit,
            gas_price,
            tx_type: TransactionType::Call {
                contract,
                method,
                args,
                value,
            },
            timestamp: Timestamp::now(),
            expires_at: None,
        }
    }

    /// Get the transaction hash (for signing)
    pub fn signing_hash(&self) -> Hash256 {
        let encoded = bincode::serialize(self).expect("Transaction serialization should not fail");
        Hash256::hash(&encoded)
    }

    /// Check if transaction has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Timestamp::now().as_millis() > expires_at.as_millis()
        } else {
            false
        }
    }

    /// Calculate the maximum cost of this transaction
    pub fn max_cost(&self) -> Amount {
        let gas_cost = Amount(self.gas_limit as u128 * self.gas_price.0);
        let value = match &self.tx_type {
            TransactionType::Transfer { amount, .. } => *amount,
            TransactionType::Call { value, .. } => *value,
            TransactionType::ValidatorRegister { stake, .. } => *stake,
            _ => Amount::ZERO,
        };
        gas_cost.saturating_add(value)
    }
}

impl Hashable for Transaction {
    fn hash(&self) -> Hash256 {
        self.signing_hash()
    }
}

/// Signed transaction ready for submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The unsigned transaction
    pub transaction: Transaction,
    /// Sender's address (derived from public key)
    pub sender: Address,
    /// PQC signature
    pub signature: PQSignature,
    /// Sender's public key (for verification)
    pub public_key: Vec<u8>,
}

impl SignedTransaction {
    /// Create a new signed transaction
    pub fn new(
        transaction: Transaction,
        sender: Address,
        signature: PQSignature,
        public_key: Vec<u8>,
    ) -> Self {
        Self {
            transaction,
            sender,
            signature,
            public_key,
        }
    }

    /// Get the transaction hash
    pub fn hash(&self) -> Hash256 {
        // Include signature in hash for unique identification
        let mut data = self.transaction.encode();
        data.extend_from_slice(&self.signature.bytes);
        Hash256::hash(&data)
    }

    /// Get inner transaction
    pub fn inner(&self) -> &Transaction {
        &self.transaction
    }

    /// Validate transaction structure (not signature)
    pub fn validate_structure(&self) -> Result<(), NexusError> {
        // Check if expired
        if self.transaction.is_expired() {
            return Err(NexusError::TransactionExpired);
        }

        // Check gas limit
        if self.transaction.gas_limit == 0 {
            return Err(NexusError::InvalidTransaction("Gas limit cannot be zero".into()));
        }

        // Validate public key matches sender
        let derived_address = Address::from_public_key(&self.public_key);
        if derived_address != self.sender {
            return Err(NexusError::InvalidTransaction(
                "Public key does not match sender address".into(),
            ));
        }

        // Validate signature scheme matches public key size
        match self.signature.scheme {
            SignatureScheme::Dilithium2 => {
                if self.public_key.len() != 1312 {
                    return Err(NexusError::InvalidPublicKey(
                        "Invalid Dilithium2 public key size".into(),
                    ));
                }
            }
            SignatureScheme::Dilithium3 => {
                if self.public_key.len() != 1952 {
                    return Err(NexusError::InvalidPublicKey(
                        "Invalid Dilithium3 public key size".into(),
                    ));
                }
            }
            SignatureScheme::Dilithium5 => {
                if self.public_key.len() != 2592 {
                    return Err(NexusError::InvalidPublicKey(
                        "Invalid Dilithium5 public key size".into(),
                    ));
                }
            }
        }

        Ok(())
    }
}

impl Hashable for SignedTransaction {
    fn hash(&self) -> Hash256 {
        self.hash()
    }
}

impl Encodable for SignedTransaction {
    fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("SignedTransaction serialization should not fail")
    }

    fn decode(bytes: &[u8]) -> Result<Self, NexusError> {
        bincode::deserialize(bytes).map_err(|e| NexusError::SerializationError(e.to_string()))
    }
}

impl Encodable for Transaction {
    fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Transaction serialization should not fail")
    }

    fn decode(bytes: &[u8]) -> Result<Self, NexusError> {
        bincode::deserialize(bytes).map_err(|e| NexusError::SerializationError(e.to_string()))
    }
}

/// Transaction receipt (result of execution)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    /// Transaction hash
    pub tx_hash: Hash256,
    /// Block hash containing this transaction
    pub block_hash: Hash256,
    /// Block height
    pub block_height: crate::BlockHeight,
    /// Index within block
    pub tx_index: u32,
    /// Execution status
    pub status: ExecutionStatus,
    /// Gas used
    pub gas_used: u64,
    /// Contract address (if deployment)
    pub contract_address: Option<Address>,
    /// Logs emitted
    pub logs: Vec<Log>,
    /// Return data (if any)
    pub return_data: Vec<u8>,
}

/// Transaction execution status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// Transaction executed successfully
    Success,
    /// Transaction reverted
    Reverted,
    /// Transaction failed (out of gas, invalid, etc.)
    Failed,
}

/// Event log emitted by transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    /// Contract that emitted the log
    pub address: Address,
    /// Log topics (indexed parameters)
    pub topics: Vec<Hash256>,
    /// Log data (non-indexed parameters)
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_transaction() {
        let tx = Transaction::transfer(
            ChainId::LOCAL,
            Nonce::new(0),
            Address::ZERO,
            Amount::from_units(100),
            21000,
            Amount(1000000000),
        );

        assert!(!tx.is_expired());
        assert!(tx.max_cost().0 > 0);
    }

    #[test]
    fn test_transaction_hash_deterministic() {
        let tx = Transaction::transfer(
            ChainId::LOCAL,
            Nonce::new(0),
            Address::ZERO,
            Amount::from_units(100),
            21000,
            Amount(1000000000),
        );

        let hash1 = tx.hash();
        let hash2 = tx.hash();
        assert_eq!(hash1, hash2);
    }
}
