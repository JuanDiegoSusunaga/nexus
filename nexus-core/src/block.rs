//! Block structures for NEXUS dual-chain
//!
//! Defines blocks for both Anchor Layer (L1) and Active Layer (L2).

use crate::{
    Address, BlockHeight, Hash256, Layer, NexusError, PQSignature, SignedTransaction,
    Timestamp, Hashable, Encodable,
};
use serde::{Deserialize, Serialize};

/// Block header containing metadata and cryptographic commitments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Protocol version
    pub version: u32,
    /// Block height
    pub height: BlockHeight,
    /// Timestamp of block creation
    pub timestamp: Timestamp,
    /// Hash of parent block
    pub parent_hash: Hash256,
    /// Merkle root of transactions
    pub transactions_root: Hash256,
    /// State root after applying transactions
    pub state_root: Hash256,
    /// Receipts root (for transaction results)
    pub receipts_root: Hash256,
    /// Layer identifier (Anchor or Active)
    pub layer: Layer,
    /// Block proposer address
    pub proposer: Address,
    /// For L2: reference to L1 block for data availability
    pub l1_reference: Option<L1Reference>,
    /// Extra data (max 32 bytes)
    pub extra_data: Vec<u8>,
}

impl BlockHeader {
    /// Create a new block header
    pub fn new(
        height: BlockHeight,
        parent_hash: Hash256,
        proposer: Address,
        layer: Layer,
    ) -> Self {
        Self {
            version: crate::PROTOCOL_VERSION,
            height,
            timestamp: Timestamp::now(),
            parent_hash,
            transactions_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            layer,
            proposer,
            l1_reference: None,
            extra_data: Vec::new(),
        }
    }
}

impl Hashable for BlockHeader {
    fn hash(&self) -> Hash256 {
        let encoded = bincode::serialize(self).expect("Header serialization should not fail");
        Hash256::hash(&encoded)
    }
}

impl Encodable for BlockHeader {
    fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Header serialization should not fail")
    }

    fn decode(bytes: &[u8]) -> Result<Self, NexusError> {
        bincode::deserialize(bytes).map_err(|e| NexusError::SerializationError(e.to_string()))
    }
}

/// Reference to L1 block (used by L2 blocks)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L1Reference {
    /// L1 block hash containing the data
    pub block_hash: Hash256,
    /// L1 block height
    pub block_height: BlockHeight,
    /// Index of batch within L1 block
    pub batch_index: u32,
    /// Merkle proof for data availability
    pub da_proof: Vec<Hash256>,
}

/// Block body containing transactions and signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockBody {
    /// Transactions in this block
    pub transactions: Vec<SignedTransaction>,
    /// Validator signatures (for finalization)
    pub signatures: Vec<ValidatorSignature>,
}

impl BlockBody {
    pub fn new(transactions: Vec<SignedTransaction>) -> Self {
        Self {
            transactions,
            signatures: Vec::new(),
        }
    }

    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }
}

/// Validator signature on a block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSignature {
    /// Validator address
    pub validator: Address,
    /// PQC signature on block hash
    pub signature: PQSignature,
}

/// Complete block structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    /// Block body
    pub body: BlockBody,
}

impl Block {
    /// Create a new block
    pub fn new(header: BlockHeader, body: BlockBody) -> Self {
        Self { header, body }
    }

    /// Get block hash (hash of header)
    pub fn hash(&self) -> Hash256 {
        self.header.hash()
    }

    /// Get block height
    pub fn height(&self) -> BlockHeight {
        self.header.height
    }

    /// Get parent hash
    pub fn parent_hash(&self) -> Hash256 {
        self.header.parent_hash
    }

    /// Get all transaction hashes
    pub fn transaction_hashes(&self) -> Vec<Hash256> {
        self.body
            .transactions
            .iter()
            .map(|tx| tx.hash())
            .collect()
    }

    /// Check if block is empty (no transactions)
    pub fn is_empty(&self) -> bool {
        self.body.transactions.is_empty()
    }

    /// Get block size in bytes
    pub fn size(&self) -> usize {
        bincode::serialize(self)
            .map(|b| b.len())
            .unwrap_or(0)
    }

    /// Create genesis block
    pub fn genesis(layer: Layer) -> Self {
        let header = BlockHeader {
            version: crate::PROTOCOL_VERSION,
            height: BlockHeight::GENESIS,
            timestamp: Timestamp::from_millis(0),
            parent_hash: Hash256::ZERO,
            transactions_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            layer,
            proposer: Address::ZERO,
            l1_reference: None,
            extra_data: b"NEXUS Genesis".to_vec(),
        };

        let body = BlockBody::new(Vec::new());
        Self { header, body }
    }

    /// Validate basic block structure
    pub fn validate_structure(&self) -> Result<(), NexusError> {
        // Check block size
        let size = self.size();
        if size > crate::MAX_BLOCK_SIZE {
            return Err(NexusError::BlockTooLarge {
                size,
                max: crate::MAX_BLOCK_SIZE,
            });
        }

        // Check transaction count
        if self.body.transactions.len() > crate::MAX_TXS_PER_BLOCK {
            return Err(NexusError::InvalidBlock(format!(
                "Too many transactions: {} (max: {})",
                self.body.transactions.len(),
                crate::MAX_TXS_PER_BLOCK
            )));
        }

        // Check extra data size
        if self.header.extra_data.len() > 32 {
            return Err(NexusError::InvalidBlock(
                "Extra data too large (max 32 bytes)".into(),
            ));
        }

        Ok(())
    }
}

impl Hashable for Block {
    fn hash(&self) -> Hash256 {
        self.header.hash()
    }
}

impl Encodable for Block {
    fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Block serialization should not fail")
    }

    fn decode(bytes: &[u8]) -> Result<Self, NexusError> {
        bincode::deserialize(bytes).map_err(|e| NexusError::SerializationError(e.to_string()))
    }
}

/// L2 Batch submitted to L1 for data availability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2Batch {
    /// Batch index
    pub index: u64,
    /// L2 block range (start, end)
    pub block_range: (BlockHeight, BlockHeight),
    /// Compressed transaction data
    pub compressed_data: Vec<u8>,
    /// State root before batch
    pub pre_state_root: Hash256,
    /// State root after batch
    pub post_state_root: Hash256,
    /// ZK proof of correct execution (optional, for validity rollup mode)
    pub validity_proof: Option<Vec<u8>>,
    /// Sequencer signature
    pub sequencer_signature: PQSignature,
}

impl L2Batch {
    /// Calculate batch hash
    pub fn hash(&self) -> Hash256 {
        let encoded = bincode::serialize(self).expect("Batch serialization should not fail");
        Hash256::hash(&encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis(Layer::Anchor);
        assert_eq!(genesis.height(), BlockHeight::GENESIS);
        assert_eq!(genesis.parent_hash(), Hash256::ZERO);
        assert!(genesis.is_empty());
    }

    #[test]
    fn test_block_hash_deterministic() {
        let genesis = Block::genesis(Layer::Active);
        let hash1 = genesis.hash();
        let hash2 = genesis.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_block_validation() {
        let block = Block::genesis(Layer::Anchor);
        assert!(block.validate_structure().is_ok());
    }
}
