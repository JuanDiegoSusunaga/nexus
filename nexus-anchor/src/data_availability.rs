//! Bounded in-memory payload storage and authenticated chunk inclusion.
//! This local profile implements neither erasure coding nor remote DAS.

use nexus_core::{BlockHeight, Hash256, MerkleTree, NexusError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const DA_CHUNK_BYTES: usize = 256;
pub const MAX_DA_DATA_SIZE: usize = nexus_core::MAX_BLOCK_SIZE;
const LOCAL_DA_VERSION: u16 = 1;

/// A trusted local receipt, distinct from consensus inclusion or an L2 proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DACommitment {
    pub encoding_version: u16,
    /// SHA3 of the exact payload; preserves the existing payload identifier.
    pub commitment: Hash256,
    /// Merkle root of ordered, domain-separated chunk leaves.
    pub chunk_root: Hash256,
    pub data_size: u64,
    pub chunk_count: u32,
    /// All original chunks are required, without parity: (chunk_count, chunk_count).
    pub coding_params: (u32, u32),
}

impl DACommitment {
    pub fn from_data(data: &[u8]) -> Result<Self, NexusError> {
        if data.is_empty() {
            return Err(NexusError::InvalidTransaction("Empty local DA payload".into()));
        }
        if data.len() > MAX_DA_DATA_SIZE { return Err(NexusError::BatchTooLarge); }
        let count = u32::try_from(data.len().div_ceil(DA_CHUNK_BYTES)).map_err(|_| NexusError::BatchTooLarge)?;
        let mut receipt = Self { encoding_version: LOCAL_DA_VERSION,
            commitment: Hash256::hash(data), chunk_root: Hash256::ZERO,
            data_size: data.len() as u64, chunk_count: count, coding_params: (count, count) };
        let leaves = data.chunks(DA_CHUNK_BYTES).enumerate()
            .map(|(index, chunk)| receipt.leaf_hash(index as u32, chunk)).collect();
        receipt.chunk_root = MerkleTree::from_leaves(leaves).root();
        Ok(receipt)
    }

    fn valid_metadata(&self) -> bool {
        if self.encoding_version != LOCAL_DA_VERSION || self.data_size == 0
            || self.data_size > MAX_DA_DATA_SIZE as u64 { return false; }
        let count = self.data_size.div_ceil(DA_CHUNK_BYTES as u64) as u32;
        self.chunk_count == count && self.coding_params == (count, count)
    }

    fn chunk_len(&self, index: u32) -> Option<usize> {
        if !self.valid_metadata() || index >= self.chunk_count { return None; }
        Some((self.data_size as usize - index as usize * DA_CHUNK_BYTES).min(DA_CHUNK_BYTES))
    }

    fn leaf_hash(&self, index: u32, chunk: &[u8]) -> Hash256 {
        let mut input = b"NEXUS/LOCAL-DA/CHUNK/V1".to_vec();
        input.extend_from_slice(self.commitment.as_bytes());
        input.extend_from_slice(&self.data_size.to_le_bytes());
        input.extend_from_slice(&self.chunk_count.to_le_bytes());
        input.extend_from_slice(&index.to_le_bytes());
        input.extend_from_slice(chunk);
        Hash256::hash(&input)
    }
}

/// Chunk inclusion under an externally trusted receipt, whose provenance is the caller's responsibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAProof {
    pub merkle_proof: Vec<Hash256>,
    pub chunk_index: u32,
    pub chunk_data: Vec<u8>,
}

impl DAProof {
    pub fn verify(&self, commitment: &DACommitment) -> bool {
        if commitment.chunk_len(self.chunk_index) != Some(self.chunk_data.len()) { return false; }
        let depth = commitment.chunk_count.next_power_of_two().trailing_zeros() as usize;
        if self.merkle_proof.len() != depth { return false; }
        let mut current = commitment.leaf_hash(self.chunk_index, &self.chunk_data);
        for (level, sibling) in self.merkle_proof.iter().enumerate() {
            let (left, right) = if (self.chunk_index >> level) & 1 == 1 {
                (sibling, &current)
            } else { (&current, sibling) };
            let mut pair = [0u8; 64];
            pair[..32].copy_from_slice(left.as_bytes());
            pair[32..].copy_from_slice(right.as_bytes());
            current = Hash256::hash(&pair);
        }
        current == commitment.chunk_root
    }
}

/// Reserved request shape for the future remote sampling protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DASample {
    pub height: BlockHeight,
    pub row_indices: Vec<u32>,
    pub col_indices: Vec<u32>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DataAvailabilityLayer {
    commitments: HashMap<BlockHeight, Vec<DACommitment>>,
    /// A payload index prevents submissions at one height overwriting each other.
    chunks: HashMap<(BlockHeight, usize, u32), Vec<u8>>,
}

impl DataAvailabilityLayer {
    pub fn new() -> Self { Self { commitments: HashMap::new(), chunks: HashMap::new() } }

    pub fn submit_data(&mut self, height: BlockHeight, data: Vec<u8>) -> Result<DACommitment, NexusError> {
        // Every fallible validation precedes publication of chunks and receipt.
        let commitment = DACommitment::from_data(&data)?;
        let batch_index = self.commitments.get(&height).map_or(0, Vec::len);
        for (index, chunk) in data.chunks(DA_CHUNK_BYTES).enumerate() {
            self.chunks.insert((height, batch_index, index as u32), chunk.to_vec());
        }
        self.commitments.entry(height).or_default().push(commitment.clone());
        Ok(commitment)
    }

    fn receipt(&self, height: BlockHeight, batch_index: usize) -> Result<&DACommitment, NexusError> {
        self.commitments.get(&height).and_then(|receipts| receipts.get(batch_index))
            .ok_or_else(|| NexusError::StateError("Local DA payload not found".into()))
    }

    fn single_batch_index(&self, height: BlockHeight) -> Result<usize, NexusError> {
        match self.commitments.get(&height) {
            Some(receipts) if receipts.len() == 1 => Ok(0),
            Some(_) => Err(NexusError::StateError("Ambiguous DA height; select a payload index".into())),
            None => Err(NexusError::StateError("No local DA payloads for height".into())),
        }
    }

    fn ordered_chunks(&self, height: BlockHeight, batch_index: usize,
        commitment: &DACommitment) -> Result<Vec<&[u8]>, NexusError> {
        if !commitment.valid_metadata() { return Err(NexusError::StateError("Invalid local DA metadata".into())); }
        (0..commitment.chunk_count).map(|index| {
            let chunk = self.chunks.get(&(height, batch_index, index))
                .ok_or_else(|| NexusError::StateError("Missing local DA chunk".into()))?;
            if commitment.chunk_len(index) != Some(chunk.len()) {
                return Err(NexusError::StateError("Invalid local DA chunk length".into()));
            }
            Ok(chunk.as_slice())
        }).collect()
    }

    /// Legacy convenience API: a height must identify exactly one payload.
    pub fn generate_proof(&self, height: BlockHeight, chunk_index: u32) -> Result<DAProof, NexusError> {
        self.generate_batch_proof(height, self.single_batch_index(height)?, chunk_index)
    }

    pub fn generate_batch_proof(&self, height: BlockHeight, batch_index: usize,
        chunk_index: u32) -> Result<DAProof, NexusError> {
        let commitment = self.receipt(height, batch_index)?;
        if commitment.chunk_len(chunk_index).is_none() {
            return Err(NexusError::StateError("Invalid local DA chunk index".into()));
        }
        let chunks = self.ordered_chunks(height, batch_index, commitment)?;
        let leaves = chunks.iter().enumerate()
            .map(|(index, chunk)| commitment.leaf_hash(index as u32, chunk)).collect();
        let tree = MerkleTree::from_leaves(leaves);
        if tree.root() != commitment.chunk_root { return Err(NexusError::StateError("Local DA chunk root mismatch".into())); }
        let proof = tree.generate_proof(chunk_index as usize)
            .ok_or_else(|| NexusError::StateError("Invalid local DA chunk index".into()))?;
        Ok(DAProof { merkle_proof: proof.proof.into_iter().map(|node| node.hash).collect(),
            chunk_index, chunk_data: chunks[chunk_index as usize].to_vec() })
    }

    /// Legacy name: checks all local payloads; it neither samples peers nor establishes network availability.
    pub fn sample(&self, height: BlockHeight) -> Result<bool, NexusError> {
        let receipts = self.commitments.get(&height)
            .ok_or_else(|| NexusError::StateError("No local DA payloads for height".into()))?;
        Ok((0..receipts.len()).all(|index| self.reconstruct_batch(height, index).is_ok()))
    }

    pub fn get_commitment(&self, height: BlockHeight) -> Option<&Vec<DACommitment>> { self.commitments.get(&height) }

    /// Legacy convenience API: rejects a height containing multiple payloads.
    pub fn reconstruct_data(&self, height: BlockHeight) -> Result<Vec<u8>, NexusError> {
        self.reconstruct_batch(height, self.single_batch_index(height)?)
    }

    pub fn reconstruct_batch(&self, height: BlockHeight, batch_index: usize) -> Result<Vec<u8>, NexusError> {
        let commitment = self.receipt(height, batch_index)?;
        let chunks = self.ordered_chunks(height, batch_index, commitment)?;
        let data: Vec<u8> = chunks.into_iter().flatten().copied().collect();
        if DACommitment::from_data(&data)? != *commitment {
            return Err(NexusError::StateError("Local DA payload commitment mismatch".into()));
        }
        Ok(data)
    }
}

impl Default for DataAvailabilityLayer { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_da_submit_and_reconstruct() {
        let mut da = DataAvailabilityLayer::new();
        let data = b"Hello, NEXUS Data Availability Layer!".to_vec();
        let commitment = da.submit_data(BlockHeight(1), data.clone()).unwrap();
        assert_eq!(commitment.commitment, Hash256::hash(&data));
        assert_eq!(da.reconstruct_data(BlockHeight(1)).unwrap(), data);
    }

    #[test]
    fn test_da_sampling() {
        let mut da = DataAvailabilityLayer::new();
        da.submit_data(BlockHeight(1), vec![0; 1024]).unwrap();
        assert!(da.sample(BlockHeight(1)).unwrap());
    }

    #[test]
    fn test_da_proof_generation() {
        let mut da = DataAvailabilityLayer::new();
        let commitment = da.submit_data(BlockHeight(1), vec![1; 512]).unwrap();
        assert!(da.generate_proof(BlockHeight(1), 0).unwrap().verify(&commitment));
    }

    #[test]
    fn corrupt_or_missing_chunks_in_any_payload_fail_the_local_integrity_check() {
        let mut da = DataAvailabilityLayer::new();
        let height = BlockHeight(1);
        da.submit_data(height, vec![1; 512]).unwrap();
        da.submit_data(height, vec![2; 700]).unwrap();
        da.chunks.get_mut(&(height, 1, 0)).unwrap()[0] ^= 1;
        assert!(!da.sample(height).unwrap());
        assert!(da.reconstruct_batch(height, 1).is_err());
        assert!(da.generate_batch_proof(height, 1, 0).is_err());
        assert_eq!(da.reconstruct_batch(height, 0).unwrap(), vec![1; 512]);
        da.chunks.remove(&(height, 0, 1));
        assert!(da.reconstruct_batch(height, 0).is_err());
        assert!(da.generate_batch_proof(height, 0, 0).is_err());
    }

    #[test]
    fn corrupted_receipt_metadata_is_rejected_without_allocating_from_it() {
        let mut da = DataAvailabilityLayer::new();
        let height = BlockHeight(1);
        da.submit_data(height, vec![1; 10]).unwrap();
        let receipt = &mut da.commitments.get_mut(&height).unwrap()[0];
        receipt.data_size = u64::MAX;
        receipt.chunk_count = u32::MAX;
        assert!(!da.sample(height).unwrap());
        assert!(da.reconstruct_batch(height, 0).is_err());
        assert!(da.generate_batch_proof(height, 0, 0).is_err());
    }
}
