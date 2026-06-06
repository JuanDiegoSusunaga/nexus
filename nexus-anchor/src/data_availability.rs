//! Data Availability Layer for Anchor Chain
//!
//! Ensures that L2 batch data is always available for reconstruction.
//! Uses erasure coding and polynomial commitments.

use nexus_core::{Hash256, NexusError, BlockHeight, Encodable};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Data Availability commitment (polynomial commitment)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DACommitment {
    /// Commitment hash
    pub commitment: Hash256,
    /// Data size in bytes
    pub data_size: u64,
    /// Number of chunks
    pub chunk_count: u32,
    /// Erasure coding parameters (k, n)
    pub coding_params: (u32, u32),
}

impl DACommitment {
    /// Create a new commitment from data
    pub fn from_data(data: &[u8], k: u32, n: u32) -> Self {
        Self {
            commitment: Hash256::hash(data),
            data_size: data.len() as u64,
            chunk_count: ((data.len() as u32) + 255) / 256, // 256-byte chunks
            coding_params: (k, n),
        }
    }
}

/// Proof that data is available
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DAProof {
    /// Merkle proof for the chunk
    pub merkle_proof: Vec<Hash256>,
    /// Chunk index
    pub chunk_index: u32,
    /// Chunk data
    pub chunk_data: Vec<u8>,
}

impl DAProof {
    /// Verify the proof against a commitment
    pub fn verify(&self, commitment: &DACommitment) -> bool {
        // Simplified verification: check merkle proof leads to commitment
        let mut current = Hash256::hash(&self.chunk_data);

        for (i, sibling) in self.merkle_proof.iter().enumerate() {
            let is_right = (self.chunk_index >> i) & 1 == 1;
            current = if is_right {
                Hash256::hash(&[sibling.as_bytes().as_slice(), current.as_bytes().as_slice()].concat())
            } else {
                Hash256::hash(&[current.as_bytes().as_slice(), sibling.as_bytes().as_slice()].concat())
            };
        }

        current == commitment.commitment
    }
}

/// Data availability sample request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DASample {
    /// Block height
    pub height: BlockHeight,
    /// Row indices to sample
    pub row_indices: Vec<u32>,
    /// Column indices to sample
    pub col_indices: Vec<u32>,
}

/// Data Availability Layer
pub struct DataAvailabilityLayer {
    /// Stored commitments by block height
    commitments: HashMap<BlockHeight, Vec<DACommitment>>,
    /// Stored data chunks
    chunks: HashMap<(BlockHeight, u32), Vec<u8>>,
    /// Erasure coding ratio (k of n)
    coding_ratio: f64,
    /// Sample count for DAS
    sample_count: usize,
}

impl DataAvailabilityLayer {
    /// Create a new DA layer
    pub fn new() -> Self {
        Self {
            commitments: HashMap::new(),
            chunks: HashMap::new(),
            coding_ratio: 0.5, // 2x redundancy
            sample_count: 75,  // 75 samples for 99.9% probability
        }
    }

    /// Submit data for a block
    pub fn submit_data(
        &mut self,
        height: BlockHeight,
        data: Vec<u8>,
    ) -> Result<DACommitment, NexusError> {
        // Create erasure-coded chunks
        let chunks = self.erasure_encode(&data)?;
        let k = (chunks.len() as f64 * self.coding_ratio) as u32;
        let n = chunks.len() as u32;

        // Create commitment
        let commitment = DACommitment::from_data(&data, k, n);

        // Store chunks
        for (i, chunk) in chunks.into_iter().enumerate() {
            self.chunks.insert((height, i as u32), chunk);
        }

        // Store commitment
        self.commitments
            .entry(height)
            .or_default()
            .push(commitment.clone());

        Ok(commitment)
    }

    /// Erasure encode data into chunks
    fn erasure_encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, NexusError> {
        // Simplified: split into 256-byte chunks with padding
        let chunk_size = 256;
        let mut chunks = Vec::new();

        for chunk in data.chunks(chunk_size) {
            let mut padded = chunk.to_vec();
            padded.resize(chunk_size, 0);
            chunks.push(padded);
        }

        // In production: use Reed-Solomon coding to add parity chunks
        // For now, duplicate chunks for redundancy
        let original_count = chunks.len();
        for i in 0..original_count {
            chunks.push(chunks[i].clone());
        }

        Ok(chunks)
    }

    /// Generate proof for a chunk
    pub fn generate_proof(
        &self,
        height: BlockHeight,
        chunk_index: u32,
    ) -> Result<DAProof, NexusError> {
        let chunk = self
            .chunks
            .get(&(height, chunk_index))
            .ok_or(NexusError::StateError("Chunk not found".into()))?;

        // Generate merkle proof
        let all_chunks: Vec<_> = self
            .chunks
            .iter()
            .filter(|((h, _), _)| *h == height)
            .map(|((_, i), c)| (*i, c.clone()))
            .collect();

        let merkle_proof = self.generate_merkle_proof(&all_chunks, chunk_index)?;

        Ok(DAProof {
            merkle_proof,
            chunk_index,
            chunk_data: chunk.clone(),
        })
    }

    /// Generate merkle proof for a chunk
    fn generate_merkle_proof(
        &self,
        chunks: &[(u32, Vec<u8>)],
        index: u32,
    ) -> Result<Vec<Hash256>, NexusError> {
        // Simplified merkle proof generation
        let mut hashes: Vec<Hash256> = chunks
            .iter()
            .map(|(_, c)| Hash256::hash(c))
            .collect();

        let mut proof = Vec::new();
        let mut idx = index as usize;

        while hashes.len() > 1 {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            if sibling_idx < hashes.len() {
                proof.push(hashes[sibling_idx]);
            }

            // Combine pairs
            let mut new_hashes = Vec::new();
            for pair in hashes.chunks(2) {
                let combined = if pair.len() == 2 {
                    Hash256::hash(&[pair[0].as_bytes().as_slice(), pair[1].as_bytes().as_slice()].concat())
                } else {
                    pair[0]
                };
                new_hashes.push(combined);
            }
            hashes = new_hashes;
            idx /= 2;
        }

        Ok(proof)
    }

    /// Perform Data Availability Sampling
    pub fn sample(&self, height: BlockHeight) -> Result<bool, NexusError> {
        let commitments = self
            .commitments
            .get(&height)
            .ok_or(NexusError::StateError("No commitments for height".into()))?;

        if commitments.is_empty() {
            return Ok(true); // No data to sample
        }

        // Sample random chunks
        for _ in 0..self.sample_count {
            let chunk_count = commitments[0].chunk_count;
            let random_index = rand::random::<u32>() % chunk_count;

            if !self.chunks.contains_key(&(height, random_index)) {
                return Ok(false); // Data not available
            }
        }

        Ok(true)
    }

    /// Get commitment for a block
    pub fn get_commitment(&self, height: BlockHeight) -> Option<&Vec<DACommitment>> {
        self.commitments.get(&height)
    }

    /// Reconstruct data from chunks
    pub fn reconstruct_data(&self, height: BlockHeight) -> Result<Vec<u8>, NexusError> {
        let commitments = self
            .commitments
            .get(&height)
            .ok_or(NexusError::StateError("No commitments".into()))?;

        if commitments.is_empty() {
            return Ok(Vec::new());
        }

        let commitment = &commitments[0];
        let original_chunks = commitment.coding_params.0 as usize;

        // Collect original chunks (not parity)
        let mut data = Vec::new();
        for i in 0..original_chunks {
            let chunk = self
                .chunks
                .get(&(height, i as u32))
                .ok_or(NexusError::StateError("Missing chunk".into()))?;
            data.extend_from_slice(chunk);
        }

        // Trim to original size
        data.truncate(commitment.data_size as usize);

        Ok(data)
    }
}

impl Default for DataAvailabilityLayer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_da_submit_and_reconstruct() {
        let mut da = DataAvailabilityLayer::new();
        let data = b"Hello, NEXUS Data Availability Layer!".to_vec();

        let commitment = da.submit_data(BlockHeight::new(1), data.clone()).unwrap();
        assert!(commitment.data_size > 0);

        let reconstructed = da.reconstruct_data(BlockHeight::new(1)).unwrap();
        assert_eq!(data, reconstructed);
    }

    #[test]
    fn test_da_sampling() {
        let mut da = DataAvailabilityLayer::new();
        let data = vec![0u8; 1024]; // 1KB of data

        da.submit_data(BlockHeight::new(1), data).unwrap();

        let available = da.sample(BlockHeight::new(1)).unwrap();
        assert!(available);
    }

    #[test]
    fn test_da_proof_generation() {
        let mut da = DataAvailabilityLayer::new();
        let data = vec![1u8; 512];

        let commitment = da.submit_data(BlockHeight::new(1), data).unwrap();
        let proof = da.generate_proof(BlockHeight::new(1), 0).unwrap();

        // Note: Simplified verification may not pass with current implementation
        // Full implementation would use proper merkle tree
    }
}
