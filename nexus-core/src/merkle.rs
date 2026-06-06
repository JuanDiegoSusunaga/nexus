//! Merkle tree implementation for NEXUS blockchain
//!
//! Provides efficient proof of inclusion for transactions and state.

use crate::{Hash256, NexusError, Hashable};
use serde::{Deserialize, Serialize};

/// Merkle tree for efficient verification of data inclusion
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Leaf hashes (bottom level)
    leaves: Vec<Hash256>,
    /// All nodes in the tree (level by level, bottom to top)
    nodes: Vec<Vec<Hash256>>,
    /// Root hash
    root: Hash256,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf data
    pub fn from_leaves(leaves: Vec<Hash256>) -> Self {
        if leaves.is_empty() {
            return Self {
                leaves: Vec::new(),
                nodes: Vec::new(),
                root: Hash256::ZERO,
            };
        }

        let mut nodes = Vec::new();
        let mut current_level = leaves.clone();

        // Pad to power of 2 if necessary
        while !current_level.len().is_power_of_two() {
            current_level.push(*current_level.last().unwrap());
        }

        nodes.push(current_level.clone());

        // Build tree bottom-up
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let combined = Self::hash_pair(&chunk[0], &chunk[1]);
                next_level.push(combined);
            }
            nodes.push(next_level.clone());
            current_level = next_level;
        }

        let root = current_level[0];

        Self {
            leaves,
            nodes,
            root,
        }
    }

    /// Build tree from hashable items
    pub fn from_data<T: Hashable>(items: &[T]) -> Self {
        let leaves: Vec<Hash256> = items.iter().map(|item| item.hash()).collect();
        Self::from_leaves(leaves)
    }

    /// Get the Merkle root
    pub fn root(&self) -> Hash256 {
        self.root
    }

    /// Get the number of leaves
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Generate a proof for a leaf at given index
    pub fn generate_proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut proof = Vec::new();
        let mut current_index = index;

        // Adjust for padding
        let padded_len = self.nodes[0].len();
        let mut idx = if index >= padded_len { padded_len - 1 } else { index };

        for level in &self.nodes[..self.nodes.len() - 1] {
            let sibling_index = if idx % 2 == 0 { idx + 1 } else { idx - 1 };

            if sibling_index < level.len() {
                let is_left = idx % 2 == 1;
                proof.push(ProofNode {
                    hash: level[sibling_index],
                    is_left,
                });
            }

            idx /= 2;
        }

        Some(MerkleProof {
            leaf_index: index,
            leaf_hash: self.leaves[index],
            proof,
            root: self.root,
        })
    }

    /// Hash two nodes together
    fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(left.as_bytes());
        combined.extend_from_slice(right.as_bytes());
        Hash256::hash(&combined)
    }
}

/// Merkle proof for a single leaf
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Index of the leaf in the tree
    pub leaf_index: usize,
    /// Hash of the leaf being proven
    pub leaf_hash: Hash256,
    /// Proof nodes (siblings along the path to root)
    pub proof: Vec<ProofNode>,
    /// Expected root hash
    pub root: Hash256,
}

/// Single node in a Merkle proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofNode {
    /// Hash of the sibling node
    pub hash: Hash256,
    /// Whether the sibling is on the left
    pub is_left: bool,
}

impl MerkleProof {
    /// Verify this proof against a root
    pub fn verify(&self) -> bool {
        self.verify_against_root(&self.root)
    }

    /// Verify against a specific root
    pub fn verify_against_root(&self, root: &Hash256) -> bool {
        let mut current = self.leaf_hash;

        for node in &self.proof {
            current = if node.is_left {
                MerkleTree::hash_pair(&node.hash, &current)
            } else {
                MerkleTree::hash_pair(&current, &node.hash)
            };
        }

        current == *root
    }

    /// Get proof size in bytes
    pub fn size(&self) -> usize {
        self.proof.len() * 33 // 32 bytes hash + 1 byte position
    }
}

/// Sparse Merkle Tree for state storage
/// Uses a fixed depth of 256 (for 256-bit keys)
#[derive(Debug, Clone)]
pub struct SparseMerkleTree {
    /// Stored leaves (key -> value hash)
    leaves: std::collections::HashMap<Hash256, Hash256>,
    /// Cached internal nodes
    cache: std::collections::HashMap<(usize, Hash256), Hash256>,
    /// Default hashes for empty subtrees at each level
    defaults: Vec<Hash256>,
    /// Current root
    root: Hash256,
}

impl SparseMerkleTree {
    /// Tree depth (256 for 256-bit keys)
    const DEPTH: usize = 256;

    /// Create a new empty sparse Merkle tree
    pub fn new() -> Self {
        // Compute default hashes for empty subtrees
        let mut defaults = vec![Hash256::ZERO; Self::DEPTH as usize + 1];
        for i in (0..Self::DEPTH as usize).rev() {
            defaults[i] = MerkleTree::hash_pair(&defaults[i + 1], &defaults[i + 1]);
        }

        let root = defaults[0].clone();

        Self {
            leaves: std::collections::HashMap::new(),
            cache: std::collections::HashMap::new(),
            defaults,
            root,
        }
    }

    /// Get the root hash
    pub fn root(&self) -> Hash256 {
        self.root
    }

    /// Insert or update a leaf
    pub fn insert(&mut self, key: Hash256, value: Hash256) {
        self.leaves.insert(key, value);
        self.recompute_root();
    }

    /// Get a leaf value
    pub fn get(&self, key: &Hash256) -> Option<Hash256> {
        self.leaves.get(key).copied()
    }

    /// Check if key exists
    pub fn contains(&self, key: &Hash256) -> bool {
        self.leaves.contains_key(key)
    }

    /// Recompute root after modifications
    fn recompute_root(&mut self) {
        // Simplified implementation - in production use incremental updates
        self.cache.clear();
        self.root = self.compute_node(0, Hash256::ZERO);
    }

    /// True iff `a` and `b` share their first `depth` bits (MSB-first within each byte).
    fn prefix_matches(a: &Hash256, b: &Hash256, depth: usize) -> bool {
        let full = depth / 8;
        if a.0[..full] != b.0[..full] {
            return false;
        }
        let rem = depth % 8;
        if rem == 0 {
            return true;
        }
        let mask = 0xFFu8 << (8 - rem); // top `rem` bits
        (a.0[full] & mask) == (b.0[full] & mask)
    }

    /// True if any stored leaf falls under the node identified by (`depth`, `path`).
    fn has_leaf_under(&self, depth: usize, path: &Hash256) -> bool {
        self.leaves.keys().any(|k| Self::prefix_matches(k, path, depth))
    }

    /// Compute hash of a node at given depth and path.
    ///
    /// Empty subtrees (those containing no stored leaf) collapse directly to the
    /// precomputed default for their depth, so the recursion only descends paths
    /// that actually contain leaves and therefore terminates (O(leaves · DEPTH)),
    /// instead of traversing the full 2^256 key space.
    fn compute_node(&mut self, depth: usize, path: Hash256) -> Hash256 {
        if depth == Self::DEPTH {
            // Leaf level
            return self.leaves.get(&path).copied().unwrap_or(Hash256::ZERO);
        }

        // Check cache
        if let Some(&hash) = self.cache.get(&(depth, path)) {
            return hash;
        }

        let left_path = path;
        let mut right_path = path;
        // Set bit at position `depth` (MSB-first within each byte)
        let byte_index = depth / 8;
        let bit_index = 7 - (depth % 8);
        if byte_index < 32 {
            right_path.0[byte_index] |= 1u8 << bit_index;
        }

        let left = if self.has_leaf_under(depth + 1, &left_path) {
            self.compute_node(depth + 1, left_path)
        } else {
            self.defaults[depth + 1]
        };
        let right = if self.has_leaf_under(depth + 1, &right_path) {
            self.compute_node(depth + 1, right_path)
        } else {
            self.defaults[depth + 1]
        };

        let hash = if left == self.defaults[depth + 1] && right == self.defaults[depth + 1] {
            self.defaults[depth]
        } else {
            MerkleTree::hash_pair(&left, &right)
        };

        self.cache.insert((depth, path), hash);
        hash
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_single_leaf() {
        let leaves = vec![Hash256::hash(b"leaf1")];
        let tree = MerkleTree::from_leaves(leaves.clone());

        assert_eq!(tree.len(), 1);
        // Single leaf tree, root equals leaf (after padding)
        let proof = tree.generate_proof(0).unwrap();
        assert!(proof.verify());
    }

    #[test]
    fn test_merkle_tree_multiple_leaves() {
        let leaves: Vec<Hash256> = (0..8)
            .map(|i| Hash256::hash(format!("leaf{}", i).as_bytes()))
            .collect();

        let tree = MerkleTree::from_leaves(leaves);
        assert_eq!(tree.len(), 8);

        // Verify all proofs
        for i in 0..8 {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify(), "Proof {} failed", i);
        }
    }

    #[test]
    fn test_merkle_tree_non_power_of_two() {
        let leaves: Vec<Hash256> = (0..5)
            .map(|i| Hash256::hash(format!("leaf{}", i).as_bytes()))
            .collect();

        let tree = MerkleTree::from_leaves(leaves);
        assert_eq!(tree.len(), 5);

        for i in 0..5 {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify(), "Proof {} failed", i);
        }
    }

    #[test]
    fn test_empty_merkle_tree() {
        let tree = MerkleTree::from_leaves(Vec::new());
        assert!(tree.is_empty());
        assert_eq!(tree.root(), Hash256::ZERO);
    }

    #[test]
    fn test_sparse_merkle_tree() {
        let mut smt = SparseMerkleTree::new();
        let key1 = Hash256::hash(b"key1");
        let value1 = Hash256::hash(b"value1");

        let empty_root = smt.root();
        smt.insert(key1, value1);

        assert_ne!(smt.root(), empty_root);
        assert_eq!(smt.get(&key1), Some(value1));
    }
}
