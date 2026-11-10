//! La prueba de inclusión debe vincular también la posición declarada.
use nexus_core::{Hash256, MerkleTree};

#[test]
fn changing_only_the_claimed_leaf_index_invalidates_the_proof() {
    let tree = MerkleTree::from_leaves((0u8..8).map(|n| Hash256::hash(&[n])).collect());
    let mut proof = tree.generate_proof(1).unwrap();
    assert!(proof.verify_against_root(&tree.root()));
    proof.leaf_index = 6;
    assert!(!proof.verify_against_root(&tree.root()));
}

#[test]
fn an_index_beyond_the_path_depth_is_not_an_alias_for_a_valid_index() {
    let tree = MerkleTree::from_leaves((0u8..8).map(|n| Hash256::hash(&[n])).collect());
    let mut proof = tree.generate_proof(1).unwrap();
    proof.leaf_index += 8;
    assert!(!proof.verify_against_root(&tree.root()));
}

#[test]
fn a_single_leaf_proof_only_accepts_position_zero() {
    let tree = MerkleTree::from_leaves(vec![Hash256::hash(b"unica")]);
    let mut proof = tree.generate_proof(0).unwrap();
    assert!(proof.verify());
    proof.leaf_index = usize::MAX;
    assert!(!proof.verify());
}
