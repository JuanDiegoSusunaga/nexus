//! Local storage and chunk inclusion; this is not remote DAS or erasure coding.
use nexus_anchor::{DACommitment, DataAvailabilityLayer};
use nexus_anchor::data_availability::{DA_CHUNK_BYTES, MAX_DA_DATA_SIZE};
use nexus_core::{BlockHeight, Hash256};

#[test]
fn multiple_submissions_at_one_height_cannot_silently_select_overwritten_data() {
    let mut da = DataAvailabilityLayer::new();
    let height = BlockHeight(1);
    da.submit_data(height, vec![1; 500]).unwrap();
    da.submit_data(height, vec![2; 700]).unwrap();
    assert!(da.reconstruct_data(height).is_err(), "a height alone is ambiguous for two payloads");
}

#[test]
fn empty_submission_is_rejected_without_registering_an_empty_commitment() {
    let mut da = DataAvailabilityLayer::new();
    let height = BlockHeight(1);
    assert!(da.submit_data(height, vec![]).is_err());
    assert!(da.get_commitment(height).is_none());
}

#[test]
fn honest_generated_proof_verifies_against_the_registered_commitment() {
    let mut da = DataAvailabilityLayer::new();
    let height = BlockHeight(1);
    let commitment = da.submit_data(height, vec![1; 512]).unwrap();
    let proof = da.generate_proof(height, 0).unwrap();
    assert!(proof.verify(&commitment));
}

#[test]
fn payload_indexes_keep_every_submission_and_its_proofs_separate() {
    let height = BlockHeight(5);
    let mut a = DataAvailabilityLayer::new();
    let mut b = DataAvailabilityLayer::new();
    let first = vec![3; 513];
    let second = vec![9; 700];
    let c0 = a.submit_data(height, first.clone()).unwrap();
    let c1 = a.submit_data(height, second.clone()).unwrap();
    b.submit_data(BlockHeight(99), vec![5; 999]).unwrap();
    b.submit_data(height, first.clone()).unwrap();
    b.submit_data(height, second.clone()).unwrap();
    for (index, bytes, receipt) in [(0, first, c0), (1, second, c1)] {
        assert_eq!(a.reconstruct_batch(height, index).unwrap(), bytes);
        for chunk in 0..receipt.chunk_count {
            let proof = a.generate_batch_proof(height, index, chunk).unwrap();
            assert!(proof.verify(&receipt));
            assert!(!proof.verify(&a.get_commitment(height).unwrap()[1 - index]));
            assert_eq!(bincode::serialize(&proof).unwrap(),
                bincode::serialize(&b.generate_batch_proof(height, index, chunk).unwrap()).unwrap());
        }
    }
    assert!(a.sample(height).unwrap());
    assert_eq!(a.get_commitment(height).unwrap().len(), 2);
}

#[test]
fn exact_chunk_lengths_and_one_two_and_odd_leaf_trees_round_trip() {
    for length in [1usize, 255, 256, 257, 512, 513, 1025] {
        let bytes: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
        let mut da = DataAvailabilityLayer::new();
        let receipt = da.submit_data(BlockHeight(1), bytes.clone()).unwrap();
        assert_eq!(receipt.commitment, Hash256::hash(&bytes));
        assert_eq!(receipt.chunk_count as usize, length.div_ceil(DA_CHUNK_BYTES));
        assert_eq!(receipt.coding_params, (receipt.chunk_count, receipt.chunk_count));
        assert_eq!(da.reconstruct_data(BlockHeight(1)).unwrap(), bytes);
        for index in 0..receipt.chunk_count {
            let proof = da.generate_proof(BlockHeight(1), index).unwrap();
            let start = index as usize * DA_CHUNK_BYTES;
            assert_eq!(proof.chunk_data, bytes[start..(start + DA_CHUNK_BYTES).min(length)]);
            assert!(proof.verify(&receipt));
        }
    }
}

#[test]
fn independent_two_leaf_oracle_matches_the_receipt_and_proof_order() {
    // Fixed vectors from Python hashlib.sha3_256, without importing Rust code.
    let bytes = vec![7; 512];
    let hash = |hex| Hash256::from_hex(hex).unwrap();
    let digest = hash("22c56c0906d47bb26ff07b8b8ab4e71004f70baf0fc82a08b27a55af7b06e643");
    let leaf0 = hash("7d403cfbe099b7a2a5a966372a479e0591a5162a19ef36eadb78c47c73f1f26f");
    let leaf1 = hash("5c93a9080a031112bc3c23b007e628827d2a53701d8a148112ba34c7a9f7e6f1");
    let expected = hash("a7e1f8cdd24b3a0a5235fc453b117d3dc3f14c8538442d616e6e7495fc59a4b9");
    let mut da = DataAvailabilityLayer::new();
    let receipt = da.submit_data(BlockHeight(1), bytes).unwrap();
    assert_eq!(receipt.commitment, digest);
    assert_eq!(receipt.chunk_root, expected);
    assert_eq!(da.generate_proof(BlockHeight(1), 0).unwrap().merkle_proof, vec![leaf1]);
    assert_eq!(da.generate_proof(BlockHeight(1), 1).unwrap().merkle_proof, vec![leaf0]);
}

#[test]
fn altered_chunk_bytes_lengths_indexes_and_paths_are_rejected() {
    let mut da = DataAvailabilityLayer::new();
    let receipt = da.submit_data(BlockHeight(1), vec![7; 513]).unwrap();
    let honest = da.generate_proof(BlockHeight(1), 2).unwrap();
    for case in 0..7 {
        let mut bad = honest.clone();
        match case {
            0 => bad.chunk_data[0] ^= 1,
            1 => bad.chunk_data.push(0),
            2 => bad.chunk_index = 3, // Reject the padded, non-existent leaf.
            3 => bad.chunk_index = u32::MAX,
            4 => { bad.merkle_proof.pop(); }
            5 => bad.merkle_proof = vec![Hash256::ZERO; 40],
            _ => bad.merkle_proof[0] = Hash256::ZERO,
        }
        assert!(!bad.verify(&receipt), "accepted tampering case {case}");
    }
}

#[test]
fn receipt_version_digest_sizes_coding_and_root_are_bound_or_validated() {
    let mut da = DataAvailabilityLayer::new();
    let receipt = da.submit_data(BlockHeight(1), vec![7; 513]).unwrap();
    let proof = da.generate_proof(BlockHeight(1), 0).unwrap();
    for case in 0..9 {
        let mut bad = receipt.clone();
        match case {
            0 => bad.encoding_version += 1,
            1 => bad.commitment = Hash256::ZERO,
            2 => bad.chunk_root = Hash256::ZERO,
            3 => bad.data_size = 514,
            4 => bad.data_size = u64::MAX,
            5 => bad.data_size = 0,
            6 => bad.chunk_count = u32::MAX,
            7 => bad.coding_params = (1, 6),
            _ => bad.chunk_count = 0,
        }
        assert!(!proof.verify(&bad), "accepted altered receipt case {case}");
    }
}

#[test]
fn empty_oversized_and_unknown_requests_preserve_registered_payloads() {
    let mut da = DataAvailabilityLayer::new();
    let height = BlockHeight(1);
    let receipt = da.submit_data(height, vec![4; MAX_DA_DATA_SIZE]).unwrap();
    assert!(da.submit_data(height, vec![]).is_err());
    assert!(da.submit_data(height, vec![1; MAX_DA_DATA_SIZE + 1]).is_err());
    assert!(DACommitment::from_data(&[]).is_err());
    assert_eq!(da.get_commitment(height).unwrap(), &vec![receipt.clone()]);
    assert_eq!(da.reconstruct_batch(height, 0).unwrap(), vec![4; MAX_DA_DATA_SIZE]);
    let last = da.generate_batch_proof(height, 0, receipt.chunk_count - 1).unwrap();
    assert!(last.verify(&receipt));
    assert!(da.generate_batch_proof(height, 0, receipt.chunk_count).is_err());
    assert!(da.reconstruct_batch(height, 1).is_err());
    assert!(da.reconstruct_batch(BlockHeight(99), 0).is_err());
    assert!(da.sample(BlockHeight(99)).is_err());
    da.submit_data(height, vec![8; 10]).unwrap();
    assert!(da.generate_proof(height, 0).is_err());
    assert!(da.reconstruct_data(height).is_err());
    assert_eq!(da.reconstruct_batch(height, 1).unwrap(), vec![8; 10]);
}
