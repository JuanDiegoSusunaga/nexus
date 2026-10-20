//! Recover a missed initial local registration from trusted processed L1 storage.
use nexus_active::{ActiveChain, ActiveChainConfig, L2Batch, verifier::VerificationMode};
use nexus_anchor::{AnchorChain, AnchorChainConfig};
use nexus_core::{Address, Amount, Block, BlockBody, BlockHeader, BlockHeight, ChainId,
    Hash256, InMemoryState, Layer, MerkleTree, Nonce, SignatureScheme, SignedTransaction,
    Timestamp, Transaction, TransactionType};
use nexus_crypto::{DilithiumKeypair, Signer};

fn key() -> DilithiumKeypair { DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap() }
fn pair(mode: VerificationMode) -> (ActiveChain, DilithiumKeypair) {
    let publisher = key();
    (ActiveChain::new(ActiveChainConfig { verification_mode: mode, batch_interval_blocks: 1,
        ..Default::default() }, publisher.clone()), publisher)
}
fn batch(chain: &ActiveChain) -> L2Batch {
    chain.submit_transaction(key().sign_transaction(Transaction::transfer(ChainId::LOCAL, Nonce(0),
        Address::ZERO, Amount(1), 21000, Amount(1_000_000_000))).unwrap()).unwrap();
    chain.produce_block().unwrap();
    chain.get_known_batch(0).unwrap()
}
fn anchor() -> AnchorChain { AnchorChain::new(Default::default(), key()) }
fn encoded(tx: &SignedTransaction) -> Vec<u8> { bincode::serialize(tx).unwrap() }
fn assert_unregistered(chain: &ActiveChain, local: &L2Batch) {
    assert!(chain.get_batch_submission(local.index).is_none());
    assert!(chain.get_batch_confirmation(local.index).is_none());
    assert_eq!(chain.stats().pending_batches, 1);
    assert_eq!(chain.stats().submitted_batches, 0);
    assert_eq!(chain.stats().confirmed_batches, 0);
    assert!(chain.verified_state_root(local.block_range.1).is_none());
}

#[tokio::test]
async fn omitted_initial_registration_recovers_exact_packet_and_original_block_once() {
    let (chain, publisher) = pair(VerificationMode::Optimistic);
    let local = batch(&chain);
    let l1 = anchor();
    let signed = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
    let block = l1.prepare_block(vec![signed.clone()], Address::ZERO).unwrap();
    let block_hash = block.hash();
    l1.process_block(block).await.unwrap();
    l1.process_block(l1.prepare_block(vec![], Address::ZERO).unwrap()).await.unwrap();
    let before = (l1.height(), l1.state_root(), l1.stats().l2_batch_count);
    assert!(chain.register_l1_submission(local.clone(), &signed, &l1).is_err());
    assert_unregistered(&chain, &local);
    let mut recovered = chain.recover_l1_submission(local.clone(), &signed, &l1).unwrap();
    assert_eq!(recovered.l1_tx_hash, signed.hash());
    assert_eq!(recovered.l1_block_hash, block_hash);
    assert_eq!(recovered.l1_height, BlockHeight(1));
    assert_eq!(recovered.attempts.len(), 1);
    assert_eq!(recovered.attempts[0].transaction_bytes, Some(encoded(&signed)));
    assert_eq!(recovered.batch.batch_hash, local.batch_hash);
    recovered.attempts[0].transaction_bytes.as_mut().unwrap().clear();
    assert_eq!(encoded(&chain.get_l1_submission_transaction(local.index, signed.hash()).unwrap()), encoded(&signed));
    assert!(chain.get_batch_submission(local.index).is_none());
    assert_eq!(chain.stats().pending_batches, 0);
    assert_eq!(chain.stats().confirmed_batches, 1);
    assert!(chain.verified_state_root(local.block_range.1).is_none());
    assert_eq!(before, (l1.height(), l1.state_root(), l1.stats().l2_batch_count));
    assert!(chain.recover_l1_submission(local.clone(), &signed, &l1).is_err());
    assert!(chain.mark_batch_confirmed(local.index, &l1).is_err());
    assert_eq!(chain.stats().confirmed_batches, 1);
}

#[tokio::test]
async fn historical_expiry_and_consumed_nonce_do_not_erase_a_processed_inclusion() {
    let (chain, publisher) = pair(VerificationMode::Optimistic);
    let local = batch(&chain);
    let l1 = anchor();
    let signed = publisher.sign_transaction(Transaction { chain_id: ChainId::LOCAL, nonce: Nonce(0),
        gas_limit: 21000, gas_price: Amount::ZERO, timestamp: Timestamp(0), expires_at: Some(Timestamp(1)),
        tx_type: TransactionType::BatchSubmit { batch_root: local.post_state_root.0,
            batch_size: local.tx_count as u32, compressed_data: local.compressed_data.clone() } }).unwrap();
    // Construct the old block and its account root independently of the current-time preparer.
    let mut header = BlockHeader::new(BlockHeight(1), l1.genesis().hash(), Address::ZERO, Layer::Anchor);
    header.timestamp = Timestamp(1);
    header.transactions_root = MerkleTree::from_leaves(vec![signed.hash()]).root();
    let mut state = InMemoryState::new();
    state.get_or_create_account(&publisher.address()).nonce = Nonce(1);
    state.get_or_create_account(&Address::ZERO).credit(Amount::from_units(2)).unwrap();
    header.state_root = state.compute_root().0;
    l1.process_block(Block::new(header, BlockBody::new(vec![signed.clone()]))).await.unwrap();
    assert!(Timestamp::now() > Timestamp(1));
    assert!(l1.validate_batch_submission(&signed).is_err());
    assert!(nexus_crypto::verify_signed_transaction(&signed).is_err());
    let recovered = chain.recover_l1_submission(local, &signed, &l1).unwrap();
    assert_eq!(recovered.l1_height, BlockHeight(1));
    assert_eq!(l1.get_account(&publisher.address()).unwrap().nonce, Nonce(1));
}

#[tokio::test]
async fn same_hash_does_not_authorize_an_altered_signed_envelope() {
    let (chain, publisher) = pair(VerificationMode::Optimistic);
    let local = batch(&chain);
    let l1 = anchor();
    let signed = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
    l1.process_block(l1.prepare_block(vec![signed.clone()], Address::ZERO).unwrap()).await.unwrap();
    for case in 0..3 {
        let mut altered = signed.clone();
        match case {
            0 => altered.public_key[0] ^= 1,
            1 => altered.signature.scheme = SignatureScheme::Dilithium2,
            _ => altered.sender = Address::ZERO,
        }
        assert_eq!(altered.hash(), signed.hash());
        assert!(l1.validate_processed_batch_submission(&altered).is_err());
        assert!(chain.recover_l1_submission(local.clone(), &altered, &l1).is_err());
        assert_unregistered(&chain, &local);
    }
    chain.recover_l1_submission(local, &signed, &l1).unwrap();
}

#[tokio::test]
async fn preparation_helpers_rejected_blocks_and_another_source_are_not_processed_inclusion() {
    let (chain, publisher) = pair(VerificationMode::Optimistic);
    let local = batch(&chain);
    let l1 = anchor();
    let signed = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
    let block = l1.prepare_block(vec![signed.clone()], Address::ZERO).unwrap();
    assert!(chain.recover_l1_submission(local.clone(), &signed, &l1).is_err());
    let mut rejected = block.clone();
    rejected.header.state_root = Hash256::hash(b"wrong root");
    assert!(l1.process_block(rejected).await.is_err());
    l1.submit_l2_batch(local.post_state_root, local.compressed_data.clone()).unwrap();
    assert!(chain.recover_l1_submission(local.clone(), &signed, &l1).is_err());
    assert_unregistered(&chain, &local);
    l1.process_block(block).await.unwrap();
    assert!(chain.recover_l1_submission(local.clone(), &signed, &anchor()).is_err());
    assert_unregistered(&chain, &local);
    chain.recover_l1_submission(local, &signed, &l1).unwrap();
}

#[tokio::test]
async fn actually_processed_different_payload_or_publisher_cannot_claim_the_local_batch() {
    let (chain, publisher) = pair(VerificationMode::Optimistic);
    let local = batch(&chain);
    for case in 0..5 {
        let l1 = anchor();
        let mut tx = l1.prepare_batch_submission(&publisher, local.post_state_root,
            local.tx_count as u32, local.compressed_data.clone(), Default::default()).unwrap().transaction;
        if let TransactionType::BatchSubmit { batch_root, batch_size, compressed_data } = &mut tx.tx_type {
            match case {
                0 => *batch_root = Hash256::hash(b"other root"),
                1 => *batch_size += 1,
                2 => compressed_data.push(19),
                _ => (),
            }
        }
        if case == 3 { tx.tx_type = TransactionType::Transfer { to: Address::ZERO, amount: Amount::ZERO }; }
        let signed = if case == 4 { key().sign_transaction(tx).unwrap() } else { publisher.sign_transaction(tx).unwrap() };
        l1.process_block(l1.prepare_block(vec![signed.clone()], Address::ZERO).unwrap()).await.unwrap();
        assert!(chain.recover_l1_submission(local.clone(), &signed, &l1).is_err());
        assert_unregistered(&chain, &local);
    }
    let mut unknown = local.clone(); unknown.index += 1;
    let l1 = anchor();
    let signed = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
    l1.process_block(l1.prepare_block(vec![signed.clone()], Address::ZERO).unwrap()).await.unwrap();
    assert!(chain.recover_l1_submission(unknown, &signed, &l1).is_err());
    let mut altered = local.clone(); altered.created_at = Timestamp(0);
    assert!(chain.recover_l1_submission(altered, &signed, &l1).is_err());
    assert_unregistered(&chain, &local);
}

#[tokio::test]
async fn recovery_cannot_replace_existing_attempts_or_discard_their_history() {
    let (chain, publisher) = pair(VerificationMode::Optimistic);
    let local = batch(&chain);
    let l1 = anchor();
    let signed = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
    chain.mark_batch_submitted(local.clone(), signed.hash()).unwrap();
    let next = Hash256::hash(b"recorded replacement intent");
    chain.retry_batch_submission(local.index, signed.hash(), next).unwrap();
    let before = chain.get_batch_submission(local.index).unwrap();
    l1.process_block(l1.prepare_block(vec![signed.clone()], Address::ZERO).unwrap()).await.unwrap();
    assert!(chain.recover_l1_submission(local.clone(), &signed, &l1).is_err());
    let after = chain.get_batch_submission(local.index).unwrap();
    assert_eq!(after.attempts, before.attempts);
    assert_eq!(after.l1_tx_hash, next);
    assert_eq!(after.retries, before.retries);
    assert_eq!(after.submitted_at, before.submitted_at);
    let confirmed = chain.mark_batch_confirmed(local.index, &l1).unwrap();
    assert_eq!(confirmed.attempts, before.attempts);
    assert_eq!(confirmed.l1_tx_hash, signed.hash());
    assert!(chain.get_l1_submission_transaction(local.index, signed.hash()).is_err());
}

#[tokio::test]
async fn concurrent_recovery_commits_one_initial_observation() {
    use std::sync::{Arc, Barrier};
    let (chain, publisher) = pair(VerificationMode::Optimistic);
    let local = batch(&chain);
    let l1 = anchor();
    let signed = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
    l1.process_block(l1.prepare_block(vec![signed.clone()], Address::ZERO).unwrap()).await.unwrap();
    let chain = Arc::new(chain); let l1 = Arc::new(l1); let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = (0..2).map(|_| {
        let (chain, l1, barrier, local, signed) = (chain.clone(), l1.clone(), barrier.clone(), local.clone(), signed.clone());
        std::thread::spawn(move || { barrier.wait(); chain.recover_l1_submission(local, &signed, &l1).is_ok() })
    }).collect();
    assert_eq!(workers.into_iter().filter_map(|worker| worker.join().unwrap().then_some(())).count(), 1);
    assert_eq!(chain.stats().confirmed_batches, 1);
    assert_eq!(chain.stats().submitted_batches, 0);
    assert_eq!(chain.get_batch_confirmation(local.index).unwrap().attempts.len(), 1);
}

#[tokio::test]
async fn processed_inclusion_cannot_bypass_validity_or_hybrid_certificate_policy() {
    for mode in [VerificationMode::ZKValidity, VerificationMode::Hybrid { threshold: usize::MAX }] {
        let (chain, publisher) = pair(mode);
        let local = batch(&chain);
        let l1 = AnchorChain::new(AnchorChainConfig::default(), key());
        let signed = l1.prepare_batch_submission(&publisher, local.post_state_root,
            local.tx_count as u32, local.compressed_data.clone(), Default::default()).unwrap();
        l1.process_block(l1.prepare_block(vec![signed.clone()], Address::ZERO).unwrap()).await.unwrap();
        for proof in [None, Some(vec![0; 4096])] {
            let mut supplied = local.clone(); supplied.validity_proof = proof;
            assert!(chain.recover_l1_submission(supplied, &signed, &l1).is_err());
            assert_unregistered(&chain, &local);
        }
    }
}
