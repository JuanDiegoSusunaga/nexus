//! Read-only construction of locally admissible L1 transactions from known L2 batches.
use nexus_active::{ActiveChain, ActiveChainConfig, L1SubmissionOptions, L2Batch,
    verifier::VerificationMode};
use nexus_anchor::{AnchorChain, AnchorChainConfig};
use nexus_core::{Address, Amount, BlockHeight, ChainId, Hash256, NexusError, Nonce,
    SignatureScheme, StateRoot, Timestamp, Transaction, TransactionType, MAX_BLOCK_SIZE};
use nexus_crypto::{DilithiumKeypair, Signer};

fn key() -> DilithiumKeypair { DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap() }
fn pair(mode: VerificationMode) -> (ActiveChain, DilithiumKeypair) {
    let publisher = key();
    let chain = ActiveChain::new(ActiveChainConfig { verification_mode: mode,
        batch_interval_blocks: 1, ..Default::default() }, publisher.clone());
    (chain, publisher)
}
fn batch(chain: &ActiveChain) -> L2Batch {
    let sender = key();
    let tx = Transaction::transfer(ChainId::LOCAL, Nonce(0), Address::ZERO,
        Amount(1), 21000, Amount(1_000_000_000));
    chain.submit_transaction(sender.sign_transaction(tx).unwrap()).unwrap();
    chain.produce_block().unwrap();
    chain.get_next_batch().unwrap()
}
fn anchor() -> AnchorChain { AnchorChain::new(AnchorChainConfig::default(), key()) }

#[tokio::test]
async fn preparation_derives_l1_domain_nonce_time_and_batch_fields_without_publishing_effects() {
    let (chain, publisher) = pair(VerificationMode::Optimistic);
    let local = batch(&chain);
    let l1 = AnchorChain::new(AnchorChainConfig { chain_id: ChainId::TESTNET, ..Default::default() }, key());
    let mut funding = l1.prepare_block(vec![], publisher.address()).unwrap();
    funding.header.timestamp = Timestamp(Timestamp::now().0 + 60_000);
    let parent_time = funding.header.timestamp;
    l1.process_block(funding).await.unwrap();
    let root = l1.state_root();
    let options = L1SubmissionOptions { gas_limit: 22_000, gas_price: Amount(7),
        expires_at: Some(Timestamp(parent_time.0 + 1)) };
    let tx = chain.prepare_l1_submission(&local, &l1, &publisher, options.clone()).unwrap();
    assert_eq!(tx.sender, publisher.address());
    assert_eq!(tx.transaction.chain_id, ChainId::TESTNET);
    assert_eq!(tx.transaction.nonce, Nonce(0));
    assert_eq!(tx.transaction.timestamp, parent_time);
    assert_eq!(tx.transaction.gas_limit, options.gas_limit);
    assert_eq!(tx.transaction.gas_price, options.gas_price);
    assert_eq!(tx.transaction.expires_at, options.expires_at);
    assert_eq!(tx.transaction.tx_type, TransactionType::BatchSubmit { batch_root: local.post_state_root.0,
        batch_size: local.tx_count as u32, compressed_data: local.compressed_data.clone() });
    assert!(nexus_crypto::signer::verify_signed_transaction_at(&tx, parent_time).unwrap());
    let again = chain.prepare_l1_submission(&local, &l1, &publisher, options).unwrap();
    assert_eq!(again.transaction.nonce, Nonce(0));
    assert_eq!(l1.height(), BlockHeight(1));
    assert_eq!(l1.state_root(), root);
    assert_eq!(l1.stats().l2_batch_count, 0);
    assert_eq!(l1.get_account(&publisher.address()).unwrap().nonce, Nonce(0));
    assert!(chain.get_batch_submission(local.index).is_none());
    assert!(chain.verified_state_root(local.block_range.1).is_none());
    chain.mark_batch_submitted(local.clone(), tx.hash()).unwrap();
    let block = l1.prepare_block(vec![tx.clone()], Address::ZERO).unwrap();
    l1.process_block(block.clone()).await.unwrap();
    let confirmed = chain.mark_batch_confirmed(local.index, &l1).unwrap();
    assert_eq!(confirmed.l1_tx_hash, tx.hash());
    assert_eq!(confirmed.l1_block_hash, block.hash());
    assert!(chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).is_err());
    let next = batch(&chain);
    let next_tx = chain.prepare_l1_submission(&next, &l1, &publisher, Default::default()).unwrap();
    assert_eq!(next_tx.transaction.nonce, Nonce(1));
    assert_eq!(l1.get_account(&publisher.address()).unwrap().nonce, Nonce(1));
}

#[test]
fn unknown_or_altered_batches_and_a_different_publisher_are_rejected() {
    let (chain, publisher) = pair(VerificationMode::Optimistic);
    let local = batch(&chain);
    let l1 = anchor();
    for case in 0..4 {
        let mut altered = local.clone();
        match case {
            0 => altered.index += 1,
            1 => altered.tx_count += 1,
            2 => altered.post_state_root = StateRoot::new(Hash256::hash(b"wrong root")),
            _ => altered.compressed_data.push(1),
        }
        altered.batch_hash = altered.compute_hash();
        assert!(chain.prepare_l1_submission(&altered, &l1, &publisher, Default::default()).is_err());
    }
    assert!(chain.prepare_l1_submission(&local, &l1, &key(), Default::default()).is_err());
    assert_eq!(chain.stats().submitted_batches, 0);
    assert_eq!(l1.height(), BlockHeight::GENESIS);
    assert_eq!(l1.stats().l2_batch_count, 0);
}

#[test]
fn validity_and_hybrid_preparation_require_a_valid_certificate_without_recording_a_root() {
    for mode in [VerificationMode::ZKValidity, VerificationMode::Hybrid { threshold: usize::MAX }] {
        let (chain, publisher) = pair(mode);
        let mut local = batch(&chain);
        let l1 = anchor();
        assert!(matches!(chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()),
            Err(NexusError::InvalidProofFormat)));
        local.validity_proof = Some(vec![0; 4096]);
        assert!(matches!(chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()),
            Err(NexusError::ProofVerificationFailed)));
        assert!(chain.verified_state_root(local.block_range.1).is_none());
        assert!(chain.get_batch_submission(local.index).is_none());
        assert!(chain.get_known_batch(local.index).unwrap().validity_proof.is_none());
        assert_eq!(l1.stats().l2_batch_count, 0);
    }
}

#[test]
fn invalid_gas_cost_expiry_and_balance_leave_both_chains_unchanged() {
    let (chain, publisher) = pair(VerificationMode::Optimistic);
    let local = batch(&chain);
    let l1 = anchor();
    let options = [
        L1SubmissionOptions { gas_limit: 0, ..Default::default() },
        L1SubmissionOptions { gas_limit: 20_999, ..Default::default() },
        L1SubmissionOptions { gas_limit: 30_000_001, ..Default::default() },
        L1SubmissionOptions { gas_price: Amount::MAX, ..Default::default() },
        L1SubmissionOptions { expires_at: Some(Timestamp(0)), ..Default::default() },
        L1SubmissionOptions { gas_price: Amount(1), ..Default::default() },
    ];
    let root = chain.state_root();
    for (index, options) in options.into_iter().enumerate() {
        let error = chain.prepare_l1_submission(&local, &l1, &publisher, options).unwrap_err();
        match index {
            0 | 1 | 3 => assert!(matches!(error, NexusError::InvalidTransaction(_))),
            2 => assert!(matches!(error, NexusError::InvalidBlock(_))),
            4 => assert!(matches!(error, NexusError::TransactionExpired)),
            _ => assert!(matches!(error, NexusError::InsufficientBalance { .. })),
        }
        assert_eq!(chain.state_root(), root);
        assert!(chain.get_batch_submission(local.index).is_none());
        assert!(chain.verified_state_root(local.block_range.1).is_none());
        assert_eq!(l1.state_root(), StateRoot::EMPTY);
        assert_eq!(l1.height(), BlockHeight::GENESIS);
        assert!(l1.get_account(&publisher.address()).is_none());
    }
}

#[test]
fn l1_budget_and_payload_bounds_are_checked_by_the_preparer() {
    let (chain, publisher) = pair(VerificationMode::Optimistic);
    let local = batch(&chain);
    let l1 = AnchorChain::new(AnchorChainConfig { block_gas_limit: 0, ..Default::default() }, key());
    assert!(matches!(chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()), Err(NexusError::InvalidBlock(_))));
    assert!(l1.prepare_batch_submission(&publisher, local.post_state_root, 1, vec![], Default::default()).is_err());
    assert!(l1.prepare_batch_submission(&publisher, local.post_state_root, 1, vec![0; MAX_BLOCK_SIZE + 1], Default::default()).is_err());
    assert_eq!(l1.stats().l2_batch_count, 0);
    assert!(l1.get_account(&publisher.address()).is_none());
}

#[test]
fn a_payload_fitting_l2_must_also_fit_the_signed_l1_block_envelope() {
    let (chain, publisher) = pair(VerificationMode::Optimistic);
    let sender = key();
    let base = Transaction::call(ChainId::LOCAL, Nonce(0), Address::ZERO, "large".into(),
        vec![], Amount::ZERO, 50000, Amount(1_000_000_000));
    let base_size = bincode::serialized_size(&sender.sign_transaction(base.clone()).unwrap()).unwrap() as usize;
    let target = MAX_BLOCK_SIZE - 512;
    let mut large = base;
    if let TransactionType::Call { args, .. } = &mut large.tx_type { *args = vec![7; target - base_size]; }
    let signed = sender.sign_transaction(large).unwrap();
    assert_eq!(bincode::serialized_size(&signed).unwrap() as usize, target);
    chain.submit_transaction(signed).unwrap();
    chain.produce_block().unwrap();
    let local = chain.get_next_batch().unwrap();
    assert!(local.compressed_data.len() < MAX_BLOCK_SIZE);
    let l1 = anchor();
    assert!(matches!(chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()),
        Err(NexusError::BlockTooLarge { size, max }) if size > max && max == MAX_BLOCK_SIZE));
    assert!(chain.get_batch_submission(local.index).is_none());
    assert_eq!(l1.stats().l2_batch_count, 0);
}

#[tokio::test]
async fn a_stale_preparation_is_rejected_and_can_be_prepared_again_for_an_explicit_retry() {
    let (chain, publisher) = pair(VerificationMode::Optimistic);
    let local = batch(&chain);
    let l1 = anchor();
    let initial = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
    chain.mark_batch_submitted(local.clone(), initial.hash()).unwrap();
    let other = publisher.sign_transaction(Transaction::transfer(ChainId::LOCAL, Nonce(0),
        Address::ZERO, Amount::ZERO, 21000, Amount::ZERO)).unwrap();
    l1.process_block(l1.prepare_block(vec![other], Address::ZERO).unwrap()).await.unwrap();
    assert!(matches!(l1.prepare_block(vec![initial.clone()], Address::ZERO),
        Err(NexusError::InvalidNonce { expected: 1, got: 0 })));
    let replacement = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
    assert_eq!(replacement.transaction.nonce, Nonce(1));
    assert_eq!(chain.get_batch_submission(local.index).unwrap().attempts.len(), 1);
    chain.retry_batch_submission(local.index, initial.hash(), replacement.hash()).unwrap();
    l1.process_block(l1.prepare_block(vec![replacement.clone()], Address::ZERO).unwrap()).await.unwrap();
    let confirmed = chain.mark_batch_confirmed(local.index, &l1).unwrap();
    assert_eq!(confirmed.l1_tx_hash, replacement.hash());
    assert_eq!(confirmed.attempts.len(), 2);
    assert!(chain.verified_state_root(local.block_range.1).is_none());
}

#[tokio::test]
async fn transaction_preflight_is_separate_from_a_proposers_reward_overflow() {
    let (chain, publisher) = pair(VerificationMode::Optimistic);
    let local = batch(&chain);
    let l1 = AnchorChain::new(AnchorChainConfig { block_reward: Amount::MAX, ..Default::default() }, key());
    l1.process_block(l1.prepare_block(vec![], Address::ZERO).unwrap()).await.unwrap();
    let root = l1.state_root();
    let prepared = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
    assert_eq!(l1.state_root(), root);
    assert_eq!(l1.get_account(&Address::ZERO).unwrap().balance, Amount::MAX);
    assert!(l1.prepare_block(vec![prepared.clone()], Address::ZERO).is_err());
    let block = l1.prepare_block(vec![prepared.clone()], publisher.address()).unwrap();
    chain.mark_batch_submitted(local.clone(), prepared.hash()).unwrap();
    l1.process_block(block).await.unwrap();
    assert!(chain.mark_batch_confirmed(local.index, &l1).is_ok());
}
