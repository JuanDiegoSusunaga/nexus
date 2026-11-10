//! Recover omitted replacement registrations without rewriting earlier local attempts.
use nexus_active::{ActiveChain, ActiveChainConfig, L2Batch, SubmittedBatch};
use nexus_anchor::AnchorChain;
use nexus_core::{Address, Amount, Block, BlockBody, BlockHeader, BlockHeight, ChainId,
    Hash256, InMemoryState, Layer, MerkleTree, Nonce, SignatureScheme, SignedTransaction,
    Timestamp, Transaction, TransactionType};
use nexus_crypto::{DilithiumKeypair, Signer};

fn key() -> DilithiumKeypair { DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap() }
fn pair() -> (ActiveChain, DilithiumKeypair) {
    let publisher = key();
    (ActiveChain::new(ActiveChainConfig { batch_interval_blocks: 1, ..Default::default() }, publisher.clone()), publisher)
}
fn batch(chain: &ActiveChain) -> L2Batch {
    chain.submit_transaction(key().sign_transaction(Transaction::transfer(ChainId::LOCAL, Nonce(0),
        Address::ZERO, Amount(1), 21000, Amount(1_000_000_000))).unwrap()).unwrap();
    chain.produce_block().unwrap();
    chain.get_next_batch().unwrap()
}
fn anchor() -> AnchorChain { AnchorChain::new(Default::default(), key()) }
fn encoded(tx: &SignedTransaction) -> Vec<u8> { bincode::serialize(tx).unwrap() }
fn assert_pending_unchanged(chain: &ActiveChain, before: &SubmittedBatch) {
    let after = chain.get_batch_submission(before.batch.index).unwrap();
    assert_eq!(after.attempts, before.attempts);
    assert_eq!(after.l1_tx_hash, before.l1_tx_hash);
    assert_eq!(after.retries, before.retries);
    assert_eq!(after.submitted_at, before.submitted_at);
    assert_eq!(bincode::serialize(&after.batch).unwrap(), bincode::serialize(&before.batch).unwrap());
    assert!(chain.get_batch_confirmation(before.batch.index).is_none());
}
fn packet(chain: &ActiveChain, local: &L2Batch, publisher: &DilithiumKeypair, l1: &AnchorChain) -> SignedTransaction {
    chain.prepare_l1_submission(local, l1, publisher, Default::default()).unwrap()
}

#[tokio::test]
async fn omitted_signed_retry_preserves_both_packets_and_original_inclusion() {
    let (chain, publisher) = pair(); let local = batch(&chain); let l1 = anchor();
    let initial = packet(&chain, &local, &publisher, &l1);
    chain.register_l1_submission(local.clone(), &initial, &l1).unwrap();
    let before = chain.get_batch_submission(local.index).unwrap();
    let other = publisher.sign_transaction(Transaction::transfer(ChainId::LOCAL, Nonce(0),
        Address::ZERO, Amount::ZERO, 21000, Amount::ZERO)).unwrap();
    l1.process_block(l1.prepare_block(vec![other], Address::ZERO).unwrap()).await.unwrap();
    let replacement = packet(&chain, &local, &publisher, &l1);
    assert_eq!(replacement.transaction.nonce, Nonce(1));
    let block = l1.prepare_block(vec![replacement.clone()], Address::ZERO).unwrap();
    let hash = block.hash();
    l1.process_block(block).await.unwrap();
    l1.process_block(l1.prepare_block(vec![], Address::ZERO).unwrap()).await.unwrap();
    assert!(chain.retry_l1_submission(local.index, initial.hash(), &replacement, &l1).is_err());
    assert_pending_unchanged(&chain, &before);
    let state = (l1.height(), l1.state_root(), l1.stats().l2_batch_count);
    let mut confirmed = chain.recover_l1_retry(local.index, initial.hash(), &replacement, &l1).unwrap();
    assert_eq!(confirmed.l1_tx_hash, replacement.hash());
    assert_eq!(confirmed.l1_height, BlockHeight(2));
    assert_eq!(confirmed.l1_block_hash, hash);
    assert_eq!(confirmed.attempts.len(), 2);
    assert_eq!(&confirmed.attempts[..1], &before.attempts);
    assert_eq!(confirmed.attempts[1].transaction_bytes, Some(encoded(&replacement)));
    assert_eq!(bincode::serialize(&confirmed.batch).unwrap(), bincode::serialize(&local).unwrap());
    confirmed.attempts[1].transaction_bytes.as_mut().unwrap().clear();
    for tx in [&initial, &replacement] {
        assert_eq!(encoded(&chain.get_l1_submission_transaction(local.index, tx.hash()).unwrap()), encoded(tx));
    }
    assert!(chain.get_batch_submission(local.index).is_none());
    assert_eq!(chain.stats().submitted_batches, 0);
    assert_eq!(chain.stats().confirmed_batches, 1);
    assert!(chain.verified_state_root(local.block_range.1).is_none());
    assert_eq!(state, (l1.height(), l1.state_root(), l1.stats().l2_batch_count));
    assert!(chain.recover_l1_retry(local.index, initial.hash(), &replacement, &l1).is_err());
    assert!(chain.mark_batch_confirmed(local.index, &l1).is_err());
    assert_eq!(chain.stats().confirmed_batches, 1);
}

#[tokio::test]
async fn a_hash_only_intent_can_recover_an_expired_but_processed_replacement() {
    let (chain, publisher) = pair(); let local = batch(&chain); let l1 = anchor();
    let initial = Hash256::hash(b"initial intent without a signed packet");
    chain.mark_batch_submitted(local.clone(), initial).unwrap();
    let signed = publisher.sign_transaction(Transaction { chain_id: ChainId::LOCAL, nonce: Nonce(0),
        gas_limit: 21000, gas_price: Amount::ZERO, timestamp: Timestamp(0), expires_at: Some(Timestamp(1)),
        tx_type: TransactionType::BatchSubmit { batch_root: local.post_state_root.0,
            batch_size: local.tx_count as u32, compressed_data: local.compressed_data.clone() } }).unwrap();
    let mut header = BlockHeader::new(BlockHeight(1), l1.genesis().hash(), Address::ZERO, Layer::Anchor);
    header.timestamp = Timestamp(1);
    header.transactions_root = MerkleTree::from_leaves(vec![signed.hash()]).root();
    let mut state = InMemoryState::new();
    state.get_or_create_account(&publisher.address()).nonce = Nonce(1);
    state.get_or_create_account(&Address::ZERO).credit(Amount::from_units(2)).unwrap();
    header.state_root = state.compute_root().0;
    l1.process_block(Block::new(header, BlockBody::new(vec![signed.clone()]))).await.unwrap();
    assert!(l1.validate_batch_submission(&signed).is_err());
    let confirmed = chain.recover_l1_retry(local.index, initial, &signed, &l1).unwrap();
    assert_eq!(confirmed.attempts.len(), 2);
    assert!(confirmed.attempts[0].transaction_bytes.is_none());
    assert_eq!(confirmed.attempts[1].transaction_bytes, Some(encoded(&signed)));
    assert_eq!(confirmed.l1_height, BlockHeight(1));
    assert!(chain.get_l1_submission_transaction(local.index, initial).is_err());
}

#[tokio::test]
async fn stale_absent_or_globally_reserved_attempts_cannot_change_pending_history() {
    let (chain, publisher) = pair(); let local = batch(&chain); let l1 = anchor();
    let signed = packet(&chain, &local, &publisher, &l1);
    l1.process_block(l1.prepare_block(vec![signed.clone()], Address::ZERO).unwrap()).await.unwrap();
    let first = Hash256::hash(b"first"); let current = Hash256::hash(b"current");
    assert!(chain.recover_l1_retry(local.index, first, &signed, &l1).is_err());
    assert!(chain.recover_l1_retry(999, first, &signed, &l1).is_err());
    assert_eq!(chain.stats().confirmed_batches, 0);
    chain.mark_batch_submitted(local.clone(), first).unwrap();
    chain.retry_batch_submission(local.index, first, current).unwrap();
    let before = chain.get_batch_submission(local.index).unwrap();
    assert!(chain.recover_l1_retry(local.index, first, &signed, &l1).is_err());
    assert_pending_unchanged(&chain, &before);
    let other_batch = batch(&chain);
    chain.mark_batch_submitted(other_batch.clone(), signed.hash()).unwrap();
    assert!(chain.recover_l1_retry(local.index, current, &signed, &l1).is_err());
    assert_pending_unchanged(&chain, &before);
    // The hash remains reserved even after the other batch is confirmed.
    let other_signed = packet(&chain, &other_batch, &publisher, &l1);
    chain.retry_l1_submission(other_batch.index, signed.hash(), &other_signed, &l1).unwrap();
    l1.process_block(l1.prepare_block(vec![other_signed], Address::ZERO).unwrap()).await.unwrap();
    chain.mark_batch_confirmed(other_batch.index, &l1).unwrap();
    assert!(chain.recover_l1_retry(local.index, current, &signed, &l1).is_err());
    assert_pending_unchanged(&chain, &before);
}

#[tokio::test]
async fn unprocessed_or_altered_packets_are_rejected_before_attempts_change() {
    let (chain, publisher) = pair(); let local = batch(&chain); let l1 = anchor();
    let initial = Hash256::hash(b"initial");
    chain.mark_batch_submitted(local.clone(), initial).unwrap();
    let before = chain.get_batch_submission(local.index).unwrap();
    let signed = packet(&chain, &local, &publisher, &l1);
    let block = l1.prepare_block(vec![signed.clone()], Address::ZERO).unwrap();
    assert!(chain.recover_l1_retry(local.index, initial, &signed, &l1).is_err());
    let mut rejected = block.clone(); rejected.header.state_root = Hash256::hash(b"wrong root");
    assert!(l1.process_block(rejected).await.is_err());
    l1.submit_l2_batch(local.post_state_root, local.compressed_data.clone()).unwrap();
    assert!(chain.recover_l1_retry(local.index, initial, &signed, &l1).is_err());
    assert_pending_unchanged(&chain, &before);
    l1.process_block(block).await.unwrap();
    assert!(chain.recover_l1_retry(local.index, initial, &signed, &anchor()).is_err());
    for case in 0..4 {
        let mut forged = signed.clone();
        match case {
            0 => forged.public_key[0] ^= 1,
            1 => forged.signature.scheme = SignatureScheme::Dilithium2,
            2 => forged.sender = Address::ZERO,
            _ => forged.signature.bytes.fill(0),
        }
        if case < 3 { assert_eq!(forged.hash(), signed.hash()); }
        assert!(chain.recover_l1_retry(local.index, initial, &forged, &l1).is_err());
        assert_pending_unchanged(&chain, &before);
    }
    chain.recover_l1_retry(local.index, initial, &signed, &l1).unwrap();
}

#[tokio::test]
async fn a_processed_different_batch_or_publisher_cannot_replace_the_local_attempt() {
    let (chain, publisher) = pair(); let local = batch(&chain);
    let initial = Hash256::hash(b"initial");
    chain.mark_batch_submitted(local.clone(), initial).unwrap();
    let before = chain.get_batch_submission(local.index).unwrap();
    for case in 0..5 {
        let l1 = anchor();
        let mut tx = packet(&chain, &local, &publisher, &l1).transaction;
        if let TransactionType::BatchSubmit { batch_root, batch_size, compressed_data } = &mut tx.tx_type {
            match case { 0 => *batch_root = Hash256::hash(b"different root"), 1 => *batch_size += 1,
                2 => compressed_data.push(13), _ => () }
        }
        if case == 3 { tx.tx_type = TransactionType::Transfer { to: Address::ZERO, amount: Amount::ZERO }; }
        let signed = if case == 4 { key().sign_transaction(tx).unwrap() } else { publisher.sign_transaction(tx).unwrap() };
        l1.process_block(l1.prepare_block(vec![signed.clone()], Address::ZERO).unwrap()).await.unwrap();
        assert!(chain.recover_l1_retry(local.index, initial, &signed, &l1).is_err(), "case {case}");
        assert_pending_unchanged(&chain, &before);
    }
}

#[tokio::test]
async fn recovery_uses_the_same_three_retry_limit_and_cannot_consume_a_fourth() {
    for retries in [2, 3] {
        let (chain, publisher) = pair(); let local = batch(&chain); let l1 = anchor();
        let hashes: Vec<_> = (0u8..4).map(|n| Hash256::hash(&[n])).collect();
        chain.mark_batch_submitted(local.clone(), hashes[0]).unwrap();
        for n in 1..=retries { chain.retry_batch_submission(local.index, hashes[n - 1], hashes[n]).unwrap(); }
        let before = chain.get_batch_submission(local.index).unwrap();
        let signed = packet(&chain, &local, &publisher, &l1);
        l1.process_block(l1.prepare_block(vec![signed.clone()], Address::ZERO).unwrap()).await.unwrap();
        let result = chain.recover_l1_retry(local.index, hashes[retries], &signed, &l1);
        if retries == 2 {
            let confirmed = result.unwrap();
            assert_eq!(confirmed.attempts.len(), 4);
            assert_eq!(&confirmed.attempts[..3], &before.attempts);
        } else {
            assert!(result.is_err());
            assert_pending_unchanged(&chain, &before);
            // A rejected recovery did not reserve its hash.
            chain.mark_batch_submitted(batch(&chain), signed.hash()).unwrap();
        }
    }
}

#[tokio::test]
async fn concurrent_recovery_or_normal_retry_has_only_one_winning_transition() {
    use std::sync::{Arc, Barrier};
    for normal_retry in [false, true] {
        let (chain, publisher) = pair(); let local = batch(&chain); let l1 = anchor();
        let initial = Hash256::hash(b"initial"); let next = Hash256::hash(b"normal retry");
        chain.mark_batch_submitted(local.clone(), initial).unwrap();
        let signed = packet(&chain, &local, &publisher, &l1);
        l1.process_block(l1.prepare_block(vec![signed.clone()], Address::ZERO).unwrap()).await.unwrap();
        let chain = Arc::new(chain); let l1 = Arc::new(l1); let barrier = Arc::new(Barrier::new(2));
        let workers: Vec<_> = (0..2).map(|worker| {
            let (chain, l1, barrier, signed) = (chain.clone(), l1.clone(), barrier.clone(), signed.clone());
            let index = local.index;
            std::thread::spawn(move || {
                barrier.wait();
                if normal_retry && worker == 1 { chain.retry_batch_submission(index, initial, next).is_ok() }
                else { chain.recover_l1_retry(index, initial, &signed, &l1).is_ok() }
            })
        }).collect();
        assert_eq!(workers.into_iter().filter_map(|w| w.join().unwrap().then_some(())).count(), 1);
        if let Some(pending) = chain.get_batch_submission(local.index) {
            assert!(normal_retry);
            assert_eq!(pending.l1_tx_hash, next);
            assert_eq!(pending.retries, 1);
            assert_eq!(pending.attempts.len(), 2);
            assert_eq!(chain.stats().confirmed_batches, 0);
            assert!(chain.get_l1_submission_transaction(local.index, signed.hash()).is_err());
        } else {
            let confirmed = chain.get_batch_confirmation(local.index).unwrap();
            assert_eq!(confirmed.attempts.len(), 2);
            assert_eq!(confirmed.l1_tx_hash, signed.hash());
            assert_eq!(chain.stats().confirmed_batches, 1);
        }
    }
}

#[tokio::test]
async fn recovery_targets_the_missing_packet_and_does_not_duplicate_an_already_recorded_attempt() {
    let (chain, publisher) = pair(); let local = batch(&chain); let l1 = anchor();
    let initial = packet(&chain, &local, &publisher, &l1);
    chain.register_l1_submission(local.clone(), &initial, &l1).unwrap();
    l1.process_block(l1.prepare_block(vec![initial.clone()], Address::ZERO).unwrap()).await.unwrap();
    let before = chain.get_batch_submission(local.index).unwrap();
    assert!(chain.recover_l1_retry(local.index, initial.hash(), &initial, &l1).is_err());
    assert_pending_unchanged(&chain, &before);
    let replacement = packet(&chain, &local, &publisher, &l1);
    l1.process_block(l1.prepare_block(vec![replacement.clone()], Address::ZERO).unwrap()).await.unwrap();
    let confirmed = chain.recover_l1_retry(local.index, initial.hash(), &replacement, &l1).unwrap();
    assert_eq!(confirmed.l1_tx_hash, replacement.hash());
    assert_eq!(confirmed.l1_height, BlockHeight(2));
    assert_eq!(&confirmed.attempts[..1], &before.attempts);
    assert!(chain.retry_batch_submission(local.index, replacement.hash(), Hash256::hash(b"later")).is_err());
    let next = batch(&chain);
    assert!(chain.mark_batch_submitted(next, replacement.hash()).is_err());
}
