//! Retry bookkeeping remains local and does not certify L2 validity or BFT finality.
use nexus_active::{ActiveChain, ActiveChainConfig, L2Batch};
use nexus_anchor::{AnchorChain, AnchorChainConfig};
use nexus_core::{Address, Amount, ChainId, Hash256, Nonce, SignatureScheme, SignedTransaction,
    Transaction, TransactionType};
use nexus_crypto::{DilithiumKeypair, Signer};

fn key() -> DilithiumKeypair { DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap() }
fn pair() -> (ActiveChain, DilithiumKeypair) {
    let publisher = key();
    let chain = ActiveChain::new(ActiveChainConfig { batch_interval_blocks: 1, ..Default::default() }, publisher.clone());
    (chain, publisher)
}
fn batch(chain: &ActiveChain) -> L2Batch {
    let sender = key();
    let tx = Transaction::transfer(ChainId::LOCAL, Nonce(0), Address::ZERO, Amount(1), 21000, Amount(1_000_000_000));
    chain.submit_transaction(sender.sign_transaction(tx).unwrap()).unwrap();
    chain.produce_block().unwrap();
    chain.get_next_batch().unwrap()
}
fn anchor() -> AnchorChain { AnchorChain::new(AnchorChainConfig::default(), key()) }
fn submission(publisher: &DilithiumKeypair, local: &L2Batch, nonce: u64) -> SignedTransaction {
    let mut tx = Transaction::transfer(ChainId::LOCAL, Nonce(nonce), Address::ZERO,
        Amount::ZERO, 21000, Amount::ZERO);
    tx.tx_type = TransactionType::BatchSubmit { batch_root: local.post_state_root.0,
        batch_size: u32::try_from(local.tx_count).unwrap(), compressed_data: local.compressed_data.clone() };
    publisher.sign_transaction(tx).unwrap()
}
async fn fund(l1: &AnchorChain, publisher: &DilithiumKeypair) {
    l1.process_block(l1.prepare_block(vec![], publisher.address()).unwrap()).await.unwrap();
}

#[tokio::test]
async fn incorrect_hash_can_be_retried_without_changing_the_local_batch() {
    let (chain, publisher) = pair();
    let local = batch(&chain);
    let first = Hash256::hash(b"incorrect intent");
    chain.mark_batch_submitted(local.clone(), first).unwrap();
    assert!(chain.mark_batch_confirmed(local.index, &anchor()).is_err());
    assert!(chain.mark_batch_submitted(local.clone(), Hash256::hash(b"corrected intent")).is_err());
    let l1 = anchor();
    fund(&l1, &publisher).await;
    let tx = submission(&publisher, &local, 0);
    let current = tx.hash();
    let before = bincode::serialize(&local).unwrap();
    chain.retry_batch_submission(local.index, first, current).unwrap();
    let pending = chain.get_batch_submission(local.index).unwrap();
    assert_eq!(bincode::serialize(&pending.batch).unwrap(), before);
    assert_eq!(pending.l1_tx_hash, current);
    assert_eq!(pending.retries, 1);
    assert_eq!(pending.attempts.iter().map(|attempt| attempt.l1_tx_hash).collect::<Vec<_>>(), vec![first, current]);
    assert!(chain.mark_batch_confirmed(local.index, &l1).is_err());
    l1.process_block(l1.prepare_block(vec![tx], Address::ZERO).unwrap()).await.unwrap();
    let confirmed = chain.mark_batch_confirmed(local.index, &l1).unwrap();
    assert_eq!(confirmed.l1_tx_hash, current);
    assert_eq!(confirmed.attempts, pending.attempts);
    assert_eq!(bincode::serialize(&confirmed.batch).unwrap(), before);
    assert!(chain.get_batch_submission(local.index).is_none());
    assert_eq!(chain.stats().submitted_batches, 0);
    assert_eq!(chain.stats().confirmed_batches, 1);
    assert!(chain.verified_state_root(local.block_range.1).is_none());
}

#[test]
fn stale_empty_and_reserved_hashes_do_not_consume_attempts_or_reservations() {
    let (chain, _) = pair();
    let first = batch(&chain);
    let second = batch(&chain);
    let a = Hash256::hash(b"a");
    let b = Hash256::hash(b"b");
    let c = Hash256::hash(b"c");
    let d = Hash256::hash(b"d");
    chain.mark_batch_submitted(first.clone(), a).unwrap();
    chain.mark_batch_submitted(second.clone(), b).unwrap();
    chain.retry_batch_submission(first.index, a, c).unwrap();
    let before = chain.get_batch_submission(first.index).unwrap();
    let root = chain.state_root();
    for (expected, next) in [(a, d), (c, Hash256::ZERO), (c, a), (c, b), (c, c)] {
        assert!(chain.retry_batch_submission(first.index, expected, next).is_err());
        let after = chain.get_batch_submission(first.index).unwrap();
        assert_eq!(after.attempts, before.attempts);
        assert_eq!(after.submitted_at, before.submitted_at);
        assert_eq!(after.retries, before.retries);
        assert_eq!(after.l1_tx_hash, c);
    }
    assert!(chain.retry_batch_submission(999, a, d).is_err());
    chain.retry_batch_submission(second.index, b, d).unwrap(); // Stale attempt did not reserve d.
    let third = batch(&chain);
    assert!(chain.retry_batch_submission(third.index, a, Hash256::hash(b"unsubmitted")).is_err());
    assert!(chain.mark_batch_submitted(third, a).is_err()); // Historical a remains reserved.
    assert_eq!(chain.state_root(), root);
    assert_eq!(chain.stats().submitted_batches, 2);
    assert_eq!(chain.stats().confirmed_batches, 0);
}

#[test]
fn three_retries_are_allowed_and_a_fourth_leaves_the_pending_attempt_intact() {
    let (chain, _) = pair();
    let local = batch(&chain);
    let hashes: Vec<_> = (0u8..5).map(|byte| Hash256::hash(&[byte])).collect();
    chain.mark_batch_submitted(local.clone(), hashes[0]).unwrap();
    for index in 1..=3 { chain.retry_batch_submission(local.index, hashes[index - 1], hashes[index]).unwrap(); }
    let before = chain.get_batch_submission(local.index).unwrap();
    assert_eq!(before.retries, 3);
    assert_eq!(before.attempts.len(), 4);
    assert!(chain.retry_batch_submission(local.index, hashes[3], hashes[4]).is_err());
    let after = chain.get_batch_submission(local.index).unwrap();
    assert_eq!(after.attempts, before.attempts);
    assert_eq!(after.l1_tx_hash, hashes[3]);
    assert_eq!(after.submitted_at, before.submitted_at);
    assert_eq!(after.retries, 3);
    let next = batch(&chain);
    chain.mark_batch_submitted(next, hashes[4]).unwrap(); // Exhaustion did not reserve a new hash.
}

#[tokio::test]
async fn a_delayed_original_attempt_can_confirm_after_a_retry() {
    let (chain, publisher) = pair();
    let local = batch(&chain);
    let l1 = anchor();
    fund(&l1, &publisher).await;
    let original = submission(&publisher, &local, 0);
    let replacement = submission(&publisher, &local, 1);
    chain.mark_batch_submitted(local.clone(), original.hash()).unwrap();
    chain.retry_batch_submission(local.index, original.hash(), replacement.hash()).unwrap();
    l1.process_block(l1.prepare_block(vec![original.clone()], Address::ZERO).unwrap()).await.unwrap();
    let confirmed = chain.mark_batch_confirmed(local.index, &l1).unwrap();
    assert_eq!(confirmed.l1_tx_hash, original.hash());
    assert_eq!(confirmed.attempts.len(), 2);
    assert!(chain.retry_batch_submission(local.index, replacement.hash(), Hash256::hash(b"after confirmation")).is_err());
    assert!(chain.mark_batch_confirmed(local.index, &l1).is_err());
    assert_eq!(chain.stats().confirmed_batches, 1);
    let next = batch(&chain);
    assert!(chain.mark_batch_submitted(next, replacement.hash()).is_err());
}

#[tokio::test]
async fn multiple_included_attempts_choose_the_first_recorded_matching_intent() {
    let (chain, publisher) = pair();
    let local = batch(&chain);
    let l1 = anchor();
    fund(&l1, &publisher).await;
    let original = submission(&publisher, &local, 1);
    let replacement = submission(&publisher, &local, 0);
    chain.mark_batch_submitted(local.clone(), original.hash()).unwrap();
    chain.retry_batch_submission(local.index, original.hash(), replacement.hash()).unwrap();
    l1.process_block(l1.prepare_block(vec![replacement, original.clone()], Address::ZERO).unwrap()).await.unwrap();
    let confirmed = chain.mark_batch_confirmed(local.index, &l1).unwrap();
    assert_eq!(confirmed.l1_tx_hash, original.hash());
    assert_eq!(confirmed.attempts.len(), 2);
    assert_eq!(chain.stats().confirmed_batches, 1);
    assert!(chain.verified_state_root(local.block_range.1).is_none());
}

#[tokio::test]
async fn an_included_mismatched_attempt_does_not_hide_a_later_matching_one() {
    let (chain, publisher) = pair();
    let local = batch(&chain);
    let mut wrong = local.clone();
    wrong.compressed_data.push(99);
    let original = submission(&publisher, &wrong, 0);
    let replacement = submission(&publisher, &local, 1);
    let l1 = anchor();
    fund(&l1, &publisher).await;
    chain.mark_batch_submitted(local.clone(), original.hash()).unwrap();
    chain.retry_batch_submission(local.index, original.hash(), replacement.hash()).unwrap();
    l1.process_block(l1.prepare_block(vec![original, replacement.clone()], Address::ZERO).unwrap()).await.unwrap();
    let confirmed = chain.mark_batch_confirmed(local.index, &l1).unwrap();
    assert_eq!(confirmed.l1_tx_hash, replacement.hash());
    assert_eq!(confirmed.batch.compressed_data, local.compressed_data);
}

#[test]
fn concurrent_retries_with_the_same_expected_hash_have_one_winner() {
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::Duration;
    let (chain, _) = pair();
    let local = batch(&chain);
    let initial = Hash256::hash(b"initial");
    chain.mark_batch_submitted(local.clone(), initial).unwrap();
    let chain = Arc::new(chain);
    let barrier = Arc::new(Barrier::new(4));
    let (send, receive) = mpsc::channel();
    let workers: Vec<_> = (0u8..4).map(|index| {
        let chain = chain.clone(); let barrier = barrier.clone(); let send = send.clone();
        std::thread::spawn(move || {
            barrier.wait();
            let hash = Hash256::hash(&[index]);
            send.send((hash, chain.retry_batch_submission(local.index, initial, hash).is_ok())).unwrap();
        })
    }).collect();
    let results: Vec<_> = (0..4).map(|_| receive.recv_timeout(Duration::from_secs(10)).unwrap()).collect();
    for worker in workers { worker.join().unwrap(); }
    assert_eq!(results.iter().filter(|(_, success)| *success).count(), 1);
    let pending = chain.get_batch_submission(local.index).unwrap();
    assert_eq!(pending.retries, 1);
    assert_eq!(pending.attempts.len(), 2);
    assert_eq!(pending.l1_tx_hash, results.iter().find(|(_, success)| *success).unwrap().0);
}

#[tokio::test]
async fn confirmation_and_retry_race_preserves_one_confirmation_and_consistent_history() {
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::Duration;
    let (chain, publisher) = pair();
    let local = batch(&chain);
    let original = submission(&publisher, &local, 0);
    let replacement = submission(&publisher, &local, 1);
    let l1 = Arc::new(anchor());
    fund(&l1, &publisher).await;
    chain.mark_batch_submitted(local.clone(), original.hash()).unwrap();
    l1.process_block(l1.prepare_block(vec![original.clone()], Address::ZERO).unwrap()).await.unwrap();
    let chain = Arc::new(chain);
    let barrier = Arc::new(Barrier::new(2));
    let (send, receive) = mpsc::channel();
    let retry_chain = chain.clone(); let retry_barrier = barrier.clone(); let retry_send = send.clone();
    let retry = std::thread::spawn(move || {
        retry_barrier.wait();
        retry_send.send((false, retry_chain.retry_batch_submission(local.index, original.hash(), replacement.hash()).is_ok())).unwrap();
    });
    let confirm_chain = chain.clone();
    let confirm = std::thread::spawn(move || {
        barrier.wait(); send.send((true, confirm_chain.mark_batch_confirmed(local.index, &l1).is_ok())).unwrap();
    });
    let results: Vec<_> = (0..2).map(|_| receive.recv_timeout(Duration::from_secs(10)).unwrap()).collect();
    retry.join().unwrap(); confirm.join().unwrap();
    assert!(results.iter().find(|(is_confirmation, _)| *is_confirmation).unwrap().1);
    let retried = results.iter().find(|(is_confirmation, _)| !*is_confirmation).unwrap().1;
    let confirmed = chain.get_batch_confirmation(local.index).unwrap();
    assert_eq!(confirmed.attempts.len(), if retried { 2 } else { 1 });
    assert!(chain.get_batch_submission(local.index).is_none());
    assert_eq!(chain.stats().submitted_batches, 0);
    assert_eq!(chain.stats().confirmed_batches, 1);
    assert!(chain.verified_state_root(local.block_range.1).is_none());
}
