//! Validate and retain real signed L1 packets, distinct from hash-only local intents.
use nexus_active::{ActiveChain, ActiveChainConfig, L1SubmissionOptions, L2Batch};
use nexus_anchor::{AnchorChain, AnchorChainConfig};
use nexus_core::{Address, Amount, ChainId, Hash256, Nonce, SignatureScheme,
    SignedTransaction, StateRoot, Timestamp, Transaction, TransactionType};
use nexus_crypto::{DilithiumKeypair, Signer};

fn key() -> DilithiumKeypair { DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap() }
fn pair() -> (ActiveChain, DilithiumKeypair) {
    let publisher = key();
    (ActiveChain::new(ActiveChainConfig { batch_interval_blocks: 1, ..Default::default() }, publisher.clone()), publisher)
}
fn batch(chain: &ActiveChain) -> L2Batch {
    let sender = key();
    chain.submit_transaction(sender.sign_transaction(Transaction::transfer(ChainId::LOCAL, Nonce(0),
        Address::ZERO, Amount(1), 21000, Amount(1_000_000_000))).unwrap()).unwrap();
    chain.produce_block().unwrap();
    chain.get_next_batch().unwrap()
}
fn anchor() -> AnchorChain { AnchorChain::new(AnchorChainConfig::default(), key()) }
fn encoded(tx: &SignedTransaction) -> Vec<u8> { bincode::serialize(tx).unwrap() }

#[tokio::test]
async fn validated_registration_retains_exact_signed_bytes_before_and_after_confirmation() {
    let (chain, publisher) = pair();
    let local = batch(&chain);
    let l1 = anchor();
    let signed = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
    let hash = chain.register_l1_submission(local.clone(), &signed, &l1).unwrap();
    assert_eq!(hash, signed.hash());
    assert_eq!(chain.get_batch_submission(local.index).unwrap().attempts[0].transaction_bytes, Some(encoded(&signed)));
    let mut recovered = chain.get_l1_submission_transaction(local.index, hash).unwrap();
    assert_eq!(encoded(&recovered), encoded(&signed));
    recovered.signature.bytes.fill(0);
    assert_eq!(encoded(&chain.get_l1_submission_transaction(local.index, hash).unwrap()), encoded(&signed));
    assert_eq!(l1.height().0, 0);
    assert_eq!(l1.state_root(), StateRoot::EMPTY);
    assert!(l1.get_account(&publisher.address()).is_none());
    assert!(chain.verified_state_root(local.block_range.1).is_none());
    assert!(chain.get_l1_submission_transaction(local.index, Hash256::ZERO).is_err());
    assert!(chain.get_l1_submission_transaction(999, hash).is_err());
    l1.process_block(l1.prepare_block(vec![signed.clone()], Address::ZERO).unwrap()).await.unwrap();
    let confirmed = chain.mark_batch_confirmed(local.index, &l1).unwrap();
    assert_eq!(confirmed.attempts[0].transaction_bytes, Some(encoded(&signed)));
    assert_eq!(encoded(&chain.get_l1_submission_transaction(local.index, hash).unwrap()), encoded(&signed));
    assert_eq!(chain.stats().confirmed_batches, 1);
}

#[test]
fn valid_signatures_for_different_payloads_or_publishers_do_not_reserve_an_intent() {
    let (chain, publisher) = pair();
    let local = batch(&chain);
    let l1 = anchor();
    let signed = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
    for case in 0..5 {
        let mut tx = signed.transaction.clone();
        if let TransactionType::BatchSubmit { batch_root, batch_size, compressed_data } = &mut tx.tx_type {
            match case {
                0 => *batch_root = Hash256::hash(b"different root"),
                1 => *batch_size += 1,
                2 => compressed_data.push(7),
                _ => (),
            }
        }
        if case == 3 { tx.tx_type = TransactionType::Transfer { to: Address::ZERO, amount: Amount::ZERO }; }
        let altered = if case == 4 { key().sign_transaction(tx).unwrap() } else { publisher.sign_transaction(tx).unwrap() };
        assert!(nexus_crypto::verify_signed_transaction(&altered).unwrap());
        assert!(chain.register_l1_submission(local.clone(), &altered, &l1).is_err());
        assert!(chain.get_batch_submission(local.index).is_none());
        assert!(chain.get_l1_submission_transaction(local.index, altered.hash()).is_err());
        assert_eq!(l1.stats().l2_batch_count, 0);
    }
    assert!(chain.register_l1_submission(local, &signed, &l1).is_ok());
}

#[test]
fn forged_envelopes_and_invalid_l1_policy_are_rejected_without_recording_bytes() {
    let (chain, publisher) = pair();
    let local = batch(&chain);
    let l1 = anchor();
    let signed = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
    for case in 0..9 {
        let mut altered = signed.clone();
        if case < 3 {
            match case {
                0 => altered.signature.bytes.fill(0),
                1 => { altered.public_key[0] ^= 1; assert_eq!(altered.hash(), signed.hash()); }
                _ => altered.signature.scheme = SignatureScheme::Dilithium2,
            }
        } else {
            let mut tx = signed.transaction.clone();
            match case {
                3 => tx.chain_id = ChainId::TESTNET,
                4 => tx.nonce = Nonce(1),
                5 => tx.expires_at = Some(Timestamp(0)),
                6 => tx.timestamp = Timestamp(u64::MAX),
                7 => tx.gas_limit = 1,
                _ => tx.gas_price = Amount::MAX,
            }
            altered = publisher.sign_transaction(tx).unwrap();
        }
        assert!(chain.register_l1_submission(local.clone(), &altered, &l1).is_err(), "accepted case {case}");
        assert!(chain.get_batch_submission(local.index).is_none());
        assert!(chain.get_l1_submission_transaction(local.index, altered.hash()).is_err());
        assert!(l1.get_account(&publisher.address()).is_none());
        assert_eq!(l1.state_root(), StateRoot::EMPTY);
        assert!(chain.verified_state_root(local.block_range.1).is_none());
    }
    assert!(chain.register_l1_submission(local, &signed, &l1).is_ok());
}

#[tokio::test]
async fn validated_retry_keeps_both_packets_and_confirms_the_new_nonce() {
    let (chain, publisher) = pair();
    let local = batch(&chain);
    let l1 = anchor();
    let initial = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
    chain.register_l1_submission(local.clone(), &initial, &l1).unwrap();
    let other = publisher.sign_transaction(Transaction::transfer(ChainId::LOCAL, Nonce(0),
        Address::ZERO, Amount::ZERO, 21000, Amount::ZERO)).unwrap();
    l1.process_block(l1.prepare_block(vec![other], Address::ZERO).unwrap()).await.unwrap();
    let current = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
    let hash = chain.retry_l1_submission(local.index, initial.hash(), &current, &l1).unwrap();
    assert_eq!(hash, current.hash());
    for tx in [&initial, &current] {
        assert_eq!(encoded(&chain.get_l1_submission_transaction(local.index, tx.hash()).unwrap()), encoded(tx));
    }
    l1.process_block(l1.prepare_block(vec![current], Address::ZERO).unwrap()).await.unwrap();
    let confirmed = chain.mark_batch_confirmed(local.index, &l1).unwrap();
    assert_eq!(confirmed.l1_tx_hash, hash);
    assert_eq!(confirmed.attempts.len(), 2);
    assert!(confirmed.attempts.iter().all(|attempt| attempt.transaction_bytes.is_some()));
}

#[test]
fn invalid_or_stale_retries_preserve_counter_packet_history_and_reservations() {
    let (chain, publisher) = pair();
    let local = batch(&chain);
    let l1 = anchor();
    let initial = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
    chain.register_l1_submission(local.clone(), &initial, &l1).unwrap();
    let next = chain.prepare_l1_submission(&local, &l1, &publisher,
        L1SubmissionOptions { gas_limit: 22_000, ..Default::default() }).unwrap();
    let before = chain.get_batch_submission(local.index).unwrap();
    let mut forged = next.clone(); forged.signature.bytes.fill(0);
    assert!(chain.retry_l1_submission(local.index, initial.hash(), &forged, &l1).is_err());
    assert!(chain.retry_l1_submission(local.index, Hash256::ZERO, &next, &l1).is_err());
    assert!(chain.retry_l1_submission(local.index, initial.hash(), &initial, &l1).is_err());
    let after = chain.get_batch_submission(local.index).unwrap();
    assert_eq!(after.attempts, before.attempts);
    assert_eq!(after.retries, 0);
    assert_eq!(after.submitted_at, before.submitted_at);
    assert!(chain.get_l1_submission_transaction(local.index, next.hash()).is_err());
    assert!(chain.retry_l1_submission(local.index, initial.hash(), &next, &l1).is_ok());
}

#[test]
fn validated_retries_remain_bounded_and_do_not_store_a_rejected_fourth_packet() {
    let (chain, publisher) = pair();
    let local = batch(&chain);
    let l1 = anchor();
    let initial = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
    let mut previous = chain.register_l1_submission(local.clone(), &initial, &l1).unwrap();
    for index in 1..=3 {
        let tx = chain.prepare_l1_submission(&local, &l1, &publisher,
            L1SubmissionOptions { gas_limit: 21_000 + index * 1000, ..Default::default() }).unwrap();
        previous = chain.retry_l1_submission(local.index, previous, &tx, &l1).unwrap();
    }
    let fourth = chain.prepare_l1_submission(&local, &l1, &publisher,
        L1SubmissionOptions { gas_limit: 25_000, ..Default::default() }).unwrap();
    let before = chain.get_batch_submission(local.index).unwrap();
    assert!(chain.retry_l1_submission(local.index, previous, &fourth, &l1).is_err());
    let after = chain.get_batch_submission(local.index).unwrap();
    assert_eq!(after.attempts, before.attempts);
    assert_eq!(after.retries, 3);
    assert_eq!(after.attempts.len(), 4);
    assert!(chain.get_l1_submission_transaction(local.index, fourth.hash()).is_err());
}

#[test]
fn hash_only_intents_remain_distinct_and_can_retry_with_a_validated_packet() {
    let (chain, publisher) = pair();
    let local = batch(&chain);
    let l1 = anchor();
    let intent = Hash256::hash(b"hash only");
    chain.mark_batch_submitted(local.clone(), intent).unwrap();
    assert!(chain.get_l1_submission_transaction(local.index, intent).is_err());
    let tx = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
    chain.retry_l1_submission(local.index, intent, &tx, &l1).unwrap();
    let pending = chain.get_batch_submission(local.index).unwrap();
    assert!(pending.attempts[0].transaction_bytes.is_none());
    assert_eq!(pending.attempts[1].transaction_bytes, Some(encoded(&tx)));
}

#[test]
fn concurrent_signed_registration_and_retries_each_have_one_winner() {
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::Duration;
    let (chain, publisher) = pair();
    let local = batch(&chain);
    let l1 = Arc::new(anchor());
    let initial = chain.prepare_l1_submission(&local, &l1, &publisher, Default::default()).unwrap();
    let chain = Arc::new(chain);
    let barrier = Arc::new(Barrier::new(4));
    let (send, receive) = mpsc::channel();
    let workers: Vec<_> = (0..4).map(|_| {
        let chain = chain.clone(); let l1 = l1.clone(); let local = local.clone();
        let tx = initial.clone(); let barrier = barrier.clone(); let send = send.clone();
        std::thread::spawn(move || { barrier.wait(); send.send(chain.register_l1_submission(local, &tx, &l1).is_ok()).unwrap(); })
    }).collect();
    let results: Vec<_> = (0..4).map(|_| receive.recv_timeout(Duration::from_secs(10)).unwrap()).collect();
    for worker in workers { worker.join().unwrap(); }
    assert_eq!(results.iter().filter(|success| **success).count(), 1);
    let candidates: Vec<_> = (1..=4).map(|index| chain.prepare_l1_submission(&local, &l1, &publisher,
        L1SubmissionOptions { gas_limit: 21_000 + index * 100, ..Default::default() }).unwrap()).collect();
    let barrier = Arc::new(Barrier::new(4));
    let (send, receive) = mpsc::channel();
    let workers: Vec<_> = candidates.into_iter().map(|tx| {
        let chain = chain.clone(); let l1 = l1.clone(); let barrier = barrier.clone(); let send = send.clone();
        let expected = initial.hash();
        std::thread::spawn(move || { barrier.wait(); send.send(chain.retry_l1_submission(local.index, expected, &tx, &l1).is_ok()).unwrap(); })
    }).collect();
    let results: Vec<_> = (0..4).map(|_| receive.recv_timeout(Duration::from_secs(10)).unwrap()).collect();
    for worker in workers { worker.join().unwrap(); }
    assert_eq!(results.iter().filter(|success| **success).count(), 1);
    let pending = chain.get_batch_submission(local.index).unwrap();
    assert_eq!(pending.retries, 1);
    assert_eq!(pending.attempts.len(), 2);
    assert!(pending.attempts.iter().all(|attempt| attempt.transaction_bytes.is_some()));
}
