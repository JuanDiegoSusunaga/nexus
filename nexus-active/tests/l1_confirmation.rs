//! A local submission marker does not establish inclusion on L1.
use nexus_active::{ActiveChain, ActiveChainConfig, L2Batch};
use nexus_anchor::{AnchorChain, AnchorChainConfig};
use nexus_core::{Address, Amount, ChainId, Hash256, Nonce, SignatureScheme,
    SignedTransaction, Transaction, TransactionType};
use nexus_crypto::{DilithiumKeypair, Signer};

fn key() -> DilithiumKeypair { DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap() }
fn pending_batch(chain: &ActiveChain) -> nexus_active::L2Batch {
    let signer = key();
    let tx = Transaction::transfer(ChainId::LOCAL, Nonce(0), Address::ZERO,
        Amount(1), 21000, Amount(1_000_000_000));
    chain.submit_transaction(signer.sign_transaction(tx).unwrap()).unwrap();
    chain.produce_block().unwrap();
    chain.get_next_batch().unwrap()
}
fn chain() -> ActiveChain {
    ActiveChain::new(ActiveChainConfig { batch_interval_blocks: 1, ..Default::default() }, key())
}
fn pair() -> (ActiveChain, DilithiumKeypair) {
    let signer = key();
    let chain = ActiveChain::new(ActiveChainConfig { batch_interval_blocks: 1, ..Default::default() }, signer.clone());
    (chain, signer)
}
fn anchor() -> AnchorChain { AnchorChain::new(AnchorChainConfig::default(), key()) }
async fn fund(l1: &AnchorChain, publisher: &DilithiumKeypair) {
    l1.process_block(l1.prepare_block(vec![], publisher.address()).unwrap()).await.unwrap();
}
fn submission(publisher: &DilithiumKeypair, batch: &L2Batch) -> SignedTransaction {
    let mut tx = Transaction::transfer(ChainId::LOCAL, Nonce(0), Address::ZERO,
        Amount::ZERO, 21000, Amount::ZERO);
    tx.tx_type = TransactionType::BatchSubmit { batch_root: batch.post_state_root.0,
        batch_size: u32::try_from(batch.tx_count).unwrap(), compressed_data: batch.compressed_data.clone() };
    publisher.sign_transaction(tx).unwrap()
}

#[test]
fn an_invented_submission_hash_cannot_confirm_a_local_batch() {
    let chain = chain();
    let batch = pending_batch(&chain);
    chain.mark_batch_submitted(batch.clone(), Hash256::hash(b"invented L1 transaction")).unwrap();
    assert!(chain.mark_batch_confirmed(batch.index, &anchor()).is_err());
    assert_eq!(chain.stats().confirmed_batches, 0);
    assert_eq!(chain.stats().submitted_batches, 1);
}

#[test]
fn zero_submission_hash_is_rejected_without_consuming_the_local_batch() {
    let chain = chain();
    let batch = pending_batch(&chain);
    assert!(chain.mark_batch_submitted(batch.clone(), Hash256::ZERO).is_err());
    assert_eq!(chain.stats().submitted_batches, 0);
    assert_eq!(chain.stats().pending_batches, 0); // Work was retrieved; local snapshot remains.
    assert!(chain.get_known_batch(batch.index).is_some());
    chain.mark_batch_submitted(batch, Hash256::hash(b"later intent")).unwrap();
}

#[tokio::test]
async fn confirmation_requires_processing_then_records_exact_local_l1_provenance() {
    let (chain, publisher) = pair();
    let batch = pending_batch(&chain);
    let l1 = anchor();
    fund(&l1, &publisher).await;
    assert!(chain.mark_batch_confirmed(batch.index, &l1).is_err());
    assert!(chain.mark_batch_confirmed(999, &l1).is_err());
    let tx = submission(&publisher, &batch);
    let tx_hash = tx.hash();
    chain.mark_batch_submitted(batch.clone(), tx_hash).unwrap();
    let block = l1.prepare_block(vec![tx], Address::ZERO).unwrap();
    assert!(chain.mark_batch_confirmed(batch.index, &l1).is_err());
    let mut rejected = block.clone();
    rejected.header.state_root = Hash256::ZERO;
    assert!(l1.process_block(rejected).await.is_err());
    assert!(l1.get_processed_batch_inclusion(&tx_hash).is_err());
    assert!(chain.mark_batch_confirmed(batch.index, &l1).is_err());
    assert_eq!(chain.stats().submitted_batches, 1);
    assert_eq!(chain.stats().confirmed_batches, 0);
    let root = chain.state_root();
    l1.process_block(block.clone()).await.unwrap();
    let inclusion = l1.get_processed_batch_inclusion(&tx_hash).unwrap();
    assert_eq!(inclusion.sender, publisher.address());
    assert_eq!(inclusion.data, batch.compressed_data);
    assert_eq!(inclusion.data_hash, Hash256::hash(&batch.compressed_data));
    let confirmed = chain.mark_batch_confirmed(batch.index, &l1).unwrap();
    assert_eq!(confirmed.batch.batch_hash, batch.batch_hash);
    assert_eq!(confirmed.l1_tx_hash, tx_hash);
    assert_eq!(confirmed.l1_block_hash, block.hash());
    assert_eq!(confirmed.l1_height, block.height());
    assert_eq!(chain.get_batch_confirmation(batch.index).unwrap().l1_block_hash, block.hash());
    assert!(chain.mark_batch_confirmed(batch.index, &l1).is_err());
    assert_eq!(chain.stats().submitted_batches, 0);
    assert_eq!(chain.stats().confirmed_batches, 1);
    assert_eq!(chain.state_root(), root);
    assert!(chain.verified_state_root(batch.block_range.1).is_none());
    assert!(!l1.is_finalized(&block.hash()));
}

#[tokio::test]
async fn processed_submission_must_match_root_count_payload_and_sequencer_identity() {
    for case in 0..4 {
        let (chain, publisher) = pair();
        let batch = pending_batch(&chain);
        let outsider = key();
        let signer = if case == 3 { &outsider } else { &publisher };
        let l1 = anchor();
        fund(&l1, signer).await;
        let mut unsigned = submission(signer, &batch).transaction;
        if let TransactionType::BatchSubmit { batch_root, batch_size, compressed_data } = &mut unsigned.tx_type {
            match case {
                0 => *batch_root = Hash256::hash(b"different root"),
                1 => *batch_size += 1,
                2 => compressed_data.push(99),
                _ => (),
            }
        }
        let tx = signer.sign_transaction(unsigned).unwrap();
        let hash = tx.hash();
        chain.mark_batch_submitted(batch.clone(), hash).unwrap();
        l1.process_block(l1.prepare_block(vec![tx], Address::ZERO).unwrap()).await.unwrap();
        assert!(l1.get_processed_batch_inclusion(&hash).is_ok());
        let before = chain.state_root();
        assert!(chain.mark_batch_confirmed(batch.index, &l1).is_err(), "accepted mismatch case {case}");
        assert!(chain.get_batch_confirmation(batch.index).is_none());
        assert_eq!(chain.stats().submitted_batches, 1);
        assert_eq!(chain.stats().confirmed_batches, 0);
        assert_eq!(chain.state_root(), before);
        assert!(chain.verified_state_root(batch.block_range.1).is_none());
    }
}

#[test]
fn local_da_helper_is_not_signed_transaction_inclusion() {
    let (chain, _) = pair();
    let batch = pending_batch(&chain);
    let l1 = anchor();
    let data_hash = l1.submit_l2_batch(batch.post_state_root, batch.compressed_data.clone()).unwrap();
    assert!(l1.get_l2_batch(0).unwrap().l1_tx_hash.is_none());
    assert!(l1.get_processed_batch_inclusion(&data_hash).is_err());
    chain.mark_batch_submitted(batch.clone(), data_hash).unwrap();
    assert!(chain.mark_batch_confirmed(batch.index, &l1).is_err());
    assert_eq!(chain.stats().confirmed_batches, 0);
}

#[tokio::test]
async fn an_included_transfer_cannot_stand_in_for_a_batch_submission() {
    let (chain, publisher) = pair();
    let batch = pending_batch(&chain);
    let l1 = anchor();
    fund(&l1, &publisher).await;
    let tx = publisher.sign_transaction(Transaction::transfer(ChainId::LOCAL, Nonce(0),
        Address::ZERO, Amount::ZERO, 21000, Amount::ZERO)).unwrap();
    chain.mark_batch_submitted(batch.clone(), tx.hash()).unwrap();
    l1.process_block(l1.prepare_block(vec![tx], Address::ZERO).unwrap()).await.unwrap();
    assert!(chain.mark_batch_confirmed(batch.index, &l1).is_err());
    assert_eq!(chain.stats().submitted_batches, 1);
    assert_eq!(chain.stats().confirmed_batches, 0);
}

#[tokio::test]
async fn concurrent_confirmations_record_exactly_one_observation() {
    use std::sync::{Arc, Barrier};
    let (chain, publisher) = pair();
    let batch = pending_batch(&chain);
    let l1 = Arc::new(anchor());
    fund(&l1, &publisher).await;
    let tx = submission(&publisher, &batch);
    chain.mark_batch_submitted(batch.clone(), tx.hash()).unwrap();
    l1.process_block(l1.prepare_block(vec![tx], Address::ZERO).unwrap()).await.unwrap();
    let chain = Arc::new(chain);
    let barrier = Arc::new(Barrier::new(4));
    let workers: Vec<_> = (0..4).map(|_| {
        let chain = chain.clone();
        let l1 = l1.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || { barrier.wait(); chain.mark_batch_confirmed(batch.index, &l1).is_ok() })
    }).collect();
    assert_eq!(workers.into_iter().map(|worker| usize::from(worker.join().unwrap())).sum::<usize>(), 1);
    assert_eq!(chain.stats().confirmed_batches, 1);
    assert_eq!(chain.stats().submitted_batches, 0);
}

#[test]
fn one_submission_hash_cannot_be_assigned_to_two_local_batches() {
    let chain = chain();
    let first = pending_batch(&chain);
    let second = pending_batch(&chain);
    let hash = Hash256::hash(b"one L1 transaction");
    chain.mark_batch_submitted(first, hash).unwrap();
    assert!(chain.mark_batch_submitted(second, hash).is_err());
    assert_eq!(chain.stats().submitted_batches, 1);
}
