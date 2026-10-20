//! The local DA payload selector survives staging, rejection and multiple L1 submissions.
use nexus_anchor::{AnchorChain, AnchorChainConfig};
use nexus_core::{Address, Amount, BlockHeight, ChainId, Hash256, NexusError, Nonce,
    SignatureScheme, SignedTransaction, StateRoot, Transaction, TransactionType};
use nexus_crypto::{DilithiumKeypair, Signer};

fn key() -> DilithiumKeypair { DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap() }
fn submission(signer: &DilithiumKeypair, nonce: u64, bytes: Vec<u8>) -> SignedTransaction {
    let mut tx = Transaction::transfer(ChainId::LOCAL, Nonce(nonce), Address::ZERO,
        Amount::ZERO, 21000, Amount::ZERO);
    tx.tx_type = TransactionType::BatchSubmit { batch_root: Hash256::hash(&bytes), batch_size: 1,
        compressed_data: bytes };
    signer.sign_transaction(tx).unwrap()
}

#[test]
fn local_registration_preserves_both_payloads_at_one_height_and_rejects_empty_data() {
    let chain = AnchorChain::new(AnchorChainConfig::default(), key());
    let first = vec![1; 500];
    let second = vec![2; 700];
    for bytes in [&first, &second] {
        assert_eq!(chain.submit_l2_batch(StateRoot::EMPTY, bytes.clone()).unwrap(), Hash256::hash(bytes));
    }
    assert!(chain.submit_l2_batch(StateRoot::EMPTY, vec![]).is_err());
    assert_eq!(chain.stats().l2_batch_count, 2);
    assert_eq!(chain.get_l2_batch(0).unwrap().da_batch_index, 0);
    assert_eq!(chain.get_l2_batch(1).unwrap().da_batch_index, 1);
    assert_eq!(chain.get_l2_batch_data(0).unwrap(), first);
    assert_eq!(chain.get_l2_batch_data(1).unwrap(), second);
    assert!(chain.get_l2_batch_data(2).is_err());
    assert!(chain.get_l2_batch_data(u64::MAX).is_err());
    assert_eq!(chain.height(), BlockHeight::GENESIS);
    assert_eq!(chain.state_root(), StateRoot::EMPTY);
}

#[tokio::test]
async fn signed_submissions_survive_root_rejection_retry_and_a_new_height() {
    let signer = key();
    let chain = AnchorChain::new(AnchorChainConfig { block_reward: Amount::from_units(64),
        ..Default::default() }, key());
    chain.process_block(chain.prepare_block(vec![], signer.address()).unwrap()).await.unwrap();
    let first = vec![3; 500];
    let second = vec![4; 700];
    let txs = vec![submission(&signer, 0, first.clone()), submission(&signer, 1, second.clone())];
    let mut invalid = txs.clone();
    invalid.push(submission(&signer, 2, vec![]));
    let before = chain.state_root();
    assert!(chain.prepare_block(invalid, Address::ZERO).is_err());
    let honest = chain.prepare_block(txs, Address::ZERO).unwrap();
    let mut wrong_root = honest.clone();
    wrong_root.header.state_root = Hash256::ZERO;
    assert!(matches!(chain.process_block(wrong_root).await, Err(NexusError::InvalidStateRoot { .. })));
    assert_eq!(chain.stats().l2_batch_count, 0);
    assert!(chain.get_l2_batch_data(0).is_err());
    assert_eq!(chain.state_root(), before);
    assert_eq!(chain.get_account(&signer.address()).unwrap().nonce, Nonce(0));
    assert_eq!(chain.height(), BlockHeight(1));
    chain.process_block(honest).await.unwrap();
    assert_eq!(chain.get_l2_batch_data(0).unwrap(), first);
    assert_eq!(chain.get_l2_batch_data(1).unwrap(), second);
    assert_eq!(chain.get_l2_batch(0).unwrap().da_batch_index, 0);
    assert_eq!(chain.get_l2_batch(1).unwrap().da_batch_index, 1);
    let third = vec![5; 1];
    chain.process_block(chain.prepare_block(vec![submission(&signer, 2, third.clone())], Address::ZERO).unwrap()).await.unwrap();
    let record = chain.get_l2_batch(2).unwrap();
    assert_eq!(record.index, 2);
    assert_eq!(record.l1_height, BlockHeight(3));
    assert_eq!(record.da_batch_index, 0);
    assert_eq!(record.data_hash, Hash256::hash(&third));
    assert_eq!(chain.get_l2_batch_data(2).unwrap(), third);
    assert_eq!(chain.get_l2_batch_data(0).unwrap(), first);
    assert_eq!(chain.get_l2_batch_data(1).unwrap(), second);
    assert_eq!(chain.get_account(&signer.address()).unwrap().nonce, Nonce(3));
}
