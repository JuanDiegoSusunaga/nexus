//! Signed transaction domains are checked at L2 admission and execution.
use nexus_active::{ActiveChain, ActiveChainConfig, ExecutionEngine, NexusSequencer, SequencerConfig};
use nexus_core::{AccountState, Address, Amount, BlockHeight, ChainId, InMemoryState,
    NexusError, Nonce, SignatureScheme, SignedTransaction, Transaction, TransactionType};
use nexus_crypto::{DilithiumKeypair, Signer};

fn key() -> DilithiumKeypair {
    DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap()
}

fn transfer(signer: &DilithiumKeypair, chain_id: ChainId, nonce: u64) -> SignedTransaction {
    signer.sign_transaction(Transaction::transfer(chain_id, Nonce(nonce), Address::new([42; 32]),
        Amount(7), 21000, Amount(1_000_000_000))).unwrap()
}

fn initial_state(signer: &DilithiumKeypair) -> InMemoryState {
    let mut state = InMemoryState::new();
    state.set_account(signer.address(), AccountState::with_balance(Amount::from_units(100)));
    state
}

#[test]
fn default_sequencer_rejects_foreign_signatures_without_reserving_a_nonce() {
    let sequencer = NexusSequencer::new(SequencerConfig::default(), key());
    let signer = key();
    let foreign = transfer(&signer, ChainId::MAINNET, 0);
    assert!(nexus_crypto::verify_signed_transaction(&foreign).unwrap());
    assert!(matches!(sequencer.submit_transaction(foreign.clone()), Err(NexusError::InvalidChainId)));
    assert_eq!(sequencer.pending_count(), 0);
    assert!(sequencer.get_transaction(&foreign.hash()).is_none());
    assert_eq!(sequencer.batch_count(), 0);
    let honest = transfer(&signer, ChainId::LOCAL, 0);
    sequencer.submit_transaction(honest.clone()).unwrap();
    let batch = sequencer.build_batch().unwrap().unwrap();
    assert_eq!(batch.tx_hashes(), vec![honest.hash()]);
}

#[test]
fn default_engine_rejects_foreign_signatures_before_balance_or_nonce_changes() {
    let signer = key();
    let mut engine = ExecutionEngine::with_state(initial_state(&signer));
    let before = engine.state_root();
    assert!(matches!(engine.execute_transaction(&transfer(&signer, ChainId::MAINNET, 0)),
        Err(NexusError::InvalidChainId)));
    assert_eq!(engine.state_root(), before);
    assert_eq!(engine.get_account(&signer.address()).unwrap().nonce, Nonce(0));
    assert!(engine.get_account(&Address::new([42; 32])).is_none());
    assert!(engine.execute_transaction(&transfer(&signer, ChainId::LOCAL, 0)).unwrap().success);
}

#[test]
fn active_chain_rejects_foreign_transactions_at_its_public_boundary() {
    let chain = ActiveChain::new(ActiveChainConfig::default(), key());
    let signer = key();
    let before = chain.state_root();
    assert!(matches!(chain.submit_transaction(transfer(&signer, ChainId::TESTNET, 0)),
        Err(NexusError::InvalidChainId)));
    assert_eq!(chain.state_root(), before);
    assert_eq!(chain.height(), BlockHeight::GENESIS);
    assert_eq!(chain.sequencer().pending_count(), 0);
    assert!(chain.submit_transaction(transfer(&signer, ChainId::LOCAL, 0)).is_ok());
}

#[test]
fn configured_sequencer_and_restored_engine_use_the_explicit_domain() {
    let signer = key();
    let sequencer = NexusSequencer::new(SequencerConfig { chain_id: ChainId::TESTNET, ..Default::default() }, key());
    let mut engine = ExecutionEngine::with_state_for_chain(initial_state(&signer), ChainId::TESTNET);
    let foreign = transfer(&signer, ChainId::LOCAL, 0);
    assert!(matches!(sequencer.submit_transaction(foreign.clone()), Err(NexusError::InvalidChainId)));
    assert!(matches!(engine.execute_transaction(&foreign), Err(NexusError::InvalidChainId)));
    let honest = transfer(&signer, ChainId::TESTNET, 0);
    sequencer.submit_transaction(honest.clone()).unwrap();
    let batch = sequencer.build_batch().unwrap().unwrap();
    let result = engine.execute_batch(&batch.transactions);
    assert_eq!(result.len(), 1);
    assert!(result[0].success);
    assert_eq!(result[0].tx_hash, honest.hash());
    assert_eq!(engine.get_account(&signer.address()).unwrap().nonce, Nonce(1));
    assert_eq!(engine.get_account(&Address::new([42; 32])).unwrap().balance, Amount(7));
}

#[test]
fn relabelling_a_foreign_transaction_does_not_replace_its_signature() {
    let signer = key();
    let sequencer = NexusSequencer::new(SequencerConfig::default(), key());
    let mut engine = ExecutionEngine::with_state(initial_state(&signer));
    let mut relabelled = transfer(&signer, ChainId::MAINNET, 0);
    relabelled.transaction.chain_id = ChainId::LOCAL;
    assert!(!nexus_crypto::verify_signed_transaction(&relabelled).unwrap());
    let before = engine.state_root();
    assert!(matches!(sequencer.submit_transaction(relabelled.clone()),
        Err(NexusError::SignatureVerificationFailed(_))));
    assert!(!engine.execute_transaction(&relabelled).unwrap().success);
    assert_eq!(engine.state_root(), before);
    assert_eq!(sequencer.pending_count(), 0);
    let honest = transfer(&signer, ChainId::LOCAL, 0);
    sequencer.submit_transaction(honest.clone()).unwrap();
    assert!(engine.execute_transaction(&honest).unwrap().success);
}

#[test]
fn mixed_batch_rejects_foreign_entries_without_consuming_the_honest_nonce() {
    let signer = key();
    let mut engine = ExecutionEngine::with_state(initial_state(&signer));
    let txs = vec![transfer(&signer, ChainId::MAINNET, 0),
        transfer(&signer, ChainId::LOCAL, 0), transfer(&signer, ChainId::LOCAL, 1)];
    let results = engine.execute_batch(&txs);
    assert_eq!(results.len(), 3);
    assert!(!results[0].success);
    assert_eq!(results[0].error.as_deref(), Some(NexusError::InvalidChainId.to_string().as_str()));
    assert_eq!(results[0].gas_used, 0);
    assert!(results[0].state_changes.is_empty());
    assert!(results[1].success && results[2].success);
    for (result, tx) in results.iter().zip(&txs) { assert_eq!(result.tx_hash, tx.hash()); }
    let mut expected = InMemoryState::new();
    let mut sender = AccountState::with_balance(Amount(Amount::from_units(100).0 - 14));
    sender.nonce = Nonce(2);
    expected.set_account(signer.address(), sender);
    expected.set_account(Address::new([42; 32]), AccountState::with_balance(Amount(14)));
    assert_eq!(engine.state_root(), expected.compute_root());
}

#[test]
fn foreign_deployment_and_call_are_rejected_before_any_execution_effect() {
    let signer = key();
    let mut engine = ExecutionEngine::for_chain(ChainId::TESTNET);
    let empty = engine.state_root();
    assert!(matches!(engine.execute_transaction(&transfer(&signer, ChainId::LOCAL, 0)),
        Err(NexusError::InvalidChainId)));
    assert_eq!(engine.state_root(), empty);
    assert!(engine.get_account(&signer.address()).is_none());
    engine.state_mut().set_account(signer.address(), AccountState::with_balance(Amount::from_units(100)));
    let before = engine.state_root();
    for tx_type in [TransactionType::Deploy { code: vec![1; 16], init_data: vec![] },
        TransactionType::Call { contract: Address::ZERO, method: "foreign".into(), args: vec![], value: Amount::ZERO }] {
        let mut tx = transfer(&signer, ChainId::LOCAL, 0).transaction;
        tx.tx_type = tx_type;
        tx.gas_limit = 50000;
        let signed = signer.sign_transaction(tx).unwrap();
        assert!(matches!(engine.execute_transaction(&signed), Err(NexusError::InvalidChainId)));
        assert_eq!(engine.state_root(), before);
        assert_eq!(engine.state().account_count(), 1);
        assert_eq!(engine.get_account(&signer.address()).unwrap().nonce, Nonce(0));
    }
}
