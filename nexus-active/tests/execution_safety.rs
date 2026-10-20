//! Regressions for the review of 20 October 2026.
use nexus_core::{Address, Amount, BlockHeight, ChainId, Hash256, Nonce,
    SignatureScheme, SignedTransaction, StateRoot, Transaction};
use nexus_crypto::{verify_signed_transaction, DilithiumKeypair, Signer};
use nexus_active::{ExecutionEngine, NexusSequencer, SequencerConfig};
use nexus_active::verifier::{ExecutionStep, FraudProof, NitroVerifier, ProofType, StateProof, VerificationMode};
use nexus_core::AccountState;
fn key() -> DilithiumKeypair {
    DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap()
}

fn transfer(signer: &DilithiumKeypair, nonce: u64, gas_limit: u64, gas_price: u128) -> SignedTransaction {
    signer.sign_transaction(Transaction::transfer(
        ChainId::LOCAL, Nonce(nonce), Address::new([42; 32]), Amount::ZERO,
        gas_limit, Amount(gas_price),
    )).unwrap()
}

#[test]
fn r07_forged_pending_transaction_must_not_block_the_real_sender_nonce() {
    let sequencer = NexusSequencer::new(SequencerConfig::default(), key());
    let victim = key();
    let legitimate = transfer(&victim, 0, 21000, 1_000_000_000);
    let mut forged = legitimate.clone();
    forged.signature.bytes.fill(0);
    assert!(!verify_signed_transaction(&forged).unwrap());
    if sequencer.submit_transaction(forged).is_ok() {
        sequencer.build_batch().unwrap();
    }
    assert!(sequencer.submit_transaction(legitimate).is_ok(),
        "forged signature consumed nonce zero before any valid execution");
}

#[test]
fn r08_honest_transactions_from_one_sender_must_be_nonce_ordered() {
    let sequencer = NexusSequencer::new(SequencerConfig::default(), key());
    let signer = key();
    sequencer.submit_transaction(transfer(&signer, 0, 21000, 1_000_000_000)).unwrap();
    sequencer.submit_transaction(transfer(&signer, 1, 21000, 2_000_000_000)).unwrap();
    let batch = sequencer.build_batch().unwrap().unwrap();
    let nonces: Vec<_> = batch.transactions.iter().map(|tx| tx.transaction.nonce.0).collect();
    assert_eq!(nonces, vec![0, 1], "gas priority puts a dependent transaction before its prerequisite");
}

#[test]
fn r09_transaction_cannot_succeed_with_less_gas_than_execution_requires() {
    let signer = key();
    let mut engine = ExecutionEngine::new();
    engine.state_mut().set_account(signer.address(), AccountState::with_balance(Amount::from_units(1)));
    let result = engine.execute_transaction(&transfer(&signer, 0, 1, 1_000_000_000)).unwrap();
    assert!(!result.success, "transfer succeeded with gas_limit=1 but gas_used={}", result.gas_used);
}

#[test]
fn r11_unrelated_attacker_supplied_trace_must_not_prove_fraud() {
    let mut verifier = NitroVerifier::with_challenge_period(VerificationMode::Optimistic, 60_000);
    let proof = StateProof { proof_type: ProofType::Optimistic, pre_state_root: StateRoot::EMPTY,
        post_state_root: StateRoot::new(Hash256::hash(b"honest")), height: BlockHeight(1),
        proof_data: vec![], public_inputs: vec![] };
    assert!(verifier.verify(&proof).unwrap().valid);
    let proof_hash = Hash256::hash(&bincode::serialize(&proof).unwrap());
    let fake = FraudProof { disputed_tx_index: 0, disputed_tx: transfer(&key(), 999, 21000, 0),
        pre_state: vec![], execution_trace: vec![ExecutionStep { op: "invented".into(),
            pre_state_hash: Hash256::ZERO, post_state_hash: Hash256::ZERO,
            computed_root: StateRoot::EMPTY }], claimed_root: proof.post_state_root,
        correct_root: StateRoot::EMPTY };
    assert!(!verifier.submit_fraud_proof(proof_hash, fake).unwrap(),
        "unverified, unrelated attacker trace deleted an optimistic proof");
}

#[test]
fn r12_oversized_high_priority_transaction_must_not_starve_other_senders() {
    let config = SequencerConfig { max_batch_bytes: 10_000, ..Default::default() };
    let sequencer = NexusSequencer::new(config, key());
    let attacker = key();
    let oversized = attacker.sign_transaction(Transaction::call(ChainId::LOCAL, Nonce(0),
        Address::ZERO, "x".into(), vec![0; 10_000], Amount::ZERO, 21000, Amount(2_000_000_000))).unwrap();
    sequencer.submit_transaction(transfer(&key(), 0, 21000, 1_000_000_000)).unwrap();
    // Rejecting the oversized transaction at admission also satisfies this invariant.
    let _ = sequencer.submit_transaction(oversized);
    assert!(sequencer.build_batch().unwrap().is_some(),
        "oversized heap head prevents a fitting transaction from entering any batch");
}

#[test]
fn failed_deployment_and_insufficient_balance_leave_state_and_nonce_unchanged() {
    let signer = key();
    let mut engine = ExecutionEngine::new();
    let empty = engine.state_root();
    assert!(!engine.execute_transaction(&transfer(&signer, 0, 21000, 1_000_000_000)).unwrap().success);
    assert_eq!(engine.state_root(), empty);
    assert!(engine.get_account(&signer.address()).is_none());
    engine.state_mut().set_account(signer.address(), AccountState::with_balance(Amount::from_units(1)));
    let before = engine.state_root();
    let mut tx = transfer(&signer, 0, 21000, 1_000_000_000).transaction;
    tx.tx_type = nexus_core::TransactionType::Deploy { code: vec![1; 1000], init_data: vec![] };
    assert!(!engine.execute_transaction(&signer.sign_transaction(tx).unwrap()).unwrap().success);
    assert_eq!(engine.state_root(), before);
    assert_eq!(engine.get_account(&signer.address()).unwrap().nonce, Nonce(0));
}

#[test]
fn batch_gas_accounting_rejects_u64_max_without_overflow_or_nonce_change() {
    let signer = key();
    let mut engine = ExecutionEngine::new();
    engine.state_mut().set_account(signer.address(), AccountState::with_balance(Amount::from_units(1)));
    let results = engine.execute_batch(&[transfer(&signer, 0, 21000, 1_000_000_000),
        transfer(&signer, 1, u64::MAX, 1_000_000_000)]);
    assert!(results[0].success);
    assert!(!results[1].success);
    assert_eq!(engine.get_account(&signer.address()).unwrap().nonce, Nonce(1));
}

#[test]
fn timeout_cannot_promote_optimistic_proof_without_a_fraud_verification_contract() {
    let mut verifier = NitroVerifier::with_challenge_period(VerificationMode::Optimistic, 0);
    let proof = StateProof { proof_type: ProofType::Optimistic, pre_state_root: StateRoot::EMPTY,
        post_state_root: StateRoot::new(Hash256::hash(b"unproven")), height: BlockHeight(1),
        proof_data: vec![], public_inputs: vec![] };
    assert!(verifier.verify(&proof).unwrap().valid);
    let hash = Hash256::hash(&bincode::serialize(&proof).unwrap());
    assert!(matches!(verifier.finalize_proof(hash), Err(nexus_core::NexusError::NotImplemented(_))));
    assert!(verifier.get_verified_root(proof.height).is_none());
}
