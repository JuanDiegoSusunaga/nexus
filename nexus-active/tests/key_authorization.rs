//! Local policy regressions. Synthetic source samples are test fixtures only.
use nexus_active::{ActiveChain, ActiveChainConfig, ExecutionEngine};
use nexus_core::{checkpoint, AccountState, Address, Amount, ChainId, InMemoryState,
    Nonce, SignatureScheme, SignedTransaction, Transaction};
use nexus_crypto::{DilithiumKeypair, KeyManager, NexusKeypair, SentinelSeed,
    verify_registered_transaction, verify_signed_transaction};

fn publisher() -> DilithiumKeypair {
    DilithiumKeypair::from_seed(&[99; 32], SignatureScheme::Dilithium3).unwrap()
}
fn manager() -> (KeyManager, Address) {
    let mut manager = KeyManager::with_sentinel(SentinelSeed::new());
    let synthetic: Vec<_> = (0..nexus_crypto::entropy::SOURCE_ASSESSMENT_SAMPLES).map(|i| i as u8).collect();
    manager.ingest_source(&synthetic).unwrap();
    let identity = manager.generate_key(SignatureScheme::Dilithium3).unwrap();
    (manager, identity)
}
fn transfer(nonce: u64) -> Transaction {
    Transaction::transfer(ChainId::LOCAL, Nonce(nonce), Address::new([42; 32]), Amount(7),
        21_000, Amount(1_000_000_000))
}
fn chain(identity: Address) -> ActiveChain {
    ActiveChain::with_genesis_balances(ActiveChainConfig::default(), publisher(),
        &[(identity, Amount::from_units(10))]).unwrap()
}
fn success(engine: &mut ExecutionEngine, tx: &SignedTransaction) -> bool {
    engine.execute_transaction(tx).map(|result| result.success).unwrap_or(false)
}

#[test]
fn rotation_releases_pending_nonces_and_new_key_spends_the_same_account() {
    let (mut manager, identity) = manager();
    let chain = chain(identity);
    chain.apply_key_record(manager.registry().records()[0].clone()).unwrap();
    let old = manager.sign_transaction(&identity, transfer(0)).unwrap();
    chain.submit_transaction(old.clone()).unwrap();
    manager.rotate_sentinel().unwrap();
    chain.apply_key_record(manager.registry().records()[1].clone()).unwrap();
    assert_eq!(chain.sequencer().pending_count(), 0);
    assert!(chain.sequencer().get_transaction(&old.hash()).is_none());
    assert!(chain.submit_transaction(old).is_err());
    let current = manager.sign_transaction(&identity, transfer(0)).unwrap();
    assert_ne!(Address::from_public_key(&current.public_key), identity);
    assert_eq!(current.sender, identity);
    chain.submit_transaction(current).unwrap();
    let block = chain.produce_block().unwrap();
    assert_eq!(block.body.transactions.len(), 1);
    assert_eq!(chain.get_account(&identity).unwrap().nonce, Nonce(1));
    assert_eq!(chain.get_account(&identity).unwrap().balance, Amount(Amount::from_units(10).0 - 7));
    assert_eq!(chain.get_account(&Address::new([42; 32])).unwrap().balance, Amount(7));
}

#[test]
fn retirement_purges_work_and_cannot_fall_back_to_a_legacy_signature() {
    let mut manager = KeyManager::new();
    let managed = NexusKeypair::generate(SignatureScheme::Dilithium3).unwrap();
    let transaction = transfer(0);
    let legacy = SignedTransaction::new(transaction.clone(), managed.address(),
        managed.sign(transaction.signing_hash().as_bytes()).unwrap().to_pq_signature(),
        managed.public_key().as_bytes().to_vec());
    let identity = manager.add_key(managed).unwrap();
    let chain = chain(identity);
    assert!(verify_signed_transaction(&legacy).unwrap());
    chain.submit_transaction(legacy.clone()).unwrap();
    chain.apply_key_record(manager.registry().records()[0].clone()).unwrap();
    assert_eq!(chain.sequencer().pending_count(), 0);
    assert!(chain.submit_transaction(legacy.clone()).is_err());
    let signed = manager.sign_transaction(&identity, transfer(0)).unwrap();
    chain.submit_transaction(signed.clone()).unwrap();
    manager.remove_key(&identity).unwrap();
    chain.apply_key_record(manager.registry().records()[1].clone()).unwrap();
    assert_eq!(chain.sequencer().pending_count(), 0);
    assert!(chain.submit_transaction(signed).is_err());
    assert!(verify_signed_transaction(&legacy).unwrap());
    assert!(chain.submit_transaction(legacy).is_err());
}

#[test]
fn registered_envelopes_bind_identity_epoch_payload_and_key_and_require_policy() {
    let (manager, identity) = manager();
    let signed = manager.sign_transaction(&identity, transfer(0)).unwrap();
    assert!(verify_registered_transaction(&signed, manager.registry()).unwrap());
    assert!(!verify_registered_transaction(&signed, &Default::default()).unwrap());
    assert!(verify_signed_transaction(&signed).is_err());
    let mut variants = Vec::new();
    let mut changed = signed.clone(); changed.authorization_epoch = Some(1); variants.push(changed);
    let mut changed = signed.clone(); changed.sender = Address::ZERO; variants.push(changed);
    let mut changed = signed.clone(); changed.transaction.nonce = Nonce(1); variants.push(changed);
    let mut changed = signed.clone(); changed.public_key[0] ^= 1; variants.push(changed);
    let mut changed = signed.clone(); changed.authorization_epoch = None; variants.push(changed);
    let mut changed = signed.clone(); changed.signature.bytes[0] ^= 1; variants.push(changed);
    let mut changed = signed.clone(); changed.transaction.chain_id = ChainId::TESTNET; variants.push(changed);
    for changed in variants {
        assert_ne!(changed.hash(), signed.hash());
        assert!(!verify_registered_transaction(&changed, manager.registry()).unwrap_or(false));
    }
    let generic = manager.sign(&identity, signed.transaction.signing_hash().as_bytes()).unwrap();
    let mut replay = signed.clone();
    replay.signature = generic.signature.to_pq_signature();
    assert!(!verify_registered_transaction(&replay, manager.registry()).unwrap());
}

#[test]
fn direct_execution_and_serialization_preserve_revocation_without_state_changes() {
    let (mut manager, identity) = manager();
    let old = manager.sign_transaction(&identity, transfer(0)).unwrap();
    let mut state = InMemoryState::new();
    state.set_account(identity, AccountState::with_balance(Amount::from_units(10)));
    let mut engine = ExecutionEngine::with_key_registry(state, ChainId::LOCAL, manager.registry().clone());
    manager.remove_key(&identity).unwrap();
    engine.apply_key_record(manager.registry().records()[1].clone()).unwrap();
    let mut engine: ExecutionEngine = checkpoint::decode(&checkpoint::encode(&engine).unwrap()).unwrap();
    let before = engine.state_root();
    assert!(!success(&mut engine, &old));
    assert_eq!(engine.state_root(), before);
    assert_eq!(engine.state().get_account(&identity).unwrap().nonce, Nonce(0));
}

#[test]
fn rejected_registry_records_do_not_change_policy_or_pending_work() {
    let (mut manager, identity) = manager();
    let chain = chain(identity);
    let enrollment = manager.registry().records()[0].clone();
    chain.apply_key_record(enrollment.clone()).unwrap();
    let signed = manager.sign_transaction(&identity, transfer(0)).unwrap();
    chain.submit_transaction(signed.clone()).unwrap();
    let before = chain.key_registry_checkpoint();
    assert!(chain.apply_key_record(enrollment).is_err());
    manager.remove_key(&identity).unwrap();
    let mut invalid = manager.registry().records()[1].clone();
    invalid.authorizations[0].previous = None;
    assert!(chain.apply_key_record(invalid).is_err());
    assert_eq!(chain.key_registry_checkpoint(), before);
    assert_eq!(chain.sequencer().pending_count(), 1);
    assert!(chain.sequencer().get_transaction(&signed.hash()).is_some());
    chain.produce_block().unwrap();
    assert_eq!(chain.get_account(&identity).unwrap().nonce, Nonce(1));
}

#[test]
fn reserved_work_blocks_policy_update_and_v1_checkpoint_is_rejected() {
    let (mut manager, identity) = manager();
    let chain = chain(identity);
    chain.apply_key_record(manager.registry().records()[0].clone()).unwrap();
    chain.submit_transaction(manager.sign_transaction(&identity, transfer(0)).unwrap()).unwrap();
    chain.sequencer().build_batch().unwrap().unwrap();
    let before = chain.key_registry_checkpoint();
    manager.remove_key(&identity).unwrap();
    assert!(chain.apply_key_record(manager.registry().records()[1].clone()).is_err());
    assert_eq!(chain.key_registry_checkpoint(), before);

    let clean = self::chain(identity);
    let mut bytes = clean.export_checkpoint().unwrap();
    bytes[..4].copy_from_slice(&1u32.to_le_bytes());
    assert!(ActiveChain::restore_checkpoint(&bytes, publisher(), &ActiveChainConfig::default()).is_err());
}

#[test]
fn concurrent_admission_leaves_no_revoked_work_after_policy_update_returns() {
    use std::sync::{Arc, Barrier};
    let (mut manager, identity) = manager();
    let chain = Arc::new(chain(identity));
    chain.apply_key_record(manager.registry().records()[0].clone()).unwrap();
    let transactions: Vec<_> = (0..8).map(|nonce|
        manager.sign_transaction(&identity, transfer(nonce)).unwrap()).collect();
    manager.remove_key(&identity).unwrap();
    let barrier = Arc::new(Barrier::new(transactions.len() + 1));
    let workers: Vec<_> = transactions.iter().cloned().map(|tx| {
        let chain = chain.clone(); let barrier = barrier.clone();
        std::thread::spawn(move || { barrier.wait(); chain.submit_transaction(tx) })
    }).collect();
    barrier.wait();
    chain.apply_key_record(manager.registry().records()[1].clone()).unwrap();
    for worker in workers { let _ = worker.join().unwrap(); }
    assert_eq!(chain.sequencer().pending_count(), 0);
    for tx in transactions {
        assert!(chain.sequencer().get_transaction(&tx.hash()).is_none());
        assert!(chain.submit_transaction(tx).is_err());
    }
    let before = chain.state_root();
    assert!(chain.produce_block().unwrap().body.transactions.is_empty());
    assert_eq!(chain.state_root(), before);
}
