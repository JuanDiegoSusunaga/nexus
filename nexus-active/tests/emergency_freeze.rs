use nexus_active::{ActiveChain, ActiveChainConfig, ExecutionEngine};
use nexus_core::{checkpoint, AccountState, Address, Amount, ChainId, Hash256, InMemoryState,
    Nonce, SignatureScheme, Timestamp, Transaction};
use nexus_crypto::{DilithiumKeypair, EmergencyFreezeRequest, KeyManager, NexusKeypair, RecoveryAuthority,
    RecoveryPolicy, SentinelSeed, Signer};

fn key(seed: u8) -> DilithiumKeypair {
    DilithiumKeypair::from_seed(&[seed; 32], SignatureScheme::Dilithium3).unwrap()
}
fn manager() -> (KeyManager, Address) {
    let mut manager = KeyManager::with_sentinel(SentinelSeed::new());
    let samples: Vec<_> = (0..nexus_crypto::entropy::SOURCE_ASSESSMENT_SAMPLES).map(|i| i as u8).collect();
    manager.ingest_source(&samples).unwrap();
    let identity = manager.generate_key(SignatureScheme::Dilithium3).unwrap();
    (manager, identity)
}
fn policy(identity: Address) -> RecoveryPolicy {
    RecoveryPolicy::new(Hash256::hash(b"freeze-test-deployment"), vec![RecoveryAuthority {
        identity, public_key: key(92).public_key().clone() }]).unwrap()
}
fn config(identity: Address) -> ActiveChainConfig {
    ActiveChainConfig { recovery: policy(identity), ..Default::default() }
}
fn transaction(nonce: u64) -> Transaction {
    Transaction::transfer(ChainId::LOCAL, Nonce(nonce), Address::new([42; 32]), Amount(7),
        21_000, Amount(1_000_000_000))
}
fn request(identity: Address) -> EmergencyFreezeRequest {
    let now = Timestamp::now();
    EmergencyFreezeRequest::sign(ChainId::LOCAL, policy(identity).domain(), identity,
        now, Timestamp(now.0 + 60_000), &key(92)).unwrap()
}
fn chain(identity: Address) -> ActiveChain {
    ActiveChain::with_genesis_balances(config(identity), key(90), &[(identity, Amount::from_units(10)),
        (key(91).address(), Amount::from_units(10)), (key(92).address(), Amount::from_units(10))]).unwrap()
}

#[test]
fn independent_freeze_cancels_work_and_survives_operational_rotations() {
    let (mut manager, identity) = manager(); let chain = chain(identity);
    chain.apply_key_record(manager.registry().records()[0].clone()).unwrap();
    let old = manager.sign_transaction(&identity, transaction(0)).unwrap();
    chain.submit_transaction(old.clone()).unwrap();
    let root = chain.state_root(); let order = request(identity);
    chain.apply_emergency_freeze(order.clone()).unwrap();
    assert_eq!(chain.state_root(), root);
    assert_eq!(chain.sequencer().pending_count(), 0);
    assert!(chain.sequencer().get_transaction(&old.hash()).is_none());
    assert!(chain.apply_emergency_freeze(order).is_err());
    assert!(chain.submit_transaction(old).is_err());
    manager.rotate_sentinel().unwrap();
    chain.apply_key_record(manager.registry().records()[1].clone()).unwrap();
    assert!(chain.submit_transaction(manager.sign_transaction(&identity, transaction(0)).unwrap()).is_err());
    assert!(chain.emergency_freeze_status(&identity).is_some());
    assert!(chain.produce_block().unwrap().body.transactions.is_empty());
    assert_eq!(chain.get_account(&identity).unwrap().nonce, Nonce(0));
    assert_eq!(chain.state_root(), root);
}

#[test]
fn freeze_cancels_external_reservations_and_leaves_other_senders_operational() {
    let identity = key(1).address(); let chain = chain(identity);
    let old = key(1).sign_transaction(transaction(0)).unwrap();
    chain.submit_transaction(old.clone()).unwrap();
    chain.sequencer().build_batch().unwrap().unwrap();
    let other = key(91).sign_transaction(transaction(0)).unwrap();
    chain.submit_transaction(other.clone()).unwrap();
    chain.apply_emergency_freeze(request(identity)).unwrap();
    assert!(chain.sequencer().get_transaction(&old.hash()).is_none());
    assert_eq!(chain.sequencer().pending_count(), 1);
    let bytes = chain.export_checkpoint().unwrap();
    let restored = ActiveChain::restore_checkpoint(&bytes, key(90), &config(identity)).unwrap();
    let block = restored.produce_block().unwrap();
    assert_eq!(block.body.transactions.len(), 1);
    assert_eq!(block.body.transactions[0].hash(), other.hash());
    assert_eq!(restored.get_account(&identity).unwrap().nonce, Nonce(0));
    assert!(restored.submit_transaction(old).is_err());
}

#[test]
fn invalid_freezes_do_not_cancel_pending_work_or_publish_status() {
    let identity = key(1).address(); let chain = chain(identity);
    let tx = key(1).sign_transaction(transaction(0)).unwrap();
    chain.submit_transaction(tx.clone()).unwrap();
    let original = request(identity); let mut variants = Vec::new();
    let mut changed = original.clone(); changed.body.identity = key(91).address(); variants.push(changed);
    let mut changed = original.clone(); changed.body.chain_id = ChainId::TESTNET; variants.push(changed);
    let mut changed = original.clone(); changed.body.deployment = Hash256::ZERO; variants.push(changed);
    let mut changed = original.clone(); changed.body.expires_at = Timestamp(0); variants.push(changed);
    let mut changed = original; changed.signature = key(1).sign(b"forged").unwrap(); variants.push(changed);
    for changed in variants {
        assert!(chain.apply_emergency_freeze(changed).is_err());
        assert!(chain.emergency_freeze_status(&identity).is_none());
        assert_eq!(chain.sequencer().pending_count(), 1);
        assert!(chain.sequencer().get_transaction(&tx.hash()).is_some());
    }
    chain.produce_block().unwrap();
    assert_eq!(chain.get_account(&identity).unwrap().nonce, Nonce(1));
}

#[test]
fn recovery_signers_cannot_transfer_even_when_funded_and_cannot_enter_operational_registry() {
    let identity = key(1).address(); let chain = chain(identity);
    assert!(chain.submit_transaction(key(92).sign_transaction(transaction(0)).unwrap()).is_err());
    assert_eq!(chain.sequencer().pending_count(), 0);
    let mut state = InMemoryState::new();
    state.set_account(key(92).address(), AccountState::with_balance(Amount::from_units(10)));
    let mut engine = ExecutionEngine::with_recovery_policy(state, ChainId::LOCAL,
        Default::default(), policy(identity)).unwrap();
    let root = engine.state_root();
    assert!(!engine.execute_transaction(&key(92).sign_transaction(transaction(0)).unwrap()).unwrap().success);
    assert_eq!(engine.state_root(), root);

    let mut manager = KeyManager::new();
    let operational = NexusKeypair::generate(SignatureScheme::Dilithium3).unwrap();
    let conflict = RecoveryPolicy::new(Hash256::hash(b"conflict"), vec![RecoveryAuthority {
        identity, public_key: operational.public_key().clone() }]).unwrap();
    manager.add_key(operational).unwrap();
    let config = ActiveChainConfig { recovery: conflict.clone(), ..Default::default() };
    let chain = ActiveChain::new(config, key(90));
    assert!(chain.apply_key_record(manager.registry().records()[0].clone()).is_err());
    assert_eq!(chain.key_registry_checkpoint().records, 0);
    assert!(ExecutionEngine::with_recovery_policy(InMemoryState::new(), ChainId::LOCAL,
        manager.registry().clone(), conflict).is_err());
}

#[test]
fn direct_execution_and_checkpoints_keep_the_full_emergency_context() {
    let identity = key(1).address(); let chain = chain(identity);
    let snapshot = chain.export_checkpoint().unwrap();
    let mut wrong = config(identity); wrong.recovery = RecoveryPolicy::default();
    assert!(ActiveChain::restore_checkpoint(&snapshot, key(90), &wrong).is_err());
    let mut state = InMemoryState::new();
    state.set_account(identity, AccountState::with_balance(Amount::from_units(10)));
    let mut engine = ExecutionEngine::with_recovery_policy(state, ChainId::LOCAL, Default::default(), policy(identity)).unwrap();
    engine.apply_emergency_freeze(request(identity)).unwrap();
    let mut restored: ExecutionEngine = checkpoint::decode(&checkpoint::encode(&engine).unwrap()).unwrap();
    let before = restored.state_root();
    assert!(!restored.execute_transaction(&key(1).sign_transaction(transaction(0)).unwrap()).unwrap().success);
    assert!(restored.emergency_freeze_status(&identity).is_some());
    assert_eq!(restored.state_root(), before);
}

#[test]
fn concurrent_admission_and_duplicate_freezes_have_one_authorized_transition() {
    use std::sync::{Arc, Barrier};
    let identity = key(1).address(); let chain = Arc::new(chain(identity));
    let barrier = Arc::new(Barrier::new(10));
    let transactions: Vec<_> = (0..8).map(|nonce| key(1).sign_transaction(transaction(nonce)).unwrap()).collect();
    let workers: Vec<_> = transactions.iter().cloned().map(|tx| {
        let chain = chain.clone(); let barrier = barrier.clone();
        std::thread::spawn(move || { barrier.wait(); let _ = chain.submit_transaction(tx); })
    }).collect();
    let order = request(identity); let other = chain.clone(); let other_barrier = barrier.clone();
    let duplicate = order.clone();
    let freezer = std::thread::spawn(move || { other_barrier.wait(); other.apply_emergency_freeze(duplicate).is_ok() });
    barrier.wait(); let first = chain.apply_emergency_freeze(order).is_ok();
    for worker in workers { worker.join().unwrap(); }
    assert_eq!(usize::from(first) + usize::from(freezer.join().unwrap()), 1);
    assert_eq!(chain.sequencer().pending_count(), 0);
    for tx in transactions { assert!(chain.submit_transaction(tx).is_err()); }
}
