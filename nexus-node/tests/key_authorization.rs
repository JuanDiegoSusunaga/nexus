//! Policy and pending work must cross the same durable boundary.
use nexus_core::{Address, Amount, ChainId, Nonce, SignatureScheme, Timestamp, Transaction};
use nexus_crypto::{DilithiumKeypair, KeyManager, SentinelSeed};
use nexus_node::{DurableNode, DurableNodeConfig};
use std::{path::{Path, PathBuf}, sync::atomic::{AtomicU64, Ordering}};

fn key() -> DilithiumKeypair {
    DilithiumKeypair::from_seed(&[91; 32], SignatureScheme::Dilithium3).unwrap()
}
fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/key-policy-tests")
        .join(format!("{}-{}-{}", std::process::id(), Timestamp::now().0, NEXT.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir_all(&path).unwrap(); path
}
fn manager() -> (KeyManager, Address) {
    let mut manager = KeyManager::with_sentinel(SentinelSeed::new());
    // Predictable samples are a synthetic functional fixture, not deployment entropy.
    let samples: Vec<_> = (0..nexus_crypto::entropy::SOURCE_ASSESSMENT_SAMPLES).map(|i| i as u8).collect();
    manager.ingest_source(&samples).unwrap();
    let identity = manager.generate_key(SignatureScheme::Dilithium3).unwrap();
    (manager, identity)
}
fn config(identity: Address) -> DurableNodeConfig {
    let mut config = DurableNodeConfig::default();
    config.genesis_balances = vec![(identity, Amount::from_units(10))]; config
}
fn transfer(nonce: u64) -> Transaction {
    Transaction::transfer(ChainId::LOCAL, Nonce(nonce), Address::new([42; 32]), Amount(7),
        21_000, Amount(1_000_000_000))
}

#[test]
fn rotation_and_retirement_survive_restarts_and_preserve_account_identity() {
    let (mut manager, identity) = manager();
    let path = directory(); let config = config(identity);
    let mut node = DurableNode::create(&path, config.clone(), key()).unwrap();
    node.apply_key_record(manager.registry().records()[0].clone()).unwrap();
    let old = manager.sign_transaction(&identity, transfer(0)).unwrap();
    node.submit_transaction(old.clone()).unwrap();
    // Reconnect admission and execution to a single recovered registry.
    drop(node);
    let mut node = DurableNode::open(&path, config.clone(), key()).unwrap();
    manager.rotate_sentinel().unwrap();
    node.apply_key_record(manager.registry().records()[1].clone()).unwrap();
    drop(node);
    let mut node = DurableNode::open(&path, config.clone(), key()).unwrap();
    assert_eq!(node.key_registry_checkpoint(), manager.registry().checkpoint());
    let generation = node.generation();
    assert!(node.submit_transaction(old).is_err());
    assert_eq!(node.generation(), generation);
    let signed = manager.sign_transaction(&identity, transfer(0)).unwrap();
    node.submit_transaction(signed).unwrap();
    assert_eq!(node.produce_block().unwrap().body.transactions.len(), 1);
    assert_eq!(node.l2_account(&identity).unwrap().nonce, Nonce(1));
    let queued = manager.sign_transaction(&identity, transfer(1)).unwrap();
    node.submit_transaction(queued.clone()).unwrap();
    manager.remove_key(&identity).unwrap();
    node.apply_key_record(manager.registry().records()[2].clone()).unwrap();
    let before = node.l2_state_root();
    drop(node);
    let mut node = DurableNode::open(&path, config, key()).unwrap();
    assert!(node.submit_transaction(queued).is_err());
    assert!(node.produce_block().unwrap().body.transactions.is_empty());
    assert_eq!(node.l2_state_root(), before);
    assert_eq!(node.l2_account(&identity).unwrap().balance, Amount(Amount::from_units(10).0 - 7));
}

#[test]
fn failed_policy_commit_restores_registry_pending_work_and_generation() {
    let (mut manager, identity) = manager();
    let path = directory(); let config = config(identity);
    let mut node = DurableNode::create(&path, config.clone(), key()).unwrap();
    node.apply_key_record(manager.registry().records()[0].clone()).unwrap();
    node.submit_transaction(manager.sign_transaction(&identity, transfer(0)).unwrap()).unwrap();
    let checkpoint = node.key_registry_checkpoint();
    let generation = node.generation(); let root = node.l2_state_root();
    manager.remove_key(&identity).unwrap();
    let record = manager.registry().records()[1].clone();
    let obstruction = path.join(format!("checkpoint-{:020}.bin", generation + 1));
    std::fs::create_dir(&obstruction).unwrap();
    assert!(node.apply_key_record(record.clone()).is_err());
    assert_eq!(node.key_registry_checkpoint(), checkpoint);
    assert_eq!(node.generation(), generation);
    assert_eq!(node.l2_state_root(), root);
    // Delete only the empty obstruction created by this test.
    std::fs::remove_dir(obstruction).unwrap();
    assert_eq!(node.produce_block().unwrap().body.transactions.len(), 1);
    assert_eq!(node.l2_account(&identity).unwrap().nonce, Nonce(1));
    node.apply_key_record(record).unwrap();
    drop(node);
    let node = DurableNode::open(&path, config, key()).unwrap();
    assert_eq!(node.key_registry_checkpoint(), manager.registry().checkpoint());
}

#[test]
fn invalid_policy_never_commits_and_managed_transactions_cannot_bypass_l1() {
    let (manager, identity) = manager();
    let path = directory(); let config = config(identity);
    let mut node = DurableNode::create(&path, config, key()).unwrap();
    let enrollment = manager.registry().records()[0].clone();
    node.apply_key_record(enrollment.clone()).unwrap();
    let generation = node.generation(); let policy = node.key_registry_checkpoint();
    assert!(node.apply_key_record(enrollment).is_err());
    assert_eq!(node.generation(), generation);
    assert_eq!(node.key_registry_checkpoint(), policy);
    let signed = manager.sign_transaction(&identity, transfer(0)).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    assert!(runtime.block_on(node.process_l1_transactions(vec![signed], Address::ZERO)).is_err());
    assert_eq!(node.generation(), generation);
    assert_eq!(node.l1_height().0, 0);
}
