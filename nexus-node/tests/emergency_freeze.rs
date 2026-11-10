use nexus_core::{Address, Amount, ChainId, Hash256, Nonce, SignatureScheme, Timestamp, Transaction};
use nexus_crypto::{DilithiumKeypair, EmergencyFreezeRequest, RecoveryAuthority, RecoveryPolicy, Signer};
use nexus_node::{DurableNode, DurableNodeConfig};
use std::{path::{Path, PathBuf}, sync::atomic::{AtomicU64, Ordering}};

fn key(seed: u8) -> DilithiumKeypair {
    DilithiumKeypair::from_seed(&[seed; 32], SignatureScheme::Dilithium3).unwrap()
}
fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/emergency-tests")
        .join(format!("{}-{}-{}", std::process::id(), Timestamp::now().0, NEXT.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir_all(&path).unwrap(); path
}
fn config() -> DurableNodeConfig {
    let mut config = DurableNodeConfig::default();
    config.active.recovery = RecoveryPolicy::new(Hash256::hash(b"durable-emergency"), vec![RecoveryAuthority {
        identity: key(1).address(), public_key: key(2).public_key().clone() }]).unwrap();
    config.genesis_balances = vec![(key(1).address(), Amount::from_units(10))]; config
}
fn request(signer: &DilithiumKeypair) -> EmergencyFreezeRequest {
    let now = Timestamp::now();
    EmergencyFreezeRequest::sign(ChainId::LOCAL, config().active.recovery.domain(), key(1).address(),
        now, Timestamp(now.0 + 60_000), signer).unwrap()
}
fn transfer() -> nexus_core::SignedTransaction {
    key(1).sign_transaction(Transaction::transfer(ChainId::LOCAL, Nonce(0), Address::new([42; 32]),
        Amount(7), 21_000, Amount(1_000_000_000))).unwrap()
}

#[test]
fn emergency_policy_survives_abrupt_process_exit_and_rejects_context_replacement() {
    const CHILD_PATH: &str = "NEXUS_EMERGENCY_CHILD_PATH";
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        let mut node = DurableNode::create(Path::new(&path), config(), key(3)).unwrap();
        node.submit_transaction(transfer()).unwrap();
        let root = node.l2_state_root();
        node.apply_emergency_freeze(request(&key(2))).unwrap();
        assert_eq!(node.l2_state_root(), root);
        // Exit without running Drop; the accepted policy must already be durable.
        std::process::exit(0);
    }
    let path = directory();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "emergency_policy_survives_abrupt_process_exit_and_rejects_context_replacement", "--nocapture"])
        .env(CHILD_PATH, &path);
    #[cfg(windows)] {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let output = command.output().unwrap();
    assert!(output.status.success(), "{} {}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    let mut node = DurableNode::open(&path, config(), key(3)).unwrap();
    let receipt = node.emergency_freeze_status(&key(1).address()).unwrap();
    let generation = node.generation(); let root = node.l2_state_root();
    assert!(node.apply_emergency_freeze(receipt.request.clone()).is_err());
    assert!(node.apply_emergency_freeze(request(&key(2))).is_err());
    assert!(node.submit_transaction(transfer()).is_err());
    assert_eq!(node.generation(), generation);
    assert!(node.produce_block().unwrap().body.transactions.is_empty());
    assert_eq!(node.l2_state_root(), root);
    drop(node);
    let mut wrong = config(); wrong.active.recovery = RecoveryPolicy::default();
    assert!(DurableNode::open(&path, wrong, key(3)).is_err());
    let mut wrong = config();
    wrong.active.recovery = RecoveryPolicy::new(Hash256::hash(b"other-deployment"),
        config().active.recovery.authorities().to_vec()).unwrap();
    assert!(DurableNode::open(&path, wrong, key(3)).is_err());
    let node = DurableNode::open(&path, config(), key(3)).unwrap();
    assert_eq!(node.emergency_freeze_status(&key(1).address()).unwrap().accepted_at, receipt.accepted_at);
}

#[test]
fn failed_emergency_commit_restores_policy_pool_and_generation() {
    let path = directory();
    let mut node = DurableNode::create(&path, config(), key(3)).unwrap();
    node.submit_transaction(transfer()).unwrap();
    let generation = node.generation(); let root = node.l2_state_root();
    let obstruction = path.join(format!("checkpoint-{:020}.bin", generation + 1));
    std::fs::create_dir(&obstruction).unwrap();
    let order = request(&key(2));
    assert!(node.apply_emergency_freeze(order.clone()).is_err());
    assert!(node.emergency_freeze_status(&key(1).address()).is_none());
    assert_eq!(node.generation(), generation); assert_eq!(node.l2_state_root(), root);
    std::fs::remove_dir(obstruction).unwrap(); // Only this test's empty obstruction.
    assert_eq!(node.produce_block().unwrap().body.transactions.len(), 1);
    assert_eq!(node.l2_account(&key(1).address()).unwrap().nonce, Nonce(1));
    node.apply_emergency_freeze(order).unwrap();
    drop(node);
    let node = DurableNode::open(&path, config(), key(3)).unwrap();
    assert!(node.emergency_freeze_status(&key(1).address()).is_some());
}

#[test]
fn operational_authority_cannot_freeze_and_rejection_preserves_pending_work() {
    let path = directory(); let mut node = DurableNode::create(&path, config(), key(3)).unwrap();
    node.submit_transaction(transfer()).unwrap();
    let generation = node.generation(); let root = node.l2_state_root();
    assert!(node.apply_emergency_freeze(request(&key(1))).is_err());
    assert_eq!(node.generation(), generation); assert_eq!(node.l2_state_root(), root);
    assert!(node.emergency_freeze_status(&key(1).address()).is_none());
    assert_eq!(node.produce_block().unwrap().body.transactions.len(), 1);
    assert_eq!(node.l2_account(&key(1).address()).unwrap().nonce, Nonce(1));
}
