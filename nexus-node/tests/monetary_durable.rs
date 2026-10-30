//! Persistence of the opt-in monetary profile. These tests are not a network.
use nexus_anchor::{MonetaryGenesis, MonetaryPolicy};
use nexus_core::{Amount, BlockHeight, ChainId, Hash256, Nonce, SignatureScheme,
    SignedTransaction, Timestamp, Transaction};
use nexus_crypto::{DilithiumKeypair, Signer};
use nexus_node::{DurableNode, DurableNodeConfig};
use std::{path::{Path, PathBuf}, sync::atomic::{AtomicU64, Ordering}};

fn key(seed: u8) -> DilithiumKeypair {
    DilithiumKeypair::from_seed(&[seed; 32], SignatureScheme::Dilithium3).unwrap()
}
fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/monetary-tests")
        .join(format!("{}-{}-{}", std::process::id(), Timestamp::now().0, NEXT.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir_all(&path).unwrap();
    path
}
fn config() -> DurableNodeConfig {
    let mut config = DurableNodeConfig::default();
    config.anchor.chain_id = ChainId::TESTNET;
    config.anchor.block_reward = Amount::ZERO;
    config.anchor.fee_percentage = 0;
    config.anchor_monetary = Some(MonetaryGenesis { deployment: Hash256::new([1; 32]),
        allocations: vec![(key(9).address(), Amount(10_000_000))],
        policy: MonetaryPolicy { max_issued: Amount(10_000_003), initial_block_reward: Amount(10),
            halving_interval: 2, min_gas_price: Amount(1), burn_basis_points: 2500 } });
    config
}
fn transfer(node: &DurableNode) -> SignedTransaction {
    let mut tx = Transaction::transfer(ChainId::TESTNET, Nonce(0), key(8).address(), Amount(100), 200_000, Amount(2));
    tx.network_domain = node.l1_network_domain();
    tx.timestamp = Timestamp(1);
    key(9).sign_transaction(tx).unwrap()
}

#[tokio::test]
async fn four_stores_replay_the_same_signed_block_and_preserve_supply_after_reopen() {
    let directories: Vec<_> = (0..4).map(|_| directory()).collect();
    let mut nodes: Vec<_> = directories.iter().enumerate().map(|(index, path)|
        DurableNode::create(path, config(), key(index as u8 + 1)).unwrap()).collect();
    let tx = transfer(&nodes[0]);
    let block = nodes[0].prepare_l1_candidate(vec![tx], key(1).address(), Timestamp(2)).unwrap();
    for node in &mut nodes {
        node.validate_l1_candidate(&block).unwrap();
        node.process_l1_block(block.clone()).await.unwrap();
    }
    let root = nodes[0].l1_state_root();
    let counters = nodes[0].l1_monetary_counters();
    drop(nodes);
    for (index, path) in directories.iter().enumerate() {
        let node = DurableNode::open(path, config(), key(index as u8 + 1)).unwrap();
        assert_eq!(node.l1_state_root(), root);
        assert_eq!(node.l1_monetary_counters(), counters);
        assert_eq!(node.l1_height(), BlockHeight(1));
        assert_eq!(node.l1_account(&key(9).address()).unwrap().nonce, Nonce(1));
        assert_eq!(node.l1_block_at(BlockHeight(1)).unwrap().hash(), block.hash());
    }
}

#[tokio::test]
async fn failed_checkpoint_rolls_back_money_and_retry_does_not_charge_twice() {
    let path = directory();
    let mut node = DurableNode::create(&path, config(), key(1)).unwrap();
    let tx = transfer(&node);
    let block = node.prepare_l1_candidate(vec![tx], key(1).address(), Timestamp(2)).unwrap();
    let before = (node.l1_state_root(), node.l1_monetary_counters(), node.l1_account(&key(9).address()), node.generation());
    let obstruction = path.join(format!("checkpoint-{:020}.bin", node.generation() + 1));
    std::fs::create_dir(&obstruction).unwrap();
    assert!(node.process_l1_block(block.clone()).await.is_err());
    assert_eq!((node.l1_state_root(), node.l1_monetary_counters(), node.l1_account(&key(9).address()), node.generation()), before);
    std::fs::remove_dir(&obstruction).unwrap();
    node.process_l1_block(block).await.unwrap();
    let after = node.l1_monetary_counters().unwrap();
    assert_eq!(after.issued, Amount(10_000_003));
    assert_eq!(node.l1_account(&key(9).address()).unwrap().nonce, Nonce(1));
    let root = node.l1_state_root();
    drop(node);
    let node = DurableNode::open(&path, config(), key(1)).unwrap();
    assert_eq!(node.l1_state_root(), root);
    assert_eq!(node.l1_monetary_counters(), Some(after));
}

#[test]
fn monetary_genesis_cannot_be_replaced_on_reopen_or_allocate_nxs_twice_across_layers() {
    let path = directory();
    let node = DurableNode::create(&path, config(), key(1)).unwrap();
    drop(node);
    let mut wrong = config();
    wrong.anchor_monetary.as_mut().unwrap().policy.max_issued.0 += 1;
    assert!(DurableNode::open(&path, wrong, key(1)).is_err());
    let mut double = config();
    double.genesis_balances.push((key(9).address(), Amount(10_000_000)));
    assert!(DurableNode::create(&directory(), double, key(1)).is_err());
    assert!(DurableNode::open(&path, config(), key(1)).is_ok());
}

#[test]
fn monetary_checkpoint_survives_abrupt_process_exit() {
    const CHILD: &str = "NEXUS_MONETARY_EXIT_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let mut node = DurableNode::create(Path::new(&path), config(), key(1)).unwrap();
            let block = node.prepare_l1_candidate(vec![transfer(&node)], key(1).address(), Timestamp(2)).unwrap();
            node.process_l1_block(block).await.unwrap();
            // Bypass Rust Drop and graceful shutdown after durable acknowledgement.
            std::process::exit(0);
        });
    }
    let path = directory();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "monetary_checkpoint_survives_abrupt_process_exit", "--nocapture"])
        .env(CHILD, &path);
    #[cfg(windows)] {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let result = command.output().unwrap();
    assert!(result.status.success(), "{} {}", String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
    let node = DurableNode::open(&path, config(), key(1)).unwrap();
    assert_eq!(node.l1_height(), BlockHeight(1));
    assert_eq!(node.l1_monetary_counters().unwrap().issued, Amount(10_000_003));
    assert!(node.l1_monetary_counters().unwrap().burned > Amount::ZERO);
    assert_eq!(node.l1_account(&key(9).address()).unwrap().nonce, Nonce(1));
    assert_eq!(node.l1_account(&key(8).address()).unwrap().balance, Amount(100));
}
