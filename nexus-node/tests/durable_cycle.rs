use nexus_node::{DurableNode, DurableNodeConfig};
use nexus_core::{checkpoint::encode, Address, Amount, Block, BlockBody, BlockHeader, BlockHeight,
    ChainId, InMemoryState, Layer, MerkleTree, Nonce, SignatureScheme, SignedTransaction,
    Timestamp, Transaction, TransactionType};
use nexus_crypto::{DilithiumKeypair, Signer};
use std::{path::{Path, PathBuf}, sync::atomic::{AtomicU64, Ordering}};

fn key(byte: u8) -> DilithiumKeypair { DilithiumKeypair::from_seed(&[byte; 32], SignatureScheme::Dilithium3).unwrap() }
fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/local-cycle-tests")
        .join(format!("{}-{}-{}", std::process::id(), Timestamp::now().0, NEXT.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir_all(&path).unwrap(); path
}
fn config(interval: u64) -> DurableNodeConfig {
    let mut config = DurableNodeConfig::default();
    config.active.batch_interval_blocks = interval;
    config.genesis_balances = vec![(key(2).address(), Amount::from_units(10))]; config
}
fn transfer(nonce: u64) -> SignedTransaction {
    key(2).sign_transaction(Transaction::transfer(ChainId::LOCAL, Nonce(nonce), Address::new([42; 32]),
        Amount(7), 21000, Amount(1_000_000_000))).unwrap()
}
fn reopen(node: DurableNode, path: &Path, config: &DurableNodeConfig) -> DurableNode {
    drop(node); DurableNode::open(path, config.clone(), key(1)).unwrap()
}
fn view(node: &DurableNode) -> Vec<u8> {
    encode(&(node.generation(), node.l1_height(), node.l2_height(), node.l1_state_root(), node.l2_state_root(),
        node.l2_account(&key(2).address()), node.batch(0), node.submission(0), node.confirmation(0))).unwrap()
}
fn fail_next_write(node: &DurableNode, directory: &Path) -> PathBuf {
    let path = directory.join(format!("checkpoint-{:020}.bin", node.generation() + 1));
    std::fs::create_dir(&path).unwrap(); path
}

#[test]
fn execution_submission_inclusion_and_confirmation_survive_separate_abrupt_process_exits() {
    let path = directory();
    for phase in ["produce", "submit", "include", "confirm", "check"] {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "checkpoint_child", "--ignored", "--nocapture"])
            .env("NEXUS_TEST_CHECKPOINT", &path).env("NEXUS_TEST_PHASE", phase);
        #[cfg(windows)] {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "phase {phase}: {} {}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    }
    let node = DurableNode::open(&path, config(1), key(1)).unwrap();
    assert_eq!(node.confirmation(0).unwrap().attempts.len(), 1);
    assert_eq!(node.l2_account(&key(2).address()).unwrap().nonce, Nonce(1));
}

#[test]
#[ignore = "Invoked only by the parent test in a separate process"]
fn checkpoint_child() {
    let path = PathBuf::from(std::env::var_os("NEXUS_TEST_CHECKPOINT").unwrap());
    let phase = std::env::var("NEXUS_TEST_PHASE").unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let mut node = if phase == "produce" { DurableNode::create(&path, config(1), key(1)).unwrap() }
            else { DurableNode::open(&path, config(1), key(1)).unwrap() };
        match phase.as_str() {
            "produce" => { node.submit_transaction(transfer(0)).unwrap(); node.produce_block().unwrap(); }
            "submit" => { node.prepare_l1_submission(node.batch(0).unwrap(), Default::default()).unwrap(); }
            "include" => {
                let hash = node.submission(0).unwrap().l1_tx_hash;
                let tx = node.signed_packet(0, hash).unwrap();
                node.process_l1_transactions(vec![tx], Address::ZERO).await.unwrap();
            }
            "confirm" => { node.confirm_batch(0).unwrap(); }
            "check" => {
                let confirmed = node.confirmation(0).unwrap();
                let tx = node.signed_packet(0, confirmed.l1_tx_hash).unwrap();
                assert_eq!(confirmed.attempts[0].transaction_bytes, Some(encode(&tx).unwrap()));
                assert_eq!(node.batch_data(0).unwrap(), confirmed.batch.compressed_data);
                let before = view(&node);
                assert!(node.submit_transaction(transfer(0)).is_err());
                assert!(node.confirm_batch(0).is_err());
                assert_eq!(before, view(&node));
                let mut expected = InMemoryState::new();
                let mut sender = nexus_core::AccountState::with_balance(Amount(Amount::from_units(10).0 - 7));
                sender.nonce = Nonce(1); expected.set_account(key(2).address(), sender);
                expected.set_account(Address::new([42; 32]), nexus_core::AccountState::with_balance(Amount(7)));
                assert_eq!(node.l2_state_root(), expected.compute_root());
            }
            _ => panic!("unknown child phase"),
        }
        // Deliberately bypass Drop: OS handles and the writer lock must recover after exit.
        std::process::exit(0);
    });
}

#[tokio::test]
async fn pending_pool_and_an_unfinished_batch_survive_restart_without_reordering_or_duplication() {
    let path = directory(); let config = config(3);
    let mut node = DurableNode::create(&path, config.clone(), key(1)).unwrap();
    let a = transfer(0); let b = transfer(1);
    node.submit_transaction(b.clone()).unwrap(); node.submit_transaction(a.clone()).unwrap();
    node = reopen(node, &path, &config);
    let block = node.produce_block().unwrap();
    assert_eq!(block.transaction_hashes(), vec![a.hash(), b.hash()]);
    assert!(node.batch(0).is_none());
    let root = node.l2_state_root(); node = reopen(node, &path, &config);
    node.produce_block().unwrap(); node.produce_block().unwrap();
    let batch = node.batch(0).unwrap();
    assert_eq!(batch.tx_count, 2);
    assert_eq!(batch.block_range, (BlockHeight(1), BlockHeight(3)));
    assert_eq!(batch.post_state_root, root);
    assert_eq!(node.l2_account(&key(2).address()).unwrap().nonce, Nonce(2));
    let tx = node.prepare_l1_submission(batch, Default::default()).unwrap();
    node.process_l1_transactions(vec![tx], Address::ZERO).await.unwrap();
    node.confirm_batch(0).unwrap();
    node = reopen(node, &path, &config);
    assert_eq!(node.confirmation(0).unwrap().batch.tx_count, 2);
}

#[tokio::test]
async fn failed_writes_roll_back_pool_state_packet_history_inclusion_and_confirmation() {
    let path = directory(); let config = config(1);
    let mut node = DurableNode::create(&path, config.clone(), key(1)).unwrap();
    node.submit_transaction(transfer(0)).unwrap();
    let before = view(&node); let obstruction = fail_next_write(&node, &path);
    assert!(node.produce_block().is_err()); assert_eq!(before, view(&node));
    std::fs::remove_dir(obstruction).unwrap(); node.produce_block().unwrap();
    let before = view(&node); let obstruction = fail_next_write(&node, &path);
    assert!(node.prepare_l1_submission(node.batch(0).unwrap(), Default::default()).is_err());
    assert_eq!(before, view(&node));
    std::fs::remove_dir(obstruction).unwrap();
    let tx = node.prepare_l1_submission(node.batch(0).unwrap(), Default::default()).unwrap();
    let before = view(&node); let obstruction = fail_next_write(&node, &path);
    assert!(node.process_l1_transactions(vec![tx.clone()], Address::ZERO).await.is_err());
    assert_eq!(before, view(&node));
    std::fs::remove_dir(obstruction).unwrap();
    node.process_l1_transactions(vec![tx], Address::ZERO).await.unwrap();
    let before = view(&node); let obstruction = fail_next_write(&node, &path);
    assert!(node.confirm_batch(0).is_err()); assert_eq!(before, view(&node));
    std::fs::remove_dir(obstruction).unwrap(); node.confirm_batch(0).unwrap();
    node = reopen(node, &path, &config);
    assert_eq!(node.confirmation(0).unwrap().attempts.len(), 1);
}

#[test]
fn reopening_rejects_another_identity_policy_or_genesis_and_never_overwrites_existing_history() {
    let path = directory(); let config = config(1);
    let node = DurableNode::create(&path, config.clone(), key(1)).unwrap();
    assert!(DurableNode::open(&path, config.clone(), key(1)).is_err());
    drop(node);
    assert!(DurableNode::open(&path, config.clone(), key(3)).is_err());
    for case in 0..4 {
        let mut altered = config.clone();
        match case { 0 => altered.active.sequencer.chain_id = ChainId::TESTNET,
            1 => altered.anchor.block_gas_limit = 1,
            2 => altered.genesis_balances[0].1 = Amount(123),
            _ => altered.active.verification_mode = nexus_active::verifier::VerificationMode::ZKValidity }
        assert!(DurableNode::open(&path, altered, key(1)).is_err());
    }
    assert!(DurableNode::create(&path, config.clone(), key(1)).is_err());
    assert_eq!(DurableNode::open(&path, config.clone(), key(1)).unwrap().generation(), 1);
    let mut duplicate = config; duplicate.genesis_balances.push(duplicate.genesis_balances[0]);
    assert!(DurableNode::create(&directory(), duplicate, key(1)).is_err());
}

#[tokio::test]
async fn signed_retries_and_their_limit_survive_restart() {
    let path = directory(); let config = config(1);
    let mut node = DurableNode::create(&path, config.clone(), key(1)).unwrap();
    node.submit_transaction(transfer(0)).unwrap(); node.produce_block().unwrap();
    let first = node.prepare_l1_submission(node.batch(0).unwrap(), Default::default()).unwrap();
    let mut packets = vec![first];
    for _ in 0..3 {
        node = reopen(node, &path, &config);
        let current = node.submission(0).unwrap().l1_tx_hash;
        packets.push(node.prepare_l1_retry(node.batch(0).unwrap(), current, Default::default()).unwrap());
    }
    node = reopen(node, &path, &config);
    let before = view(&node); let current = packets.last().unwrap();
    assert!(node.prepare_l1_retry(node.batch(0).unwrap(), current.hash(), Default::default()).is_err());
    assert_eq!(before, view(&node));
    assert_eq!(node.submission(0).unwrap().retries, 3);
    node.process_l1_transactions(vec![current.clone()], Address::ZERO).await.unwrap();
    node = reopen(node, &path, &config); node.confirm_batch(0).unwrap();
    node = reopen(node, &path, &config);
    assert_eq!(node.confirmation(0).unwrap().attempts.len(), 4);
    for tx in packets { assert_eq!(encode(&node.signed_packet(0, tx.hash()).unwrap()).unwrap(), encode(&tx).unwrap()); }
}

#[tokio::test]
async fn historical_expired_inclusion_and_da_remain_recoverable_after_restart() {
    let path = directory(); let config = config(1);
    let mut node = DurableNode::create(&path, config.clone(), key(1)).unwrap();
    node.submit_transaction(transfer(0)).unwrap(); node.produce_block().unwrap();
    let batch = node.batch(0).unwrap();
    let signed = key(1).sign_transaction(Transaction { chain_id: ChainId::LOCAL, nonce: Nonce(0),
        gas_limit: 21000, gas_price: Amount::ZERO, timestamp: Timestamp(0), expires_at: Some(Timestamp(1)),
        tx_type: TransactionType::BatchSubmit { batch_root: batch.post_state_root.0,
            batch_size: batch.tx_count as u32, compressed_data: batch.compressed_data.clone() } }).unwrap();
    let genesis = Block::genesis(Layer::Anchor);
    let mut header = BlockHeader::new(BlockHeight(1), genesis.hash(), Address::ZERO, Layer::Anchor);
    header.timestamp = Timestamp(1); header.transactions_root = MerkleTree::from_leaves(vec![signed.hash()]).root();
    let mut state = InMemoryState::new(); state.get_or_create_account(&key(1).address()).nonce = Nonce(1);
    state.get_or_create_account(&Address::ZERO).credit(Amount::from_units(2)).unwrap();
    header.state_root = state.compute_root().0;
    node.process_l1_block(Block::new(header, BlockBody::new(vec![signed.clone()]))).await.unwrap();
    node = reopen(node, &path, &config);
    assert!(nexus_crypto::verify_signed_transaction(&signed).is_err());
    node.recover_l1_submission(batch.clone(), &signed).unwrap();
    node = reopen(node, &path, &config);
    assert_eq!(node.batch_data(0).unwrap(), batch.compressed_data);
    assert_eq!(node.confirmation(0).unwrap().l1_tx_hash, signed.hash());
    assert_eq!(encode(&node.signed_packet(0, signed.hash()).unwrap()).unwrap(), encode(&signed).unwrap());
}
