//! Four actual executables, TCP, signed client queries, crashes and catchup.
use nexus_anchor::bft::block_id;
use nexus_core::{Amount, BlockHeight, SignatureScheme};
use nexus_crypto::DilithiumKeypair;
use nexus_network::testnet::{exchange, Reply, Request, Status};
use nexus_node::{BftNode, BftNodeConfig};
use std::{fs::{self, File, OpenOptions}, net::{SocketAddr, TcpListener}, path::{Path, PathBuf},
    process::{Child, Command, Stdio}, time::Duration};

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nexus"));
    command.stdin(Stdio::null());
    #[cfg(windows)] {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    command
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
}
fn launch(root: &Path, addresses: &[SocketAddr], index: usize) -> Process {
    let log = OpenOptions::new().create(true).append(true).open(root.join(format!("node-{index}.log"))).unwrap();
    let mut cmd = command();
    cmd.args(["testnet", "run", "--genesis"]).arg(root.join("lab/genesis.json"))
        .arg("--data-dir").arg(root.join(format!("node-{index}")))
        .arg("--key").arg(root.join(format!("lab/validator-{index}.key")))
        .args(["--listen", &addresses[index].to_string(), "--poll-ms", "200"])
        .stdout(Stdio::from(log.try_clone().unwrap())).stderr(Stdio::from(log));
    for (peer, address) in addresses.iter().enumerate() {
        if peer != index { cmd.args(["--peer", &address.to_string()]); }
    }
    Process(cmd.spawn().unwrap())
}
async fn status(address: SocketAddr, config: &BftNodeConfig) -> Option<Status> {
    let (_, committee) = config.bootstrap().unwrap();
    let response = exchange(address, &committee, Request::Status, Duration::from_secs(2)).await.ok()?;
    match response.reply { Reply::Status(status) => Some(status), _ => None }
}
async fn wait_height(addresses: &[SocketAddr], config: &BftNodeConfig, minimum: u64) -> Vec<Status> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    loop {
        let mut statuses = Vec::new();
        for address in addresses {
            if let Some(status) = status(*address, config).await { statuses.push(status); }
        }
        if statuses.len() == addresses.len() && statuses.iter().all(|status| status.height.0 >= minimum) { return statuses; }
        assert!(tokio::time::Instant::now() < deadline, "nodes did not reach height {minimum}; got {:?}",
            statuses.iter().map(|status| (status.height.0, status.round, status.phase)).collect::<Vec<_>>());
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}
async fn wait_balance(addresses: &[SocketAddr], config: &BftNodeConfig, address: nexus_core::Address, expected: Amount) {
    let (_, committee) = config.bootstrap().unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    loop {
        let mut correct = 0;
        for node in addresses {
            if let Ok(response) = exchange(*node, &committee, Request::Account(address), Duration::from_secs(2)).await {
                if let Reply::Account { account: Some(account), .. } = response.reply {
                    if account.balance == expected { correct += 1; }
                }
            }
        }
        if correct == addresses.len() { return; }
        assert!(tokio::time::Instant::now() < deadline, "balance not confirmed at all nodes");
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}
fn transfer(root: &Path, node: SocketAddr, recipient: nexus_core::Address, amount: &str) -> String {
    let result = command().args(["testnet", "transfer", "--genesis"]).arg(root.join("lab/genesis.json"))
        .arg("--key").arg(root.join("lab/faucet.key"))
        .args(["--node", &node.to_string(), "--to", &recipient.to_hex(), "--amount", amount]).output().unwrap();
    assert!(result.status.success(), "{} {}", String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
    serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap()["hash"].as_str().unwrap().to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn four_tcp_processes_transfer_halt_without_quorum_restart_and_verify_history() {
    let root: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/tcp-process-tests")
        .join(format!("{}-{}", std::process::id(), nexus_core::Timestamp::now().0));
    fs::create_dir_all(&root).unwrap();
    let init = command().args(["testnet", "init", "--out"]).arg(root.join("lab"))
        .args(["--block-time-ms", "400"]).output().unwrap();
    assert!(init.status.success(), "{}", String::from_utf8_lossy(&init.stderr));
    let before = fs::read(root.join("lab/genesis.json")).unwrap();
    let again = command().args(["testnet", "init", "--out"]).arg(root.join("lab")).output().unwrap();
    assert!(!again.status.success());
    assert_eq!(before, fs::read(root.join("lab/genesis.json")).unwrap());
    let document: nexus_node::testnet::PublicGenesis = serde_json::from_slice(&before).unwrap();
    document.validate().unwrap();
    let config = document.config;
    let (_, committee) = config.bootstrap().unwrap();
    let listeners: Vec<_> = (0..4).map(|_| TcpListener::bind("127.0.0.1:0").unwrap()).collect();
    let addresses: Vec<_> = listeners.iter().map(|listener| listener.local_addr().unwrap()).collect();
    drop(listeners);
    let mut processes: Vec<_> = (0..4).map(|index| Some(launch(&root, &addresses, index))).collect();
    let initial = wait_height(&addresses, &config, 2).await;
    let recipient = DilithiumKeypair::from_seed(&[77; 32], SignatureScheme::Dilithium3).unwrap().address();
    let first_hash = transfer(&root, addresses[0], recipient, "2.5");
    wait_balance(&addresses, &config, recipient, Amount(2_500_000_000_000_000_000)).await;

    // Reusing a pending-ID trick or a signature with an altered key must not be accepted.
    {
        use nexus_crypto::Signer;
        let faucet = DilithiumKeypair::from_bytes(&fs::read(root.join("lab/faucet.key")).unwrap()).unwrap();
        let mut tx = nexus_core::Transaction::transfer(config.anchor.chain_id, nexus_core::Nonce(1), recipient,
            Amount::from_units(1), 200_000, config.monetary.policy.min_gas_price);
        tx.network_domain = Some(committee.network_domain());
        let mut signed = faucet.sign_transaction(tx).unwrap(); signed.public_key[0] ^= 1;
        let response = exchange(addresses[0], &committee, Request::Submit(Box::new(signed)), Duration::from_secs(5)).await.unwrap();
        assert!(matches!(response.reply, Reply::Rejected(_)));
    }

    // A malformed length header is rejected without bringing down the service.
    {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(addresses[0]).await.unwrap();
        stream.write_all(b"NXSNET04").await.unwrap();
        stream.write_all(&u32::MAX.to_le_bytes()).await.unwrap();
    }
    assert!(status(addresses[0], &config).await.is_some());

    drop(processes[3].take());
    let minimum = initial.iter().map(|status| status.height.0).max().unwrap() + 3;
    let with_three = wait_height(&addresses[..3], &config, minimum).await;
    drop(processes[2].take());
    let second_hash = transfer(&root, addresses[0], recipient, "1");
    tokio::time::sleep(Duration::from_secs(4)).await;
    for node in &addresses[..2] {
        let response = exchange(*node, &committee, Request::Account(recipient), Duration::from_secs(5)).await.unwrap();
        let Reply::Account { account: Some(account), .. } = response.reply else { panic!("missing recipient"); };
        assert_eq!(account.balance, Amount(2_500_000_000_000_000_000), "two validators finalized a new transfer");
    }
    processes[2] = Some(launch(&root, &addresses, 2));
    wait_balance(&addresses[..3], &config, recipient, Amount(3_500_000_000_000_000_000)).await;
    processes[3] = Some(launch(&root, &addresses, 3));
    let target = status(addresses[0], &config).await.unwrap().height.0;
    let final_statuses = wait_height(&addresses, &config, target).await;
    let common = final_statuses.iter().map(|status| status.height.0).min().unwrap();
    let mut expected = None;
    for node in &addresses {
        let response = exchange(*node, &committee, Request::Commit(BlockHeight(common)), Duration::from_secs(5)).await.unwrap();
        let Reply::Commit(Some(commit)) = response.reply else { panic!("missing common block"); };
        let id = block_id(commit.block()).unwrap();
        if let Some(expected) = expected { assert_eq!(id, expected); } else { expected = Some(id); }
    }
    let mut verifier = BftNode::create(&root.join("independent-verifier"), config.clone(), None).unwrap();
    let mut hashes = Vec::new();
    for height in 1..=common {
        let response = exchange(addresses[0], &committee, Request::Commit(BlockHeight(height)), Duration::from_secs(5)).await.unwrap();
        let Reply::Commit(Some(commit)) = response.reply else { panic!("missing history"); };
        hashes.extend(commit.block().body.transactions.iter().map(|tx| tx.hash().to_hex()));
        verifier.receive(nexus_anchor::bft::Message::Commit(Box::new(commit)), nexus_core::Timestamp::now()).await.unwrap();
    }
    assert!(hashes.contains(&first_hash)); assert!(hashes.contains(&second_hash));
    assert_eq!(verifier.account(&recipient).unwrap().balance, Amount(3_500_000_000_000_000_000));
    assert_eq!(verifier.monetary_counters().issued, Amount::from_units(1_000_000 + common));
    assert!(verifier.monetary_counters().burned > Amount::ZERO);
    let evidence = serde_json::json!({"genesis":verifier.genesis().hash().to_hex(),
        "network_domain":verifier.network_domain().to_hex(), "processes":4, "transport":"TCP loopback",
        "initial_heights":initial.iter().map(|status|status.height.0).collect::<Vec<_>>(),
        "three_node_heights":with_three.iter().map(|status|status.height.0).collect::<Vec<_>>(),
        "verified_height":common,"verified_state_root":verifier.state_root().0.to_hex(),
        "transfer_hashes":[first_hash,second_hash],"recipient_balance_raw":verifier.account(&recipient).unwrap().balance.0.to_string(),
        "issued_raw":verifier.monetary_counters().issued.0.to_string(),"burned_raw":verifier.monetary_counters().burned.0.to_string(),
        "two_node_transfer_stayed_pending":true,"restarted_and_caught_up":true});
    serde_json::to_writer_pretty(File::create(root.join("result.json")).unwrap(), &evidence).unwrap();
    println!("TCP_TEST_EVIDENCE={}", root.join("result.json").display());
    drop(processes);
}
