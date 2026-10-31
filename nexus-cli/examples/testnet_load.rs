//! Closed-loop load on an existing LAB testnet. Uses real ML-DSA transactions.
//! One outstanding transaction per sender; confirms exact hashes in certified
//! blocks, not submission acknowledgements. Keys stay in memory and are not saved.
use clap::Parser;
use nexus_anchor::bft::Committee;
use nexus_core::{Address, Amount, BlockHeight, Hash256, Nonce, SignatureScheme, Timestamp, Transaction};
use nexus_crypto::{DilithiumKeypair, Signer};
use nexus_network::testnet::{exchange, encode, Reply, Request, Status};
use nexus_node::testnet::PublicGenesis;
use serde::Serialize;
use std::{collections::{HashMap, HashSet}, fs, net::SocketAddr, path::PathBuf, time::{Duration, Instant}};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
struct Args {
    #[arg(long)] genesis: PathBuf,
    #[arg(long)] faucet: PathBuf,
    #[arg(long, required = true, num_args = 4)] nodes: Vec<SocketAddr>,
    #[arg(long)] out: PathBuf,
    #[arg(long, default_value_t = 30)] phase_seconds: u64,
    #[arg(long, default_value_t = 3)] repetitions: usize,
}

#[derive(Serialize)]
struct Receipt {
    sender: usize, nonce: u64, hash: String, signed_bytes: usize,
    submit_ack_ms: f64, confirmation_ms: f64, height: u64,
    observed_unix_ms: u64,
    #[serde(skip)] observed: Instant,
}
struct Pending { sender: usize, nonce: u64, sent: Instant, ack_ms: f64, bytes: usize }
#[derive(Serialize)]
struct Phase {
    repetition: usize, concurrency: usize, started_unix_ms: u64, finished_unix_ms: u64,
    offer_seconds: u64, elapsed_including_drain_seconds: f64,
    confirmed_in_offer_window: usize, confirmed_total: usize,
    confirmed_tps_offer_window: f64, confirmed_tps_including_drain: f64,
    latency_ms_p50: f64, latency_ms_p95: f64, latency_ms_p99: f64,
    receipts: Vec<Receipt>,
}
#[derive(Serialize)]
struct Report {
    success: bool, scope: &'static str, genesis: String, signature: &'static str,
    nodes: Vec<SocketAddr>, block_time_ms: u64, poll_ms: u64,
    funding_excluded: bool, funding: Vec<Receipt>, phases: Vec<Phase>,
    initial_statuses: Vec<serde_json::Value>, final_statuses: Vec<serde_json::Value>,
    limitations: Vec<&'static str>, error: Option<String>,
}

async fn query(node: SocketAddr, committee: &Committee, request: Request) -> Result<Reply> {
    Ok(exchange(node, committee, request, Duration::from_secs(10)).await?.reply)
}
async fn status(node: SocketAddr, committee: &Committee) -> Result<Status> {
    match query(node, committee, Request::Status).await? {
        Reply::Status(status) => Ok(status), _ => Err("Unexpected status reply".into()),
    }
}
async fn nonce(node: SocketAddr, committee: &Committee, address: Address) -> Result<u64> {
    match query(node, committee, Request::Account(address)).await? {
        Reply::Account { account, .. } => Ok(account.map_or(0, |account| account.nonce.0)),
        _ => Err("Unexpected account reply".into()),
    }
}
async fn snapshot(nodes: &[SocketAddr], committee: &Committee) -> Result<Vec<serde_json::Value>> {
    let mut values = Vec::new();
    let mut identities = HashSet::new();
    for node in nodes {
        let response = exchange(*node, committee, Request::Status, Duration::from_secs(10)).await?;
        let identity = response.attestation.ok_or("Missing validator attestation")?.validator;
        identities.insert(identity);
        let Reply::Status(s) = response.reply else { return Err("Unexpected status".into()); };
        values.push(serde_json::json!({"validator":identity,"height":s.height.0,
            "state_root":s.state_root.0.to_hex(),"pending":s.pending}));
    }
    if identities.len() != 4 { return Err("Four distinct validator identities required".into()); }
    Ok(values)
}

struct Cursor { next: u64, parent: Hash256 }
impl Cursor {
    async fn at_tip(node: SocketAddr, committee: &Committee) -> Result<Self> {
        let status = status(node, committee).await?;
        let parent = status.tip.map_or_else(|| status.genesis.hash(), |tip| tip.block().hash());
        Ok(Self { next: status.height.0.checked_add(1).ok_or("Height overflow")?, parent })
    }
    async fn confirmed(&mut self, node: SocketAddr, committee: &Committee,
        pending: &mut HashMap<Hash256, Pending>) -> Result<Vec<Receipt>> {
        let mut receipts = Vec::new();
        loop {
            let commit = match query(node, committee, Request::Commit(BlockHeight(self.next))).await? {
                Reply::Commit(Some(commit)) => commit,
                Reply::Commit(None) => break,
                _ => return Err("Unexpected commit reply".into()),
            };
            let block = commit.block(); // exchange verified the quorum certificate and height.
            if block.parent_hash() != self.parent { return Err("Certified block chain discontinuity".into()); }
            for tx in &block.body.transactions {
                if let Some(item) = pending.remove(&tx.hash()) {
                    receipts.push(Receipt { sender: item.sender, nonce: item.nonce, hash: tx.hash().to_hex(),
                        signed_bytes: item.bytes, submit_ack_ms: item.ack_ms,
                        confirmation_ms: item.sent.elapsed().as_secs_f64()*1000.0,
                        height: self.next, observed_unix_ms: Timestamp::now().0, observed: Instant::now() });
                }
            }
            self.parent = block.hash();
            self.next = self.next.checked_add(1).ok_or("Height overflow")?;
        }
        Ok(receipts)
    }
}

async fn submit(node: SocketAddr, document: &PublicGenesis, committee: &Committee,
    key: &DilithiumKeypair, sender: usize, nonce: u64, to: Address, amount: Amount,
    pending: &mut HashMap<Hash256, Pending>) -> Result<()> {
    let sent = Instant::now(); // Includes client signing, transport and verification of ack.
    let mut tx = Transaction::transfer(document.config.anchor.chain_id, Nonce(nonce), to,
        amount, 200_000, document.config.monetary.policy.min_gas_price);
    tx.network_domain = Some(committee.network_domain());
    tx.expires_at = Some(Timestamp(Timestamp::now().0.checked_add(300_000).ok_or("Expiry overflow")?));
    let signed = key.sign_transaction(tx)?;
    let hash = signed.hash();
    let bytes = encode(&signed)?.len();
    match query(node, committee, Request::Submit(Box::new(signed))).await? {
        Reply::Submitted { hash: accepted } if accepted == hash => (),
        Reply::Rejected(error) => return Err(format!("Submission rejected: {error}").into()),
        _ => return Err("Unexpected submission acknowledgement".into()),
    }
    pending.insert(hash, Pending { sender, nonce, sent, ack_ms: sent.elapsed().as_secs_f64()*1000.0, bytes });
    Ok(())
}

fn percentile(values: &[f64], quantile: f64) -> f64 {
    if values.is_empty() { return 0.0; }
    values[((values.len() as f64 * quantile).ceil() as usize).saturating_sub(1).min(values.len()-1)]
}

async fn run(args: &Args, document: &PublicGenesis, committee: &Committee, report: &mut Report) -> Result<()> {
    let faucet_bytes = zeroize::Zeroizing::new(fs::read(&args.faucet)?);
    let faucet = DilithiumKeypair::from_bytes(&faucet_bytes)?;
    drop(faucet_bytes);
    let senders: Vec<_> = (0..32).map(|_| DilithiumKeypair::generate(SignatureScheme::Dilithium3))
        .collect::<std::result::Result<_, _>>()?;
    let recipient = DilithiumKeypair::generate(SignatureScheme::Dilithium3)?.address();
    let node = args.nodes[0];
    let mut faucet_nonce = nonce(node, committee, faucet.address()).await?;
    let mut cursor = Cursor::at_tip(node, committee).await?;
    let mut pending = HashMap::new();
    report.initial_statuses = snapshot(&args.nodes, committee).await?;
    for (index, sender) in senders.iter().enumerate() {
        submit(node, document, committee, &faucet, index, faucet_nonce, sender.address(),
            Amount::from_units(1), &mut pending).await?;
        let deadline = Instant::now()+Duration::from_secs(90);
        while !pending.is_empty() {
            report.funding.extend(cursor.confirmed(node, committee, &mut pending).await?);
            if Instant::now() >= deadline { return Err("Funding confirmation timed out".into()); }
            if !pending.is_empty() { tokio::time::sleep(Duration::from_millis(200)).await; }
        }
        faucet_nonce = faucet_nonce.checked_add(1).ok_or("Nonce overflow")?;
        println!("funded {}/32", index+1);
        fs::write(&args.out, serde_json::to_vec_pretty(report)?)?;
    }
    drop(faucet);
    let mut nonces = [0u64; 32];
    let orders = [[1,8,32], [32,1,8], [8,32,1]];
    for repetition in 0..args.repetitions {
        for concurrency in orders[repetition % orders.len()] {
            let started_unix_ms = Timestamp::now().0;
            let started = Instant::now();
            let cutoff = started+Duration::from_secs(args.phase_seconds);
            let drain_deadline = cutoff+Duration::from_secs(90);
            let mut receipts = Vec::new();
            let mut in_window = 0;
            for index in 0..concurrency {
                submit(node, document, committee, &senders[index], index, nonces[index], recipient,
                    Amount(1_000_000_000_000), &mut pending).await?;
            }
            loop {
                let confirmed = cursor.confirmed(node, committee, &mut pending).await?;
                for receipt in confirmed {
                    let index = receipt.sender;
                    nonces[index] = nonces[index].checked_add(1).ok_or("Nonce overflow")?;
                    if receipt.observed < cutoff { in_window += 1; }
                    receipts.push(receipt);
                }
                if Instant::now() < cutoff {
                    let active: HashSet<_> = pending.values().map(|item| item.sender).collect();
                    for index in 0..concurrency {
                        if !active.contains(&index) && Instant::now() < cutoff {
                            submit(node, document, committee, &senders[index], index, nonces[index], recipient,
                                Amount(1_000_000_000_000), &mut pending).await?;
                        }
                    }
                } else if pending.is_empty() { break; }
                if Instant::now() >= drain_deadline { return Err("Phase confirmation timed out".into()); }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            let elapsed = started.elapsed().as_secs_f64();
            let mut latencies: Vec<_> = receipts.iter().map(|item| item.confirmation_ms).collect();
            latencies.sort_by(f64::total_cmp);
            let phase = Phase { repetition, concurrency, started_unix_ms,
                finished_unix_ms: Timestamp::now().0, offer_seconds: args.phase_seconds,
                elapsed_including_drain_seconds: elapsed, confirmed_in_offer_window: in_window,
                confirmed_total: receipts.len(), confirmed_tps_offer_window: in_window as f64/args.phase_seconds as f64,
                confirmed_tps_including_drain: receipts.len() as f64/elapsed,
                latency_ms_p50: percentile(&latencies,0.50), latency_ms_p95: percentile(&latencies,0.95),
                latency_ms_p99: percentile(&latencies,0.99), receipts };
            println!("repetition={} concurrency={} confirmed={} tps={:.3}", repetition,
                concurrency, phase.confirmed_total, phase.confirmed_tps_including_drain);
            report.phases.push(phase);
            fs::write(&args.out, serde_json::to_vec_pretty(report)?)?;
        }
    }
    let deadline = Instant::now()+Duration::from_secs(30);
    loop {
        report.final_statuses = snapshot(&args.nodes, committee).await?;
        let roots: HashSet<_> = report.final_statuses.iter().map(|s| (s["height"].to_string(),s["state_root"].to_string())).collect();
        if roots.len()==1 && report.final_statuses.iter().all(|s| s["pending"]==0) { break; }
        if Instant::now()>=deadline { return Err("Final validator convergence timed out".into()); }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Ok(())
}

#[tokio::main(flavor="multi_thread", worker_threads=2)]
async fn main() -> Result<()> {
    let args=Args::parse();
    if !(5..=300).contains(&args.phase_seconds) || !(1..=10).contains(&args.repetitions)
        || args.nodes.len()!=4 || args.nodes.iter().collect::<HashSet<_>>().len()!=4 {
        return Err("Use four distinct nodes, 5..300 seconds, 1..10 repetitions".into());
    }
    let document: PublicGenesis=serde_json::from_slice(&fs::read(&args.genesis)?)?;
    document.validate()?;
    if document.config.anchor.chain_id != nexus_core::ChainId::TESTNET {
        return Err("Load generator is restricted to the testnet chain ID".into());
    }
    let (_, committee)=document.config.bootstrap()?;
    let mut report=Report { success:false, scope:"Closed-loop monetary L1 transfers on four endpoints; no L2 proof benchmark",
        genesis:document.genesis_hash.to_hex(), signature:"ML-DSA-65", nodes:args.nodes.clone(),
        block_time_ms:document.config.anchor.consensus.block_time_ms, poll_ms:200,
        funding_excluded:true, funding:Vec::new(), phases:Vec::new(), initial_statuses:Vec::new(),
        final_statuses:Vec::new(), error:None,
        limitations:vec!["Client and validators may share a host; no independent operators established",
            "Confirmation is exact transaction-hash inclusion in verified quorum certificates; no full state replay",
            "Latency includes client signing, transport, certificate verification and polling; quantiles are empirical",
            "Fixed-window throughput and throughput including drain are reported separately",
            "No admission retries: rejection or transport failure aborts the run and preserves partial evidence",
            "Transient sender keys are not persisted; use only test NXS"] };
    fs::OpenOptions::new().create_new(true).write(true).open(&args.out)?;
    fs::write(&args.out,serde_json::to_vec_pretty(&report)?)?;
    let result=run(&args,&document,&committee,&mut report).await;
    report.success=result.is_ok();
    if let Err(error)=&result { report.error=Some(error.to_string()); }
    fs::write(&args.out,serde_json::to_vec_pretty(&report)?)?;
    result
}
