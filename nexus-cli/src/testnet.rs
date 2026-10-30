use clap::Subcommand;
use nexus_anchor::{AnchorChainConfig, MonetaryGenesis, MonetaryPolicy};
use nexus_core::{Address, Amount, Hash256, Nonce, SignatureScheme, Timestamp, Transaction};
use nexus_crypto::{DilithiumKeypair, Signer};
use nexus_network::testnet::{exchange, Reply, Request};
use nexus_node::{BftNode, BftNodeConfig, testnet::{serve, PublicGenesis, RuntimeConfig}};
use rand::RngCore;
use std::{fs::{self, OpenOptions}, io::{Read, Write}, net::SocketAddr, path::{Path, PathBuf}, time::Duration};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Subcommand)]
pub enum Command {
    /// Generate a LAB genesis and five unencrypted TEST key files. No real value.
    Init {
        #[arg(long)] out: PathBuf,
        #[arg(long, default_value_t = 1_000_000)] initial_nxs: u64,
        #[arg(long, default_value_t = 2_000_000)] max_nxs: u64,
        #[arg(long, default_value_t = 1)] reward_nxs: u64,
        #[arg(long, default_value_t = 1_000_000)] halving_interval: u64,
        #[arg(long, default_value_t = 2500)] burn_bps: u16,
        #[arg(long, default_value_t = 1000)] block_time_ms: u64,
    },
    /// Run a validator with --key, or an observer without one
    Run {
        #[arg(long)] genesis: PathBuf,
        #[arg(long)] data_dir: PathBuf,
        #[arg(long)] key: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:19001")] listen: SocketAddr,
        #[arg(long)] peer: Vec<SocketAddr>,
        #[arg(long, default_value_t = 500)] poll_ms: u64,
        #[arg(long)] run_for_seconds: Option<u64>,
    },
    Status { #[arg(long)] genesis: PathBuf, #[arg(long)] node: SocketAddr },
    Account { #[arg(long)] genesis: PathBuf, #[arg(long)] node: SocketAddr, #[arg(long)] address: String },
    /// Submit a signed transfer; acceptance is pending, not finality
    Transfer {
        #[arg(long)] genesis: PathBuf, #[arg(long)] node: SocketAddr,
        #[arg(long)] key: PathBuf, #[arg(long)] to: String,
        #[arg(long)] amount: String,
        #[arg(long, default_value_t = 200_000)] gas_limit: u64,
    },
}

fn address(text: &str) -> Result<Address> {
    Address::from_hex(text.strip_prefix("0x").unwrap_or(text)).ok_or_else(|| "Invalid address".into())
}
fn amount(text: &str) -> Result<Amount> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() || !whole.bytes().all(|c| c.is_ascii_digit()) || fraction.len() > 18
        || !fraction.bytes().all(|c| c.is_ascii_digit()) { return Err("Use a nonnegative NXS amount with at most 18 decimal places".into()); }
    let whole: u128 = whole.parse()?;
    let fraction: u128 = if fraction.is_empty() { 0 } else { fraction.parse()? };
    whole.checked_mul(1_000_000_000_000_000_000).and_then(|value|
        fraction.checked_mul(10u128.pow(18 - text.split_once('.').map_or(0, |parts| parts.1.len()) as u32))
            .and_then(|fraction| value.checked_add(fraction))).map(Amount).ok_or_else(|| "NXS amount overflow".into())
}
fn load_config(path: &Path) -> Result<BftNodeConfig> {
    let bytes = read_limited(path, 1024 * 1024)?;
    let document: PublicGenesis = serde_json::from_slice(&bytes)?;
    document.validate()?;
    Ok(document.config)
}
fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new(); fs::File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit { return Err("Input file exceeds limit".into()); }
    Ok(bytes)
}
fn load_key(path: &Path) -> Result<DilithiumKeypair> {
    let bytes = read_limited(path, 16 * 1024)?;
    let key = DilithiumKeypair::from_bytes(&bytes)?;
    if key.scheme() != SignatureScheme::Dilithium3 || key.to_bytes() != bytes { return Err("Noncanonical ML-DSA-65 key file".into()); }
    let challenge = b"NEXUS_TESTNET_KEY_FILE_CHECK_V1";
    if !key.verify(challenge, &key.sign(challenge)?)? { return Err("Public and private key do not match".into()); }
    Ok(key)
}
fn write_new(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let mut options = OpenOptions::new(); options.write(true).create_new(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        if secret { options.mode(0o600); }
    }
    #[cfg(not(unix))] let _ = secret;
    let mut file = options.open(path)?; file.write_all(bytes)?; file.sync_all()?;
    Ok(())
}
fn print(value: serde_json::Value) -> Result<()> { println!("{}", serde_json::to_string_pretty(&value)?); Ok(()) }

pub async fn execute(command: Command) -> Result<()> {
    match command {
        Command::Init { out, initial_nxs, max_nxs, reward_nxs, halving_interval, burn_bps, block_time_ms } => {
            if out.exists() { return Err("Init output already exists; choose a new directory".into()); }
            let keys: Vec<_> = (0..4).map(|_| DilithiumKeypair::generate(SignatureScheme::Dilithium3)).collect::<std::result::Result<_, _>>()?;
            let faucet = DilithiumKeypair::generate(SignatureScheme::Dilithium3)?;
            let mut nonce = [0; 32]; rand::thread_rng().fill_bytes(&mut nonce);
            let mut anchor = AnchorChainConfig { chain_id: nexus_core::ChainId::TESTNET,
                block_reward: Amount::ZERO, fee_percentage: 0, ..Default::default() };
            anchor.consensus.committee_size = 4; anchor.consensus.block_time_ms = block_time_ms;
            let config = BftNodeConfig { anchor, proposal_future_ms: 30_000,
                validators: keys.iter().map(|key| key.public_key().clone()).collect(),
                monetary: MonetaryGenesis { deployment: Hash256::new(nonce),
                    allocations: vec![(faucet.address(), Amount::from_units(initial_nxs))],
                    policy: MonetaryPolicy { max_issued: Amount::from_units(max_nxs),
                        initial_block_reward: Amount::from_units(reward_nxs), halving_interval,
                        min_gas_price: Amount(1_000_000_000), burn_basis_points: burn_bps } } };
            let (genesis, committee) = config.bootstrap()?;
            fs::create_dir_all(&out)?;
            let document = PublicGenesis::new(config)?;
            write_new(&out.join("genesis.json"), serde_json::to_string_pretty(&document)?.as_bytes(), false)?;
            for (index, key) in keys.iter().enumerate() { write_new(&out.join(format!("validator-{index}.key")), &key.to_bytes(), true)?; }
            write_new(&out.join("faucet.key"), &faucet.to_bytes(), true)?;
            print(serde_json::json!({"profile":"laboratory test NXS", "genesis":genesis.hash().to_hex(),
                "network_domain":committee.network_domain().to_hex(), "faucet":faucet.address().to_hex(),
                "validators":keys.iter().map(|key| key.address().to_hex()).collect::<Vec<_>>(),
                "public_file":out.join("genesis.json").to_string_lossy(), "secret_files":"validator-*.key and faucet.key; unencrypted test keys"}))
        }
        Command::Run { genesis, data_dir, key, listen, peer, poll_ms, run_for_seconds } => {
            let config = load_config(&genesis)?;
            let key = key.as_deref().map(load_key).transpose()?;
            let runtime = RuntimeConfig { peers: peer, poll_ms, io_timeout_ms: 5000 }; runtime.validate()?;
            let listener = tokio::net::TcpListener::bind(listen).await?;
            let existing = BftNode::storage_exists(&data_dir)?;
            let node = if existing { BftNode::open(&data_dir, config, key)? } else { BftNode::create(&data_dir, config, key)? };
            print(serde_json::json!({"listening":listener.local_addr()?.to_string(), "height":node.height().0,
                "network_domain":node.network_domain().to_hex()}))?;
            let (stop, shutdown) = tokio::sync::watch::channel(false);
            let worker = tokio::spawn(async move {
                if let Some(seconds) = run_for_seconds { tokio::time::sleep(Duration::from_secs(seconds)).await; }
                else { let _ = tokio::signal::ctrl_c().await; }
                let _ = stop.send(true);
            });
            let result = serve(node, runtime, listener, shutdown).await;
            worker.abort(); result?; Ok(())
        }
        Command::Status { genesis, node } => {
            let (_, committee) = load_config(&genesis)?.bootstrap()?;
            let response = exchange(node, &committee, Request::Status, Duration::from_secs(10)).await?;
            let validator = response.attestation.as_ref().map(|proof| proof.validator);
            let Reply::Status(status) = response.reply else { return Err("Unexpected status response".into()); };
            print(serde_json::json!({"height":status.height.0,"round":status.round,"phase":format!("{:?}",status.phase),
                "state_root":status.state_root.0.to_hex(),"pending":status.pending,
                "issued_raw":status.money.issued.0.to_string(),"burned_raw":status.money.burned.0.to_string(),
                "supply_raw":status.money.supply()?.0.to_string(),"attested_by_validator":validator}))
        }
        Command::Account { genesis, node, address: text } => {
            let (_, committee) = load_config(&genesis)?.bootstrap()?;
            let address = address(&text)?;
            let response = exchange(node, &committee, Request::Account(address), Duration::from_secs(10)).await?;
            let validator = response.attestation.as_ref().map(|proof| proof.validator);
            let Reply::Account { height, account } = response.reply else { return Err("Unexpected account response".into()); };
            let account = account.unwrap_or_default();
            print(serde_json::json!({"address":address.to_hex(),"height":height.0,"balance_raw":account.balance.0.to_string(),
                "balance":account.balance.to_string(),"nonce":account.nonce.0,"attested_by_validator":validator}))
        }
        Command::Transfer { genesis, node, key, to, amount: text, gas_limit } => {
            let config = load_config(&genesis)?;
            let (_, committee) = config.bootstrap()?;
            let key = load_key(&key)?;
            let response = exchange(node, &committee, Request::Account(key.address()), Duration::from_secs(10)).await?;
            let Reply::Account { account, .. } = response.reply else { return Err("Unexpected nonce response".into()); };
            let nonce = account.map(|account| account.nonce).unwrap_or(Nonce(0));
            let mut transaction = Transaction::transfer(config.anchor.chain_id, nonce, address(&to)?, amount(&text)?,
                gas_limit, config.monetary.policy.min_gas_price);
            transaction.network_domain = Some(committee.network_domain());
            transaction.expires_at = Some(Timestamp(Timestamp::now().0.checked_add(300_000).ok_or("Expiry overflow")?));
            let signed = key.sign_transaction(transaction)?;
            let hash = signed.hash();
            let response = exchange(node, &committee, Request::Submit(Box::new(signed)), Duration::from_secs(10)).await?;
            match response.reply {
                Reply::Submitted { hash: accepted } if accepted == hash => print(serde_json::json!({"hash":hash.to_hex(),"state":"pending"})),
                Reply::Rejected(error) => Err(error.into()), _ => Err("Unexpected submission response".into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decimal_amounts_are_exact_and_reject_ambiguous_or_overflowing_input() {
        assert_eq!(amount("1.000000000000000001").unwrap(), Amount(1_000_000_000_000_000_001));
        assert_eq!(amount("0.1").unwrap(), Amount(100_000_000_000_000_000));
        for value in ["-1", "NaN", "1e3", ".1", "1.2.3", "0.0000000000000000001", "340282366920938463463374607431768211455"] {
            assert!(amount(value).is_err(), "{value}");
        }
    }
}
