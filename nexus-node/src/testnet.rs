//! Actual TCP polling, certified catchup, bounded transaction gossip and timers.
//! The actor exclusively owns the durable BFT node; connection tasks never sign.
use crate::{BftNode, BftNodeConfig};
use nexus_anchor::bft::{Message, Phase, Timeout};
use nexus_core::{BlockHeight, Hash256, NexusError, SignedTransaction, Timestamp};
use nexus_network::testnet::{self as wire, Envelope, PeerUpdate, Reply, Request, Response, Status};
use std::{collections::{HashMap, HashSet, VecDeque}, net::{IpAddr, SocketAddr}, sync::{Arc,
    atomic::{AtomicU64, Ordering}}, time::Duration};
use tokio::{net::TcpListener, sync::{mpsc, oneshot, watch, Semaphore}, task::JoinSet, time::{Instant, MissedTickBehavior}};

const MAX_POOL: usize = 512;
const MAX_POOL_BYTES: usize = 4 * 1024 * 1024;
const MAX_TX_BYTES: usize = 256 * 1024;
const MAX_CONNECTIONS: usize = 16;
const MAX_IPS: usize = 1024;
const REQUESTS_PER_SECOND: u32 = 64;

/// JSON distribution artifact. Pins the executable protocol and computed trust
/// roots so an upgrade cannot silently reinterpret an old genesis input.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PublicGenesis {
    pub protocol_version: u32,
    pub genesis_hash: Hash256,
    pub network_domain: Hash256,
    pub committee_context: Hash256,
    pub config: BftNodeConfig,
}
impl PublicGenesis {
    pub fn new(config: BftNodeConfig) -> Result<Self, NexusError> {
        let (genesis, committee) = config.bootstrap()?;
        Ok(Self { protocol_version: nexus_core::PROTOCOL_VERSION, genesis_hash: genesis.hash(),
            network_domain: committee.network_domain(), committee_context: committee.context(), config })
    }
    pub fn validate(&self) -> Result<(), NexusError> {
        let expected = Self::new(self.config.clone())?;
        if self.protocol_version != expected.protocol_version || self.genesis_hash != expected.genesis_hash
            || self.network_domain != expected.network_domain || self.committee_context != expected.committee_context {
            return Err(NexusError::ConfigError("Public genesis protocol or trust roots differ".into()));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct RuntimeConfig { pub peers: Vec<SocketAddr>, pub poll_ms: u64, pub io_timeout_ms: u64 }
impl RuntimeConfig {
    pub fn validate(&self) -> Result<(), NexusError> {
        if self.peers.len() > 64 || !(100..=30_000).contains(&self.poll_ms)
            || !(500..=30_000).contains(&self.io_timeout_ms) {
            return Err(NexusError::ConfigError("Invalid testnet peer/poll/deadline limits".into()));
        }
        let unique: HashSet<_> = self.peers.iter().collect();
        if unique.len() != self.peers.len() { return Err(NexusError::ConfigError("Duplicate bootstrap peer".into())); }
        Ok(())
    }
}

enum Event {
    Query(Envelope, oneshot::Sender<Response>),
    Peer(PeerUpdate),
}
struct Pool { entries: VecDeque<(Hash256, SignedTransaction, usize)>, bytes: usize, cursor: usize }
impl Pool {
    fn new() -> Self { Self { entries: VecDeque::new(), bytes: 0, cursor: 0 } }
    fn insert(&mut self, node: &BftNode, tx: SignedTransaction) -> Result<Hash256, NexusError> {
        let size = wire::encode(&tx)?.len();
        if size > MAX_TX_BYTES { return Err(NexusError::InvalidTransaction("Submission exceeds testnet byte limit".into())); }
        let hash = tx.hash();
        if self.entries.iter().any(|entry| entry.0 == hash) { return Ok(hash); }
        if self.entries.len() >= MAX_POOL || size > MAX_POOL_BYTES.saturating_sub(self.bytes) {
            return Err(NexusError::InvalidTransaction("Testnet pending pool is full".into()));
        }
        if self.entries.iter().any(|entry| entry.1.sender == tx.sender && entry.1.transaction.nonce == tx.transaction.nonce) {
            return Err(NexusError::InvalidTransaction("A transaction with this sender/nonce is already pending".into()));
        }
        node.validate_transaction(&tx, Timestamp::now())?;
        self.bytes += size;
        self.entries.push_back((hash, tx, size));
        Ok(hash)
    }
    fn prune(&mut self, node: &BftNode) {
        self.entries.retain(|entry| node.validate_transaction(&entry.1, Timestamp::now()).is_ok());
        self.bytes = self.entries.iter().map(|entry| entry.2).sum();
    }
    fn gossip(&mut self) -> Vec<SignedTransaction> {
        let mut output = Vec::new();
        let mut bytes = 0;
        for _ in 0..self.entries.len().min(16) {
            let index = self.cursor % self.entries.len(); self.cursor = self.cursor.wrapping_add(1);
            let entry = &self.entries[index];
            if bytes + entry.2 > 1024 * 1024 { break; }
            bytes += entry.2; output.push(entry.1.clone());
        }
        output
    }
    fn candidate(&self, gas_limit: u64) -> Vec<SignedTransaction> {
        let mut gas = 0u64; let mut bytes = 1024; let mut output = Vec::new();
        for (_, tx, size) in &self.entries {
            if output.len() >= 16 { break; }
            if tx.transaction.gas_limit > gas_limit.saturating_sub(gas)
                || *size > nexus_core::MAX_BLOCK_SIZE.saturating_sub(bytes) { continue; }
            gas += tx.transaction.gas_limit; bytes += size; output.push(tx.clone());
        }
        output
    }
}

fn message_height(message: &Message) -> Option<BlockHeight> {
    Some(match message {
        Message::Proposal(proposal) => proposal.body.height,
        Message::Vote(vote) => vote.height,
        Message::RoundStart(start) => start.height,
        Message::Commit(commit) => commit.block().height(),
        Message::RoundCatchup(starts) => starts.first()?.height,
    })
}

async fn listen(listener: TcpListener, events: mpsc::Sender<Event>, deadline: Duration, mut shutdown: watch::Receiver<bool>) {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut tasks = JoinSet::new();
    let mut ips: HashMap<IpAddr, (Instant, u32)> = HashMap::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tasks.join_next(), if !tasks.is_empty() => (),
            connection = listener.accept() => {
                let Ok((mut stream, address)) = connection else { continue; };
                let now = Instant::now();
                ips.retain(|_, (start, _)| now.duration_since(*start) < Duration::from_secs(2));
                if ips.len() >= MAX_IPS && !ips.contains_key(&address.ip()) { continue; }
                let budget = ips.entry(address.ip()).or_insert((now, 0));
                if now.duration_since(budget.0) >= Duration::from_secs(1) { *budget = (now, 0); }
                if budget.1 >= REQUESTS_PER_SECOND { continue; } budget.1 += 1;
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                let events = events.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = tokio::time::timeout(deadline, async {
                        let request: Envelope = wire::read_frame(&mut stream).await?;
                        let (send, receive) = oneshot::channel();
                        events.try_send(Event::Query(request, send)).map_err(|_| NexusError::NetworkError("Request queue is full".into()))?;
                        let response = receive.await.map_err(|_| NexusError::NetworkError("Node stopped".into()))?;
                        wire::write_frame(&mut stream, &response).await
                    }).await;
                });
            }
        }
    }
    tasks.abort_all();
}

fn reply(node: &BftNode, pool: &mut Pool, request: &Request) -> Reply {
    match request {
        Request::Poll { next } => Reply::Poll(PeerUpdate { height: node.height(), commit: node.commit_at(*next),
            messages: node.retransmit(), transactions: pool.gossip() }),
        Request::Status => Reply::Status(Status { genesis: node.genesis(), height: node.height(), round: node.consensus_state().round(),
            phase: node.consensus_state().phase(), state_root: node.state_root(), money: node.monetary_counters(),
            pending: pool.entries.len(), tip: node.commit_at(node.height()) }),
        Request::Account(address) => Reply::Account { height: node.height(), account: node.account(address) },
        Request::Commit(height) => Reply::Commit(node.commit_at(*height)),
        Request::Submit(_) => unreachable!(),
    }
}

/// Growing phase timeout; an overflow is an explicit configuration/runtime error.
fn timeout_ms(base: u64, round: u32) -> Result<u64, NexusError> {
    base.checked_mul(u64::from(round) + 1)
        .ok_or_else(|| NexusError::ConfigError("Consensus timeout duration overflow".into()))
}

pub async fn serve(mut node: BftNode, config: RuntimeConfig, listener: TcpListener,
    mut shutdown: watch::Receiver<bool>) -> Result<(), NexusError> {
    config.validate()?;
    let timing = node.consensus_parameters();
    let block_gas = node.block_gas_limit();
    let committee = node.committee().clone();
    let (send, mut receive) = mpsc::channel(64);
    let next = Arc::new(AtomicU64::new(node.consensus_state().height().0));
    let deadline = Duration::from_millis(config.io_timeout_ms);
    let mut tasks = JoinSet::new();
    tasks.spawn(listen(listener, send.clone(), deadline, shutdown.clone()));
    for address in &config.peers {
        let address = *address; let committee = committee.clone(); let send = send.clone();
        let next = next.clone(); let mut stop = shutdown.clone(); let poll_ms = config.poll_ms;
        tasks.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(poll_ms));
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    _ = interval.tick() => {
                        let request = Request::Poll { next: BlockHeight(next.load(Ordering::Relaxed)) };
                        if let Ok(response) = wire::exchange(address, &committee, request, deadline).await {
                            if let Reply::Poll(update) = response.reply { let _ = send.try_send(Event::Peer(update)); }
                        }
                    }
                }
            }
        });
    }
    let mut pool = Pool::new();
    let mut seen = HashSet::new(); let mut seen_order = VecDeque::new();
    let mut last_height = node.height(); let mut height_started = Instant::now();
    let mut timer: Option<(Timeout, Instant)> = None;
    let mut tick = tokio::time::interval(Duration::from_millis(25));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            event = receive.recv() => {
                match event {
                    None => break,
                    Some(Event::Query(request, response)) => {
                        if request.context != committee.context() { continue; }
                        let body = match &request.request {
                            Request::Submit(tx) => match pool.insert(&node, (**tx).clone()) {
                                Ok(hash) => Reply::Submitted { hash }, Err(error) => Reply::Rejected(error.to_string()),
                            },
                            other => reply(&node, &mut pool, other),
                        };
                        let request_hash = request.request_hash()?;
                        let body_hash = Hash256::hash(&wire::encode(&body)?);
                        let attestation = node.attest_query(request.nonce, request_hash, body_hash)?;
                        let _ = response.send(Response { context: committee.context(), nonce: request.nonce, reply: body, attestation });
                    }
                    Some(Event::Peer(update)) => {
                        if let Some(commit) = update.commit {
                            if commit.block().height() == node.consensus_state().height() {
                                if let Err(error) = node.receive(Message::Commit(Box::new(commit)), Timestamp::now()).await {
                                    tracing::debug!(%error, "Rejected peer commit");
                                }
                            }
                        }
                        for message in update.messages {
                            if message_height(&message) != Some(node.consensus_state().height()) { continue; }
                            let hash = Hash256::hash(&wire::encode(&message)?);
                            if seen.contains(&hash) { continue; }
                            match node.receive(message, Timestamp::now()).await {
                                Ok(_) => {
                                    seen.insert(hash); seen_order.push_back(hash);
                                    if seen_order.len() > 4096 { seen.remove(&seen_order.pop_front().unwrap()); }
                                }
                                Err(error) => tracing::debug!(%error, "Rejected peer message"),
                            }
                        }
                        for tx in update.transactions { let _ = pool.insert(&node, tx); }
                    }
                }
            }
            _ = tick.tick() => {
                let now = Instant::now();
                if node.height() != last_height {
                    last_height = node.height(); height_started = now; pool.prune(&node);
                }
                if node.is_proposer() && (node.consensus_state().round() > 0
                    || now.duration_since(height_started) >= Duration::from_millis(timing.block_time_ms)) {
                    pool.prune(&node);
                    if let Err(error) = node.propose(pool.candidate(block_gas), Timestamp::now()).await {
                        tracing::warn!(%error, "Could not propose testnet block");
                    }
                }
                let eligible = node.timeout_ready();
                if timer.as_ref().map(|entry| entry.0) != eligible {
                    timer = if let Some(token) = eligible {
                        let base = match token.phase { Phase::Propose => timing.proposal_timeout_ms,
                            Phase::Prevote => timing.prevote_timeout_ms, Phase::Precommit => timing.precommit_timeout_ms };
                        let mut delay = timeout_ms(base, token.round)?;
                        if token.phase == Phase::Propose && token.round == 0 {
                            let remaining = Duration::from_millis(timing.block_time_ms).saturating_sub(now.duration_since(height_started));
                            delay = delay.checked_add(remaining.as_millis() as u64)
                                .ok_or_else(|| NexusError::ConfigError("Proposal delay overflow".into()))?;
                        }
                        Some((token, now.checked_add(Duration::from_millis(delay))
                            .ok_or_else(|| NexusError::ConfigError("Timer exceeds platform instant range".into()))?))
                    } else { None };
                }
                if let Some((token, deadline)) = timer {
                    if now >= deadline {
                        if let Err(error) = node.timeout(token).await { tracing::warn!(%error, "Consensus timeout failed"); }
                        timer = None;
                    }
                }
            }
        }
        next.store(node.consensus_state().height().0, Ordering::Relaxed);
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_timeouts_grow_and_overflow_is_an_error() {
        assert_eq!(timeout_ms(1000, 0).unwrap(), 1000);
        assert_eq!(timeout_ms(1000, 5).unwrap(), 6000);
        assert_eq!(timeout_ms(1000, u32::MAX).unwrap(), 4_294_967_296_000);
        assert!(timeout_ms(u64::MAX, 1).is_err());
    }
    #[test]
    fn public_genesis_pins_protocol_and_trust_roots() {
        let keys: Vec<_> = (1..=4).map(|seed| nexus_crypto::DilithiumKeypair::from_seed(&[seed; 32],
            nexus_core::SignatureScheme::Dilithium3).unwrap()).collect();
        let mut anchor = nexus_anchor::AnchorChainConfig { block_reward: nexus_core::Amount::ZERO,
            fee_percentage: 0, ..Default::default() }; anchor.consensus.committee_size = 4;
        let config = BftNodeConfig { anchor, proposal_future_ms: 30_000,
            validators: keys.iter().map(|key| key.public_key().clone()).collect(),
            monetary: nexus_anchor::MonetaryGenesis { deployment: Hash256::new([1; 32]), allocations: vec![],
                policy: nexus_anchor::MonetaryPolicy { max_issued: nexus_core::Amount::from_units(2_000_000), initial_block_reward: nexus_core::Amount(1),
                    halving_interval: 100, min_gas_price: nexus_core::Amount(1), burn_basis_points: 2500 } } };
        let document = PublicGenesis::new(config).unwrap(); document.validate().unwrap();
        let decoded: PublicGenesis = serde_json::from_str(&serde_json::to_string(&document).unwrap()).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded.config.monetary.policy.max_issued, document.config.monetary.policy.max_issued);
        for case in 0..4 {
            let mut wrong = document.clone();
            match case { 0 => wrong.protocol_version -= 1, 1 => wrong.genesis_hash = Hash256::ZERO,
                2 => wrong.network_domain = Hash256::ZERO, _ => wrong.committee_context = Hash256::ZERO }
            assert!(wrong.validate().is_err());
        }
    }
}
