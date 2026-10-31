//! Testnet durable con comité fijo y transporte separado.
//! Persiste cada entrada y su salida firmada exacta antes de exponerla.
use nexus_anchor::{bft::{BftState, CommittedBlock, Committee, ConsensusSigner, Message, RecordedSigner, Timeout},
    AnchorChain, AnchorChainConfig, MonetaryCounters, MonetaryGenesis};
use nexus_core::{checkpoint::{decode, encode}, journal::JournalStore, AccountState, Address, Block,
    BlockHeight, Hash256, NexusError, SignedTransaction, StateRoot, Timestamp};
use nexus_crypto::{DilithiumKeypair, DilithiumPublicKey};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Serialize, Deserialize)]
pub struct BftNodeConfig {
    pub anchor: AnchorChainConfig,
    /// Input deployment nonce/policy/allocations. The actual monetary deployment
    /// is derived from this entire domain AND the canonical validator keys.
    pub monetary: MonetaryGenesis,
    pub validators: Vec<DilithiumPublicKey>,
    pub proposal_future_ms: u64,
}

impl BftNodeConfig {
    pub fn bootstrap(&self) -> Result<(Block, Committee), NexusError> {
        let config = self.canonical()?;
        let (ledger, committee, _) = config.build()?;
        Ok((ledger.genesis().clone(), committee))
    }
    fn canonical(&self) -> Result<Self, NexusError> {
        if self.proposal_future_ms == 0 || self.proposal_future_ms > 300_000
            || self.anchor.consensus.committee_size != 4 || self.anchor.consensus.block_time_ms == 0
            || (self.anchor.consensus.bft_threshold != 0.667 && self.anchor.consensus.bft_threshold != 2.0 / 3.0)
            || self.anchor.consensus.proposal_timeout_ms == 0
            || self.anchor.consensus.prevote_timeout_ms == 0 || self.anchor.consensus.precommit_timeout_ms == 0 {
            return Err(NexusError::ConfigError("Invalid testnet clock/timeout policy".into()));
        }
        let mut config = self.clone();
        config.validators = Committee::canonical_keys(config.validators)?;
        config.monetary.allocations.sort_by_key(|entry| entry.0.0);
        config.monetary.network_domain(&config.anchor)?;
        Ok(config)
    }
    fn build(&self) -> Result<(AnchorChain, Committee, MonetaryGenesis), NexusError> {
        let base = self.monetary.network_domain(&self.anchor)?;
        let mut monetary = self.monetary.clone();
        monetary.deployment = Hash256::hash(&encode(&(b"NEXUS_BOOTSTRAP_GENESIS_V1".as_slice(),
            base, &self.validators, self.proposal_future_ms))?);
        let ledger = AnchorChain::new_monetary(self.anchor.clone(), monetary.clone())?;
        let committee = Committee::new(ledger.genesis().hash(), ledger.network_domain().unwrap(), self.validators.clone())?;
        Ok((ledger, committee, monetary))
    }
}

#[derive(Clone, Serialize, Deserialize)]
enum Input {
    Receive { message: Message, at: Timestamp },
    Propose { candidate: Option<Box<Block>>, at: Timestamp },
    Timeout(Timeout),
}
#[derive(Serialize, Deserialize)]
enum Entry {
    Genesis { version: u32, protocol: u32, config: BftNodeConfig, identity: Option<Address>,
        output: Vec<Message>, fingerprint: Hash256, ledger_root: StateRoot },
    Change { input: Input, output: Vec<Message>, fingerprint: Hash256, ledger_root: StateRoot },
}
struct Effects { state: BftState, output: Vec<Message>, commit: Option<CommittedBlock> }
fn fingerprint(state: &BftState) -> Result<Hash256, NexusError> { Ok(Hash256::hash(&encode(state)?)) }

pub struct BftNode {
    store: JournalStore,
    config: BftNodeConfig,
    key: Option<DilithiumKeypair>,
    committee: Committee,
    ledger: AnchorChain,
    state: BftState,
    commits: Vec<CommittedBlock>,
    poisoned: bool,
}

impl BftNode {
    /// None selecciona un observador que nunca firma mensajes de consenso.
    pub fn create(directory: &Path, config: BftNodeConfig, key: Option<DilithiumKeypair>) -> Result<Self, NexusError> {
        let config = config.canonical()?;
        let (ledger, committee, _) = config.build()?;
        let mut state = BftState::new(&committee, key.as_ref().map(DilithiumKeypair::address),
            BlockHeight(1), ledger.genesis().hash())?;
        let output = state.activate(&committee, key.as_ref().map(|key| key as &dyn ConsensusSigner))?;
        state.validate_restored(&committee, key.as_ref().map(DilithiumKeypair::address), BlockHeight(1),
            ledger.genesis().hash(), |block| ledger.validate_candidate(block))?;
        let entry = Entry::Genesis { version: 2, protocol: nexus_core::PROTOCOL_VERSION, config: config.clone(),
            identity: key.as_ref().map(DilithiumKeypair::address), output, fingerprint: fingerprint(&state)?, ledger_root: ledger.state_root() };
        let mut store = JournalStore::create(directory)?;
        store.commit(&encode(&entry)?)?;
        Ok(Self { store, config, key, committee, ledger, state, commits: Vec::new(), poisoned: false })
    }

    pub fn open(directory: &Path, config: BftNodeConfig, key: Option<DilithiumKeypair>) -> Result<Self, NexusError> {
        let config = config.canonical()?;
        let (ledger, committee, _) = config.build()?;
        let identity = key.as_ref().map(DilithiumKeypair::address);
        let mut state = BftState::new(&committee, identity, BlockHeight(1), ledger.genesis().hash())?;
        let mut commits = Vec::new();
        let store = JournalStore::open(directory, |sequence, bytes|
            Self::recover(&config, &committee, identity, &ledger, &mut state, &mut commits, sequence, bytes))?;
        state.validate_restored(&committee, identity, BlockHeight(ledger.height().0.checked_add(1)
            .ok_or_else(|| NexusError::StateError("Consensus height exhausted".into()))?),
            ledger.latest_block().unwrap().hash(), |block| ledger.validate_candidate(block))?;
        Ok(Self { store, config, key, committee, ledger, state, commits, poisoned: false })
    }

    pub fn storage_exists(directory: &Path) -> Result<bool, NexusError> { JournalStore::exists(directory) }
    fn ready(&self) -> Result<(), NexusError> {
        if self.poisoned { return Err(NexusError::StateError("BFT node requires journal recovery".into())); }
        Ok(())
    }

    fn run_input(state: &BftState, committee: &Committee, signer: Option<&dyn ConsensusSigner>,
        ledger: &AnchorChain, future: u64, input: &Input) -> Result<Effects, NexusError> {
        let mut state = state.clone();
        let mut output = match input {
            Input::Receive { message, at } => {
                let live = !matches!(message, Message::Commit(_));
                state.receive(committee, signer, message.clone(), |block|
                    if live { Self::validate_live(ledger, block, *at, future) } else { ledger.validate_candidate(block) })?
            }
            Input::Propose { candidate, at } => state.propose(committee, signer.ok_or(NexusError::NotValidator)?,
                candidate.as_ref().map(|block| (**block).clone()), |block| Self::validate_live(ledger, block, *at, future))?,
            Input::Timeout(token) => state.timeout(committee, signer, *token)?,
        };
        let commit = state.decision().cloned();
        if let Some(commit) = &commit {
            commit.verify(committee)?;
            ledger.validate_candidate(commit.block())?;
            if !output.iter().any(|message| matches!(message, Message::Commit(_))) {
                output.push(Message::Commit(Box::new(commit.clone())));
            }
            output.extend(state.advance(committee, signer)?);
        }
        Ok(Effects { state, output, commit })
    }

    fn recover(config: &BftNodeConfig, committee: &Committee, identity: Option<Address>, ledger: &AnchorChain,
        state: &mut BftState, commits: &mut Vec<CommittedBlock>, sequence: u64, bytes: &[u8]) -> Result<(), NexusError> {
        let entry: Entry = decode(bytes)?;
        let (output, expected, root) = match &entry {
            Entry::Genesis { version, protocol, config: stored, identity: owner, output, fingerprint, ledger_root } => {
                if sequence != 1 || *version != 2 || *protocol != nexus_core::PROTOCOL_VERSION || *owner != identity
                    || encode(stored)? != encode(config)? {
                    return Err(NexusError::ConfigError("Journal genesis, identity or protocol differs".into()));
                }
                (output, fingerprint, ledger_root)
            }
            Entry::Change { output, fingerprint, ledger_root, .. } => {
                if sequence == 1 { return Err(NexusError::StateError("Journal is missing its genesis record".into())); }
                (output, fingerprint, ledger_root)
            }
        };
        let recorded = identity.map(|owner| RecordedSigner::new(committee, owner, output)).transpose()?;
        let signer = recorded.as_ref().map(|signer| signer as &dyn ConsensusSigner);
        let effects = match &entry {
            Entry::Genesis { .. } => {
                let mut initial = state.clone();
                let generated = initial.activate(committee, signer)?;
                Effects { state: initial, output: generated, commit: None }
            }
            Entry::Change { input, .. } => Self::run_input(state, committee, signer, ledger, config.proposal_future_ms, input)?,
        };
        if let Some(recorded) = &recorded { recorded.finish()?; }
        let expected_root = effects.commit.as_ref().map(|commit| StateRoot(commit.block().header.state_root))
            .unwrap_or_else(|| ledger.state_root());
        if encode(&effects.output)? != encode(output)? || fingerprint(&effects.state)? != *expected || expected_root != *root {
            return Err(NexusError::StateError("Journal output or derived state differs from replay".into()));
        }
        if let Some(commit) = effects.commit {
            ledger.process_block_now(commit.block().clone())?;
            commits.push(commit);
        }
        *state = effects.state;
        Ok(())
    }

    async fn transition(&mut self, input: Input) -> Result<Vec<Message>, NexusError> {
        self.ready()?;
        let effects = Self::run_input(&self.state, &self.committee,
            self.key.as_ref().map(|key| key as &dyn ConsensusSigner), &self.ledger, self.config.proposal_future_ms, &input)?;
        let next = fingerprint(&effects.state)?;
        if next == fingerprint(&self.state)? && effects.commit.is_none() && effects.output.is_empty() { return Ok(Vec::new()); }
        if let Some(key) = &self.key { RecordedSigner::new(&self.committee, key.address(), &effects.output)?; }
        let root = effects.commit.as_ref().map(|commit| StateRoot(commit.block().header.state_root)).unwrap_or_else(|| self.state_root());
        let record = Entry::Change { input, output: effects.output.clone(), fingerprint: next, ledger_root: root };
        if let Err(error) = self.store.commit(&encode(&record)?) {
            // A post-rename sync failure leaves a visible decision in the journal.
            // Do not sign again from the old in-memory state; require exact replay.
            self.poisoned = self.store.requires_recovery();
            return Err(error);
        }
        if let Some(commit) = effects.commit {
            if let Err(error) = self.ledger.process_block_now(commit.block().clone()) {
                self.poisoned = true;
                return Err(NexusError::StateError(format!("Durable decision requires journal recovery: {error}")));
            }
            self.commits.push(commit);
        }
        self.state = effects.state;
        Ok(effects.output)
    }

    fn validate_live(ledger: &AnchorChain, block: &Block, now: Timestamp, future_ms: u64) -> Result<(), NexusError> {
        let latest = now.0.checked_add(future_ms).unwrap_or(u64::MAX);
        if block.header.timestamp.0 > latest {
            return Err(NexusError::InvalidBlockTimestamp);
        }
        ledger.validate_candidate(block)
    }

    pub async fn receive(&mut self, message: Message, now: Timestamp) -> Result<Vec<Message>, NexusError> {
        self.transition(Input::Receive { message, at: now }).await
    }
    pub async fn propose(&mut self, transactions: Vec<SignedTransaction>, now: Timestamp) -> Result<Vec<Message>, NexusError> {
        self.ready()?;
        let key = self.key.as_ref().ok_or(NexusError::NotValidator)?;
        if !self.state.is_proposer(&self.committee) { return Err(NexusError::NotValidator); }
        let candidate = if self.state.preferred_block().is_some() { None } else {
            let timestamp = now.max(self.ledger.latest_block().unwrap().header.timestamp);
            Some(Box::new(self.ledger.prepare_block_at(transactions, key.address(), timestamp)?))
        };
        self.transition(Input::Propose { candidate, at: now }).await
    }
    pub async fn timeout(&mut self, token: Timeout) -> Result<Vec<Message>, NexusError> {
        self.transition(Input::Timeout(token)).await
    }

    pub fn timeout_ready(&self) -> Option<Timeout> { self.state.timeout_ready() }
    pub fn consensus_parameters(&self) -> nexus_anchor::ConsensusConfig { self.config.anchor.consensus.clone() }
    pub fn block_gas_limit(&self) -> u64 { self.config.anchor.block_gas_limit }
    pub fn is_proposer(&self) -> bool { self.state.is_proposer(&self.committee) }
    pub fn committee(&self) -> &Committee { &self.committee }
    pub fn consensus_state(&self) -> &BftState { &self.state }
    pub fn height(&self) -> BlockHeight { self.ledger.height() }
    pub fn state_root(&self) -> StateRoot { self.ledger.state_root() }
    pub fn network_domain(&self) -> Hash256 { self.ledger.network_domain().unwrap() }
    pub fn genesis(&self) -> Block { self.ledger.genesis().clone() }
    pub fn account(&self, address: &Address) -> Option<AccountState> { self.ledger.get_account(address) }
    pub fn monetary_counters(&self) -> MonetaryCounters { self.ledger.monetary_counters().unwrap() }
    pub fn validate_transaction(&self, tx: &SignedTransaction, now: Timestamp) -> Result<(), NexusError> {
        self.ready()?;
        let proposer = self.committee.member(self.committee.proposer(self.state.height(), self.state.round()))?;
        let timestamp = now.max(self.ledger.latest_block().unwrap().header.timestamp);
        self.ledger.prepare_block_at(vec![tx.clone()], proposer, timestamp).map(|_| ())
    }
    pub fn attest_query(&self, nonce: Hash256, request: Hash256, reply: Hash256)
        -> Result<Option<nexus_network::testnet::QueryAttestation>, NexusError> {
        self.ready()?;
        self.key.as_ref().map(|key| nexus_network::testnet::QueryAttestation::sign(
            &self.committee, nonce, request, reply, key)).transpose()
    }
    pub fn generation(&self) -> u64 { self.store.sequence() }
    pub fn commit_at(&self, height: BlockHeight) -> Option<CommittedBlock> {
        height.0.checked_sub(1).and_then(|index| usize::try_from(index).ok()).and_then(|index| self.commits.get(index)).cloned()
    }
    pub fn retransmit(&self) -> Vec<Message> {
        let mut messages = self.state.local_messages();
        if let Some(commit) = self.commits.last() { messages.push(Message::Commit(Box::new(commit.clone()))); }
        messages
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_anchor::{bft::{block_id, Phase, Vote, VoteCertificate}, MonetaryPolicy};
    use nexus_core::{Amount, SignatureScheme};

    fn setup() -> (BftNodeConfig, Vec<DilithiumKeypair>, std::path::PathBuf) {
        let mut keys: Vec<_> = (1..=4).map(|seed|
            DilithiumKeypair::from_seed(&[seed; 32], SignatureScheme::Dilithium3).unwrap()).collect();
        keys.sort_by_key(|key| key.address().0);
        let mut anchor = AnchorChainConfig { block_reward: Amount::ZERO, fee_percentage: 0, ..Default::default() };
        anchor.consensus.committee_size = 4;
        let config = BftNodeConfig { anchor, proposal_future_ms: 30_000,
            validators: keys.iter().map(|key| key.public_key().clone()).collect(),
            monetary: MonetaryGenesis { deployment: Hash256::new([1; 32]), allocations: vec![],
                policy: MonetaryPolicy { max_issued: Amount(100), initial_block_reward: Amount(10),
                    halving_interval: 100, min_gas_price: Amount(1), burn_basis_points: 2500 } } };
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/bft-private-tests")
            .join(format!("{}-{}", std::process::id(), Timestamp::now().0));
        (config, keys, base)
    }

    fn records(path: &Path) -> Vec<Vec<u8>> {
        let mut records = Vec::new();
        let store = JournalStore::open(path, |_, bytes| { records.push(bytes.to_vec()); Ok(()) }).unwrap();
        drop(store);
        records
    }
    fn write_records(path: &Path, records: &[Vec<u8>]) {
        let mut store = JournalStore::create(path).unwrap();
        for bytes in records { store.commit(bytes).unwrap(); }
    }
    fn certified(node: &BftNode, keys: &[DilithiumKeypair], height: u64) -> CommittedBlock {
        let height = BlockHeight(height);
        let leader = node.committee.proposer(height, 0) as usize;
        let block = node.ledger.prepare_block_at(vec![], keys[leader].address(), Timestamp(height.0)).unwrap();
        let proposal = nexus_anchor::bft::Proposal::sign(&node.committee, height, 0, block, None, &keys[leader]).unwrap();
        let value = block_id(&proposal.body.block).unwrap();
        let certificate = VoteCertificate { height, round: 0, phase: Phase::Precommit, value,
            votes: keys.iter().take(3).map(|key|
                Vote::sign(&node.committee, height, 0, Phase::Precommit, Some(value), key).unwrap()).collect() };
        CommittedBlock { proposal, certificate }
    }

    #[tokio::test]
    async fn replay_preserves_exact_signatures_and_rejects_missing_reordered_or_extra_output() {
        let (config, keys, base) = setup();
        let path = base.join("proposer");
        let mut node = BftNode::create(&path, config.clone(), Some(keys[1].clone())).unwrap();
        node.propose(vec![], Timestamp(1)).await.unwrap();
        let expected = encode(&node.retransmit()).unwrap();
        drop(node);
        let original = records(&path);
        for variant in 0..4 {
            let mut changed = original.clone();
            let mut entry: Entry = decode(&changed[1]).unwrap();
            if let Entry::Change { output, fingerprint, .. } = &mut entry {
                match variant {
                    0 => { output.pop(); }
                    1 => output.reverse(),
                    2 => output.push(output.last().unwrap().clone()),
                    _ => *fingerprint = Hash256::ZERO,
                }
            } else { panic!("Falta el registro de propuesta"); }
            changed[1] = encode(&entry).unwrap();
            let fork = base.join(format!("corrupt-{variant}"));
            write_records(&fork, &changed);
            assert!(BftNode::open(&fork, config.clone(), Some(keys[1].clone())).is_err());
        }
        let recovered = BftNode::open(&path, config, Some(keys[1].clone())).unwrap();
        assert_eq!(encode(&recovered.retransmit()).unwrap(), expected);
        assert_eq!(recovered.state.phase(), Phase::Prevote);
    }

    #[tokio::test]
    async fn replay_rejects_a_rehashed_journal_with_an_invalid_finality_certificate() {
        let (config, keys, base) = setup();
        let path = base.join("observer");
        let mut node = BftNode::create(&path, config.clone(), None).unwrap();
        let commit = certified(&node, &keys, 1);
        node.receive(Message::Commit(Box::new(commit)), Timestamp(1)).await.unwrap();
        let root = node.state_root();
        drop(node);
        let mut changed = records(&path);
        let mut entry: Entry = decode(&changed[1]).unwrap();
        if let Entry::Change { input: Input::Receive { message: Message::Commit(commit), .. }, .. } = &mut entry {
            commit.certificate.votes[2] = commit.certificate.votes[0].clone();
        } else { panic!("Falta el certificado"); }
        changed[1] = encode(&entry).unwrap();
        let fork = base.join("bad-certificate");
        write_records(&fork, &changed);
        assert!(BftNode::open(&fork, config.clone(), None).is_err());
        assert_eq!(BftNode::open(&path, config, None).unwrap().state_root(), root);
    }

    #[tokio::test]
    async fn incremental_records_do_not_grow_with_preceding_block_history() {
        let (config, keys, base) = setup();
        let path = base.join("growth");
        let mut node = BftNode::create(&path, config.clone(), None).unwrap();
        let mut sizes = Vec::new();
        for height in 1..=24 {
            let commit = certified(&node, &keys, height);
            node.receive(Message::Commit(Box::new(commit)), Timestamp(height)).await.unwrap();
            sizes.push(std::fs::metadata(path.join(JournalStore::record_name(node.generation()))).unwrap().len());
        }
        assert_eq!(sizes[0], sizes[23]);
        assert!(sizes.iter().sum::<u64>() < 24 * 100_000);
        let root = node.state_root();
        drop(node);
        let recovered = BftNode::open(&path, config, None).unwrap();
        assert_eq!(recovered.height(), BlockHeight(24));
        assert_eq!(recovered.state_root(), root);
    }
}
