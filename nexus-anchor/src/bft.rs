//! Experimental fixed-committee, two-phase BFT for the four-validator testnet.
//! Exact quorum uses Nexus.Modelos.Quorum; round/lock rules follow the
//! Tendermint design (arXiv:1807.04938v3), with ML-DSA-65 and explicit POLs.
//! This is an implementation to test, not a formal refinement of that paper.
//! Callers MUST durably commit transitions before broadcasting returned messages.
use nexus_core::{checkpoint::encode, Address, Block, BlockHeight, Hash256, Layer,
    NexusError, SignatureScheme};
use nexus_crypto::{DilithiumKeypair, DilithiumPublicKey, DilithiumSignature};
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, collections::VecDeque};

/// El firmante activo usa la clave secreta; la recuperación suministra únicamente
/// firmas guardadas para las mismas solicitudes con separación de dominio.
pub trait ConsensusSigner {
    fn address(&self) -> Address;
    fn scheme(&self) -> SignatureScheme;
    fn sign(&self, bytes: &[u8]) -> Result<DilithiumSignature, NexusError>;
}
impl ConsensusSigner for DilithiumKeypair {
    fn address(&self) -> Address { DilithiumKeypair::address(self) }
    fn scheme(&self) -> SignatureScheme { DilithiumKeypair::scheme(self) }
    fn sign(&self, bytes: &[u8]) -> Result<DilithiumSignature, NexusError> { DilithiumKeypair::sign(self, bytes) }
}

pub const VALIDATORS: usize = 4;
pub const QUORUM: usize = 3;
pub const MAX_ROUND_AHEAD: u32 = 8;
const PAST_ROUNDS: u32 = 2;

fn failure(message: &str) -> NexusError { NexusError::ConsensusFailure(message.into()) }

#[derive(Clone, Serialize, Deserialize)]
pub struct Committee {
    genesis: Hash256,
    network_domain: Hash256,
    keys: Vec<DilithiumPublicKey>,
}

impl Committee {
    pub fn canonical_keys(mut keys: Vec<DilithiumPublicKey>) -> Result<Vec<DilithiumPublicKey>, NexusError> {
        if keys.len() != VALIDATORS { return Err(failure("Testnet requires exactly four validators")); }
        keys.sort_by_key(|key| key.to_address().0);
        for (index, key) in keys.iter().enumerate() {
            if key.scheme() != SignatureScheme::Dilithium3 || key.as_bytes().len() != 1952
                || (index > 0 && keys[index - 1].to_address() == key.to_address()) {
                return Err(failure("Committee requires distinct ML-DSA-65 keys"));
            }
        }
        Ok(keys)
    }

    pub fn new(genesis: Hash256, network_domain: Hash256, keys: Vec<DilithiumPublicKey>) -> Result<Self, NexusError> {
        if genesis == Hash256::ZERO || network_domain == Hash256::ZERO {
            return Err(failure("Missing genesis or network domain"));
        }
        debug_assert_eq!(crate::consensus::strict_quorum_threshold(VALIDATORS as u128), Some(QUORUM as u128));
        Ok(Self { genesis, network_domain, keys: Self::canonical_keys(keys)? })
    }

    pub fn context(&self) -> Hash256 {
        Hash256::hash(&encode(&(b"NEXUS_BFT_CONTEXT_V1".as_slice(), nexus_core::PROTOCOL_VERSION,
            self.genesis, self.network_domain, &self.keys)).expect("Fixed committee encoding"))
    }
    pub fn genesis(&self) -> Hash256 { self.genesis }
    pub fn network_domain(&self) -> Hash256 { self.network_domain }
    pub fn keys(&self) -> &[DilithiumPublicKey] { &self.keys }
    pub fn member(&self, index: u8) -> Result<Address, NexusError> {
        self.keys.get(index as usize).map(DilithiumPublicKey::to_address).ok_or(NexusError::NotValidator)
    }
    pub fn index(&self, address: Address) -> Result<u8, NexusError> {
        self.keys.iter().position(|key| key.to_address() == address).map(|index| index as u8)
            .ok_or(NexusError::NotValidator)
    }
    pub fn proposer(&self, height: BlockHeight, round: u32) -> u8 {
        ((u128::from(height.0) + u128::from(round)) % VALIDATORS as u128) as u8
    }
    fn verify(&self, index: u8, bytes: &[u8], signature: &[u8]) -> Result<(), NexusError> {
        let key = self.keys.get(index as usize).ok_or(NexusError::NotValidator)?;
        let signature = DilithiumSignature::from_bytes(signature.to_vec(), SignatureScheme::Dilithium3)?;
        if !key.verify(bytes, &signature)? { return Err(NexusError::InvalidValidatorSignature); }
        Ok(())
    }
    fn block_context(&self, block: &Block, height: BlockHeight, parent: Hash256) -> Result<(), NexusError> {
        block.validate_structure()?;
        if block.height() != height || block.parent_hash() != parent || block.header.layer != Layer::Anchor
            || block.header.version != nexus_core::PROTOCOL_VERSION || !block.body.signatures.is_empty() {
            return Err(failure("Invalid BFT block context"));
        }
        self.index(block.header.proposer)?;
        Ok(())
    }
}

/// Commits the full envelope, including sender/key/scheme and all body fields.
pub fn block_id(block: &Block) -> Result<Hash256, NexusError> {
    let mut bytes = b"NEXUS_BFT_BLOCK_V1".to_vec();
    bytes.extend(encode(block)?);
    Ok(Hash256::hash(&bytes))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase { Propose, Prevote, Precommit }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub context: Hash256,
    pub height: BlockHeight,
    pub round: u32,
    pub phase: Phase,
    pub value: Option<Hash256>,
    pub validator: u8,
    pub signature: Vec<u8>,
}

impl Vote {
    fn bytes(&self) -> Result<Vec<u8>, NexusError> {
        encode(&(b"NEXUS_BFT_VOTE_V1".as_slice(), self.context, self.height, self.round,
            self.phase, self.value, self.validator))
    }
    pub fn sign(committee: &Committee, height: BlockHeight, round: u32, phase: Phase,
        value: Option<Hash256>, signer: &dyn ConsensusSigner) -> Result<Self, NexusError> {
        if phase == Phase::Propose { return Err(failure("Proposal is not a voting phase")); }
        let mut vote = Self { context: committee.context(), height, round, phase, value,
            validator: committee.index(signer.address())?, signature: Vec::new() };
        if signer.scheme() != SignatureScheme::Dilithium3 { return Err(NexusError::NotValidator); }
        vote.signature = signer.sign(&vote.bytes()?)?.as_bytes().to_vec();
        Ok(vote)
    }
    pub fn verify(&self, committee: &Committee) -> Result<(), NexusError> {
        if self.context != committee.context() || self.phase == Phase::Propose || self.height == BlockHeight::GENESIS {
            return Err(failure("Invalid vote context"));
        }
        committee.verify(self.validator, &self.bytes()?, &self.signature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteCertificate {
    pub height: BlockHeight,
    pub round: u32,
    pub phase: Phase,
    pub value: Hash256,
    pub votes: Vec<Vote>,
}

impl VoteCertificate {
    pub fn verify(&self, committee: &Committee) -> Result<(), NexusError> {
        if self.votes.len() != QUORUM || self.phase == Phase::Propose {
            return Err(failure("Certificate requires three distinct votes"));
        }
        let mut previous = None;
        for vote in &self.votes {
            if vote.height != self.height || vote.round != self.round || vote.phase != self.phase
                || vote.value != Some(self.value) || previous.is_some_and(|index| index >= vote.validator) {
                return Err(failure("Noncanonical or conflicting certificate votes"));
            }
            vote.verify(committee)?;
            previous = Some(vote.validator);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalBody {
    pub context: Hash256,
    pub height: BlockHeight,
    pub round: u32,
    pub block: Block,
    /// A prior-round prevote quorum for exactly this full block.
    pub justification: Option<VoteCertificate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal { pub body: ProposalBody, pub signature: Vec<u8> }

impl Proposal {
    fn bytes(&self) -> Result<Vec<u8>, NexusError> {
        encode(&(b"NEXUS_BFT_PROPOSAL_V1".as_slice(), &self.body))
    }
    pub fn sign(committee: &Committee, height: BlockHeight, round: u32, block: Block,
        justification: Option<VoteCertificate>, signer: &dyn ConsensusSigner) -> Result<Self, NexusError> {
        if committee.index(signer.address())? != committee.proposer(height, round) {
            return Err(NexusError::NotValidator);
        }
        let mut proposal = Self { body: ProposalBody { context: committee.context(), height,
            round, block, justification }, signature: Vec::new() };
        proposal.signature = signer.sign(&proposal.bytes()?)?.as_bytes().to_vec();
        Ok(proposal)
    }
    pub fn verify(&self, committee: &Committee) -> Result<(), NexusError> {
        let body = &self.body;
        if body.context != committee.context() || body.height == BlockHeight::GENESIS {
            return Err(failure("Invalid proposal domain/height"));
        }
        body.block.validate_structure()?;
        if !body.block.body.signatures.is_empty() || body.block.height() != body.height
            || body.block.header.layer != Layer::Anchor || body.block.header.version != nexus_core::PROTOCOL_VERSION {
            return Err(failure("Invalid proposed block envelope"));
        }
        committee.index(body.block.header.proposer)?;
        committee.verify(committee.proposer(body.height, body.round), &self.bytes()?, &self.signature)?;
        if let Some(certificate) = &body.justification {
            certificate.verify(committee)?;
            if certificate.height != body.height || certificate.round >= body.round
                || certificate.phase != Phase::Prevote || certificate.value != block_id(&body.block)? {
                return Err(failure("Invalid proof of prior-round prevotes"));
            }
        } else if body.block.header.proposer != committee.member(committee.proposer(body.height, body.round))? {
            return Err(failure("Fresh block must name the current proposer"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundStart {
    pub context: Hash256, pub height: BlockHeight, pub round: u32,
    pub validator: u8, pub signature: Vec<u8>,
}
impl RoundStart {
    fn bytes(&self) -> Result<Vec<u8>, NexusError> {
        encode(&(b"NEXUS_BFT_ROUND_V1".as_slice(), self.context, self.height, self.round, self.validator))
    }
    pub fn sign(committee: &Committee, height: BlockHeight, round: u32,
        signer: &dyn ConsensusSigner) -> Result<Self, NexusError> {
        let mut start = Self { context: committee.context(), height, round,
            validator: committee.index(signer.address())?, signature: Vec::new() };
        start.signature = signer.sign(&start.bytes()?)?.as_bytes().to_vec();
        Ok(start)
    }
    pub fn verify(&self, committee: &Committee) -> Result<(), NexusError> {
        if self.context != committee.context() || self.height == BlockHeight::GENESIS {
            return Err(failure("Invalid round announcement context"));
        }
        committee.verify(self.validator, &self.bytes()?, &self.signature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommittedBlock { pub proposal: Proposal, pub certificate: VoteCertificate }
impl CommittedBlock {
    pub fn verify(&self, committee: &Committee) -> Result<(), NexusError> {
        self.proposal.verify(committee)?;
        self.certificate.verify(committee)?;
        let body = &self.proposal.body;
        if self.certificate.height != body.height || self.certificate.round != body.round
            || self.certificate.phase != Phase::Precommit || self.certificate.value != block_id(&body.block)? {
            return Err(failure("Commit certificate does not bind the proposed block"));
        }
        Ok(())
    }
    pub fn block(&self) -> &Block { &self.proposal.body.block }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Proposal(Box<Proposal>), Vote(Vote), RoundStart(RoundStart), Commit(Box<CommittedBlock>),
    /// A bounded f+1 proof lets a long-offline node catch up without allocating
    /// arbitrary future-round logs or discarding its current lock.
    RoundCatchup(Vec<RoundStart>),
}

/// Verifica la salida guardada y devuelve sus firmas solo en el orden original
/// y para los mismos bytes. No utiliza claves secretas, aleatoriedad ni genera firmas.
pub struct RecordedSigner {
    identity: Address,
    transcript: RefCell<VecDeque<(Vec<u8>, Vec<u8>)>>,
}
impl RecordedSigner {
    pub fn new(committee: &Committee, identity: Address, output: &[Message]) -> Result<Self, NexusError> {
        let index = committee.index(identity)?;
        let mut transcript = VecDeque::new();
        for message in output {
            let pair = match message {
                Message::Proposal(proposal) => {
                    proposal.verify(committee)?;
                    if committee.proposer(proposal.body.height, proposal.body.round) != index {
                        return Err(failure("Recorded proposal belongs to another signer"));
                    }
                    Some((proposal.bytes()?, proposal.signature.clone()))
                }
                Message::Vote(vote) => {
                    vote.verify(committee)?;
                    if vote.validator != index { return Err(failure("Recorded vote belongs to another signer")); }
                    Some((vote.bytes()?, vote.signature.clone()))
                }
                Message::RoundStart(start) => {
                    start.verify(committee)?;
                    if start.validator != index { return Err(failure("Recorded round belongs to another signer")); }
                    Some((start.bytes()?, start.signature.clone()))
                }
                Message::Commit(commit) => { commit.verify(committee)?; None }
                Message::RoundCatchup(_) => return Err(failure("Unexpected newly signed output")),
            };
            if let Some(pair) = pair { transcript.push_back(pair); }
        }
        Ok(Self { identity, transcript: RefCell::new(transcript) })
    }
    pub fn finish(&self) -> Result<(), NexusError> {
        if !self.transcript.borrow().is_empty() { return Err(failure("Unused signatures in journal record")); }
        Ok(())
    }
}
impl ConsensusSigner for RecordedSigner {
    fn address(&self) -> Address { self.identity }
    fn scheme(&self) -> SignatureScheme { SignatureScheme::Dilithium3 }
    fn sign(&self, bytes: &[u8]) -> Result<DilithiumSignature, NexusError> {
        let mut transcript = self.transcript.borrow_mut();
        let Some((expected, signature)) = transcript.front() else { return Err(failure("Recovery would require a new signature")); };
        if expected != bytes { return Err(failure("Recovery signing request differs from recorded transcript")); }
        let result = DilithiumSignature::from_bytes(signature.clone(), SignatureScheme::Dilithium3)?;
        transcript.pop_front();
        Ok(result)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timeout { pub height: BlockHeight, pub round: u32, pub phase: Phase }

#[derive(Clone, Serialize, Deserialize)]
struct RoundData {
    round: u32,
    proposal: Option<Proposal>,
    starts: [Option<RoundStart>; VALIDATORS],
    prevotes: [Option<Vote>; VALIDATORS],
    precommits: [Option<Vote>; VALIDATORS],
}
impl RoundData {
    fn new(round: u32) -> Self {
        Self { round, proposal: None, starts: std::array::from_fn(|_| None),
            prevotes: std::array::from_fn(|_| None), precommits: std::array::from_fn(|_| None) }
    }
    fn votes(&self, phase: Phase) -> &[Option<Vote>; VALIDATORS] {
        if phase == Phase::Prevote { &self.prevotes } else { &self.precommits }
    }
    fn count(&self, phase: Phase, value: Option<Option<Hash256>>) -> usize {
        self.votes(phase).iter().flatten().filter(|vote| value.is_none_or(|hash| vote.value == hash)).count()
    }
    fn certificate(&self, phase: Phase, value: Hash256) -> Option<VoteCertificate> {
        let votes: Vec<_> = self.votes(phase).iter().flatten()
            .filter(|vote| vote.value == Some(value)).take(QUORUM).cloned().collect();
        (votes.len() == QUORUM).then(|| VoteCertificate { height: votes[0].height, round: self.round, phase, value, votes })
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Prepared { block: Block, certificate: VoteCertificate }

/// Pure transition state. Production use goes through the durable node wrapper.
#[derive(Clone, Serialize, Deserialize)]
pub struct BftState {
    version: u32,
    context: Hash256,
    local: Option<u8>,
    height: BlockHeight,
    parent: Hash256,
    round: u32,
    phase: Phase,
    rounds: Vec<RoundData>,
    locked: Option<Prepared>,
    valid: Option<Prepared>,
    decision: Option<CommittedBlock>,
}

impl BftState {
    pub fn new(committee: &Committee, local: Option<Address>, height: BlockHeight, parent: Hash256) -> Result<Self, NexusError> {
        if height == BlockHeight::GENESIS { return Err(failure("Consensus starts after genesis")); }
        Ok(Self { version: 1, context: committee.context(), local: local.map(|a| committee.index(a)).transpose()?,
            height, parent, round: 0, phase: Phase::Propose, rounds: vec![RoundData::new(0)],
            locked: None, valid: None, decision: None })
    }
    pub fn height(&self) -> BlockHeight { self.height }
    pub fn round(&self) -> u32 { self.round }
    pub fn phase(&self) -> Phase { self.phase }
    pub fn decision(&self) -> Option<&CommittedBlock> { self.decision.as_ref() }
    pub fn locked_value(&self) -> Option<(u32, Hash256)> {
        self.locked.as_ref().map(|value| (value.certificate.round, value.certificate.value))
    }
    pub fn preferred_block(&self) -> Option<Block> { self.valid.as_ref().map(|value| value.block.clone()) }
    pub fn is_proposer(&self, committee: &Committee) -> bool {
        self.local == Some(committee.proposer(self.height, self.round)) && self.phase == Phase::Propose && self.decision.is_none()
    }
    fn check_signer(&self, committee: &Committee, signer: Option<&dyn ConsensusSigner>) -> Result<(), NexusError> {
        if self.context != committee.context()
            || signer.map(|key| committee.index(key.address())).transpose()? != self.local {
            return Err(failure("Consensus identity/context differs"));
        }
        Ok(())
    }
    fn data_mut(&mut self, round: u32) -> &mut RoundData {
        if let Some(index) = self.rounds.iter().position(|data| data.round == round) { return &mut self.rounds[index]; }
        self.rounds.push(RoundData::new(round));
        self.rounds.sort_by_key(|data| data.round);
        self.rounds.iter_mut().find(|data| data.round == round).unwrap()
    }
    fn current(&self) -> &RoundData { self.rounds.iter().find(|data| data.round == self.round).unwrap() }
    fn record_vote(&mut self, vote: Vote) -> Result<(), NexusError> {
        let data = self.data_mut(vote.round);
        let slot = if vote.phase == Phase::Prevote { &mut data.prevotes[vote.validator as usize] }
            else { &mut data.precommits[vote.validator as usize] };
        if slot.as_ref().is_some_and(|prior| prior.value != vote.value) { return Err(failure("Equivocating vote")); }
        if slot.is_none() { *slot = Some(vote); }
        Ok(())
    }
    fn vote(&mut self, committee: &Committee, signer: Option<&dyn ConsensusSigner>, phase: Phase,
        value: Option<Hash256>, output: &mut Vec<Message>) -> Result<(), NexusError> {
        if let Some(key) = signer {
            let vote = Vote::sign(committee, self.height, self.round, phase, value, key)?;
            self.record_vote(vote.clone())?;
            output.push(Message::Vote(vote));
        }
        self.phase = if phase == Phase::Prevote { Phase::Prevote } else { Phase::Precommit };
        Ok(())
    }
    fn enter_round(&mut self, committee: &Committee, signer: Option<&dyn ConsensusSigner>, round: u32,
        output: &mut Vec<Message>) -> Result<(), NexusError> {
        if round < self.round { return Err(failure("Cannot move consensus backwards")); }
        self.round = round;
        self.phase = Phase::Propose;
        self.rounds.retain(|data| data.round >= round.saturating_sub(PAST_ROUNDS));
        self.data_mut(round);
        if let Some(key) = signer {
            let index = self.local.unwrap() as usize;
            if self.current().starts[index].is_none() {
                let start = RoundStart::sign(committee, self.height, round, key)?;
                self.data_mut(round).starts[index] = Some(start.clone());
                output.push(Message::RoundStart(start));
            }
        }
        Ok(())
    }
    pub fn activate(&mut self, committee: &Committee, signer: Option<&dyn ConsensusSigner>) -> Result<Vec<Message>, NexusError> {
        self.check_signer(committee, signer)?;
        let mut output = Vec::new();
        // Activation cannot reset a persisted voting phase.
        if self.phase == Phase::Propose { self.enter_round(committee, signer, self.round, &mut output)?; }
        Ok(output)
    }

    fn validate_proposal(&self, proposal: &Proposal, committee: &Committee,
        validate: &impl Fn(&Block) -> Result<(), NexusError>) -> Result<(), NexusError> {
        proposal.verify(committee)?;
        committee.block_context(&proposal.body.block, self.height, self.parent)?;
        if proposal.body.height != self.height { return Err(failure("Unexpected proposal height")); }
        validate(&proposal.body.block)
    }

    fn drive(&mut self, committee: &Committee, signer: Option<&dyn ConsensusSigner>,
        output: &mut Vec<Message>) -> Result<(), NexusError> {
        loop {
            if self.decision.is_some() { return Ok(()); }
            for data in &self.rounds {
                if let Some(proposal) = &data.proposal {
                    let value = block_id(&proposal.body.block)?;
                    if let Some(certificate) = data.certificate(Phase::Precommit, value) {
                        let commit = CommittedBlock { proposal: proposal.clone(), certificate };
                        self.decision = Some(commit.clone());
                        output.push(Message::Commit(Box::new(commit)));
                        return Ok(());
                    }
                }
            }
            let proposal = self.current().proposal.clone();
            if self.phase == Phase::Propose {
                if let Some(proposal) = &proposal {
                    let value = block_id(&proposal.body.block)?;
                    let safe = self.locked.as_ref().is_none_or(|locked|
                        locked.certificate.value == value || proposal.body.justification.as_ref()
                            .is_some_and(|proof| locked.certificate.round <= proof.round));
                    self.vote(committee, signer, Phase::Prevote, safe.then_some(value), output)?;
                    continue;
                }
            }
            if self.phase != Phase::Propose {
                if let Some(proposal) = proposal {
                    let value = block_id(&proposal.body.block)?;
                    if let Some(certificate) = self.current().certificate(Phase::Prevote, value) {
                        let prepared = Prepared { block: proposal.body.block, certificate };
                        if self.valid.as_ref().is_none_or(|valid| valid.certificate.round < self.round) {
                            self.valid = Some(prepared.clone());
                        }
                        if self.phase == Phase::Prevote {
                            self.locked = Some(prepared);
                            self.vote(committee, signer, Phase::Precommit, Some(value), output)?;
                            continue;
                        }
                    }
                }
                if self.phase == Phase::Prevote && self.current().count(Phase::Prevote, Some(None)) >= QUORUM {
                    self.vote(committee, signer, Phase::Precommit, None, output)?;
                    continue;
                }
            }
            return Ok(());
        }
    }

    pub fn receive(&mut self, committee: &Committee, signer: Option<&dyn ConsensusSigner>, message: Message,
        validate: impl Fn(&Block) -> Result<(), NexusError>) -> Result<Vec<Message>, NexusError> {
        self.check_signer(committee, signer)?;
        let mut staged = self.clone();
        let mut output = Vec::new();
        if let Message::RoundCatchup(starts) = &message {
            if starts.len() != 2 { return Err(failure("Round catchup requires two announcements")); }
            for start in starts { start.verify(committee)?; }
            let first = &starts[0];
            if starts[1].height != first.height || starts[1].round != first.round
                || starts[1].validator <= first.validator {
                return Err(failure("Invalid round catchup certificate"));
            }
            if first.height < staged.height || first.round <= staged.round { return Ok(output); }
            if first.height != staged.height { return Err(failure("Round catchup has a different height")); }
            if staged.decision.is_some() { return Ok(output); }
            // Prune before creating the one certified future round.
            staged.enter_round(committee, signer, first.round, &mut output)?;
            for start in starts { staged.data_mut(first.round).starts[start.validator as usize].get_or_insert(start.clone()); }
            staged.drive(committee, signer, &mut output)?;
            *self = staged;
            return Ok(output);
        }
        if let Message::Commit(commit) = message {
            commit.verify(committee)?;
            if commit.block().height() < staged.height { return Ok(output); }
            staged.validate_proposal(&commit.proposal, committee, &validate)?;
            if staged.decision.as_ref().is_some_and(|prior| prior.certificate.value != commit.certificate.value) {
                return Err(failure("Conflicting committed values"));
            }
            staged.decision = Some(*commit);
        } else {
            let (height, round) = match &message {
                Message::Proposal(proposal) => { proposal.verify(committee)?; (proposal.body.height, proposal.body.round) }
                Message::Vote(vote) => { vote.verify(committee)?; (vote.height, vote.round) }
                Message::RoundStart(start) => { start.verify(committee)?; (start.height, start.round) }
                Message::Commit(_) | Message::RoundCatchup(_) => unreachable!(),
            };
            if height < staged.height || round < staged.round.saturating_sub(PAST_ROUNDS) { return Ok(output); }
            if height != staged.height || u64::from(round) > u64::from(staged.round) + u64::from(MAX_ROUND_AHEAD) {
                return Err(failure("Consensus message outside bounded height/round window"));
            }
            if staged.decision.is_some() { return Ok(output); }
            match message {
                Message::Proposal(proposal) => {
                    staged.validate_proposal(&proposal, committee, &validate)?;
                    let data = staged.data_mut(round);
                    if let Some(previous) = &data.proposal {
                        if block_id(&previous.body.block)? != block_id(&proposal.body.block)? {
                            return Err(failure("Equivocating proposal"));
                        }
                    } else { data.proposal = Some(*proposal); }
                }
                Message::Vote(vote) => staged.record_vote(vote)?,
                Message::RoundStart(start) => {
                    let index = start.validator as usize;
                    staged.data_mut(round).starts[index].get_or_insert(start);
                }
                Message::Commit(_) | Message::RoundCatchup(_) => unreachable!(),
            }
            if let Some(future) = staged.rounds.iter().filter(|data| data.round > staged.round
                && data.starts.iter().flatten().count() >= 2).map(|data| data.round).max() {
                staged.enter_round(committee, signer, future, &mut output)?;
            }
            staged.drive(committee, signer, &mut output)?;
        }
        *self = staged;
        Ok(output)
    }

    pub fn propose(&mut self, committee: &Committee, signer: &dyn ConsensusSigner, candidate: Option<Block>,
        validate: impl Fn(&Block) -> Result<(), NexusError>) -> Result<Vec<Message>, NexusError> {
        self.check_signer(committee, Some(signer))?;
        if !self.is_proposer(committee) { return Err(NexusError::NotValidator); }
        let (block, proof) = if let Some(valid) = &self.valid {
            (valid.block.clone(), Some(valid.certificate.clone()))
        } else { (candidate.ok_or_else(|| failure("Missing proposal candidate"))?, None) };
        let proposal = Proposal::sign(committee, self.height, self.round, block, proof, signer)?;
        let mut staged = self.clone();
        let mut output = staged.receive(committee, Some(signer), Message::Proposal(Box::new(proposal.clone())), validate)?;
        output.insert(0, Message::Proposal(Box::new(proposal)));
        *self = staged;
        Ok(output)
    }

    /// Timer durations are a runtime responsibility. Prevote/precommit timers
    /// become eligible only after a quorum has reached the respective phase.
    pub fn timeout_ready(&self) -> Option<Timeout> {
        if self.local.is_none() || self.decision.is_some() { return None; }
        let ready = match self.phase {
            Phase::Propose => true,
            Phase::Prevote => self.current().count(Phase::Prevote, None) >= QUORUM,
            Phase::Precommit => self.current().count(Phase::Precommit, None) >= QUORUM,
        };
        ready.then_some(Timeout { height: self.height, round: self.round, phase: self.phase })
    }
    pub fn timeout(&mut self, committee: &Committee, signer: Option<&dyn ConsensusSigner>, token: Timeout)
        -> Result<Vec<Message>, NexusError> {
        self.check_signer(committee, signer)?;
        if self.timeout_ready() != Some(token) { return Ok(Vec::new()); }
        let mut staged = self.clone();
        let mut output = Vec::new();
        match token.phase {
            Phase::Propose => staged.vote(committee, signer, Phase::Prevote, None, &mut output)?,
            Phase::Prevote => staged.vote(committee, signer, Phase::Precommit, None, &mut output)?,
            Phase::Precommit => staged.enter_round(committee, signer,
                staged.round.checked_add(1).ok_or_else(|| failure("Consensus rounds exhausted"))?, &mut output)?,
        }
        staged.drive(committee, signer, &mut output)?;
        *self = staged;
        Ok(output)
    }

    pub fn advance(&mut self, committee: &Committee, signer: Option<&dyn ConsensusSigner>) -> Result<Vec<Message>, NexusError> {
        self.check_signer(committee, signer)?;
        let commit = self.decision.as_ref().ok_or_else(|| failure("No decision to advance"))?;
        let height = BlockHeight(self.height.0.checked_add(1).ok_or_else(|| failure("Consensus heights exhausted"))?);
        let parent = commit.block().hash();
        let mut next = Self::new(committee, signer.map(|key| key.address()), height, parent)?;
        let output = next.activate(committee, signer)?;
        *self = next;
        Ok(output)
    }

    /// Safe retransmission of already recorded messages; no signatures are made.
    pub fn local_messages(&self) -> Vec<Message> {
        let Some(local) = self.local else { return Vec::new(); };
        let mut messages = Vec::new();
        for data in &self.rounds {
            if let Some(start) = &data.starts[local as usize] { messages.push(Message::RoundStart(start.clone())); }
            if let Some(proposal) = &data.proposal {
                // Proposer is determined by (height, round), independent of the block's original author.
                if ((u128::from(self.height.0) + u128::from(data.round)) % VALIDATORS as u128) as u8 == local {
                    messages.push(Message::Proposal(Box::new(proposal.clone())));
                }
            }
            for votes in [&data.prevotes, &data.precommits] {
                if let Some(vote) = &votes[local as usize] { messages.push(Message::Vote(vote.clone())); }
            }
        }
        let starts: Vec<_> = self.current().starts.iter().flatten().take(2).cloned().collect();
        if starts.len() == 2 { messages.push(Message::RoundCatchup(starts)); }
        messages
    }

    /// Structural/cryptographic validation of a trusted local journal. This does
    /// not protect against an owner rolling the entire journal/key back in time.
    pub fn validate_restored(&self, committee: &Committee, local: Option<Address>, height: BlockHeight,
        parent: Hash256, validate: impl Fn(&Block) -> Result<(), NexusError>) -> Result<(), NexusError> {
        if self.version != 1 || self.context != committee.context() || self.height != height || self.parent != parent
            || self.local != local.map(|address| committee.index(address)).transpose()?
            || self.decision.is_some() || self.rounds.is_empty()
            || self.rounds.len() > (MAX_ROUND_AHEAD + PAST_ROUNDS + 1) as usize {
            return Err(failure("Invalid restored consensus context"));
        }
        let mut previous = None;
        let mut current = false;
        for data in &self.rounds {
            if previous.is_some_and(|round| round >= data.round) || data.round < self.round.saturating_sub(PAST_ROUNDS)
                || u64::from(data.round) > u64::from(self.round) + u64::from(MAX_ROUND_AHEAD) {
                return Err(failure("Invalid journal round window"));
            }
            previous = Some(data.round);
            current |= data.round == self.round;
            if let Some(proposal) = &data.proposal {
                if proposal.body.round != data.round { return Err(failure("Journal proposal round mismatch")); }
                self.validate_proposal(proposal, committee, &validate)?;
            }
            for (index, start) in data.starts.iter().enumerate() {
                if let Some(start) = start {
                    start.verify(committee)?;
                    if start.height != height || start.round != data.round || start.validator as usize != index {
                        return Err(failure("Journal announcement slot mismatch"));
                    }
                }
            }
            for (phase, votes) in [(Phase::Prevote, &data.prevotes), (Phase::Precommit, &data.precommits)] {
                for (index, vote) in votes.iter().enumerate() {
                    if let Some(vote) = vote {
                        vote.verify(committee)?;
                        if vote.height != height || vote.round != data.round || vote.phase != phase || vote.validator as usize != index {
                            return Err(failure("Journal vote slot mismatch"));
                        }
                    }
                }
            }
        }
        if !current { return Err(failure("Journal missing current round")); }
        for prepared in [&self.locked, &self.valid].into_iter().flatten() {
            prepared.certificate.verify(committee)?;
            if prepared.certificate.height != height || prepared.certificate.phase != Phase::Prevote
                || prepared.certificate.round > self.round || prepared.certificate.value != block_id(&prepared.block)? {
                return Err(failure("Invalid journal lock/proof"));
            }
            committee.block_context(&prepared.block, height, parent)?;
            validate(&prepared.block)?;
        }
        if let Some(locked) = &self.locked {
            if self.valid.as_ref().is_none_or(|valid| valid.certificate.round < locked.certificate.round
                || (valid.certificate.round == locked.certificate.round && valid.certificate.value != locked.certificate.value)) {
                return Err(failure("Journal lock has no corresponding valid value"));
            }
        }
        if let Some(local) = self.local {
            let data = self.current();
            let prevote = &data.prevotes[local as usize];
            let precommit = &data.precommits[local as usize];
            if data.starts[local as usize].is_none() || (self.phase == Phase::Propose && (prevote.is_some() || precommit.is_some()))
                || (self.phase == Phase::Prevote && (prevote.is_none() || precommit.is_some()))
                || (self.phase == Phase::Precommit && (prevote.is_none() || precommit.is_none())) {
                return Err(failure("Journal phase does not match local signed votes"));
            }
            if let Some(vote) = precommit {
                if let Some(value) = vote.value {
                    if self.locked.as_ref().is_none_or(|locked|
                        locked.certificate.round != self.round || locked.certificate.value != value) {
                        return Err(failure("Journal precommit has no matching lock"));
                    }
                }
            }
        }
        Ok(())
    }
}
