use nexus_anchor::{bft::{block_id, BftState, CommittedBlock, Committee, Message, Phase,
    Proposal, RoundStart, Vote, VoteCertificate, QUORUM}, AnchorChain, AnchorChainConfig, MonetaryGenesis, MonetaryPolicy};
use nexus_core::{checkpoint::{decode, encode}, Address, Amount, Block, BlockHeight,
    Hash256, SignatureScheme, Timestamp};
use nexus_crypto::DilithiumKeypair;

fn fixture() -> (AnchorChain, Committee, Vec<DilithiumKeypair>) {
    let mut keys: Vec<_> = (1..=4).map(|seed|
        DilithiumKeypair::from_seed(&[seed; 32], SignatureScheme::Dilithium3).unwrap()).collect();
    keys.sort_by_key(|key| key.address().0);
    let config = AnchorChainConfig { block_reward: Amount::ZERO, fee_percentage: 0, ..Default::default() };
    let monetary = MonetaryGenesis { deployment: Hash256::new([1; 32]), allocations: vec![],
        policy: MonetaryPolicy { max_issued: Amount(100), initial_block_reward: Amount(10),
            halving_interval: 100, min_gas_price: Amount(1), burn_basis_points: 2500 } };
    let ledger = AnchorChain::new_monetary(config, monetary).unwrap();
    let committee = Committee::new(ledger.genesis().hash(), ledger.network_domain().unwrap(),
        keys.iter().map(|key| key.public_key().clone()).collect()).unwrap();
    (ledger, committee, keys)
}
fn candidate(ledger: &AnchorChain, committee: &Committee, round: u32) -> Block {
    ledger.prepare_block_at(vec![], committee.member(committee.proposer(BlockHeight(1), round)).unwrap(), Timestamp(1)).unwrap()
}
fn certificate(committee: &Committee, keys: &[DilithiumKeypair], round: u32, phase: Phase, block: &Block) -> VoteCertificate {
    let value = block_id(block).unwrap();
    VoteCertificate { height: BlockHeight(1), round, phase, value,
        votes: keys.iter().take(QUORUM).map(|key| Vote::sign(committee, BlockHeight(1), round, phase, Some(value), key).unwrap()).collect() }
}
fn state(committee: &Committee, key: &DilithiumKeypair) -> BftState {
    let mut state = BftState::new(committee, Some(key.address()), BlockHeight(1), committee.genesis()).unwrap();
    state.activate(committee, Some(key)).unwrap();
    state
}

#[test]
fn signatures_bind_phase_height_round_member_context_and_full_block_body() {
    let (ledger, committee, keys) = fixture();
    let block = candidate(&ledger, &committee, 0);
    let vote = Vote::sign(&committee, BlockHeight(1), 0, Phase::Prevote, Some(block_id(&block).unwrap()), &keys[0]).unwrap();
    for case in 0..5 {
        let mut altered = vote.clone();
        match case {
            0 => altered.phase = Phase::Precommit,
            1 => altered.height = BlockHeight(2),
            2 => altered.round = 1,
            3 => altered.validator = 1,
            _ => altered.context = Hash256::new([7; 32]),
        }
        assert!(altered.verify(&committee).is_err());
    }
    let proposal = Proposal::sign(&committee, BlockHeight(1), 0, block.clone(), None, &keys[1]).unwrap();
    let commit = CommittedBlock { proposal,
        certificate: certificate(&committee, &keys, 0, Phase::Precommit, &block) };
    commit.verify(&committee).unwrap();
    let mut changed = commit.clone();
    // Header hashes do not include this field; BFT's full-block commitment does.
    changed.proposal.body.block.body.signatures.push(nexus_core::block::ValidatorSignature {
        validator: Address::ZERO, signature: keys[0].sign(b"unrelated").unwrap().to_pq_signature() });
    assert_eq!(changed.block().hash(), block.hash());
    assert_ne!(block_id(changed.block()).unwrap(), block_id(&block).unwrap());
    assert!(changed.verify(&committee).is_err());
    let mut repeated = commit.certificate.clone();
    repeated.votes[2] = repeated.votes[0].clone();
    assert!(repeated.verify(&committee).is_err());
    let other = Committee::new(committee.genesis(), Hash256::new([9; 32]), committee.keys().to_vec()).unwrap();
    assert!(commit.verify(&other).is_err());
}

#[test]
fn two_votes_and_retransmissions_do_not_create_a_quorum_or_timeout() {
    let (ledger, committee, keys) = fixture();
    let mut state = state(&committee, &keys[0]);
    let block = candidate(&ledger, &committee, 0);
    let proposal = Proposal::sign(&committee, BlockHeight(1), 0, block.clone(), None, &keys[1]).unwrap();
    state.receive(&committee, Some(&keys[0]), Message::Proposal(Box::new(proposal)), |block| ledger.validate_candidate(block)).unwrap();
    let second = Vote::sign(&committee, BlockHeight(1), 0, Phase::Prevote, Some(block_id(&block).unwrap()), &keys[1]).unwrap();
    for _ in 0..8 {
        state.receive(&committee, Some(&keys[0]), Message::Vote(second.clone()), |block| ledger.validate_candidate(block)).unwrap();
    }
    assert_eq!(state.phase(), Phase::Prevote);
    assert_eq!(state.locked_value(), None);
    assert!(state.timeout_ready().is_none());
    assert!(state.decision().is_none());
    let before = encode(&state).unwrap();
    let conflicting = Vote::sign(&committee, BlockHeight(1), 0, Phase::Prevote, None, &keys[1]).unwrap();
    assert!(state.receive(&committee, Some(&keys[0]), Message::Vote(conflicting), |block| ledger.validate_candidate(block)).is_err());
    assert_eq!(encode(&state).unwrap(), before);
    let third = Vote::sign(&committee, BlockHeight(1), 0, Phase::Prevote, Some(block_id(&block).unwrap()), &keys[2]).unwrap();
    state.receive(&committee, Some(&keys[0]), Message::Vote(third), |block| ledger.validate_candidate(block)).unwrap();
    assert_eq!(state.phase(), Phase::Precommit);
    assert_eq!(state.locked_value(), Some((0, block_id(&block).unwrap())));
}

#[test]
fn restored_lock_rejects_conflicting_proposal_and_accepts_only_a_sufficiently_new_pol() {
    let (ledger, committee, keys) = fixture();
    let mut state = state(&committee, &keys[0]);
    let a = candidate(&ledger, &committee, 0);
    let proposal = Proposal::sign(&committee, BlockHeight(1), 0, a.clone(), None, &keys[1]).unwrap();
    state.receive(&committee, Some(&keys[0]), Message::Proposal(Box::new(proposal)), |block| ledger.validate_candidate(block)).unwrap();
    for key in &keys[1..3] {
        let vote = Vote::sign(&committee, BlockHeight(1), 0, Phase::Prevote, Some(block_id(&a).unwrap()), key).unwrap();
        state.receive(&committee, Some(&keys[0]), Message::Vote(vote), |block| ledger.validate_candidate(block)).unwrap();
    }
    let mut restored: BftState = decode(&encode(&state).unwrap()).unwrap();
    restored.validate_restored(&committee, Some(keys[0].address()), BlockHeight(1), committee.genesis(),
        |block| ledger.validate_candidate(block)).unwrap();
    // Future round announcements require two distinct senders, preserving the lock.
    for key in &keys[1..3] {
        let start = RoundStart::sign(&committee, BlockHeight(1), 1, key).unwrap();
        restored.receive(&committee, Some(&keys[0]), Message::RoundStart(start), |block| ledger.validate_candidate(block)).unwrap();
    }
    let b = candidate(&ledger, &committee, 1);
    let conflicting = Proposal::sign(&committee, BlockHeight(1), 1, b.clone(), None, &keys[2]).unwrap();
    let messages = restored.receive(&committee, Some(&keys[0]), Message::Proposal(Box::new(conflicting)),
        |block| ledger.validate_candidate(block)).unwrap();
    assert!(messages.iter().any(|message| matches!(message, Message::Vote(vote) if vote.phase == Phase::Prevote && vote.value.is_none())));
    assert_eq!(restored.locked_value(), Some((0, block_id(&a).unwrap())));

    // These independently signed test certificates deliberately exercise hostile
    // histories; this does not claim all of them can occur with only one fault.
    let b_pol = certificate(&committee, &keys, 1, Phase::Prevote, &b);
    for key in &keys[1..3] {
        restored.receive(&committee, Some(&keys[0]), Message::RoundStart(RoundStart::sign(&committee,
            BlockHeight(1), 2, key).unwrap()), |block| ledger.validate_candidate(block)).unwrap();
    }
    let justified = Proposal::sign(&committee, BlockHeight(1), 2, b.clone(), Some(b_pol), &keys[3]).unwrap();
    let messages = restored.receive(&committee, Some(&keys[0]), Message::Proposal(Box::new(justified)),
        |block| ledger.validate_candidate(block)).unwrap();
    assert!(messages.iter().any(|message| matches!(message, Message::Vote(vote) if vote.phase == Phase::Prevote && vote.value == Some(block_id(&b).unwrap()))));
    for key in &keys[1..3] {
        let vote = Vote::sign(&committee, BlockHeight(1), 2, Phase::Prevote, Some(block_id(&b).unwrap()), key).unwrap();
        restored.receive(&committee, Some(&keys[0]), Message::Vote(vote), |block| ledger.validate_candidate(block)).unwrap();
    }
    assert_eq!(restored.locked_value(), Some((2, block_id(&b).unwrap())));
    for key in &keys[1..3] {
        restored.receive(&committee, Some(&keys[0]), Message::RoundStart(RoundStart::sign(&committee,
            BlockHeight(1), 4, key).unwrap()), |block| ledger.validate_candidate(block)).unwrap();
    }
    let stale = Proposal::sign(&committee, BlockHeight(1), 4, a.clone(),
        Some(certificate(&committee, &keys, 1, Phase::Prevote, &a)), &keys[1]).unwrap();
    let messages = restored.receive(&committee, Some(&keys[0]), Message::Proposal(Box::new(stale)),
        |block| ledger.validate_candidate(block)).unwrap();
    assert!(messages.iter().any(|message| matches!(message, Message::Vote(vote) if vote.phase == Phase::Prevote && vote.value.is_none())));
    assert_eq!(restored.locked_value(), Some((2, block_id(&b).unwrap())));
}

#[test]
fn a_single_sender_cannot_jump_rounds_or_allocate_unbounded_future_state() {
    let (ledger, committee, keys) = fixture();
    let mut state = state(&committee, &keys[0]);
    let start = RoundStart::sign(&committee, BlockHeight(1), 2, &keys[1]).unwrap();
    for _ in 0..4 {
        state.receive(&committee, Some(&keys[0]), Message::RoundStart(start.clone()), |block| ledger.validate_candidate(block)).unwrap();
    }
    assert_eq!(state.round(), 0);
    let before = encode(&state).unwrap();
    let far = RoundStart::sign(&committee, BlockHeight(1), 100, &keys[1]).unwrap();
    assert!(state.receive(&committee, Some(&keys[0]), Message::RoundStart(far), |block| ledger.validate_candidate(block)).is_err());
    assert_eq!(encode(&state).unwrap(), before);
    let second = RoundStart::sign(&committee, BlockHeight(1), 2, &keys[2]).unwrap();
    state.receive(&committee, Some(&keys[0]), Message::RoundStart(second), |block| ledger.validate_candidate(block)).unwrap();
    assert_eq!(state.round(), 2);
    state.validate_restored(&committee, Some(keys[0].address()), BlockHeight(1), committee.genesis(),
        |block| ledger.validate_candidate(block)).unwrap();
    let one = RoundStart::sign(&committee, BlockHeight(1), 100, &keys[1]).unwrap();
    assert!(state.receive(&committee, Some(&keys[0]), Message::RoundCatchup(vec![one.clone(), one.clone()]),
        |block| ledger.validate_candidate(block)).is_err());
    let two = RoundStart::sign(&committee, BlockHeight(1), 100, &keys[2]).unwrap();
    state.receive(&committee, Some(&keys[0]), Message::RoundCatchup(vec![one, two]),
        |block| ledger.validate_candidate(block)).unwrap();
    assert_eq!(state.round(), 100);
    state.validate_restored(&committee, Some(keys[0].address()), BlockHeight(1), committee.genesis(),
        |block| ledger.validate_candidate(block)).unwrap();
}
