//! Stake boundaries and authenticated votes from thesis 3.9 and Lean QuorumIncentivos.
use nexus_anchor::{ConsensusConfig, ConsensusEngine, ProofOfStake, Validator, ValidatorSet};
use nexus_anchor::consensus::{vote_signing_bytes, ConsensusMessage, VotePhase};
use nexus_core::{Amount, Block, BlockHeight, Hash256, SignatureScheme};
use nexus_crypto::DilithiumKeypair;

fn fixture(weights: &[u128]) -> (ProofOfStake, Vec<DilithiumKeypair>, Block) {
    let keys: Vec<_> = weights.iter().map(|_| DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap()).collect();
    let mut set = ValidatorSet::new();
    for (key, weight) in keys.iter().zip(weights) {
        set.add_validator(Validator::new(key.address(), key.public_key().as_bytes().to_vec(), Amount(*weight))).unwrap();
        set.activate_validator(&key.address()).unwrap();
    }
    let proposer = set.active_validators()[1 % keys.len()].address;
    let signer = keys.iter().find(|key| key.address() == proposer).unwrap().clone();
    let engine = ProofOfStake::new(ConsensusConfig::default(), set, signer);
    let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let proposal = runtime.block_on(engine.propose_block(vec![])).unwrap();
    (engine, keys, proposal)
}

fn vote(key: &DilithiumKeypair, phase: VotePhase, block: &Block) -> ConsensusMessage {
    let height = block.height();
    let hash = Some(block.hash());
    let signature = key.sign(&vote_signing_bytes(phase, height, 0, hash).unwrap()).unwrap().as_bytes().to_vec();
    match phase {
        VotePhase::Prevote => ConsensusMessage::Prevote { height, round: 0, block_hash: hash, validator: key.address(), signature },
        VotePhase::Precommit => ConsensusMessage::Precommit { height, round: 0, block_hash: hash, validator: key.address(), signature },
    }
}

fn bounded(body: impl FnOnce() + Send + 'static) {
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
        let _ = send.send(result.is_ok());
    });
    assert!(receive.recv_timeout(std::time::Duration::from_secs(5)).expect("consensus did not return"));
}

#[test]
fn exactly_two_thirds_and_repeated_votes_cannot_commit_but_full_quorum_can() {
    bounded(|| {
        let (engine, keys, block) = fixture(&[1, 1, 1]);
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            for key in &keys[..2] { engine.process_message(vote(key, VotePhase::Prevote, &block)).await.unwrap(); }
            for _ in 0..5 { engine.process_message(vote(&keys[0], VotePhase::Prevote, &block)).await.unwrap(); }
            assert!(engine.process_message(vote(&keys[0], VotePhase::Precommit, &block)).await.is_err());
            engine.process_message(vote(&keys[2], VotePhase::Prevote, &block)).await.unwrap();
            for key in &keys[..2] { engine.process_message(vote(key, VotePhase::Precommit, &block)).await.unwrap(); }
            for _ in 0..5 { engine.process_message(vote(&keys[0], VotePhase::Precommit, &block)).await.unwrap(); }
            assert_eq!(engine.current_height(), BlockHeight::GENESIS);
            engine.process_message(vote(&keys[2], VotePhase::Precommit, &block)).await.unwrap();
            assert_eq!(engine.current_height(), block.height());
            assert!(engine.process_message(vote(&keys[2], VotePhase::Precommit, &block)).await.is_err());
        });
    });
}

#[test]
fn quorum_uses_stake_not_validator_count_or_truncated_whole_tokens() {
    bounded(|| {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        for weights in [[100, 1, 1], [u128::MAX - 2, 1, 1]] {
            let (engine, keys, block) = fixture(&weights);
            rt.block_on(async {
                engine.process_message(vote(&keys[0], VotePhase::Prevote, &block)).await.unwrap();
                engine.process_message(vote(&keys[0], VotePhase::Precommit, &block)).await.unwrap();
                assert_eq!(engine.current_height(), block.height());
            });
        }
    });
}

#[test]
fn rejects_unknown_voters_and_cross_phase_replays_without_advancing() {
    let (engine, keys, block) = fixture(&[1, 1, 1]);
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    rt.block_on(async {
        let outsider = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        assert!(engine.process_message(vote(&outsider, VotePhase::Prevote, &block)).await.is_err());
        for key in &keys { engine.process_message(vote(key, VotePhase::Prevote, &block)).await.unwrap(); }
        let ConsensusMessage::Prevote { height, round, block_hash, validator, signature } = vote(&keys[0], VotePhase::Prevote, &block) else { unreachable!() };
        assert!(engine.process_message(ConsensusMessage::Precommit { height, round, block_hash, validator, signature }).await.is_err());
        assert_eq!(engine.current_height(), BlockHeight::GENESIS);
    });
}

#[test]
fn malformed_conflicting_and_wrong_context_votes_do_not_replace_honest_votes() {
    let (engine, keys, block) = fixture(&[1, 1, 1]);
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    rt.block_on(async {
        let mut invalid = vote(&keys[0], VotePhase::Prevote, &block);
        if let ConsensusMessage::Prevote { signature, .. } = &mut invalid { signature.fill(0); }
        assert!(engine.process_message(invalid).await.is_err());
        engine.process_message(vote(&keys[0], VotePhase::Prevote, &block)).await.unwrap();
        let signature = keys[0].sign(&vote_signing_bytes(VotePhase::Prevote, block.height(), 0, None).unwrap()).unwrap();
        assert!(engine.process_message(ConsensusMessage::Prevote { height: block.height(), round: 0,
            block_hash: None, validator: keys[0].address(), signature: signature.as_bytes().to_vec() }).await.is_err());
        let mut wrong_round = vote(&keys[1], VotePhase::Prevote, &block);
        if let ConsensusMessage::Prevote { round, .. } = &mut wrong_round { *round = 1; }
        assert!(engine.process_message(wrong_round).await.is_err());
        let mut unsigned = block.clone();
        unsigned.body.signatures.clear();
        assert!(!engine.validate_block(&unsigned).await.unwrap());
        let mut altered = block.clone();
        altered.header.state_root = Hash256::hash(b"altered");
        assert!(engine.validate_block(&altered).await.is_err());
    });
}

#[tokio::test]
async fn weaker_float_policy_is_rejected_instead_of_overriding_the_lean_quorum() {
    let signer = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
    let config = ConsensusConfig { bft_threshold: 0.5, ..Default::default() };
    let engine = ProofOfStake::new(config, ValidatorSet::new(), signer);
    assert!(engine.start().await.is_err());
}
