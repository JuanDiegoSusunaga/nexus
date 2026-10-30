//! Real durable runtimes with a deterministic in-process message scheduler.
//! TCP transport and independent-operator deployment are separate requirements.
use nexus_anchor::{bft::{block_id, Message, Phase, Proposal, Vote}, AnchorChainConfig, MonetaryGenesis, MonetaryPolicy};
use nexus_core::{Amount, BlockHeight, ChainId, Hash256, Nonce, SignatureScheme,
    SignedTransaction, Timestamp, Transaction};
use nexus_crypto::{DilithiumKeypair, Signer};
use nexus_node::{BftNode, BftNodeConfig};
use std::{collections::VecDeque, path::{Path, PathBuf}, sync::atomic::{AtomicU64, Ordering}};

fn key(seed: u8) -> DilithiumKeypair {
    DilithiumKeypair::from_seed(&[seed; 32], SignatureScheme::Dilithium3).unwrap()
}
fn keys() -> Vec<DilithiumKeypair> {
    let mut keys: Vec<_> = (1..=4).map(key).collect();
    keys.sort_by_key(|key| key.address().0);
    keys
}
fn config() -> BftNodeConfig {
    let mut anchor = AnchorChainConfig { chain_id: ChainId::TESTNET, block_reward: Amount::ZERO,
        fee_percentage: 0, ..Default::default() };
    anchor.consensus.committee_size = 4;
    BftNodeConfig { anchor, proposal_future_ms: 30_000,
        validators: keys().iter().map(|key| key.public_key().clone()).collect(),
        monetary: MonetaryGenesis { deployment: Hash256::new([1; 32]),
            allocations: vec![(key(9).address(), Amount(10_000_000))],
            policy: MonetaryPolicy { max_issued: Amount(100_000_000), initial_block_reward: Amount(10),
                halving_interval: 100, min_gas_price: Amount(1), burn_basis_points: 2500 } } }
}
fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/bft-tests")
        .join(format!("{}-{}-{}", std::process::id(), Timestamp::now().0, NEXT.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir_all(&path).unwrap(); path
}
fn nodes() -> (Vec<BftNode>, Vec<PathBuf>) {
    let directories: Vec<_> = (0..4).map(|_| directory()).collect();
    let nodes = directories.iter().zip(keys()).map(|(path, key)|
        BftNode::create(path, config(), Some(key)).unwrap()).collect();
    (nodes, directories)
}
fn height(message: &Message) -> BlockHeight {
    match message {
        Message::Proposal(proposal) => proposal.body.height,
        Message::Vote(vote) => vote.height,
        Message::RoundStart(start) => start.height,
        Message::Commit(commit) => commit.block().height(),
        Message::RoundCatchup(starts) => starts[0].height,
    }
}
async fn deliver(nodes: &mut [BftNode], messages: Vec<Message>, online: &[bool; 4]) {
    let mut queue: VecDeque<_> = messages.into();
    let mut processed = 0;
    while let Some(message) = queue.pop_front() {
        processed += 1;
        assert!(processed <= 2048, "message exchange did not converge");
        for (index, node) in nodes.iter_mut().enumerate() {
            if !online[index] { continue; }
            let future = height(&message) > node.consensus_state().height();
            match node.receive(message.clone(), Timestamp(100)).await {
                Ok(output) => queue.extend(output),
                Err(_) if future => (), // A following commit/retransmission closes this height gap.
                Err(error) => panic!("node {index}: {error}; message {message:?}"),
            }
        }
    }
}
fn transfer(node: &BftNode, nonce: u64) -> SignedTransaction {
    let mut tx = Transaction::transfer(ChainId::TESTNET, Nonce(nonce), key(8).address(), Amount(123), 200_000, Amount(2));
    tx.network_domain = Some(node.network_domain());
    tx.timestamp = Timestamp(1);
    key(9).sign_transaction(tx).unwrap()
}

#[tokio::test]
async fn four_validators_certify_transfers_and_an_observer_syncs_without_signing() {
    let (mut nodes, directories) = nodes();
    for number in 1..=2 {
        let proposer = nodes.iter().position(BftNode::is_proposer).unwrap();
        let tx = transfer(&nodes[proposer], number - 1);
        let messages = nodes[proposer].propose(vec![tx], Timestamp(number * 10)).await.unwrap();
        deliver(&mut nodes, messages, &[true; 4]).await;
        let root = nodes[0].state_root();
        let counters = nodes[0].monetary_counters();
        for node in &nodes {
            assert_eq!(node.height(), BlockHeight(number));
            assert_eq!(node.state_root(), root);
            assert_eq!(node.monetary_counters(), counters);
            node.commit_at(BlockHeight(number)).unwrap().verify(node.committee()).unwrap();
        }
    }
    let mut observer = BftNode::create(&directory(), config(), None).unwrap();
    for number in 1..=2 {
        observer.receive(Message::Commit(Box::new(nodes[0].commit_at(BlockHeight(number)).unwrap())), Timestamp(0)).await.unwrap();
    }
    assert_eq!(observer.state_root(), nodes[0].state_root());
    assert_eq!(observer.account(&key(8).address()).unwrap().balance, Amount(246));
    assert!(observer.propose(vec![], Timestamp(100)).await.is_err());
    assert!(observer.retransmit().iter().all(|message| matches!(message, Message::Commit(_))));
    let root = nodes[0].state_root();
    drop(nodes);
    for (path, validator_key) in directories.iter().zip(keys()) {
        let node = BftNode::open(path, config(), Some(validator_key)).unwrap();
        assert_eq!(node.height(), BlockHeight(2));
        assert_eq!(node.state_root(), root);
        assert_eq!(node.account(&key(9).address()).unwrap().nonce, Nonce(2));
    }
}

#[tokio::test]
async fn an_absent_leader_is_replaced_after_nil_quorums_and_three_nodes_make_progress() {
    let (mut nodes, _) = nodes();
    let absent = nodes.iter().position(BftNode::is_proposer).unwrap();
    let mut online = [true; 4]; online[absent] = false;
    let mut messages = Vec::new();
    for (index, node) in nodes.iter_mut().enumerate() {
        if online[index] {
            let timeout = node.timeout_ready().unwrap();
            assert_eq!(timeout.phase, Phase::Propose);
            messages.extend(node.timeout(timeout).await.unwrap());
        }
    }
    deliver(&mut nodes, messages, &online).await;
    let mut messages = Vec::new();
    for (index, node) in nodes.iter_mut().enumerate() {
        if online[index] {
            let timeout = node.timeout_ready().unwrap();
            assert_eq!(timeout.phase, Phase::Precommit);
            messages.extend(node.timeout(timeout).await.unwrap());
        }
    }
    deliver(&mut nodes, messages, &online).await;
    let proposer = nodes.iter().enumerate().position(|(index, node)| online[index] && node.is_proposer()).unwrap();
    assert_eq!(nodes[proposer].consensus_state().round(), 1);
    let messages = nodes[proposer].propose(vec![], Timestamp(10)).await.unwrap();
    deliver(&mut nodes, messages, &online).await;
    let committed = nodes[proposer].commit_at(BlockHeight(1)).unwrap();
    for (index, node) in nodes.iter().enumerate() {
        assert_eq!(node.height(), if online[index] { BlockHeight(1) } else { BlockHeight(0) });
    }
    nodes[absent].receive(Message::Commit(Box::new(committed)), Timestamp(100)).await.unwrap();
    assert_eq!(nodes[absent].state_root(), nodes[proposer].state_root());
}

#[tokio::test]
async fn two_nodes_halt_without_quorum_and_resume_when_a_third_returns() {
    let (mut nodes, _) = nodes();
    let proposer = nodes.iter().position(BftNode::is_proposer).unwrap();
    let second = (proposer + 1) % 4;
    let third = (proposer + 2) % 4;
    let mut online = [false; 4]; online[proposer] = true; online[second] = true;
    let messages = nodes[proposer].propose(vec![], Timestamp(10)).await.unwrap();
    deliver(&mut nodes, messages, &online).await;
    for index in [proposer, second] {
        assert_eq!(nodes[index].height(), BlockHeight(0));
        assert_eq!(nodes[index].consensus_state().phase(), Phase::Prevote);
        assert!(nodes[index].timeout_ready().is_none());
    }
    online[third] = true;
    let messages = [proposer, second].into_iter().flat_map(|index| nodes[index].retransmit()).collect();
    deliver(&mut nodes, messages, &online).await;
    for index in [proposer, second, third] { assert_eq!(nodes[index].height(), BlockHeight(1)); }
}

#[tokio::test]
async fn proposal_is_durable_before_return_and_reopen_cannot_sign_a_different_value() {
    let path = directory();
    let proposer_key = keys()[1].clone();
    let mut node = BftNode::create(&path, config(), Some(proposer_key.clone())).unwrap();
    let messages = node.propose(vec![], Timestamp(10)).await.unwrap();
    let original = messages.iter().find_map(|message| if let Message::Proposal(proposal) = message {
        Some(block_id(&proposal.body.block).unwrap()) } else { None }).unwrap();
    let generation = node.generation();
    drop(node);
    let mut reopened = BftNode::open(&path, config(), Some(proposer_key)).unwrap();
    assert_eq!(reopened.consensus_state().phase(), Phase::Prevote);
    assert!(reopened.propose(vec![], Timestamp(20)).await.is_err());
    assert_eq!(reopened.generation(), generation);
    assert!(reopened.retransmit().iter().any(|message| matches!(message, Message::Proposal(proposal)
        if block_id(&proposal.body.block).unwrap() == original)));
    let obstruction = path.join(nexus_core::journal::JournalStore::record_name(generation + 1));
    std::fs::create_dir(&obstruction).unwrap();
    let before = reopened.retransmit();
    let vote = Vote::sign(reopened.committee(), BlockHeight(1), 0, Phase::Prevote, Some(original), &keys()[0]).unwrap();
    assert!(reopened.receive(Message::Vote(vote), Timestamp(100)).await.is_err());
    assert_eq!(nexus_core::checkpoint::encode(&reopened.retransmit()).unwrap(), nexus_core::checkpoint::encode(&before).unwrap());
    std::fs::remove_dir(obstruction).unwrap();
}

#[tokio::test]
async fn failed_commit_checkpoint_preserves_lock_and_retry_applies_the_reward_once() {
    let (mut nodes, paths) = nodes();
    let keys = keys();
    let messages = nodes[1].propose(vec![], Timestamp(10)).await.unwrap();
    let proposal = messages.into_iter().find_map(|message| if let Message::Proposal(proposal) = message { Some(proposal) } else { None }).unwrap();
    let value = block_id(&proposal.body.block).unwrap();
    nodes[0].receive(Message::Proposal(proposal), Timestamp(100)).await.unwrap();
    for key in &keys[1..3] {
        let vote = Vote::sign(nodes[0].committee(), BlockHeight(1), 0, Phase::Prevote, Some(value), key).unwrap();
        nodes[0].receive(Message::Vote(vote), Timestamp(100)).await.unwrap();
    }
    assert_eq!(nodes[0].consensus_state().locked_value(), Some((0, value)));
    let first = Vote::sign(nodes[0].committee(), BlockHeight(1), 0, Phase::Precommit, Some(value), &keys[1]).unwrap();
    nodes[0].receive(Message::Vote(first), Timestamp(100)).await.unwrap();
    let last = Vote::sign(nodes[0].committee(), BlockHeight(1), 0, Phase::Precommit, Some(value), &keys[2]).unwrap();
    let generation = nodes[0].generation();
    let obstruction = paths[0].join(nexus_core::journal::JournalStore::record_name(generation + 1));
    std::fs::create_dir(&obstruction).unwrap();
    assert!(nodes[0].receive(Message::Vote(last.clone()), Timestamp(100)).await.is_err());
    assert_eq!(nodes[0].height(), BlockHeight(0));
    assert_eq!(nodes[0].consensus_state().locked_value(), Some((0, value)));
    assert_eq!(nodes[0].generation(), generation);
    std::fs::remove_dir(obstruction).unwrap();
    let victim = nodes.remove(0); drop(victim);
    let mut reopened = BftNode::open(&paths[0], config(), Some(keys[0].clone())).unwrap();
    reopened.receive(Message::Vote(last), Timestamp(100)).await.unwrap();
    assert_eq!(reopened.height(), BlockHeight(1));
    assert_eq!(reopened.monetary_counters().issued, Amount(10_000_010));
    let generation = reopened.generation();
    let duplicate = Message::Commit(Box::new(reopened.commit_at(BlockHeight(1)).unwrap()));
    reopened.receive(duplicate, Timestamp(100)).await.unwrap();
    assert_eq!(reopened.generation(), generation);
}

#[tokio::test]
async fn invalid_proposals_and_changed_committee_or_clock_policy_do_not_change_state() {
    let (mut nodes, _) = nodes();
    let committee = nodes[0].committee().clone();
    let messages = nodes[1].propose(vec![], Timestamp(10)).await.unwrap();
    let proposal = messages.into_iter().find_map(|message| if let Message::Proposal(proposal) = message { Some(proposal) } else { None }).unwrap();
    let before = (nodes[0].generation(), nodes[0].state_root());
    let mut bad = proposal.clone(); bad.body.block.header.state_root = Hash256::ZERO;
    assert!(nodes[0].receive(Message::Proposal(bad), Timestamp(100)).await.is_err());
    let mut future = proposal.body.block.clone(); future.header.timestamp = Timestamp(40_001);
    let signed = Proposal::sign(&committee, BlockHeight(1), 0, future, None, &keys()[1]).unwrap();
    assert!(nodes[0].receive(Message::Proposal(Box::new(signed)), Timestamp(1)).await.is_err());
    assert_eq!((nodes[0].generation(), nodes[0].state_root()), before);
    let mut changed = config(); changed.validators[0] = key(7).public_key().clone();
    let observer = BftNode::create(&directory(), changed, None).unwrap();
    assert_ne!(observer.network_domain(), nodes[0].network_domain());
    let mut clock = config(); clock.proposal_future_ms += 1;
    let observer = BftNode::create(&directory(), clock, None).unwrap();
    assert_ne!(observer.network_domain(), nodes[0].network_domain());
}

#[tokio::test]
async fn an_equivocating_leader_cannot_finalize_conflicting_blocks_at_honest_nodes() {
    let (mut nodes, _) = nodes();
    let keys = keys();
    // Validator 1 is the sole Byzantine actor. Honest nodes 0 and 2 see A,
    // node 3 sees B. Only validator 1 signs two values in the same phase.
    let messages = nodes[1].propose(vec![], Timestamp(10)).await.unwrap();
    let a = messages.into_iter().find_map(|message| if let Message::Proposal(proposal) = message { Some(proposal) } else { None }).unwrap();
    let mut b_block = a.body.block.clone(); b_block.header.timestamp = Timestamp(11);
    let b = Proposal::sign(nodes[0].committee(), BlockHeight(1), 0, b_block, None, &keys[1]).unwrap();
    let a_id = block_id(&a.body.block).unwrap();
    let b_id = block_id(&b.body.block).unwrap();
    let mut honest_prevotes = Vec::new();
    for index in [0, 2] {
        honest_prevotes.extend(nodes[index].receive(Message::Proposal(a.clone()), Timestamp(100)).await.unwrap());
    }
    nodes[3].receive(Message::Proposal(Box::new(b)), Timestamp(100)).await.unwrap();
    let byzantine_a = Vote::sign(nodes[0].committee(), BlockHeight(1), 0, Phase::Prevote, Some(a_id), &keys[1]).unwrap();
    let byzantine_b = Vote::sign(nodes[0].committee(), BlockHeight(1), 0, Phase::Prevote, Some(b_id), &keys[1]).unwrap();
    for index in [0, 2] { nodes[index].receive(Message::Vote(byzantine_a.clone()), Timestamp(100)).await.unwrap(); }
    nodes[3].receive(Message::Vote(byzantine_b), Timestamp(100)).await.unwrap();
    let mut honest_precommits = Vec::new();
    for message in honest_prevotes {
        for index in [0, 2] {
            honest_precommits.extend(nodes[index].receive(message.clone(), Timestamp(100)).await.unwrap());
        }
    }
    for index in [0, 2] { assert_eq!(nodes[index].consensus_state().locked_value(), Some((0, a_id))); }
    assert_eq!(nodes[3].consensus_state().phase(), Phase::Prevote);
    let byzantine_commit_a = Vote::sign(nodes[0].committee(), BlockHeight(1), 0, Phase::Precommit, Some(a_id), &keys[1]).unwrap();
    let byzantine_commit_b = Vote::sign(nodes[0].committee(), BlockHeight(1), 0, Phase::Precommit, Some(b_id), &keys[1]).unwrap();
    for index in [0, 2] { nodes[index].receive(Message::Vote(byzantine_commit_a.clone()), Timestamp(100)).await.unwrap(); }
    nodes[3].receive(Message::Vote(byzantine_commit_b), Timestamp(100)).await.unwrap();
    for message in honest_precommits {
        for index in [0, 2] { nodes[index].receive(message.clone(), Timestamp(100)).await.unwrap(); }
    }
    assert_eq!(nodes[0].height(), BlockHeight(1));
    assert_eq!(nodes[2].height(), BlockHeight(1));
    assert_eq!(nodes[3].height(), BlockHeight(0));
    let commit = nodes[0].commit_at(BlockHeight(1)).unwrap();
    assert_eq!(commit.certificate.value, a_id);
    nodes[3].receive(Message::Commit(Box::new(commit)), Timestamp(100)).await.unwrap();
    assert_eq!(nodes[3].state_root(), nodes[0].state_root());
}

#[test]
fn a_signed_proposal_survives_abrupt_process_exit_before_any_peer_receives_it() {
    const CHILD: &str = "NEXUS_BFT_EXIT_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let mut node = BftNode::create(Path::new(&path), config(), Some(keys()[1].clone())).unwrap();
            node.propose(vec![], Timestamp(10)).await.unwrap();
            std::process::exit(0);
        });
    }
    let path = directory();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "a_signed_proposal_survives_abrupt_process_exit_before_any_peer_receives_it", "--nocapture"])
        .env(CHILD, &path);
    #[cfg(windows)] {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let result = command.output().unwrap();
    assert!(result.status.success(), "{} {}", String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
    let node = BftNode::open(&path, config(), Some(keys()[1].clone())).unwrap();
    assert_eq!(node.consensus_state().phase(), Phase::Prevote);
    assert!(node.retransmit().iter().any(|message| matches!(message, Message::Proposal(_))));
    assert!(node.retransmit().iter().any(|message| matches!(message, Message::Vote(vote) if vote.phase == Phase::Prevote)));
}
