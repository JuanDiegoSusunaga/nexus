//! Regressions for the review of 20 October 2026.
use nexus_core::{Address, Amount, BlockHeight, ChainId, Hash256, Nonce,
    SignatureScheme, SignedTransaction, StateRoot, Transaction};
use nexus_crypto::{verify_signed_transaction, DilithiumKeypair, Signer};
use nexus_anchor::{AnchorChain, AnchorChainConfig, ConsensusConfig, ConsensusEngine, ProofOfStake, Validator, ValidatorSet};
use nexus_anchor::consensus::ConsensusMessage;
use nexus_core::{Block, BlockBody, BlockHeader, Layer, MerkleTree};
fn key() -> DilithiumKeypair {
    DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap()
}

fn transfer(signer: &DilithiumKeypair, nonce: u64, gas_limit: u64, gas_price: u128) -> SignedTransaction {
    signer.sign_transaction(Transaction::transfer(
        ChainId::LOCAL, Nonce(nonce), Address::new([42; 32]), Amount::ZERO,
        gas_limit, Amount(gas_price),
    )).unwrap()
}

fn anchor_block(chain: &AnchorChain, transactions: Vec<SignedTransaction>) -> Block {
    let mut header = BlockHeader::new(
        BlockHeight(1), chain.genesis().hash(), Address::new([43; 32]), Layer::Anchor,
    );
    header.transactions_root = MerkleTree::from_leaves(transactions.iter().map(|tx| tx.hash()).collect()).root();
    Block::new(header, BlockBody::new(transactions))
}

#[tokio::test]
async fn r01_l1_must_reject_a_cryptographically_invalid_signature() {
    let chain = AnchorChain::new(AnchorChainConfig::default(), key());
    let mut tx = transfer(&key(), 0, 21000, 0);
    tx.signature.bytes.fill(0);
    assert!(!verify_signed_transaction(&tx).unwrap(), "control: forged signature must be invalid");
    assert!(chain.process_block(anchor_block(&chain, vec![tx])).await.is_err(),
        "L1 accepted a transaction whose signature verifier returned false");
}

#[tokio::test]
async fn r02_accepting_a_block_must_advance_l1_height() {
    let chain = AnchorChain::new(AnchorChainConfig::default(), key());
    chain.process_block(chain.prepare_block(vec![], Address::new([43; 32])).unwrap()).await.unwrap();
    assert_eq!(chain.height(), BlockHeight(1), "accepted block leaves public height at genesis");
}

#[tokio::test]
async fn r03_processing_the_same_l1_block_must_not_mint_rewards_twice() {
    let config = AnchorChainConfig::default();
    let reward = config.block_reward;
    let chain = AnchorChain::new(config, key());
    let block = chain.prepare_block(vec![], Address::new([43; 32])).unwrap();
    let proposer = block.header.proposer;
    chain.process_block(block.clone()).await.unwrap();
    assert_eq!(chain.get_account(&proposer).unwrap().balance, reward);
    let accepted_twice = chain.process_block(block).await.is_ok();
    assert!(!accepted_twice, "same block accepted twice; proposer balance is {:?}",
        chain.get_account(&proposer).unwrap().balance);
}

#[tokio::test]
async fn r04_rejected_l1_block_must_not_keep_earlier_transaction_mutations() {
    let chain = AnchorChain::new(AnchorChainConfig::default(), key());
    let signer = key();
    let root_before = chain.state_root();
    let block = anchor_block(&chain, vec![transfer(&signer, 0, 21000, 0), transfer(&signer, 2, 21000, 0)]);
    assert!(chain.process_block(block).await.is_err(), "control: second nonce must reject block");
    assert_eq!(chain.state_root(), root_before, "rejected block kept account changes from its first transaction");
}

#[tokio::test]
async fn r05_unsigned_precommit_from_a_nonvalidator_must_not_commit_or_hang() {
    let signer = key();
    let mut validators = ValidatorSet::new();
    validators.add_validator(Validator::new(signer.address(), signer.public_key().as_bytes().to_vec(), Amount::from_units(32))).unwrap();
    validators.activate_validator(&signer.address()).unwrap();
    let engine = ProofOfStake::new(ConsensusConfig::default(), validators, signer);
    let proposal = engine.propose_block(vec![]).await.unwrap();
    let initial_height = engine.current_height();
    // A blocking RwLock cannot be interrupted by a Tokio timeout. Run this
    // particular call on a detached thread so the review suite always terminates.
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let result = runtime.block_on(engine.process_message(ConsensusMessage::Precommit {
            height: proposal.height(), round: 0, block_hash: Some(proposal.hash()),
            validator: Address::ZERO, signature: vec![],
        }));
        let _ = send.send((result, engine.current_height()));
    });
    let (_, resulting_height) = receive.recv_timeout(std::time::Duration::from_secs(2))
        .expect("empty nonvalidator signature reached quorum and deadlocked the consensus engine");
    assert_eq!(resulting_height, initial_height,
        "an empty signature from an unregistered address committed the proposal");
}

fn next_block(chain: &AnchorChain, transactions: Vec<SignedTransaction>, proposer: Address) -> Block {
    let parent = chain.latest_block().unwrap();
    let mut header = BlockHeader::new(BlockHeight(parent.height().0 + 1), parent.hash(), proposer, Layer::Anchor);
    header.transactions_root = MerkleTree::from_leaves(transactions.iter().map(|tx| tx.hash()).collect()).root();
    Block::new(header, BlockBody::new(transactions))
}

#[tokio::test]
async fn accepts_linked_successive_blocks_and_rejects_concurrent_duplicate_rewards() {
    let chain = AnchorChain::new(AnchorChainConfig::default(), key());
    let first = chain.prepare_block(vec![], Address::new([43; 32])).unwrap();
    let (a, b) = tokio::join!(chain.process_block(first.clone()), chain.process_block(first));
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let second = chain.prepare_block(vec![], Address::new([43; 32])).unwrap();
    chain.process_block(second).await.unwrap();
    assert_eq!(chain.height(), BlockHeight(2));
    assert_eq!(chain.stats().block_count, 3);
    assert_eq!(chain.get_account(&Address::new([43; 32])).unwrap().balance, Amount::from_units(4));
    assert_eq!(chain.finalized_height(), BlockHeight::GENESIS);
}

#[tokio::test]
async fn failed_block_rolls_back_validator_registration_balance_and_batch_side_effects() {
    use nexus_core::TransactionType;
    let chain = AnchorChain::new(AnchorChainConfig { block_reward: Amount::from_units(64), ..Default::default() }, key());
    let signer = key();
    chain.process_block(chain.prepare_block(vec![], signer.address()).unwrap()).await.unwrap();
    let before = chain.state_root();
    for register in [true, false] {
        let mut tx = transfer(&signer, 0, 21000, 0).transaction;
        tx.tx_type = if register { TransactionType::ValidatorRegister {
            public_key: signer.public_key().as_bytes().to_vec(), stake: Amount::from_units(32)
        } } else { TransactionType::BatchSubmit { batch_root: Hash256::hash(b"batch"), batch_size: 1, compressed_data: vec![1; 500] } };
        let transactions = vec![signer.sign_transaction(tx).unwrap(), transfer(&signer, 2, 21000, 0)];
        assert!(chain.process_block(next_block(&chain, transactions, Address::ZERO)).await.is_err());
        assert_eq!(chain.state_root(), before);
        assert_eq!(chain.stats().validator_count, 0);
        assert_eq!(chain.stats().l2_batch_count, 0);
        assert_eq!(chain.height(), BlockHeight(1));
    }
    chain.process_block(chain.prepare_block(vec![transfer(&signer, 0, 21000, 0)], Address::ZERO).unwrap()).await.unwrap();
    assert_eq!(chain.get_account(&signer.address()).unwrap().nonce, Nonce(1));
}
