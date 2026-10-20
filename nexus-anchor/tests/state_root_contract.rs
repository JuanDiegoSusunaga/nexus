//! Account-state contract, independently calculated expected balances and roots.
//! The SHA3 account root is separate from the scalar AIR/FRI relation in Lean.
use nexus_anchor::{AnchorChain, AnchorChainConfig};
use nexus_core::{AccountState, Address, Amount, Block, BlockBody, BlockHeader, BlockHeight,
    ChainId, Hash256, InMemoryState, Layer, MerkleTree, NexusError, Nonce, SignatureScheme,
    SignedTransaction, StateRoot, Timestamp, Transaction, TransactionType};
use nexus_crypto::{DilithiumKeypair, Signer};

fn key() -> DilithiumKeypair { DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap() }
fn chain(reward: Amount) -> AnchorChain {
    AnchorChain::new(AnchorChainConfig { block_reward: reward, ..Default::default() }, key())
}
fn raw_block(chain: &AnchorChain, transactions: Vec<SignedTransaction>, proposer: Address) -> Block {
    let parent = chain.latest_block().unwrap();
    let mut header = BlockHeader::new(BlockHeight(parent.height().0 + 1), parent.hash(), proposer, Layer::Anchor);
    header.transactions_root = MerkleTree::from_leaves(transactions.iter().map(|tx| tx.hash()).collect()).root();
    Block::new(header, BlockBody::new(transactions))
}
fn transfer(key: &DilithiumKeypair, nonce: u64, to: Address, amount: Amount, price: Amount) -> SignedTransaction {
    key.sign_transaction(Transaction::transfer(ChainId::LOCAL, Nonce(nonce), to, amount, 22000, price)).unwrap()
}

#[tokio::test]
async fn empty_block_root_includes_reward_and_preparation_has_no_effects() {
    let chain = chain(Amount(100));
    let proposer = Address::new([7; 32]);
    let block = chain.prepare_block(vec![], proposer).unwrap();
    let mut reference = InMemoryState::new();
    reference.set_account(proposer, AccountState::with_balance(Amount(100)));
    assert_eq!(block.header.state_root, reference.compute_root().0);
    assert_eq!(chain.state_root(), StateRoot::EMPTY);
    assert!(chain.get_account(&proposer).is_none());
    assert_eq!(chain.height(), BlockHeight::GENESIS);
    chain.process_block(block.clone()).await.unwrap();
    assert_eq!(chain.state_root(), reference.compute_root());
    assert_eq!(chain.get_block(&block.hash()).unwrap().header.state_root, chain.state_root().0);
}

#[tokio::test]
async fn empty_or_arbitrary_claimed_root_is_rejected_without_reward_or_storage() {
    let chain = chain(Amount(100));
    let proposer = Address::new([7; 32]);
    let honest = chain.prepare_block(vec![], proposer).unwrap();
    for root in [Hash256::ZERO, Hash256::hash(b"invented state")] {
        let mut altered = honest.clone();
        altered.header.state_root = root;
        let error = chain.process_block(altered.clone()).await.unwrap_err();
        assert!(matches!(error, NexusError::InvalidStateRoot { expected, got }
            if expected == honest.header.state_root && got == root));
        assert_eq!(chain.state_root(), StateRoot::EMPTY);
        assert!(chain.get_account(&proposer).is_none());
        assert!(chain.get_block(&altered.hash()).is_none());
        assert_eq!(chain.stats().block_count, 1);
        assert_eq!(chain.height(), BlockHeight::GENESIS);
    }
    chain.process_block(honest).await.unwrap();
    assert_eq!(chain.get_account(&proposer).unwrap().balance, Amount(100));
}

#[tokio::test]
async fn transfer_root_commits_nonce_balances_and_final_reward_without_inventing_gas_fees() {
    let reward = Amount::from_units(64);
    let chain = chain(reward);
    let sender = key();
    let receiver = Address::new([2; 32]);
    let proposer = Address::new([3; 32]);
    chain.process_block(chain.prepare_block(vec![], sender.address()).unwrap()).await.unwrap();
    let tx = transfer(&sender, 0, receiver, Amount::from_units(5), Amount(7));
    let block = chain.prepare_block(vec![tx], proposer).unwrap();
    let mut reference = InMemoryState::new();
    let mut sender_account = AccountState::with_balance(Amount::from_units(59));
    sender_account.nonce = Nonce(1);
    reference.set_account(sender.address(), sender_account);
    reference.set_account(receiver, AccountState::with_balance(Amount::from_units(5)));
    reference.set_account(proposer, AccountState::with_balance(reward));
    assert_eq!(block.header.state_root, reference.compute_root().0);
    chain.process_block(block).await.unwrap();
    assert_eq!(chain.state_root(), reference.compute_root());
    assert_eq!(chain.get_account(&sender.address()).unwrap().balance, Amount::from_units(59));
}

#[tokio::test]
async fn self_transfer_and_reward_to_the_sender_have_one_exact_balance_update() {
    let chain = chain(Amount::from_units(64));
    let sender = key();
    chain.process_block(chain.prepare_block(vec![], sender.address()).unwrap()).await.unwrap();
    let block = chain.prepare_block(vec![transfer(&sender, 0, sender.address(), Amount::from_units(5), Amount::ZERO)], sender.address()).unwrap();
    let mut reference = InMemoryState::new();
    let mut account = AccountState::with_balance(Amount::from_units(128));
    account.nonce = Nonce(1);
    reference.set_account(sender.address(), account);
    assert_eq!(block.header.state_root, reference.compute_root().0);
    chain.process_block(block).await.unwrap();
    assert_eq!(chain.state_root(), reference.compute_root());
}

#[tokio::test]
async fn wrong_root_rolls_back_valid_registry_and_da_effects_then_allows_honest_retry() {
    let chain = chain(Amount::from_units(64));
    let sender = key();
    chain.process_block(chain.prepare_block(vec![], sender.address()).unwrap()).await.unwrap();
    let before = chain.state_root();
    let mut enrollment = transfer(&sender, 0, Address::ZERO, Amount::ZERO, Amount::ZERO).transaction;
    enrollment.tx_type = TransactionType::ValidatorRegister {
        public_key: sender.public_key().as_bytes().to_vec(), stake: Amount::from_units(32) };
    let mut batch = transfer(&sender, 1, Address::ZERO, Amount::ZERO, Amount::ZERO).transaction;
    batch.tx_type = TransactionType::BatchSubmit { batch_root: Hash256::hash(b"local batch"),
        batch_size: 1, compressed_data: vec![1; 500] };
    let honest = chain.prepare_block(vec![sender.sign_transaction(enrollment).unwrap(),
        sender.sign_transaction(batch).unwrap()], Address::ZERO).unwrap();
    assert_eq!(chain.state_root(), before);
    assert_eq!(chain.stats().validator_count, 0);
    assert_eq!(chain.stats().l2_batch_count, 0);
    let mut bad = honest.clone();
    bad.header.state_root = Hash256::ZERO;
    assert!(matches!(chain.process_block(bad).await, Err(NexusError::InvalidStateRoot { .. })));
    assert_eq!(chain.state_root(), before);
    assert_eq!(chain.get_account(&sender.address()).unwrap().nonce, Nonce(0));
    assert_eq!(chain.stats().validator_count, 0);
    assert_eq!(chain.stats().l2_batch_count, 0);
    assert_eq!(chain.height(), BlockHeight(1));
    chain.process_block(honest.clone()).await.unwrap();
    assert_eq!(chain.stats().validator_count, 1);
    assert_eq!(chain.stats().l2_batch_count, 1);
    assert_eq!(chain.get_account(&sender.address()).unwrap().nonce, Nonce(2));
    assert_eq!(chain.state_root().0, honest.header.state_root);
}

#[tokio::test]
async fn root_is_checked_against_local_reward_policy_and_the_current_parent() {
    let a = chain(Amount(100));
    let b = chain(Amount(101));
    let proposer = Address::new([7; 32]);
    let candidate = a.prepare_block(vec![], proposer).unwrap();
    assert!(matches!(b.process_block(candidate.clone()).await, Err(NexusError::InvalidStateRoot { .. })));
    assert_eq!(b.height(), BlockHeight::GENESIS);
    let stale = a.prepare_block(vec![], Address::ZERO).unwrap();
    a.process_block(candidate).await.unwrap();
    assert!(a.process_block(stale).await.is_err());
    assert_eq!(a.stats().block_count, 2);
    assert!(a.get_account(&Address::ZERO).is_none());
}

#[tokio::test]
async fn block_time_controls_expiry_and_historical_replay_is_deterministic() {
    let reward = Amount::from_units(64);
    let a = chain(reward);
    let b = chain(reward);
    let expired = chain(reward);
    let sender = key();
    let mut reference = InMemoryState::new();
    reference.set_account(sender.address(), AccountState::with_balance(reward));
    let mut funding = raw_block(&a, vec![], sender.address());
    funding.header.timestamp = Timestamp(1);
    funding.header.state_root = reference.compute_root().0;
    for node in [&a, &b, &expired] { node.process_block(funding.clone()).await.unwrap(); }
    let mut transaction = transfer(&sender, 0, Address::new([2; 32]), Amount::from_units(5), Amount::ZERO).transaction;
    transaction.timestamp = Timestamp(2);
    transaction.expires_at = Some(Timestamp(4));
    let signed = sender.sign_transaction(transaction).unwrap();
    assert!(nexus_crypto::verify_signed_transaction(&signed).is_err());
    assert!(nexus_crypto::signer::verify_signed_transaction_at(&signed, Timestamp(3)).unwrap());
    assert!(nexus_crypto::signer::verify_signed_transaction_at(&signed, Timestamp(4)).unwrap());
    let mut historical = raw_block(&a, vec![signed], Address::new([3; 32]));
    historical.header.timestamp = Timestamp(3);
    let mut sender_state = AccountState::with_balance(Amount::from_units(59));
    sender_state.nonce = Nonce(1);
    reference.set_account(sender.address(), sender_state);
    reference.set_account(Address::new([2; 32]), AccountState::with_balance(Amount::from_units(5)));
    reference.set_account(Address::new([3; 32]), AccountState::with_balance(reward));
    historical.header.state_root = reference.compute_root().0;
    for node in [&a, &b] {
        node.process_block(historical.clone()).await.unwrap();
        assert_eq!(node.state_root(), reference.compute_root());
    }
    let before = expired.state_root();
    historical.header.timestamp = Timestamp(5);
    assert!(matches!(expired.process_block(historical).await, Err(NexusError::TransactionExpired)));
    assert_eq!(expired.state_root(), before);
}

#[tokio::test]
async fn header_version_receipts_and_backdated_time_are_rejected_before_publication() {
    let chain = chain(Amount(100));
    let first = chain.prepare_block(vec![], Address::new([7; 32])).unwrap();
    chain.process_block(first.clone()).await.unwrap();
    let honest = chain.prepare_block(vec![], Address::new([8; 32])).unwrap();
    let before = chain.state_root();
    for case in 0..3 {
        let mut bad = honest.clone();
        match case {
            0 => bad.header.version += 1,
            1 => bad.header.receipts_root = Hash256::hash(b"unsupported receipts"),
            _ => bad.header.timestamp = Timestamp(first.header.timestamp.0 - 1),
        }
        assert!(chain.process_block(bad).await.is_err());
        assert_eq!(chain.state_root(), before);
        assert_eq!(chain.height(), BlockHeight(1));
    }
    chain.process_block(honest).await.unwrap();
}

#[tokio::test]
async fn reward_overflow_rejects_even_an_empty_block_without_advancing_height() {
    let chain = chain(Amount::MAX);
    let proposer = Address::new([7; 32]);
    chain.process_block(chain.prepare_block(vec![], proposer).unwrap()).await.unwrap();
    let before = chain.state_root();
    assert!(chain.prepare_block(vec![], proposer).is_err());
    assert!(chain.process_block(raw_block(&chain, vec![], proposer)).await.is_err());
    assert_eq!(chain.state_root(), before);
    assert_eq!(chain.height(), BlockHeight(1));
}
