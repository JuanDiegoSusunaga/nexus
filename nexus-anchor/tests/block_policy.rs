//! Local transaction-domain and declared-gas admission policies.
use nexus_anchor::{AnchorChain, AnchorChainConfig};
use nexus_core::{Address, Amount, BlockHeight, ChainId, MerkleTree, NexusError, Nonce, SignatureScheme,
    SignedTransaction, Transaction};
use nexus_crypto::{DilithiumKeypair, Signer};

fn key() -> DilithiumKeypair {
    DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap()
}

fn transfer(key: &DilithiumKeypair, chain_id: ChainId, nonce: u64, gas: u64) -> SignedTransaction {
    key.sign_transaction(Transaction::transfer(chain_id, Nonce(nonce), Address::new([42; 32]),
        Amount(1), gas, Amount::ZERO)).unwrap()
}

async fn funded(config: AnchorChainConfig, sender: &DilithiumKeypair) -> AnchorChain {
    let chain = AnchorChain::new(config, key());
    chain.process_block(chain.prepare_block(vec![], sender.address()).unwrap()).await.unwrap();
    chain
}

#[tokio::test]
async fn default_chain_rejects_a_valid_signature_for_another_chain() {
    let sender = key();
    let chain = funded(AnchorChainConfig::default(), &sender).await;
    let before = chain.state_root();
    let tx = transfer(&sender, ChainId::MAINNET, 0, 21000);
    assert!(nexus_crypto::verify_signed_transaction(&tx).unwrap());
    assert!(matches!(chain.prepare_block(vec![tx], Address::ZERO), Err(NexusError::InvalidChainId)));
    assert_eq!(chain.state_root(), before);
    assert_eq!(chain.get_account(&sender.address()).unwrap().nonce, Nonce(0));
}

#[tokio::test]
async fn default_budget_rejects_aggregate_declared_gas_even_at_zero_price() {
    let sender = key();
    let chain = funded(AnchorChainConfig::default(), &sender).await;
    let before = chain.state_root();
    let txs = vec![transfer(&sender, ChainId::LOCAL, 0, 15_000_000),
        transfer(&sender, ChainId::LOCAL, 1, 15_000_001)];
    assert!(matches!(chain.prepare_block(txs, Address::ZERO), Err(NexusError::InvalidBlock(_))));
    assert_eq!(chain.state_root(), before);
    assert_eq!(chain.get_account(&sender.address()).unwrap().nonce, Nonce(0));
}

#[tokio::test]
async fn configured_domain_accepts_its_signature_and_rejects_a_relabelled_signature() {
    let sender = key();
    let chain = funded(AnchorChainConfig { chain_id: ChainId::TESTNET, ..Default::default() }, &sender).await;
    let original = transfer(&sender, ChainId::LOCAL, 0, 21000);
    let mut relabelled = original.clone();
    relabelled.transaction.chain_id = ChainId::TESTNET;
    assert!(chain.prepare_block(vec![relabelled], Address::ZERO).is_err());
    assert!(matches!(chain.prepare_block(vec![original], Address::ZERO), Err(NexusError::InvalidChainId)));
    let honest = chain.prepare_block(vec![transfer(&sender, ChainId::TESTNET, 0, 21000)], Address::ZERO).unwrap();
    chain.process_block(honest).await.unwrap();
    assert_eq!(chain.get_account(&sender.address()).unwrap().nonce, Nonce(1));
    assert_eq!(chain.get_account(&Address::new([42; 32])).unwrap().balance, Amount(1));
}

#[tokio::test]
async fn received_block_with_a_correct_root_still_must_match_the_local_domain() {
    let sender = key();
    let local = funded(AnchorChainConfig::default(), &sender).await;
    let foreign = AnchorChain::new(AnchorChainConfig { chain_id: ChainId::MAINNET, ..Default::default() }, key());
    foreign.process_block(local.latest_block().unwrap()).await.unwrap();
    let candidate = foreign.prepare_block(vec![transfer(&sender, ChainId::MAINNET, 0, 21000)], Address::ZERO).unwrap();
    let before = local.state_root();
    assert!(matches!(local.process_block(candidate.clone()).await, Err(NexusError::InvalidChainId)));
    assert_eq!(local.state_root(), before);
    assert_eq!(local.height(), BlockHeight(1));
    assert!(local.get_block(&candidate.hash()).is_none());
    assert!(local.get_account(&Address::ZERO).is_none());
    assert!(local.get_account(&Address::new([42; 32])).is_none());
    assert_eq!(local.get_account(&sender.address()).unwrap().nonce, Nonce(0));
    foreign.process_block(candidate).await.unwrap();
}

#[tokio::test]
async fn received_overbudget_block_is_atomic_and_exact_budget_can_be_retried() {
    let sender = key();
    let strict = funded(AnchorChainConfig { block_gas_limit: 42000, ..Default::default() }, &sender).await;
    let permissive = AnchorChain::new(AnchorChainConfig { block_gas_limit: 42001, ..Default::default() }, key());
    permissive.process_block(strict.latest_block().unwrap()).await.unwrap();
    let txs = vec![transfer(&sender, ChainId::LOCAL, 0, 21000), transfer(&sender, ChainId::LOCAL, 1, 21001)];
    let candidate = permissive.prepare_block(txs, Address::ZERO).unwrap();
    let before = strict.state_root();
    let balance = strict.get_account(&sender.address()).unwrap().balance;
    assert!(matches!(strict.process_block(candidate.clone()).await,
        Err(NexusError::InvalidBlock(message)) if message == "L1 declared block gas limit exceeded"));
    assert_eq!(strict.state_root(), before);
    assert_eq!(strict.height(), BlockHeight(1));
    assert_eq!(strict.stats().block_count, 2);
    assert!(strict.get_block(&candidate.hash()).is_none());
    assert!(strict.get_account(&Address::ZERO).is_none());
    assert!(strict.get_account(&Address::new([42; 32])).is_none());
    assert_eq!(strict.get_account(&sender.address()).unwrap().nonce, Nonce(0));
    let honest = strict.prepare_block(vec![transfer(&sender, ChainId::LOCAL, 0, 21000),
        transfer(&sender, ChainId::LOCAL, 1, 21000)], Address::ZERO).unwrap();
    strict.process_block(honest).await.unwrap();
    assert_eq!(strict.get_account(&sender.address()).unwrap().nonce, Nonce(2));
    assert_eq!(strict.get_account(&sender.address()).unwrap().balance, Amount(balance.0 - 2));
    assert_eq!(strict.get_account(&Address::new([42; 32])).unwrap().balance, Amount(2));
    permissive.process_block(candidate).await.unwrap();
}

#[tokio::test]
async fn aggregate_gas_cannot_wrap_at_u64_maximum() {
    let sender = key();
    let chain = funded(AnchorChainConfig { block_gas_limit: u64::MAX, ..Default::default() }, &sender).await;
    let honest = chain.prepare_block(vec![transfer(&sender, ChainId::LOCAL, 0, 21000),
        transfer(&sender, ChainId::LOCAL, 1, 21000)], Address::ZERO).unwrap();
    let overflowing = vec![transfer(&sender, ChainId::LOCAL, 0, u64::MAX),
        transfer(&sender, ChainId::LOCAL, 1, u64::MAX)];
    assert!(matches!(chain.prepare_block(overflowing.clone(), Address::ZERO), Err(NexusError::InvalidBlock(_))));
    // Gas reservations do not alter balances, so the original root is still correct.
    let mut received = honest.clone();
    received.body.transactions = overflowing;
    received.header.timestamp = received.body.transactions.iter()
        .map(|tx| tx.transaction.timestamp).max().unwrap().max(received.header.timestamp);
    received.header.transactions_root = MerkleTree::from_leaves(received.transaction_hashes()).root();
    let before = chain.state_root();
    assert!(matches!(chain.process_block(received).await, Err(NexusError::InvalidBlock(_))));
    assert_eq!(chain.state_root(), before);
    assert_eq!(chain.height(), BlockHeight(1));
    chain.process_block(honest).await.unwrap();
}

#[tokio::test]
async fn single_reservation_at_u64_maximum_is_representable_and_accepted() {
    let sender = key();
    let chain = funded(AnchorChainConfig { block_gas_limit: u64::MAX, ..Default::default() }, &sender).await;
    let block = chain.prepare_block(vec![transfer(&sender, ChainId::LOCAL, 0, u64::MAX)], Address::ZERO).unwrap();
    chain.process_block(block).await.unwrap();
    assert_eq!(chain.get_account(&sender.address()).unwrap().nonce, Nonce(1));
}

#[tokio::test]
async fn zero_budget_accepts_empty_blocks_and_rejects_transactions() {
    let sender = key();
    let chain = funded(AnchorChainConfig { block_gas_limit: 0, ..Default::default() }, &sender).await;
    assert!(matches!(chain.prepare_block(vec![transfer(&sender, ChainId::LOCAL, 0, 21000)], Address::ZERO),
        Err(NexusError::InvalidBlock(_))));
    chain.process_block(chain.prepare_block(vec![], Address::ZERO).unwrap()).await.unwrap();
    assert_eq!(chain.height(), BlockHeight(2));
    assert_eq!(chain.get_account(&sender.address()).unwrap().nonce, Nonce(0));
}
