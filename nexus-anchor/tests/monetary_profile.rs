//! Monetary transitions, replay domains and byte fees for the public-testnet profile.
//! Small integer fixtures are test parameters, not a proposed production allocation.
use nexus_anchor::{AnchorChain, AnchorChainConfig, MonetaryGenesis, MonetaryPolicy};
use nexus_core::{checkpoint::encode, Address, Amount, BlockHeight, ChainId, Hash256,
    Nonce, SignatureScheme, SignedTransaction, StateRoot, Timestamp, Transaction, TransactionType};
use nexus_crypto::{DilithiumKeypair, Signer};

fn key(seed: u8) -> DilithiumKeypair {
    DilithiumKeypair::from_seed(&[seed; 32], SignatureScheme::Dilithium3).unwrap()
}
fn config() -> AnchorChainConfig {
    AnchorChainConfig { chain_id: ChainId::TESTNET, block_reward: Amount::ZERO,
        fee_percentage: 0, ..Default::default() }
}
fn genesis(deployment: u8, balances: &[(Address, Amount)]) -> MonetaryGenesis {
    MonetaryGenesis { deployment: Hash256::new([deployment; 32]), allocations: balances.to_vec(),
        policy: MonetaryPolicy { max_issued: Amount(20_000_000), initial_block_reward: Amount(16),
            halving_interval: 2, min_gas_price: Amount(1), burn_basis_points: 2500 } }
}
fn transfer(chain: &AnchorChain, key: &DilithiumKeypair, nonce: u64, to: Address, amount: Amount) -> SignedTransaction {
    let mut tx = Transaction::transfer(ChainId::TESTNET, Nonce(nonce), to, amount, 200_000, Amount(2));
    tx.network_domain = chain.network_domain();
    tx.timestamp = Timestamp(1);
    tx.expires_at = Some(Timestamp(100));
    key.sign_transaction(tx).unwrap()
}

#[test]
fn genesis_is_canonical_binds_policy_and_rejects_invalid_allocations() {
    let a = key(1).address();
    let b = key(2).address();
    let expected = genesis(1, &[(a, Amount(1000)), (b, Amount(2000))]);
    let mut reordered = expected.clone();
    reordered.allocations.reverse();
    let first = AnchorChain::new_monetary(config(), expected.clone()).unwrap();
    let second = AnchorChain::new_monetary(config(), reordered).unwrap();
    assert_eq!(encode(first.genesis()).unwrap(), encode(second.genesis()).unwrap());
    assert_eq!(first.monetary_counters().unwrap().issued, Amount(3000));
    assert_eq!(first.monetary_counters().unwrap().supply().unwrap(), Amount(3000));
    let mut changed = expected.clone();
    changed.policy.burn_basis_points += 1;
    let other = AnchorChain::new_monetary(config(), changed).unwrap();
    assert_ne!(first.genesis().hash(), other.genesis().hash());
    assert_ne!(first.network_domain(), other.network_domain());
    for case in 0..7 {
        let mut bad = expected.clone();
        match case {
            0 => bad.allocations.push((a, Amount(1))),
            1 => bad.allocations[0].1 = Amount::ZERO,
            2 => bad.allocations[0].0 = Address::ZERO,
            3 => bad.policy.max_issued = Amount(2999),
            4 => bad.deployment = Hash256::ZERO,
            5 => bad.policy.halving_interval = 0,
            _ => bad.policy.burn_basis_points = 10_001,
        }
        assert!(AnchorChain::new_monetary(config(), bad).is_err(), "case {case}");
    }
    assert!(AnchorChain::new_monetary(AnchorChainConfig::default(), expected).is_err());
    let mut overflowing = genesis(1, &[(a, Amount::MAX), (b, Amount(1))]);
    overflowing.policy.max_issued = Amount::MAX;
    assert!(AnchorChain::new_monetary(config(), overflowing).is_err());
}

#[test]
fn issuance_halves_at_exact_heights_and_burn_never_reopens_the_lifetime_cap() {
    let policy = genesis(1, &[]).policy;
    let rewards: Vec<_> = (1..=12).map(|height|
        policy.reward(BlockHeight(height), Amount::ZERO).unwrap().0).collect();
    assert_eq!(rewards, vec![16, 16, 8, 8, 4, 4, 2, 2, 1, 1, 0, 0]);
    assert_eq!(policy.reward(BlockHeight(u64::MAX), Amount::ZERO).unwrap(), Amount::ZERO);
    assert_eq!(policy.reward(BlockHeight(1), Amount(19_999_997)).unwrap(), Amount(3));
    assert_eq!(policy.reward(BlockHeight(1), policy.max_issued).unwrap(), Amount::ZERO);
    assert!(policy.reward(BlockHeight(1), Amount(20_000_001)).is_err());
    assert!(policy.reward(BlockHeight::GENESIS, Amount::ZERO).is_err());
}

#[test]
fn fee_split_has_exact_rounding_and_handles_the_entire_amount_range() {
    let mut policy = genesis(1, &[]).policy;
    for points in [0, 1, 3333, 5000, 10_000] {
        policy.burn_basis_points = points;
        for fee in 0..=1000u128 {
            let (burned, paid) = policy.split_fee(Amount(fee)).unwrap();
            // This small-value oracle can safely multiply before dividing.
            assert_eq!(burned.0, fee * u128::from(points) / 10_000);
            assert_eq!(burned.checked_add(paid), Some(Amount(fee)));
        }
    }
    for (points, expected) in [(0, 0), (5000, u128::MAX / 2), (10_000, u128::MAX)] {
        policy.burn_basis_points = points;
        let (burned, paid) = policy.split_fee(Amount::MAX).unwrap();
        assert_eq!(burned, Amount(expected));
        assert_eq!(burned.checked_add(paid), Some(Amount::MAX));
    }
}

#[tokio::test]
async fn transfers_charge_actual_fees_split_burn_and_replay_identically_on_four_replicas() {
    let sender = key(1);
    let receiver = key(2).address();
    let proposer = key(3).address();
    let initial = genesis(1, &[(sender.address(), Amount(10_000_000))]);
    let nodes: Vec<_> = (0..4).map(|_| AnchorChain::new_monetary(config(), initial.clone()).unwrap()).collect();
    let tx = transfer(&nodes[0], &sender, 0, receiver, Amount(123));
    let expected_gas = 21_000 + 16 * encode(&tx).unwrap().len() as u128;
    let fee = expected_gas * 2;
    let burned = fee / 4;
    assert!(expected_gas < 200_000);
    let block = nodes[0].prepare_block_at(vec![tx], proposer, Timestamp(2)).unwrap();
    let before = nodes[0].state_root();
    nodes[0].validate_candidate(&block).unwrap();
    assert_eq!(nodes[0].state_root(), before);
    for node in &nodes {
        node.process_block(block.clone()).await.unwrap();
        assert_eq!(node.get_account(&sender.address()).unwrap().balance, Amount(10_000_000 - 123 - fee));
        assert_eq!(node.get_account(&sender.address()).unwrap().nonce, Nonce(1));
        assert_eq!(node.get_account(&receiver).unwrap().balance, Amount(123));
        assert_eq!(node.get_account(&proposer).unwrap().balance, Amount(fee - burned + 16));
        let counters = node.monetary_counters().unwrap();
        assert_eq!(counters.issued, Amount(10_000_016));
        assert_eq!(counters.burned, Amount(burned));
        assert_eq!(counters.fees_collected, Amount(fee));
        assert_eq!(counters.supply().unwrap(), Amount(10_000_016 - burned));
        assert_eq!(node.state_root().0, block.header.state_root);
    }
}

#[tokio::test]
async fn exhausted_cap_stays_exhausted_after_faucet_transfer_and_burning() {
    let faucet = key(1);
    let recipient = key(2).address();
    let mut initial = genesis(1, &[(faucet.address(), Amount(10_000_000))]);
    initial.policy.max_issued = Amount(10_000_003);
    let chain = AnchorChain::new_monetary(config(), initial).unwrap();
    chain.process_block(chain.prepare_block_at(vec![], faucet.address(), Timestamp(1)).unwrap()).await.unwrap();
    assert_eq!(chain.monetary_counters().unwrap().issued, Amount(10_000_003));
    let tx = transfer(&chain, &faucet, 0, recipient, Amount(100));
    chain.process_block(chain.prepare_block_at(vec![tx], faucet.address(), Timestamp(2)).unwrap()).await.unwrap();
    let counters = chain.monetary_counters().unwrap();
    assert_eq!(counters.issued, Amount(10_000_003));
    assert!(counters.burned > Amount::ZERO);
    chain.process_block(chain.prepare_block_at(vec![], faucet.address(), Timestamp(3)).unwrap()).await.unwrap();
    assert_eq!(chain.monetary_counters(), Some(counters));
}

#[tokio::test]
async fn deployment_domain_prevents_replay_and_cannot_be_added_after_signing() {
    let signer = key(1);
    let allocations = [(signer.address(), Amount(10_000_000))];
    let first = AnchorChain::new_monetary(config(), genesis(1, &allocations)).unwrap();
    let reset = AnchorChain::new_monetary(config(), genesis(2, &allocations)).unwrap();
    let tx = transfer(&first, &signer, 0, key(2).address(), Amount(1));
    let before = reset.export_checkpoint().unwrap();
    assert!(reset.prepare_block_at(vec![tx.clone()], signer.address(), Timestamp(2)).is_err());
    let mut altered = tx;
    altered.transaction.network_domain = reset.network_domain();
    assert!(reset.prepare_block_at(vec![altered], signer.address(), Timestamp(2)).is_err());
    let mut without_domain = transfer(&reset, &signer, 0, key(2).address(), Amount(1)).transaction;
    without_domain.network_domain = None;
    let without_domain = signer.sign_transaction(without_domain).unwrap();
    assert!(reset.prepare_block_at(vec![without_domain], signer.address(), Timestamp(2)).is_err());
    assert_eq!(reset.export_checkpoint().unwrap(), before);
}

#[tokio::test]
async fn failed_batch_and_forged_root_leave_balances_supply_nonce_and_da_unchanged() {
    let signer = key(1);
    let chain = AnchorChain::new_monetary(config(), genesis(1, &[(signer.address(), Amount(10_000_000))])).unwrap();
    let proposer = key(3).address();
    let valid = transfer(&chain, &signer, 0, key(2).address(), Amount(10));
    let wrong_nonce = transfer(&chain, &signer, 0, key(2).address(), Amount(20));
    let before = chain.export_checkpoint().unwrap();
    assert!(chain.prepare_block_at(vec![valid.clone(), wrong_nonce], proposer, Timestamp(2)).is_err());
    let mut forged = chain.prepare_block_at(vec![valid], proposer, Timestamp(2)).unwrap();
    forged.header.state_root = Hash256::ZERO;
    assert!(chain.process_block(forged).await.is_err());
    assert!(chain.submit_l2_batch(StateRoot::EMPTY, vec![1]).is_err());
    assert_eq!(chain.export_checkpoint().unwrap(), before);
    assert_eq!(chain.stats().l2_batch_count, 0);
}

#[tokio::test]
async fn checkpoint_requires_expected_genesis_and_replays_money_before_accepting_it() {
    let signer = key(1);
    let initial = genesis(1, &[(signer.address(), Amount(10_000_000))]);
    let chain = AnchorChain::new_monetary(config(), initial.clone()).unwrap();
    let tx = transfer(&chain, &signer, 0, key(2).address(), Amount(100));
    chain.process_block(chain.prepare_block_at(vec![tx], key(3).address(), Timestamp(2)).unwrap()).await.unwrap();
    let archive = chain.export_checkpoint().unwrap();
    let restored = AnchorChain::restore_monetary_checkpoint(&archive, &config(), &initial).unwrap();
    assert_eq!(restored.state_root(), chain.state_root());
    assert_eq!(restored.monetary_counters(), chain.monetary_counters());
    assert_eq!(restored.height(), chain.height());
    assert!(AnchorChain::restore_checkpoint(&archive, &config()).is_err());
    let mut wrong = initial.clone();
    wrong.policy.max_issued.0 += 1;
    assert!(AnchorChain::restore_monetary_checkpoint(&archive, &config(), &wrong).is_err());
    let next = chain.prepare_block_at(vec![], key(3).address(), Timestamp(3)).unwrap();
    for node in [&chain, &restored] { node.process_block(next.clone()).await.unwrap(); }
    assert_eq!(restored.state_root(), chain.state_root());
}

#[test]
fn payload_bytes_are_metered_and_unsupported_operations_cannot_create_escrow() {
    let signer = key(1);
    let policy = genesis(1, &[]).policy;
    let mut transaction = Transaction::transfer(ChainId::TESTNET, Nonce(0), signer.address(), Amount(1), 1_000_000, Amount(1));
    transaction.timestamp = Timestamp(1);
    transaction.tx_type = TransactionType::BatchSubmit { batch_root: Hash256::ZERO, batch_size: 1, compressed_data: vec![1] };
    let small = signer.sign_transaction(transaction.clone()).unwrap();
    transaction.tx_type = TransactionType::BatchSubmit { batch_root: Hash256::ZERO, batch_size: 1, compressed_data: vec![1; 101] };
    let large = signer.sign_transaction(transaction.clone()).unwrap();
    assert_eq!(policy.transaction_gas(&large).unwrap() - policy.transaction_gas(&small).unwrap(), 1600);
    transaction.tx_type = TransactionType::ValidatorRegister { public_key: signer.public_key().as_bytes().to_vec(), stake: Amount(1) };
    assert!(policy.transaction_gas(&signer.sign_transaction(transaction).unwrap()).is_err());
}

#[tokio::test]
async fn fee_accounting_handles_sender_receiver_and_proposer_aliases() {
    let signer = key(1);
    let addresses = [signer.address(), key(2).address(), key(3).address()];
    for receiver in 0..=1 {
        for proposer in 0..=2 {
            let initial = genesis(1, &[(signer.address(), Amount(10_000_000))]);
            let chain = AnchorChain::new_monetary(config(), initial).unwrap();
            let tx = transfer(&chain, &signer, 0, addresses[receiver], Amount(123));
            let fee = (21_000 + 16 * encode(&tx).unwrap().len() as u128) * 2;
            let burned = fee / 4;
            let mut balances = [10_000_000u128, 0, 0];
            balances[0] -= 123 + fee;
            balances[receiver] += 123;
            balances[proposer] += fee - burned + 16;
            let block = chain.prepare_block_at(vec![tx], addresses[proposer], Timestamp(2)).unwrap();
            chain.process_block(block).await.unwrap();
            for (address, balance) in addresses.iter().zip(balances) {
                assert_eq!(chain.get_account(address).unwrap_or_default().balance, Amount(balance));
            }
            assert_eq!(chain.get_account(&signer.address()).unwrap().nonce, Nonce(1));
            assert_eq!(chain.monetary_counters().unwrap().supply().unwrap(), Amount(balances.iter().sum()));
        }
    }
}

#[tokio::test]
async fn signed_batch_submission_charges_bytes_and_reconstructs_payload_after_replay() {
    let signer = key(1);
    let initial = genesis(1, &[(signer.address(), Amount(10_000_000))]);
    let chain = AnchorChain::new_monetary(config(), initial.clone()).unwrap();
    let payload = vec![7; 512];
    let before = chain.export_checkpoint().unwrap();
    let signed = chain.prepare_batch_submission(&signer, StateRoot(Hash256::hash(b"L2 commitment")), 3,
        payload.clone(), nexus_anchor::L1SubmissionOptions {
            gas_limit: 500_000, gas_price: Amount(2), expires_at: None }).unwrap();
    assert_eq!(chain.export_checkpoint().unwrap(), before);
    let fee = (21_000 + 16 * encode(&signed).unwrap().len() as u128) * 2;
    let timestamp = signed.transaction.timestamp;
    let block = chain.prepare_block_at(vec![signed.clone()], key(3).address(), timestamp).unwrap();
    chain.process_block(block).await.unwrap();
    let restored = AnchorChain::restore_monetary_checkpoint(&chain.export_checkpoint().unwrap(), &config(), &initial).unwrap();
    for node in [&chain, &restored] {
        assert_eq!(node.get_l2_batch_data(0).unwrap(), payload);
        assert_eq!(node.validate_processed_batch_submission(&signed).unwrap().data, payload);
        assert_eq!(node.monetary_counters().unwrap().fees_collected, Amount(fee));
        assert_eq!(node.monetary_counters().unwrap().supply().unwrap(), Amount(10_000_016 - fee / 4));
        assert_eq!(node.get_account(&signer.address()).unwrap().nonce, Nonce(1));
    }
}
