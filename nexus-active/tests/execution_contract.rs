//! Unsupported contracts must not report execution that did not happen.
use nexus_active::ExecutionEngine;
use nexus_core::{AccountState, Address, Amount, ChainId, Hash256, Nonce, SignatureScheme,
    Transaction, TransactionType};
use nexus_crypto::{DilithiumKeypair, Signer};

fn key() -> DilithiumKeypair { DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap() }

#[test]
fn a_funded_call_to_existing_code_must_not_claim_a_simulated_success() {
    let signer = key(); let mut engine = ExecutionEngine::new();
    engine.state_mut().set_account(signer.address(), AccountState::with_balance(Amount::from_units(10)));
    let contract = Address::new([12; 32]);
    let code = vec![1, 2, 3]; let code_hash = engine.state_mut().set_code(code.clone());
    let mut account = AccountState::new(); account.code_hash = Some(code_hash);
    engine.state_mut().set_account(contract, account.clone());
    let before = engine.state_root();
    let tx = signer.sign_transaction(Transaction::call(ChainId::LOCAL, Nonce(0), contract,
        "pay".into(), vec![9], Amount(7), 50000, Amount(1_000_000_000))).unwrap();
    let result = engine.execute_transaction(&tx).unwrap();
    assert!(!result.success, "there is no contract interpreter");
    assert!(result.error.unwrap().contains("not supported"));
    assert!(result.return_data.is_empty() && result.state_changes.is_empty() && result.logs.is_empty());
    assert_eq!(result.gas_used, 0);
    assert_eq!(engine.state_root(), before);
    assert_eq!(engine.get_account(&contract), Some(&account));
    assert_eq!(engine.state().get_code(&code_hash), Some(&code));
    assert_eq!(engine.get_account(&signer.address()).unwrap().nonce, Nonce(0));
}

#[test]
fn deployment_cannot_claim_success_while_ignoring_initialization() {
    for init_data in [vec![], vec![5, 6]] {
        let signer = key(); let mut engine = ExecutionEngine::new();
        engine.state_mut().set_account(signer.address(), AccountState::with_balance(Amount::from_units(10)));
        let code = vec![10, 20]; let before = engine.state_root();
        let mut tx = Transaction::transfer(ChainId::LOCAL, Nonce(0), Address::ZERO, Amount::ZERO,
            50000, Amount(1_000_000_000));
        tx.tx_type = TransactionType::Deploy { code: code.clone(), init_data };
        let result = engine.execute_transaction(&signer.sign_transaction(tx).unwrap()).unwrap();
        assert!(!result.success, "no deployment or initialization interpreter exists");
        assert!(result.error.unwrap().contains("not supported"));
        assert!(result.return_data.is_empty() && result.state_changes.is_empty() && result.logs.is_empty());
        assert_eq!(engine.state_root(), before);
        assert!(engine.state().get_code(&Hash256::hash(&code)).is_none());
        assert_eq!(engine.get_account(&signer.address()).unwrap().nonce, Nonce(0));
        assert_eq!(engine.state().account_count(), 1);
    }
}

#[test]
fn unsupported_contract_work_does_not_prevent_a_real_transfer_at_the_same_nonce() {
    let signer = key(); let mut engine = ExecutionEngine::new();
    engine.state_mut().set_account(signer.address(), AccountState::with_balance(Amount::from_units(10)));
    let receiver = Address::new([42; 32]);
    let call = signer.sign_transaction(Transaction::call(ChainId::LOCAL, Nonce(0), Address::ZERO,
        "missing".into(), vec![], Amount::ZERO, 50000, Amount(1_000_000_000))).unwrap();
    let transfer = signer.sign_transaction(Transaction::transfer(ChainId::LOCAL, Nonce(0), receiver,
        Amount(11), 21000, Amount(1_000_000_000))).unwrap();
    let results = engine.execute_batch(&[call, transfer]);
    assert!(!results[0].success && results[1].success);
    assert_eq!(engine.get_account(&receiver).unwrap().balance, Amount(11));
    assert_eq!(engine.get_account(&signer.address()).unwrap().nonce, Nonce(1));
}
