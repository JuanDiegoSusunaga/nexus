//! Regressions for the review of 20 October 2026.
use nexus_core::{AccountState, Address, Amount, ChainId, InMemoryState, Nonce, Transaction};
#[test]
fn r06_failed_transfer_must_not_debit_sender() {
    let from = Address::new([1; 32]);
    let to = Address::new([2; 32]);
    let mut state = InMemoryState::new();
    state.set_account(from, AccountState::with_balance(Amount(100)));
    state.set_account(to, AccountState::with_balance(Amount::MAX));
    let before = state.compute_root();
    assert!(state.transfer(&from, &to, Amount(1)).is_err(), "control: recipient overflows");
    assert_eq!(state.compute_root(), before, "sender lost balance despite transfer failure");
}

#[test]
fn r10_max_cost_must_not_panic_on_public_numeric_inputs() {
    let tx = Transaction::transfer(ChainId::LOCAL, Nonce(0), Address::ZERO,
        Amount::ZERO, u64::MAX, Amount::MAX);
    assert!(std::panic::catch_unwind(|| tx.max_cost()).is_ok(),
        "unchecked gas_limit * gas_price panics in debug and wraps in release");
    assert!(tx.checked_max_cost().is_err());
    assert_eq!(tx.max_cost(), Amount::MAX);
}

#[test]
fn cost_overflow_is_rejected_and_legacy_estimation_saturates() {
    let tx = Transaction::transfer(ChainId::LOCAL, Nonce(0), Address::ZERO,
        Amount::MAX, 21000, Amount(1));
    assert!(tx.checked_max_cost().is_err());
    assert_eq!(tx.max_cost(), Amount::MAX);
}

#[test]
fn self_transfer_preserves_balance_and_failed_unknown_sender_creates_no_accounts() {
    let address = Address::new([1; 32]);
    let mut state = InMemoryState::new();
    let empty = state.compute_root();
    assert!(state.transfer(&address, &address, Amount(1)).is_err());
    assert_eq!(state.compute_root(), empty);
    assert_eq!(state.account_count(), 0);
    state.set_account(address, AccountState::with_balance(Amount(100)));
    let before = state.compute_root();
    state.transfer(&address, &address, Amount(100)).unwrap();
    assert_eq!(state.compute_root(), before);
}
