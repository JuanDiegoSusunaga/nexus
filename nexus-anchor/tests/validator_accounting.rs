//! Monetary accounting boundaries required before using stake on a public testnet.
use nexus_anchor::{Validator, ValidatorRegistry, ValidatorSet};
use nexus_anchor::validator::SlashType;
use nexus_core::{Address, Amount};

#[test]
fn stake_overflow_rejects_registration_without_changing_the_set() {
    let first = Address::new([1; 32]);
    let second = Address::new([2; 32]);
    let mut set = ValidatorSet::new();
    set.add_validator(Validator::new(first, vec![], Amount::MAX)).unwrap();
    assert!(set.add_validator(Validator::new(second, vec![], Amount(1))).is_err());
    assert_eq!(set.count(), 1);
    assert!(set.get_validator(&second).is_none());
    assert_eq!(set.total_stake(), Amount::MAX);
    set.remove_validator(&first).unwrap();
    assert_eq!(set.total_stake(), Amount::ZERO);
}

#[test]
fn slashing_updates_total_stake_and_removal_conserves_the_remainder() {
    let first = Address::new([1; 32]);
    let second = Address::new([2; 32]);
    let mut registry = ValidatorRegistry::new(Amount(1));
    registry.register(first, vec![], Amount(101)).unwrap();
    registry.register(second, vec![], Amount(99)).unwrap();
    let penalty = registry.slash(&first, SlashType::DoubleSigning).unwrap();
    assert_eq!(penalty, Amount(5));
    assert_eq!(registry.validator_set().total_stake(), Amount(195));
    let validator = registry.validator_set().get_validator(&first).unwrap();
    assert_eq!(validator.stake, Amount(96));
    assert!(validator.is_jailed());
    registry.validator_set_mut().remove_validator(&first).unwrap();
    assert_eq!(registry.validator_set().total_stake(), Amount(99));
    registry.validator_set_mut().remove_validator(&second).unwrap();
    assert_eq!(registry.validator_set().total_stake(), Amount::ZERO);
}

#[test]
fn maximum_stake_penalty_uses_exact_percentage_without_overflow() {
    for (kind, percent) in [(SlashType::DoubleSigning, 5), (SlashType::Downtime, 1)] {
        let address = Address::new([1; 32]);
        let mut registry = ValidatorRegistry::new(Amount(1));
        registry.register(address, vec![], Amount::MAX).unwrap();
        // An independent quotient/remainder form avoids overflowing MAX * percent.
        let expected = (u128::MAX / 100) * percent + (u128::MAX % 100) * percent / 100;
        let penalty = registry.slash(&address, kind).unwrap();
        assert_eq!(penalty, Amount(expected));
        assert_eq!(registry.validator_set().total_stake(), Amount(u128::MAX - expected));
        assert_eq!(registry.validator_set().get_validator(&address).unwrap().stake,
            Amount(u128::MAX - expected));
    }
}
