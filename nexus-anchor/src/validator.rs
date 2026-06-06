//! Validator Management for Anchor Layer
//!
//! Handles validator registration, staking, slashing, and set management.

use nexus_core::{Address, Amount, BlockHeight, Hash256, NexusError, Timestamp};
use nexus_crypto::DilithiumPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Individual validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    /// Validator address
    pub address: Address,
    /// Public key for signing
    pub public_key: Vec<u8>,
    /// Staked amount
    pub stake: Amount,
    /// Commission rate (0-100%)
    pub commission: u8,
    /// Registration timestamp
    pub registered_at: Timestamp,
    /// Validator status
    pub status: ValidatorStatus,
    /// Number of blocks proposed
    pub blocks_proposed: u64,
    /// Number of blocks missed
    pub blocks_missed: u64,
    /// Accumulated rewards
    pub rewards: Amount,
    /// Jailed until (if jailed)
    pub jailed_until: Option<Timestamp>,
}

impl Validator {
    /// Create a new validator
    pub fn new(address: Address, public_key: Vec<u8>, stake: Amount) -> Self {
        Self {
            address,
            public_key,
            stake,
            commission: 10, // 10% default
            registered_at: Timestamp::now(),
            status: ValidatorStatus::Pending,
            blocks_proposed: 0,
            blocks_missed: 0,
            rewards: Amount::ZERO,
            jailed_until: None,
        }
    }

    /// Check if validator is active
    pub fn is_active(&self) -> bool {
        matches!(self.status, ValidatorStatus::Active)
    }

    /// Check if validator is jailed
    pub fn is_jailed(&self) -> bool {
        matches!(self.status, ValidatorStatus::Jailed)
    }

    /// Calculate voting power (stake-weighted)
    pub fn voting_power(&self) -> u64 {
        if self.is_active() {
            // Voting power proportional to stake
            (self.stake.0 / 1_000_000_000_000_000_000) as u64
        } else {
            0
        }
    }

    /// Record a proposed block
    pub fn record_proposed(&mut self) {
        self.blocks_proposed += 1;
    }

    /// Record a missed block
    pub fn record_missed(&mut self) {
        self.blocks_missed += 1;
    }

    /// Add rewards
    pub fn add_rewards(&mut self, amount: Amount) {
        self.rewards = self.rewards.saturating_add(amount);
    }

    /// Calculate uptime percentage
    pub fn uptime(&self) -> f64 {
        let total = self.blocks_proposed + self.blocks_missed;
        if total == 0 {
            100.0
        } else {
            (self.blocks_proposed as f64 / total as f64) * 100.0
        }
    }
}

/// Validator status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    /// Pending activation
    Pending,
    /// Active and validating
    Active,
    /// Jailed for misbehavior
    Jailed,
    /// Voluntarily exiting
    Exiting,
    /// Exited
    Exited,
}

/// Validator set management
#[derive(Debug, Clone, Default)]
pub struct ValidatorSet {
    /// All validators by address
    validators: HashMap<Address, Validator>,
    /// Total staked amount
    total_stake: Amount,
    /// Maximum number of active validators
    max_validators: usize,
}

impl ValidatorSet {
    /// Create a new empty validator set
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
            total_stake: Amount::ZERO,
            max_validators: 100,
        }
    }

    /// Create with custom max validators
    pub fn with_max_validators(max: usize) -> Self {
        Self {
            validators: HashMap::new(),
            total_stake: Amount::ZERO,
            max_validators: max,
        }
    }

    /// Add a validator
    pub fn add_validator(&mut self, validator: Validator) -> Result<(), NexusError> {
        if self.validators.contains_key(&validator.address) {
            return Err(NexusError::InvalidTransaction(
                "Validator already exists".into(),
            ));
        }

        self.total_stake = self.total_stake.saturating_add(validator.stake);
        self.validators.insert(validator.address, validator);

        Ok(())
    }

    /// Remove a validator
    pub fn remove_validator(&mut self, address: &Address) -> Option<Validator> {
        if let Some(validator) = self.validators.remove(address) {
            self.total_stake = self.total_stake.saturating_sub(validator.stake);
            Some(validator)
        } else {
            None
        }
    }

    /// Get a validator
    pub fn get_validator(&self, address: &Address) -> Option<&Validator> {
        self.validators.get(address)
    }

    /// Get mutable validator
    pub fn get_validator_mut(&mut self, address: &Address) -> Option<&mut Validator> {
        self.validators.get_mut(address)
    }

    /// Get all active validators (sorted by stake)
    pub fn active_validators(&self) -> Vec<&Validator> {
        let mut active: Vec<_> = self
            .validators
            .values()
            .filter(|v| v.is_active())
            .collect();

        // Sort by stake (descending)
        active.sort_by(|a, b| b.stake.0.cmp(&a.stake.0));

        // Limit to max validators
        active.truncate(self.max_validators);

        active
    }

    /// Get number of active validators
    pub fn active_count(&self) -> usize {
        self.validators.values().filter(|v| v.is_active()).count()
    }

    /// Get total stake
    pub fn total_stake(&self) -> Amount {
        self.total_stake
    }

    /// Calculate total voting power
    pub fn total_voting_power(&self) -> u64 {
        self.validators.values().map(|v| v.voting_power()).sum()
    }

    /// Activate a pending validator
    pub fn activate_validator(&mut self, address: &Address) -> Result<(), NexusError> {
        let validator = self
            .validators
            .get_mut(address)
            .ok_or(NexusError::AccountNotFound(*address))?;

        if validator.status != ValidatorStatus::Pending {
            return Err(NexusError::InvalidTransaction(
                "Validator is not pending".into(),
            ));
        }

        validator.status = ValidatorStatus::Active;
        Ok(())
    }

    /// Jail a validator
    pub fn jail_validator(
        &mut self,
        address: &Address,
        until: Timestamp,
    ) -> Result<(), NexusError> {
        let validator = self
            .validators
            .get_mut(address)
            .ok_or(NexusError::AccountNotFound(*address))?;

        validator.status = ValidatorStatus::Jailed;
        validator.jailed_until = Some(until);

        Ok(())
    }

    /// Unjail a validator
    pub fn unjail_validator(&mut self, address: &Address) -> Result<(), NexusError> {
        let validator = self
            .validators
            .get_mut(address)
            .ok_or(NexusError::AccountNotFound(*address))?;

        if validator.status != ValidatorStatus::Jailed {
            return Err(NexusError::InvalidTransaction(
                "Validator is not jailed".into(),
            ));
        }

        if let Some(until) = validator.jailed_until {
            if Timestamp::now().as_millis() < until.as_millis() {
                return Err(NexusError::InvalidTransaction(
                    "Jail period not over".into(),
                ));
            }
        }

        validator.status = ValidatorStatus::Active;
        validator.jailed_until = None;

        Ok(())
    }

    /// Start validator exit
    pub fn start_exit(&mut self, address: &Address) -> Result<(), NexusError> {
        let validator = self
            .validators
            .get_mut(address)
            .ok_or(NexusError::AccountNotFound(*address))?;

        if validator.status != ValidatorStatus::Active {
            return Err(NexusError::InvalidTransaction(
                "Validator is not active".into(),
            ));
        }

        validator.status = ValidatorStatus::Exiting;
        Ok(())
    }

    /// Check if address is a validator
    pub fn is_validator(&self, address: &Address) -> bool {
        self.validators.contains_key(address)
    }

    /// Get validator count
    pub fn count(&self) -> usize {
        self.validators.len()
    }
}

/// Validator registry for on-chain management
pub struct ValidatorRegistry {
    /// Current validator set
    validator_set: ValidatorSet,
    /// Minimum stake required
    min_stake: Amount,
    /// Unbonding period in blocks
    unbonding_period: u64,
    /// Slashing parameters
    slashing_params: SlashingParams,
}

/// Slashing parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingParams {
    /// Slash percentage for double signing (0-100)
    pub double_sign_slash: u8,
    /// Slash percentage for downtime (0-100)
    pub downtime_slash: u8,
    /// Minimum blocks before downtime is penalized
    pub downtime_threshold: u64,
    /// Jail duration in milliseconds
    pub jail_duration_ms: u64,
}

impl Default for SlashingParams {
    fn default() -> Self {
        Self {
            double_sign_slash: 5,    // 5%
            downtime_slash: 1,       // 1%
            downtime_threshold: 100, // 100 missed blocks
            jail_duration_ms: 86_400_000, // 24 hours
        }
    }
}

impl ValidatorRegistry {
    /// Create a new validator registry
    pub fn new(min_stake: Amount) -> Self {
        Self {
            validator_set: ValidatorSet::new(),
            min_stake,
            unbonding_period: 21 * 24 * 60, // 21 days in blocks (assuming 1 block/min)
            slashing_params: SlashingParams::default(),
        }
    }

    /// Register a new validator
    pub fn register(
        &mut self,
        address: Address,
        public_key: Vec<u8>,
        stake: Amount,
    ) -> Result<(), NexusError> {
        if stake.0 < self.min_stake.0 {
            return Err(NexusError::InsufficientBalance {
                required: self.min_stake.0,
                available: stake.0,
            });
        }

        let validator = Validator::new(address, public_key, stake);
        self.validator_set.add_validator(validator)?;
        self.validator_set.activate_validator(&address)?;

        Ok(())
    }

    /// Slash a validator for misbehavior
    pub fn slash(
        &mut self,
        address: &Address,
        slash_type: SlashType,
    ) -> Result<Amount, NexusError> {
        let validator = self
            .validator_set
            .get_validator_mut(address)
            .ok_or(NexusError::AccountNotFound(*address))?;

        let slash_percent = match slash_type {
            SlashType::DoubleSigning => self.slashing_params.double_sign_slash,
            SlashType::Downtime => self.slashing_params.downtime_slash,
        };

        let slash_amount = Amount((validator.stake.0 * slash_percent as u128) / 100);
        validator.stake = validator.stake.saturating_sub(slash_amount);

        // Jail the validator
        let jail_until = Timestamp::from_millis(
            Timestamp::now().as_millis() + self.slashing_params.jail_duration_ms,
        );
        self.validator_set.jail_validator(address, jail_until)?;

        Ok(slash_amount)
    }

    /// Get current validator set
    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    /// Get mutable validator set
    pub fn validator_set_mut(&mut self) -> &mut ValidatorSet {
        &mut self.validator_set
    }
}

/// Types of slashable offenses
#[derive(Debug, Clone, Copy)]
pub enum SlashType {
    /// Signing two different blocks at same height
    DoubleSigning,
    /// Extended downtime
    Downtime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_creation() {
        let validator = Validator::new(
            Address::ZERO,
            vec![0u8; 1952],
            Amount::from_units(100),
        );

        assert_eq!(validator.status, ValidatorStatus::Pending);
        assert_eq!(validator.voting_power(), 0); // Not active yet
    }

    #[test]
    fn test_validator_set() {
        let mut set = ValidatorSet::new();

        let v1 = Validator::new(Address::new([1u8; 32]), vec![], Amount::from_units(100));
        let v2 = Validator::new(Address::new([2u8; 32]), vec![], Amount::from_units(200));

        set.add_validator(v1).unwrap();
        set.add_validator(v2).unwrap();

        assert_eq!(set.count(), 2);
        assert_eq!(set.active_count(), 0); // Both pending

        set.activate_validator(&Address::new([1u8; 32])).unwrap();
        assert_eq!(set.active_count(), 1);
    }

    #[test]
    fn test_validator_registry() {
        let mut registry = ValidatorRegistry::new(Amount::from_units(32));

        let result = registry.register(
            Address::new([1u8; 32]),
            vec![0u8; 1952],
            Amount::from_units(100),
        );

        assert!(result.is_ok());
        assert_eq!(registry.validator_set().active_count(), 1);
    }

    #[test]
    fn test_slashing() {
        let mut registry = ValidatorRegistry::new(Amount::from_units(32));

        registry
            .register(Address::new([1u8; 32]), vec![], Amount::from_units(100))
            .unwrap();

        let slashed = registry
            .slash(&Address::new([1u8; 32]), SlashType::DoubleSigning)
            .unwrap();

        assert!(slashed.0 > 0);

        let validator = registry
            .validator_set()
            .get_validator(&Address::new([1u8; 32]))
            .unwrap();
        assert!(validator.is_jailed());
    }
}
