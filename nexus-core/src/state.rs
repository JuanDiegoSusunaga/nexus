//! State management for NEXUS blockchain
//!
//! Defines account state and state root structures for both layers.

use crate::{Address, Amount, Hash256, Nonce, NexusError, Hashable, Encodable};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Account state in the NEXUS blockchain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountState {
    /// Account balance
    pub balance: Amount,
    /// Transaction nonce (for replay protection)
    pub nonce: Nonce,
    /// Code hash (for contract accounts)
    pub code_hash: Option<Hash256>,
    /// Storage root (for contract accounts)
    pub storage_root: Option<Hash256>,
    /// Public key epoch (for key rotation tracking)
    pub key_epoch: u64,
    /// Validator stake (if validator)
    pub stake: Option<ValidatorStake>,
}

impl AccountState {
    /// Create a new empty account
    pub fn new() -> Self {
        Self {
            balance: Amount::ZERO,
            nonce: Nonce::new(0),
            code_hash: None,
            storage_root: None,
            key_epoch: 0,
            stake: None,
        }
    }

    /// Create account with initial balance
    pub fn with_balance(balance: Amount) -> Self {
        Self {
            balance,
            nonce: Nonce::new(0),
            code_hash: None,
            storage_root: None,
            key_epoch: 0,
            stake: None,
        }
    }

    /// Check if this is a contract account
    pub fn is_contract(&self) -> bool {
        self.code_hash.is_some()
    }

    /// Check if this is a validator account
    pub fn is_validator(&self) -> bool {
        self.stake.is_some()
    }

    /// Increment nonce
    pub fn increment_nonce(&mut self) {
        self.nonce.increment();
    }

    /// Add balance
    pub fn credit(&mut self, amount: Amount) -> Result<(), NexusError> {
        self.balance = self.balance.checked_add(amount).ok_or_else(|| {
            NexusError::StateError("Balance overflow".into())
        })?;
        Ok(())
    }

    /// Subtract balance
    pub fn debit(&mut self, amount: Amount) -> Result<(), NexusError> {
        self.balance = self.balance.checked_sub(amount).ok_or_else(|| {
            NexusError::InsufficientBalance {
                required: amount.0,
                available: self.balance.0,
            }
        })?;
        Ok(())
    }
}

impl Default for AccountState {
    fn default() -> Self {
        Self::new()
    }
}

impl Hashable for AccountState {
    fn hash(&self) -> Hash256 {
        let encoded = bincode::serialize(self).expect("AccountState serialization should not fail");
        Hash256::hash(&encoded)
    }
}

impl Encodable for AccountState {
    fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("AccountState serialization should not fail")
    }

    fn decode(bytes: &[u8]) -> Result<Self, NexusError> {
        bincode::deserialize(bytes).map_err(|e| NexusError::SerializationError(e.to_string()))
    }
}

/// Validator stake information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorStake {
    /// Staked amount
    pub amount: Amount,
    /// Epoch when stake was deposited
    pub start_epoch: u64,
    /// Epoch when stake can be withdrawn (if exiting)
    pub exit_epoch: Option<u64>,
    /// Accumulated rewards
    pub rewards: Amount,
    /// Slashing history
    pub slashed: bool,
}

impl ValidatorStake {
    pub fn new(amount: Amount, start_epoch: u64) -> Self {
        Self {
            amount,
            start_epoch,
            exit_epoch: None,
            rewards: Amount::ZERO,
            slashed: false,
        }
    }

    /// Check if validator is active (not exiting)
    pub fn is_active(&self) -> bool {
        self.exit_epoch.is_none() && !self.slashed
    }

    /// Total stake including rewards
    pub fn effective_stake(&self) -> Amount {
        if self.slashed {
            Amount::ZERO
        } else {
            self.amount.saturating_add(self.rewards)
        }
    }
}

/// State root representing the entire state trie
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StateRoot(pub Hash256);

impl StateRoot {
    pub const EMPTY: Self = Self(Hash256::ZERO);

    pub fn new(hash: Hash256) -> Self {
        Self(hash)
    }

    pub fn as_hash(&self) -> Hash256 {
        self.0
    }
}

impl From<Hash256> for StateRoot {
    fn from(hash: Hash256) -> Self {
        Self(hash)
    }
}

/// In-memory state for testing and quick operations
#[derive(Debug, Clone, Default)]
pub struct InMemoryState {
    accounts: HashMap<Address, AccountState>,
    code: HashMap<Hash256, Vec<u8>>,
    storage: HashMap<(Address, Hash256), Vec<u8>>,
}

impl InMemoryState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get account state
    pub fn get_account(&self, address: &Address) -> Option<&AccountState> {
        self.accounts.get(address)
    }

    /// Get mutable account state
    pub fn get_account_mut(&mut self, address: &Address) -> Option<&mut AccountState> {
        self.accounts.get_mut(address)
    }

    /// Set account state
    pub fn set_account(&mut self, address: Address, state: AccountState) {
        self.accounts.insert(address, state);
    }

    /// Get or create account
    pub fn get_or_create_account(&mut self, address: &Address) -> &mut AccountState {
        self.accounts.entry(*address).or_insert_with(AccountState::new)
    }

    /// Check if account exists
    pub fn account_exists(&self, address: &Address) -> bool {
        self.accounts.contains_key(address)
    }

    /// Get contract code
    pub fn get_code(&self, code_hash: &Hash256) -> Option<&Vec<u8>> {
        self.code.get(code_hash)
    }

    /// Set contract code
    pub fn set_code(&mut self, code: Vec<u8>) -> Hash256 {
        let hash = Hash256::hash(&code);
        self.code.insert(hash, code);
        hash
    }

    /// Get storage value
    pub fn get_storage(&self, address: &Address, key: &Hash256) -> Option<&Vec<u8>> {
        self.storage.get(&(*address, *key))
    }

    /// Set storage value
    pub fn set_storage(&mut self, address: Address, key: Hash256, value: Vec<u8>) {
        self.storage.insert((address, key), value);
    }

    /// Compute state root
    pub fn compute_root(&self) -> StateRoot {
        // An empty account set has the canonical empty root.
        if self.accounts.is_empty() {
            return StateRoot::EMPTY;
        }
        // Simplified: just hash all account data
        // In production, use a Merkle Patricia Trie
        let mut data = Vec::new();
        let mut sorted_accounts: Vec<_> = self.accounts.iter().collect();
        sorted_accounts.sort_by_key(|(addr, _)| addr.0);

        for (addr, state) in sorted_accounts {
            data.extend_from_slice(&addr.0);
            data.extend_from_slice(&state.encode());
        }

        StateRoot(Hash256::hash(&data))
    }

    /// Transfer between accounts
    pub fn transfer(
        &mut self,
        from: &Address,
        to: &Address,
        amount: Amount,
    ) -> Result<(), NexusError> {
        // Debit from sender
        let sender = self.get_or_create_account(from);
        sender.debit(amount)?;

        // Credit to receiver
        let receiver = self.get_or_create_account(to);
        receiver.credit(amount)?;

        Ok(())
    }

    /// Get total number of accounts
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }
}

/// State diff for efficient synchronization
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StateDiff {
    /// Modified accounts
    pub modified: HashMap<Address, AccountState>,
    /// Deleted accounts
    pub deleted: Vec<Address>,
    /// New code
    pub new_code: HashMap<Hash256, Vec<u8>>,
    /// Modified storage
    pub storage_changes: HashMap<(Address, Hash256), Option<Vec<u8>>>,
}

impl StateDiff {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.modified.is_empty()
            && self.deleted.is_empty()
            && self.new_code.is_empty()
            && self.storage_changes.is_empty()
    }

    pub fn add_modified(&mut self, address: Address, state: AccountState) {
        self.modified.insert(address, state);
    }

    pub fn add_deleted(&mut self, address: Address) {
        self.deleted.push(address);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_state() {
        let mut account = AccountState::with_balance(Amount::from_units(100));

        assert!(account.credit(Amount::from_units(50)).is_ok());
        assert_eq!(account.balance, Amount::from_units(150));

        assert!(account.debit(Amount::from_units(100)).is_ok());
        assert_eq!(account.balance, Amount::from_units(50));

        assert!(account.debit(Amount::from_units(100)).is_err());
    }

    #[test]
    fn test_in_memory_state_transfer() {
        let mut state = InMemoryState::new();

        let alice = Address::new([1u8; 32]);
        let bob = Address::new([2u8; 32]);

        state.set_account(alice, AccountState::with_balance(Amount::from_units(1000)));
        state.set_account(bob, AccountState::new());

        assert!(state.transfer(&alice, &bob, Amount::from_units(100)).is_ok());

        assert_eq!(
            state.get_account(&alice).unwrap().balance,
            Amount::from_units(900)
        );
        assert_eq!(
            state.get_account(&bob).unwrap().balance,
            Amount::from_units(100)
        );
    }
}
