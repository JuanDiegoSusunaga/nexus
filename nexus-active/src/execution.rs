//! Execution Engine for Active Layer
//!
//! Processes transactions and updates state at high throughput.

use nexus_core::{
    Address, Amount, Hash256, InMemoryState, NexusError, SignedTransaction,
    StateRoot, TransactionType, AccountState,
};
use nexus_crypto::verify_signed_transaction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Result of transaction execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Transaction hash
    pub tx_hash: Hash256,
    /// Execution success
    pub success: bool,
    /// Gas used
    pub gas_used: u64,
    /// Return data
    pub return_data: Vec<u8>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// State changes
    pub state_changes: Vec<StateChange>,
    /// Logs emitted
    pub logs: Vec<ExecutionLog>,
}

impl ExecutionResult {
    pub fn success(tx_hash: Hash256, gas_used: u64) -> Self {
        Self {
            tx_hash,
            success: true,
            gas_used,
            return_data: Vec::new(),
            error: None,
            state_changes: Vec::new(),
            logs: Vec::new(),
        }
    }

    pub fn failure(tx_hash: Hash256, error: String, gas_used: u64) -> Self {
        Self {
            tx_hash,
            success: false,
            gas_used,
            return_data: Vec::new(),
            error: Some(error),
            state_changes: Vec::new(),
            logs: Vec::new(),
        }
    }
}

/// State change from execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    /// Affected address
    pub address: Address,
    /// Change type
    pub change_type: ChangeType,
    /// Old value (if applicable)
    pub old_value: Option<Vec<u8>>,
    /// New value
    pub new_value: Vec<u8>,
}

/// Type of state change
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ChangeType {
    BalanceUpdate,
    NonceIncrement,
    StorageUpdate,
    CodeDeploy,
    AccountCreate,
}

/// Log emitted during execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionLog {
    /// Emitting address
    pub address: Address,
    /// Log topics
    pub topics: Vec<Hash256>,
    /// Log data
    pub data: Vec<u8>,
}

/// Execution engine for L2
pub struct ExecutionEngine {
    /// Current state
    state: InMemoryState,
    /// Gas price (minimum)
    min_gas_price: Amount,
    /// Block gas limit
    block_gas_limit: u64,
}

impl ExecutionEngine {
    /// Create a new execution engine
    pub fn new() -> Self {
        Self {
            state: InMemoryState::new(),
            min_gas_price: Amount(1_000_000_000), // 1 Gwei equivalent
            block_gas_limit: 30_000_000,
        }
    }

    /// Create with initial state
    pub fn with_state(state: InMemoryState) -> Self {
        Self {
            state,
            min_gas_price: Amount(1_000_000_000),
            block_gas_limit: 30_000_000,
        }
    }

    /// Execute a single transaction
    pub fn execute_transaction(
        &mut self,
        tx: &SignedTransaction,
    ) -> Result<ExecutionResult, NexusError> {
        let tx_hash = tx.hash();

        // Verify signature
        if !verify_signed_transaction(tx)? {
            return Ok(ExecutionResult::failure(
                tx_hash,
                "Invalid signature".into(),
                0,
            ));
        }

        // Check gas price
        if tx.transaction.gas_price.0 < self.min_gas_price.0 {
            return Ok(ExecutionResult::failure(
                tx_hash,
                "Gas price too low".into(),
                0,
            ));
        }

        // Get sender account
        let sender = self.state.get_or_create_account(&tx.sender);

        // Check nonce
        if tx.transaction.nonce.0 != sender.nonce.0 {
            return Ok(ExecutionResult::failure(
                tx_hash,
                format!(
                    "Invalid nonce: expected {}, got {}",
                    sender.nonce.0, tx.transaction.nonce.0
                ),
                0,
            ));
        }

        // Check balance
        let max_cost = tx.transaction.max_cost();
        if sender.balance.0 < max_cost.0 {
            return Ok(ExecutionResult::failure(
                tx_hash,
                "Insufficient balance".into(),
                0,
            ));
        }

        // Execute based on type
        let result = match &tx.transaction.tx_type {
            TransactionType::Transfer { to, amount } => {
                self.execute_transfer(&tx.sender, to, *amount, tx_hash)
            }
            TransactionType::Call { contract, method, args, value } => {
                self.execute_call(&tx.sender, contract, method, args, *value, tx_hash)
            }
            TransactionType::Deploy { code, init_data } => {
                self.execute_deploy(&tx.sender, code, init_data, tx_hash)
            }
            _ => Ok(ExecutionResult::failure(
                tx_hash,
                "Unsupported transaction type".into(),
                21000,
            )),
        };

        // Increment nonce on success or specific failures
        if let Ok(ref res) = result {
            if res.success {
                let sender = self.state.get_or_create_account(&tx.sender);
                sender.increment_nonce();
            }
        }

        result
    }

    /// Execute a transfer
    fn execute_transfer(
        &mut self,
        from: &Address,
        to: &Address,
        amount: Amount,
        tx_hash: Hash256,
    ) -> Result<ExecutionResult, NexusError> {
        let gas_used = 21000; // Base transfer gas

        // Perform transfer
        match self.state.transfer(from, to, amount) {
            Ok(()) => {
                let mut result = ExecutionResult::success(tx_hash, gas_used);
                result.state_changes.push(StateChange {
                    address: *from,
                    change_type: ChangeType::BalanceUpdate,
                    old_value: None,
                    new_value: amount.0.to_le_bytes().to_vec(),
                });
                result.state_changes.push(StateChange {
                    address: *to,
                    change_type: ChangeType::BalanceUpdate,
                    old_value: None,
                    new_value: amount.0.to_le_bytes().to_vec(),
                });
                Ok(result)
            }
            Err(e) => Ok(ExecutionResult::failure(tx_hash, e.to_string(), gas_used)),
        }
    }

    /// Execute a contract call
    fn execute_call(
        &mut self,
        _caller: &Address,
        contract: &Address,
        method: &str,
        _args: &[u8],
        value: Amount,
        tx_hash: Hash256,
    ) -> Result<ExecutionResult, NexusError> {
        // Check contract exists
        let contract_state = self.state.get_account(contract);
        if contract_state.is_none() || contract_state.unwrap().code_hash.is_none() {
            return Ok(ExecutionResult::failure(
                tx_hash,
                "Contract not found".into(),
                21000,
            ));
        }

        // Simplified: just return success with base gas
        // Full implementation would execute contract code
        let gas_used = 50000; // Placeholder

        let mut result = ExecutionResult::success(tx_hash, gas_used);
        result.return_data = format!("Called {}()", method).into_bytes();

        Ok(result)
    }

    /// Execute contract deployment
    fn execute_deploy(
        &mut self,
        deployer: &Address,
        code: &[u8],
        _init_data: &[u8],
        tx_hash: Hash256,
    ) -> Result<ExecutionResult, NexusError> {
        // Calculate contract address
        let deployer_nonce = self
            .state
            .get_account(deployer)
            .map(|a| a.nonce.0)
            .unwrap_or(0);

        let mut addr_input = Vec::new();
        addr_input.extend_from_slice(deployer.as_bytes());
        addr_input.extend_from_slice(&deployer_nonce.to_le_bytes());
        let contract_address = Address::from_public_key(&Hash256::hash(&addr_input).0);

        // Store code
        let code_hash = self.state.set_code(code.to_vec());

        // Create contract account
        let contract_account = AccountState {
            balance: Amount::ZERO,
            nonce: nexus_core::Nonce::new(0),
            code_hash: Some(code_hash),
            storage_root: None,
            key_epoch: 0,
            stake: None,
        };
        self.state.set_account(contract_address, contract_account);

        let gas_used = 21000 + (code.len() as u64 * 200); // Base + code cost

        let mut result = ExecutionResult::success(tx_hash, gas_used);
        result.return_data = contract_address.as_bytes().to_vec();
        result.state_changes.push(StateChange {
            address: contract_address,
            change_type: ChangeType::CodeDeploy,
            old_value: None,
            new_value: code.to_vec(),
        });

        Ok(result)
    }

    /// Execute a batch of transactions
    pub fn execute_batch(
        &mut self,
        transactions: &[SignedTransaction],
    ) -> Vec<ExecutionResult> {
        let mut results = Vec::with_capacity(transactions.len());
        let mut total_gas = 0u64;

        for tx in transactions {
            // Check block gas limit
            if total_gas + tx.transaction.gas_limit > self.block_gas_limit {
                results.push(ExecutionResult::failure(
                    tx.hash(),
                    "Block gas limit exceeded".into(),
                    0,
                ));
                continue;
            }

            match self.execute_transaction(tx) {
                Ok(result) => {
                    total_gas += result.gas_used;
                    results.push(result);
                }
                Err(e) => {
                    results.push(ExecutionResult::failure(tx.hash(), e.to_string(), 0));
                }
            }
        }

        results
    }

    /// Get current state root
    pub fn state_root(&self) -> StateRoot {
        self.state.compute_root()
    }

    /// Get account state
    pub fn get_account(&self, address: &Address) -> Option<&AccountState> {
        self.state.get_account(address)
    }

    /// Get state reference
    pub fn state(&self) -> &InMemoryState {
        &self.state
    }

    /// Get mutable state reference
    pub fn state_mut(&mut self) -> &mut InMemoryState {
        &mut self.state
    }
}

impl Default for ExecutionEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_core::{ChainId, Nonce, SignatureScheme, Transaction};
    use nexus_crypto::{DilithiumKeypair, Signer};

    #[test]
    fn test_execution_engine_creation() {
        let engine = ExecutionEngine::new();
        assert_eq!(engine.state_root(), StateRoot::EMPTY);
    }

    #[test]
    fn test_execute_transfer() {
        let mut engine = ExecutionEngine::new();

        // Create sender with balance
        let sender_keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
        let sender = sender_keypair.address();
        let receiver = Address::new([2u8; 32]);

        engine.state_mut().set_account(
            sender,
            AccountState::with_balance(Amount::from_units(1000)),
        );

        // Create transfer transaction
        let tx = Transaction::transfer(
            ChainId::LOCAL,
            Nonce::new(0),
            receiver,
            Amount::from_units(100),
            21000,
            Amount(1_000_000_000),
        );
        let signed = sender_keypair.sign_transaction(tx).unwrap();

        let result = engine.execute_transaction(&signed).unwrap();
        assert!(result.success);
        assert_eq!(result.gas_used, 21000);

        // Verify balances
        assert_eq!(
            engine.get_account(&sender).unwrap().balance,
            Amount::from_units(900)
        );
        assert_eq!(
            engine.get_account(&receiver).unwrap().balance,
            Amount::from_units(100)
        );
    }
}
