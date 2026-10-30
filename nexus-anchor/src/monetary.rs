//! Deterministic monetary rules for an opt-in public testnet profile.
//! Parameters are explicit genesis data, not a mainnet allocation or price model.
use crate::AnchorChainConfig;
use nexus_core::{checkpoint::encode, Address, Amount, BlockHeight, Hash256,
    NexusError, SignedTransaction, TransactionType};
use serde::{Deserialize, Serialize};

pub const MAX_GENESIS_ALLOCATIONS: usize = 10_000;
const BASIS_POINTS: u128 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonetaryPolicy {
    /// Lifetime issuance ceiling, including genesis. Burning does not reopen it.
    pub max_issued: Amount,
    /// Subsidy at heights 1..=halving_interval; halves thereafter, then becomes zero.
    pub initial_block_reward: Amount,
    pub halving_interval: u64,
    /// Explicit fixed-price floor; this is not an EIP-1559 fee market.
    pub min_gas_price: Amount,
    /// Burn this fraction of actual fees. The remainder goes to the block proposer.
    pub burn_basis_points: u16,
}

impl MonetaryPolicy {
    pub fn validate(&self) -> Result<(), NexusError> {
        if self.max_issued == Amount::ZERO || self.halving_interval == 0
            || self.min_gas_price == Amount::ZERO || u128::from(self.burn_basis_points) > BASIS_POINTS {
            return Err(NexusError::ConfigError("Invalid monetary cap, interval, gas price or burn fraction".into()));
        }
        Ok(())
    }

    pub fn reward(&self, height: BlockHeight, issued: Amount) -> Result<Amount, NexusError> {
        self.validate()?;
        if height == BlockHeight::GENESIS {
            return Err(NexusError::ConfigError("Block reward requires a post-genesis height".into()));
        }
        let remaining = self.max_issued.checked_sub(issued)
            .ok_or_else(|| NexusError::StateError("Lifetime issuance exceeds cap".into()))?;
        let era = (height.0 - 1) / self.halving_interval;
        let scheduled = if era >= 128 { 0 } else { self.initial_block_reward.0 >> era as u32 };
        Ok(Amount(scheduled.min(remaining.0)))
    }

    /// Actual fee split, avoiding an intermediate fee * basis_points overflow.
    pub fn split_fee(&self, fee: Amount) -> Result<(Amount, Amount), NexusError> {
        self.validate()?;
        let points = u128::from(self.burn_basis_points);
        let burned = (fee.0 / BASIS_POINTS) * points + (fee.0 % BASIS_POINTS) * points / BASIS_POINTS;
        Ok((Amount(burned), Amount(fee.0 - burned)))
    }

    /// Bounded work/byte fee for the operations supported by this profile.
    /// ML-DSA signatures and public keys are metered as part of the full envelope.
    pub fn transaction_gas(&self, tx: &SignedTransaction) -> Result<u64, NexusError> {
        match &tx.transaction.tx_type {
            TransactionType::Transfer { .. } | TransactionType::BatchSubmit { .. } => (),
            _ => return Err(NexusError::NotImplemented("Transaction type in monetary testnet profile".into())),
        }
        u64::try_from(encode(tx)?.len()).ok()
            .and_then(|size| size.checked_mul(16))
            .and_then(|cost| cost.checked_add(21_000))
            .ok_or_else(|| NexusError::InvalidTransaction("Monetary gas cost overflow".into()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonetaryGenesis {
    /// Fresh, nonzero 256-bit identifier for each reset/deployment.
    pub deployment: Hash256,
    pub policy: MonetaryPolicy,
    /// Canonicalized by address; duplicates and zero allocations are rejected.
    pub allocations: Vec<(Address, Amount)>,
}

impl MonetaryGenesis {
    pub(crate) fn canonical(&self, config: &AnchorChainConfig) -> Result<Self, NexusError> {
        self.policy.validate()?;
        if self.deployment == Hash256::ZERO || self.allocations.len() > MAX_GENESIS_ALLOCATIONS
            || config.block_reward != Amount::ZERO || config.fee_percentage != 0 {
            return Err(NexusError::ConfigError("Monetary genesis requires a deployment and disabled legacy rewards/fees".into()));
        }
        let mut canonical = self.clone();
        canonical.allocations.sort_by_key(|entry| entry.0.0);
        for (index, (address, amount)) in canonical.allocations.iter().enumerate() {
            if *address == Address::ZERO || *amount == Amount::ZERO
                || (index > 0 && canonical.allocations[index - 1].0 == *address) {
                return Err(NexusError::ConfigError("Invalid or duplicate monetary genesis allocation".into()));
            }
        }
        MonetaryCounters::genesis(&canonical)?;
        Ok(canonical)
    }

    pub fn network_domain(&self, config: &AnchorChainConfig) -> Result<Hash256, NexusError> {
        let canonical = self.canonical(config)?;
        Ok(Hash256::hash(&encode(&(b"NEXUS_MONETARY_GENESIS_V1".as_slice(),
            nexus_core::PROTOCOL_VERSION, config, canonical))?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonetaryCounters {
    pub issued: Amount,
    pub burned: Amount,
    pub fees_collected: Amount,
}

impl MonetaryCounters {
    pub(crate) fn genesis(genesis: &MonetaryGenesis) -> Result<Self, NexusError> {
        let issued = genesis.allocations.iter().try_fold(Amount::ZERO, |total, entry|
            total.checked_add(entry.1).ok_or_else(|| NexusError::ConfigError("Genesis supply overflow".into())))?;
        if issued > genesis.policy.max_issued {
            return Err(NexusError::ConfigError("Genesis issuance exceeds cap".into()));
        }
        Ok(Self { issued, burned: Amount::ZERO, fees_collected: Amount::ZERO })
    }

    pub fn supply(&self) -> Result<Amount, NexusError> {
        self.issued.checked_sub(self.burned)
            .ok_or_else(|| NexusError::StateError("Burned amount exceeds issuance".into()))
    }

    pub(crate) fn charge(&mut self, fee: Amount, burned: Amount) -> Result<(), NexusError> {
        let new_fees = self.fees_collected.checked_add(fee)
            .ok_or_else(|| NexusError::StateError("Lifetime fee counter overflow".into()))?;
        let new_burned = self.burned.checked_add(burned)
            .ok_or_else(|| NexusError::StateError("Lifetime burn counter overflow".into()))?;
        if burned > fee || new_burned > self.issued {
            return Err(NexusError::StateError("Invalid fee or burn accounting".into()));
        }
        self.fees_collected = new_fees;
        self.burned = new_burned;
        Ok(())
    }
}
