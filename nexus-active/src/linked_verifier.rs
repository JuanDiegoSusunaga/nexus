//! Sobre de aplicación para el certificado matemático de Lean.
//! Admite escalares Goldilocks canónicos, no raíces SHA3 arbitrarias.
//! La altura y la autorización son contexto externo, no restricciones del AIR.

use crate::verifier::{ProofType, StateProof};
use nexus_core::{BlockHeight, Hash256, NexusError, StateRoot};
use nexus_zk::stark::{air::TransitionStatement, field::{Felt, P}, linked::{self, LinkedProof},
    linked_codec::{decode_certificate, encode_certificate}, params::POW_BITS_RUNTIME};

#[derive(Clone, Debug)]
pub struct ExpectedTransition {
    pub pre: StateRoot,
    pub post: StateRoot,
    pub height: BlockHeight,
    pub steps: usize,
    pub pow_bits: u32,
}

#[derive(Clone, Debug)]
pub struct LinkedValidityProof {
    pub statement: TransitionStatement,
    pub proof: LinkedProof,
}

fn reject(message: &str) -> NexusError { NexusError::SecurityViolation(message.into()) }

fn verification_error(error: linked::VerifyError) -> NexusError {
    reject(&format!("El contrato del verificador rechazó: {error:?}"))
}

pub fn canonical_scalar(root: &StateRoot) -> Result<Felt, NexusError> {
    let bytes = root.0.as_bytes();
    let mut low = [0; 8];
    low.copy_from_slice(&bytes[..8]);
    let value = u64::from_le_bytes(low);
    if value >= P || bytes[8..].iter().any(|&b| b != 0) {
        return Err(reject("El modelo exige un escalar canónico, no un hash de 256 bits"));
    }
    Ok(Felt::new(value))
}

pub fn scalar_root(value: Felt) -> StateRoot {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&value.to_bytes());
    StateRoot::new(Hash256(bytes))
}

pub fn public_inputs(expected: &ExpectedTransition) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(72);
    bytes.extend_from_slice(expected.pre.0.as_bytes());
    bytes.extend_from_slice(expected.post.0.as_bytes());
    bytes.extend_from_slice(&expected.height.0.to_le_bytes());
    bytes
}

impl LinkedValidityProof {
    pub fn prove(pre: &StateRoot, witness: u64, steps: usize) -> Result<Self, NexusError> {
        if witness >= P { return Err(reject("Testigo no canónico")); }
        let (statement, proof) = linked::prove_transition(canonical_scalar(pre)?, Felt::new(witness), steps)
            .map_err(verification_error)?;
        Ok(Self { statement, proof })
    }

    pub fn post_root(&self) -> StateRoot { scalar_root(self.statement.output) }

    pub fn to_bytes(&self) -> Result<Vec<u8>, NexusError> {
        encode_certificate(&self.statement, &self.proof).map_err(verification_error)
    }

    pub fn runtime_pow_bits() -> u32 { POW_BITS_RUNTIME }
}

/// No altera estado. El contexto debe obtenerse por una ruta confiable del llamante.
pub fn verify_expected(proof: &StateProof, expected: &ExpectedTransition) -> Result<(), NexusError> {
    if !(linked::MIN_ROWS..=linked::MAX_ROWS).contains(&expected.steps) || !expected.steps.is_power_of_two()
        || (expected.pow_bits != 12 && expected.pow_bits != 20) {
        return Err(reject("Contexto fuera del perfil formalizado"));
    }
    let start = canonical_scalar(&expected.pre)?;
    let output = canonical_scalar(&expected.post)?;
    if proof.proof_type != ProofType::ZKValidity || proof.pre_state_root != expected.pre
        || proof.post_state_root != expected.post || proof.height != expected.height
        || proof.public_inputs != public_inputs(expected) {
        return Err(reject("El sobre no coincide con el contexto confiable"));
    }
    let (statement, linked) = decode_certificate(&proof.proof_data).map_err(verification_error)?;
    if statement.steps != expected.steps || statement.start != start || statement.output != output {
        return Err(reject("El certificado no corresponde al enunciado esperado"));
    }
    linked::verify_with_profile(&statement, &linked, expected.pow_bits).map_err(verification_error)
}
