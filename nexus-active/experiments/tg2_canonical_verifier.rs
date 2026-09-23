//! Perfil experimental TG2 para la recurrencia del PoC; no valida una L2.
//! Acepta únicamente escalares canónicos de Goldilocks, NO hashes arbitrarios
//! de 256 bits. El núcleo heredado y su ruta de aceptación permanecen separados.

use bincode::Options;
use nexus_active::pq_verifier::PqValidityProof;
use nexus_active::verifier::{ProofType, StateProof};
use nexus_core::{BlockHeight, NexusError, StateRoot};
use nexus_zk::stark::{air::BLOWUP, field::{Felt, Fp2, P}, fri::NUM_QUERIES};

pub const MAX_PROOF_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_STEPS: usize = 1 << 18;

/// Contexto obtenido por el llamante de su estado confiable; no del mensaje remoto.
/// La altura se compara externamente, pero NO forma parte del enunciado del AIR.
#[derive(Clone, Debug)]
pub struct ExpectedTransition {
    pub pre: StateRoot,
    pub post: StateRoot,
    pub height: BlockHeight,
    pub steps: usize,
}

fn reject(message: &str) -> NexusError {
    NexusError::SecurityViolation(message.into())
}

pub fn canonical_scalar(root: &StateRoot) -> Result<Felt, NexusError> {
    let bytes = root.0.as_bytes();
    let mut low = [0; 8];
    low.copy_from_slice(&bytes[..8]);
    let value = u64::from_le_bytes(low);
    if value >= P || bytes[8..].iter().any(|&byte| byte != 0) {
        return Err(reject("El perfil admite escalares canónicos, no raíces SHA3 de 256 bits"));
    }
    Ok(Felt::new(value))
}

pub fn public_inputs(expected: &ExpectedTransition) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(72);
    bytes.extend_from_slice(expected.pre.0.as_bytes());
    bytes.extend_from_slice(expected.post.0.as_bytes());
    bytes.extend_from_slice(&expected.height.0.to_le_bytes());
    bytes
}

fn canonical_extension(value: Fp2) -> bool {
    value.c0.value() < P && value.c1.value() < P
}

/// Comprobaciones previas a cualquier aritmética del verificador heredado.
fn check_shape(pq: &PqValidityProof, steps: usize) -> Result<(), NexusError> {
    let domain = steps * BLOWUP;
    let depth = domain.trailing_zeros() as usize;
    let layers = (2 * steps).trailing_zeros() as usize;
    if pq.statement.start.value() >= P || pq.statement.output.value() >= P
        || !canonical_extension(pq.proof.fri_final)
        || pq.proof.fri_roots.len() != layers
        || pq.proof.queries.len() != NUM_QUERIES {
        return Err(reject("Enunciado, campo o dimensiones de prueba inválidos"));
    }
    for query in &pq.proof.queries {
        if query.trace.len() != 6 || query.fri.layers.len() != layers {
            return Err(reject("Número de aperturas inválido"));
        }
        for point in &query.trace {
            if point.value.value() >= P || point.proof.siblings.len() != depth {
                return Err(reject("Apertura de traza no canónica"));
            }
        }
        for (index, layer) in query.fri.layers.iter().enumerate() {
            if !canonical_extension(layer.left) || !canonical_extension(layer.right)
                || layer.left_proof.siblings.len() != depth - index
                || layer.right_proof.siblings.len() != depth - index {
                return Err(reject("Apertura FRI no canónica"));
            }
        }
    }
    Ok(())
}

/// Rechazo por defecto: no hay ruta alternativa de aceptación por formato.
/// No actualiza un libro mayor ni establece finalidad, ZK o soundness global.
pub fn verify_canonical_transition(proof: &StateProof, expected: &ExpectedTransition)
    -> Result<(), NexusError> {
    if expected.steps < 16 || expected.steps > MAX_STEPS || !expected.steps.is_power_of_two() {
        return Err(reject("El perfil exige 16..2^18 filas, potencia de dos"));
    }
    let start = canonical_scalar(&expected.pre)?;
    let output = canonical_scalar(&expected.post)?;
    if proof.proof_type != ProofType::ZKValidity || proof.pre_state_root != expected.pre
        || proof.post_state_root != expected.post || proof.height != expected.height
        || proof.public_inputs != public_inputs(expected) {
        return Err(reject("El sobre no coincide con el contexto esperado"));
    }
    if proof.proof_data.is_empty() || proof.proof_data.len() > MAX_PROOF_BYTES {
        return Err(reject("Tamaño de prueba fuera del perfil"));
    }
    let pq: PqValidityProof = bincode::DefaultOptions::new().with_fixint_encoding()
        .with_limit(MAX_PROOF_BYTES as u64).reject_trailing_bytes()
        .deserialize(&proof.proof_data)?;
    if pq.statement.steps != expected.steps || pq.statement.start != start
        || pq.statement.output != output {
        return Err(reject("La prueba no corresponde al enunciado esperado"));
    }
    check_shape(&pq, expected.steps)?;
    if !pq.verify() { return Err(reject("La comprobación STARK rechazó la prueba")); }
    Ok(())
}
