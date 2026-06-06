//! Puente post-cuántico del Nitro Verifier.
//!
//! Conecta el STARK hash-based de [`nexus_zk::stark`] con el flujo de validación
//! de la capa de anclaje. Es el **sustituto post-cuántico** del andamiaje
//! Groth16/BN254: la validez de una transición de estado L2 se certifica con una
//! prueba cuya seguridad reposa solo en funciones hash (Merkle + Fiat–Shamir) y
//! aritmética de campo (NTT/FRI) — sin emparejamientos, por tanto sin la
//! vulnerabilidad a Shor de los SNARK basados en curvas.
//!
//! Alcance (PoC): el enunciado ata `start ↔ pre-state root` y
//! `output ↔ post-state root` mediante una codificación de 64 bits del root. En
//! un sistema de producción el *boundary* ataría el root completo (varias
//! columnas de traza); aquí basta una codificación inyectiva sobre 8 bytes.

use nexus_core::{Hash256, StateRoot};
use nexus_zk::stark::field::Felt;
use nexus_zk::{prove_state_transition, verify_state_transition, StarkProof, TransitionStatement};
use serde::{Deserialize, Serialize};

/// Prueba de validez post-cuántica: enunciado público + prueba STARK.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqValidityProof {
    pub statement: TransitionStatement,
    pub proof: StarkProof,
}

/// Codifica un *state root* en un elemento de campo (primeros 8 bytes, LE).
pub fn encode_root(root: &StateRoot) -> Felt {
    let mut le = [0u8; 8];
    le.copy_from_slice(&root.0.as_bytes()[..8]);
    Felt::new(u64::from_le_bytes(le))
}

/// Reconstruye un *state root* cuya codificación es `f` (resto de bytes en cero).
pub fn root_from_felt(f: Felt) -> StateRoot {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&f.to_bytes());
    StateRoot::new(Hash256(bytes))
}

impl PqValidityProof {
    /// Genera la prueba de que el `pre_root` evoluciona (testigo `witness`,
    /// `steps` pasos de la función de transición) a un post-state calculado.
    pub fn prove(pre_root: &StateRoot, witness: u64, steps: usize) -> Self {
        let start = encode_root(pre_root);
        let (statement, proof) = prove_state_transition(start, Felt::new(witness), steps);
        PqValidityProof { statement, proof }
    }

    /// *Post-state root* (codificado) que la prueba certifica.
    pub fn post_root(&self) -> StateRoot {
        root_from_felt(self.statement.output)
    }

    /// Verificación autónoma del STARK (bajo grado + restricciones).
    pub fn verify(&self) -> bool {
        verify_state_transition(&self.statement, &self.proof)
    }

    /// Verifica la prueba **y** que ata los roots pre/post reclamados.
    pub fn verify_bound(&self, pre: &StateRoot, post: &StateRoot) -> bool {
        self.statement.start == encode_root(pre)
            && self.statement.output == encode_root(post)
            && self.verify()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pre_root() -> StateRoot {
        StateRoot::new(Hash256::hash(b"pre-state"))
    }

    #[test]
    fn prove_and_verify_bound() {
        let pre = pre_root();
        let pq = PqValidityProof::prove(&pre, 7, 16);
        let post = pq.post_root();
        assert!(pq.verify_bound(&pre, &post));
    }

    #[test]
    fn serialization_roundtrip() {
        let pre = pre_root();
        let pq = PqValidityProof::prove(&pre, 3, 16);
        let bytes = pq.to_bytes();
        let back = PqValidityProof::from_bytes(&bytes).expect("deserializa");
        assert!(back.verify_bound(&pre, &pq.post_root()));
    }

    #[test]
    fn wrong_post_root_rejected() {
        let pre = pre_root();
        let pq = PqValidityProof::prove(&pre, 5, 16);
        let bad_post = StateRoot::new(Hash256::hash(b"otro-post"));
        assert!(!pq.verify_bound(&pre, &bad_post));
    }

    #[test]
    fn garbage_bytes_do_not_deserialize_as_proof() {
        assert!(PqValidityProof::from_bytes(&[1, 2, 3, 4]).is_none());
    }
}
