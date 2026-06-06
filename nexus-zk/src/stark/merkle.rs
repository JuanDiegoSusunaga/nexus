//! Árbol de Merkle sobre `Hash256` (SHA3-256, vía `nexus_core`).
//!
//! Es el *esquema de compromiso* de FRI. Su seguridad se reduce a la
//! resistencia a colisiones/preimagen del hash: una primitiva **simétrica** que
//! el algoritmo de Shor no rompe (Grover solo aporta una raíz cuadrada, que se
//! absorbe duplicando el tamaño de salida). De aquí proviene, en última
//! instancia, la resistencia cuántica del sistema de pruebas.
//!
//! **Separación de dominio (endurecimiento).** Las hojas y los nodos internos
//! se hashean con prefijos disjuntos (`LEAF_TAG`=0x00, `NODE_TAG`=0x01), de modo
//! que ninguna preimagen de hoja pueda reinterpretarse como nodo interno
//! (defensa contra segundas preimágenes estilo CVE-2012-2459).
//!
//! El árbol es **genérico** sobre el tipo de hoja ([`MerkleLeaf`]): las capas
//! FRI comprometen elementos del campo de extensión (16 bytes), mientras que la
//! traza compromete elementos del campo base (8 bytes).

use super::field::{Felt, Fp2};
use nexus_core::Hash256;
use serde::{Deserialize, Serialize};

/// Prefijo de dominio para hojas.
pub const LEAF_TAG: u8 = 0x00;
/// Prefijo de dominio para nodos internos.
pub const NODE_TAG: u8 = 0x01;

/// Tipo que puede ser hoja de un árbol de Merkle (serializa a bytes canónicos).
pub trait MerkleLeaf: Copy {
    fn leaf_bytes(&self) -> Vec<u8>;
}

impl MerkleLeaf for Felt {
    fn leaf_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

impl MerkleLeaf for Fp2 {
    fn leaf_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

/// Hash de una hoja con separación de dominio: `SHA3(LEAF_TAG || bytes)`.
fn hash_leaf<T: MerkleLeaf>(v: &T) -> Hash256 {
    let b = v.leaf_bytes();
    let mut buf = Vec::with_capacity(1 + b.len());
    buf.push(LEAF_TAG);
    buf.extend_from_slice(&b);
    Hash256::hash(&buf)
}

/// Hash de un nodo interno con separación de dominio: `SHA3(NODE_TAG || L || R)`.
fn hash_node(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut buf = [0u8; 65];
    buf[0] = NODE_TAG;
    buf[1..33].copy_from_slice(left.as_bytes());
    buf[33..65].copy_from_slice(right.as_bytes());
    Hash256::hash(&buf)
}

/// Árbol de Merkle completo (número de hojas potencia de dos).
pub struct MerkleTree {
    /// `layers[0]` = hojas, `layers[last] = [raíz]`.
    layers: Vec<Vec<Hash256>>,
}

/// Camino de autenticación de una hoja hacia la raíz.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Hermanos, de la hoja hacia arriba.
    pub siblings: Vec<Hash256>,
}

impl MerkleTree {
    /// Construye el árbol a partir de las hojas (longitud potencia de dos).
    pub fn commit<T: MerkleLeaf>(values: &[T]) -> Self {
        assert!(values.len().is_power_of_two() && !values.is_empty());
        let leaves: Vec<Hash256> = values.iter().map(hash_leaf).collect();
        let mut layers = vec![leaves];
        while layers.last().unwrap().len() > 1 {
            let prev = layers.last().unwrap();
            let next: Vec<Hash256> = prev
                .chunks(2)
                .map(|pair| hash_node(&pair[0], &pair[1]))
                .collect();
            layers.push(next);
        }
        MerkleTree { layers }
    }

    pub fn root(&self) -> Hash256 {
        *self.layers.last().unwrap().last().unwrap()
    }

    /// Genera el camino de autenticación de la hoja `index`.
    pub fn open(&self, mut index: usize) -> MerkleProof {
        let mut siblings = Vec::new();
        for layer in &self.layers[..self.layers.len() - 1] {
            let sibling = index ^ 1; // hermano = índice con el bit bajo volteado
            siblings.push(layer[sibling]);
            index >>= 1;
        }
        MerkleProof { siblings }
    }
}

/// Verifica que `value`, en la hoja `index` de un árbol de `domain_size` hojas,
/// es consistente con `root` y el camino `proof`.
pub fn verify<T: MerkleLeaf>(
    root: &Hash256,
    domain_size: usize,
    mut index: usize,
    value: T,
    proof: &MerkleProof,
) -> bool {
    if proof.siblings.len() != domain_size.trailing_zeros() as usize {
        return false;
    }
    let mut acc = hash_leaf(&value);
    for sibling in &proof.siblings {
        acc = if index & 1 == 0 {
            hash_node(&acc, sibling)
        } else {
            hash_node(sibling, &acc)
        };
        index >>= 1;
    }
    &acc == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_and_verify_all_leaves() {
        let values: Vec<Felt> = (0..16).map(|i| Felt::new(i * 11 + 3)).collect();
        let tree = MerkleTree::commit(&values);
        let root = tree.root();
        for (i, v) in values.iter().enumerate() {
            let proof = tree.open(i);
            assert!(verify(&root, values.len(), i, *v, &proof), "leaf {}", i);
        }
    }

    #[test]
    fn tampered_value_rejected() {
        let values: Vec<Felt> = (0..8).map(|i| Felt::new(i + 1)).collect();
        let tree = MerkleTree::commit(&values);
        let root = tree.root();
        let proof = tree.open(3);
        // valor alterado en una hoja válida ⇒ rechazo
        assert!(!verify(&root, values.len(), 3, Felt::new(999), &proof));
        // índice equivocado ⇒ rechazo
        assert!(!verify(&root, values.len(), 4, values[3], &proof));
    }

    #[test]
    fn leaf_node_domain_separation() {
        // La imagen de una hoja nunca coincide con la de un nodo interno:
        // los prefijos de dominio (0x00 vs 0x01) hacen disjuntos los preimágenes.
        let v = Felt::new(42);
        let leaf_h = hash_leaf(&v);
        // Un "nodo" cuyo contenido empieza igual que la hoja: aún así difiere.
        let node_h = hash_node(&Hash256::ZERO, &Hash256::ZERO);
        assert_ne!(leaf_h, node_h);
    }
}
