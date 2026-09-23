//! Caracteriza parámetros y límites del PoC sin modificar la implementación heredada.
use nexus_core::Hash256;
use nexus_zk::stark::{
    air::{BLOWUP, StarkProof, TransitionStatement},
    channel::{Channel, TAG_FINAL, TAG_FRI_ROOT},
    field::{Felt, Fp2, GENERATOR, P},
    fri::{self, FriProof, FriProverData, NUM_QUERIES},
    merkle::{self, MerkleTree},
    ntt::intt,
    params::{budget, POW_BITS_RUNTIME},
    prove_state_transition, verify_state_transition,
};
use std::collections::HashSet;
use std::sync::OnceLock;

#[test]
fn consultas_reales_sin_reemplazo_segun_tamano() {
    for (filas, esperado) in [(4, 16), (8, 32), (16, 40), (64, 40), (4096, 40)] {
        let mut canal = Channel::new(b"TG2-consultas");
        let indices = fri::derive_query_indices(&mut canal, filas * BLOWUP);
        assert_eq!(indices.len(), esperado);
        assert_eq!(indices.iter().copied().collect::<HashSet<_>>().len(), esperado);
        assert!(indices.iter().all(|&i| i < filas * BLOWUP / 2));
    }
}

#[test]
fn presupuesto_nominal_no_depende_de_las_filas_ni_del_perfil() {
    let nominal = budget();
    assert_eq!(nominal.num_queries, NUM_QUERIES);
    assert_eq!(nominal.bits_total_pg, 100.0);
    let mut canal = Channel::new(b"TG2-presupuesto");
    assert_eq!(fri::derive_query_indices(&mut canal, 4 * BLOWUP).len(), 16);
    assert_eq!(nominal.pow_bits, 20);
    assert_eq!(POW_BITS_RUNTIME, if cfg!(debug_assertions) { 12 } else { 20 });
}

fn ejemplo_air() -> &'static (TransitionStatement, StarkProof) {
    static EJEMPLO: OnceLock<(TransitionStatement, StarkProof)> = OnceLock::new();
    EJEMPLO.get_or_init(|| prove_state_transition(Felt::new(3), Felt::new(5), 16))
}

#[test]
fn air_liga_enunciado_compromiso_y_valor_final() {
    let (enunciado, prueba) = ejemplo_air();
    assert!(verify_state_transition(enunciado, prueba));
    for cambio in 0..3 {
        let mut otro = enunciado.clone();
        match cambio {
            0 => otro.start = otro.start.add(Felt::ONE),
            1 => otro.output = otro.output.add(Felt::ONE),
            _ => otro.steps *= 2,
        }
        assert!(!verify_state_transition(&otro, prueba));
    }
    let mut otra = prueba.clone();
    otra.trace_root = Hash256::hash(b"TG2-compromiso-distinto");
    assert!(!verify_state_transition(enunciado, &otra));
    otra = prueba.clone();
    otra.fri_final = otra.fri_final.add(Fp2::from_base(Felt::ONE));
    assert!(!verify_state_transition(enunciado, &otra));
}

#[test]
fn grinding_admite_varios_nonces_validos() {
    let mut primero = Channel::new(b"TG2-nonces-publicos");
    let minimo = primero.grind(8);
    let mut alternativo = None;
    for nonce in minimo + 1..minimo + 65536 {
        let mut candidato = Channel::new(b"TG2-nonces-publicos");
        if candidato.check_grinding(nonce, 8) {
            alternativo = Some((nonce, candidato));
            break;
        }
    }
    let (nonce, mut segundo) = alternativo.expect("debe existir otro nonce en este ensayo fijo");
    assert!(nonce > minimo);
    assert_ne!(primero.challenge_ext(), segundo.challenge_ext());
}

#[test]
fn retos_de_extension_reproducibles_y_canonicos() {
    let mut primero = Channel::new(b"TG2-retos");
    let mut segundo = primero.clone();
    for _ in 0..128 {
        let reto = primero.challenge_ext();
        assert_eq!(reto, segundo.challenge_ext());
        assert!(reto.c0.value() < P && reto.c1.value() < P);
    }
}

#[test]
fn merkle_de_bajo_nivel_presupone_indice_en_dominio() {
    let valores: Vec<_> = (0..16).map(Felt::new).collect();
    let arbol = MerkleTree::commit(&valores);
    let apertura = arbol.open(3);
    assert!(merkle::verify(&arbol.root(), 16, 3, valores[3], &apertura));
    // Se documenta una precondición de la API; AIR deriva índices dentro del dominio.
    assert!(merkle::verify(&arbol.root(), 16, 19, valores[3], &apertura));
}

#[test]
fn fri_puede_aceptar_palabra_cercana_con_grado_exacto_alto() {
    let n = 512usize;
    let cota = 128usize;
    let capas = cota.trailing_zeros() as usize;
    let mut palabra = vec![Felt::ZERO; n];
    palabra[0] = Felt::ONE;
    // La interpolación de una delta tiene grado N-1, también en un coset no nulo.
    let coeficientes = intt(&palabra);
    assert_ne!(coeficientes[n - 1], Felt::ZERO);
    let mut aceptadas = 0usize;
    let mut rechazadas = 0usize;
    for contexto in 0u64..32 {
        let dominio = [b"TG2-proximidad-".as_slice(), &contexto.to_le_bytes()].concat();
        let mut canal = Channel::new(&dominio);
        let mut datos = FriProverData { layer_evals: Vec::new(), layer_trees: Vec::new() };
        let mut raices = Vec::new();
        for capa in 0..capas {
            let mut valores = vec![Fp2::ZERO; n >> capa];
            if capa == 0 { valores[0] = Fp2::from_base(Felt::ONE); }
            // A partir de la segunda capa se compromete cero: hay una pareja inconsistente.
            let arbol = MerkleTree::commit(&valores);
            let raiz = arbol.root();
            canal.absorb_tagged(TAG_FRI_ROOT, raiz.as_bytes());
            let _reto = canal.challenge_ext();
            datos.layer_evals.push(valores);
            datos.layer_trees.push(arbol);
            raices.push(raiz);
        }
        canal.absorb_tagged(TAG_FINAL, &Fp2::ZERO.to_bytes());
        let indices = fri::derive_query_indices(&mut canal, n);
        let prueba = FriProof {
            layer_roots: raices,
            final_value: Fp2::ZERO,
            queries: indices.iter().map(|&i| fri::open(&datos, i, n)).collect(),
        };
        let acepta = fri::verify(&prueba, cota, n, Felt::new(GENERATOR), &mut Channel::new(&dominio));
        assert_eq!(acepta, !indices.contains(&0));
        if acepta { aceptadas += 1; } else { rechazadas += 1; }
    }
    assert!(aceptadas > 0 && rechazadas > 0);
    eprintln!("TG2_PROXIMIDAD n={n} grado={} cota={cota} aceptadas={aceptadas} rechazadas={rechazadas}", n - 1);
    // Distancia 1/N respecto de cero: no es una falsificación del enunciado AIR.
}
