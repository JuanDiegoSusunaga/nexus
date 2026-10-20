//! La API pública deriva contexto local y rechaza raíces fuera del AIR sin truncarlas.
use nexus_active::{ActiveChain, ActiveChainConfig, verifier::VerificationMode};
use nexus_core::{Address, Amount, BlockHeight, ChainId, Hash256, Nonce, SignatureScheme, Transaction};
use nexus_crypto::{DilithiumKeypair, Signer};
use std::sync::Arc;

fn chain(mode: VerificationMode, interval: u64, max_transactions: usize) -> ActiveChain {
    let mut config = ActiveChainConfig::default();
    config.verification_mode = mode;
    config.batch_interval_blocks = interval;
    config.sequencer.max_batch_size = max_transactions;
    let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
    ActiveChain::new(config, keypair)
}

fn submit_transaction(chain: &ActiveChain) {
    let signer = DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap();
    let transaction = Transaction::transfer(ChainId::LOCAL, Nonce(0), Address::ZERO,
        Amount::from_units(1), 21000, Amount(1_000_000_000));
    // La ejecución puede fallar por saldo: la prueba no se confunde con éxito de la transacción.
    chain.submit_transaction(signer.sign_transaction(transaction).unwrap()).unwrap();
}

#[test]
fn lote_local_sin_certificado_valido_no_se_envia_y_un_rechazo_no_muta_el_estado() {
    for mode in [VerificationMode::ZKValidity, VerificationMode::Hybrid { threshold: usize::MAX }] {
        let chain = chain(mode, 1, 10);
        let pre = chain.state_root();
        submit_transaction(&chain);
        let block = chain.produce_block().unwrap();
        let mut batch = chain.get_next_batch().unwrap();
        assert_eq!(batch.pre_state_root, pre);
        assert_eq!(batch.post_state_root.0, block.header.state_root);
        // Insufficient balance must leave the state untouched.
        assert_eq!(batch.pre_state_root, batch.post_state_root);
        assert!(chain.create_state_proof(&batch).is_err());
        batch.validity_proof = Some(vec![0; 4096]);
        let proof = chain.create_state_proof(&batch).unwrap();
        assert_eq!(proof.public_inputs.len(), 72);
        assert!(!chain.verify_state_proof(&batch, &proof).unwrap().valid);
        let before = chain.state_root();
        assert!(chain.mark_batch_submitted(batch.clone(), Hash256::hash(b"envio")).is_err());
        assert_eq!(chain.stats().submitted_batches, 0);
        assert_eq!(chain.state_root(), before);
        assert!(chain.verified_state_root(block.height()).is_none());
        assert!(chain.get_known_batch(batch.index).is_some());
        let l1 = nexus_anchor::AnchorChain::new(Default::default(),
            DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap());
        assert!(chain.mark_batch_confirmed(batch.index, &l1).is_err());
    }
}

#[test]
fn modo_optimista_permanece_provisional_y_no_admite_envios_duplicados() {
    let chain = chain(VerificationMode::Optimistic, 1, 10);
    submit_transaction(&chain);
    chain.produce_block().unwrap();
    let batch = chain.get_next_batch().unwrap();
    let proof = chain.create_state_proof(&batch).unwrap();
    assert!(!chain.verify_state_proof(&batch, &proof).unwrap().valid);
    chain.mark_batch_submitted(batch.clone(), Hash256::hash(b"optimista")).unwrap();
    assert!(chain.verified_state_root(batch.block_range.1).is_none());
    assert!(chain.mark_batch_submitted(batch.clone(), Hash256::hash(b"duplicado")).is_err());
    assert_eq!(chain.stats().submitted_batches, 1);
    let l1 = nexus_anchor::AnchorChain::new(Default::default(),
        DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap());
    assert!(chain.mark_batch_confirmed(batch.index, &l1).is_err());
    assert_eq!(chain.stats().confirmed_batches, 0);
    assert!(chain.verified_state_root(batch.block_range.1).is_none());
    assert!(chain.mark_batch_submitted(batch, Hash256::hash(b"reenvio confirmado")).is_err());
}

#[test]
fn cambiar_el_lote_y_recalcular_su_hash_no_cambia_el_contexto_local() {
    let chain = chain(VerificationMode::Optimistic, 1, 10);
    submit_transaction(&chain);
    chain.produce_block().unwrap();
    let batch = chain.get_next_batch().unwrap();
    for case in 0..9 {
        let mut changed = batch.clone();
        match case {
            0 => changed.index += 1,
            1 => changed.block_range.0 = BlockHeight(0),
            2 => changed.block_range.1 = BlockHeight(2),
            3 => changed.pre_state_root.0 = Hash256::hash(b"otra inicial"),
            4 => changed.post_state_root.0 = Hash256::hash(b"otra final"),
            5 => changed.tx_count += 1,
            6 => changed.compressed_data.push(1),
            7 => changed.created_at.0 += 1,
            _ => changed.signature = Some(vec![1]),
        }
        changed.batch_hash = changed.compute_hash();
        assert!(chain.create_state_proof(&changed).is_err());
        assert!(chain.mark_batch_submitted(changed, Hash256::ZERO).is_err());
        assert_eq!(chain.stats().submitted_batches, 0);
        assert!(chain.verified_state_root(BlockHeight(1)).is_none());
    }
}

#[test]
fn vacios_conservan_raiz_y_la_rotacion_del_lote_no_parte_bloques() {
    let chain = chain(VerificationMode::Optimistic, 3, 2);
    let initial = chain.state_root();
    submit_transaction(&chain);
    let first = chain.produce_block().unwrap();
    submit_transaction(&chain);
    submit_transaction(&chain);
    let second = chain.produce_block().unwrap();
    let first_batch = chain.get_next_batch().unwrap();
    assert_eq!(first_batch.tx_count, 1);
    assert_eq!(first_batch.block_range, (BlockHeight(1), BlockHeight(1)));
    assert_eq!(first_batch.pre_state_root, initial);
    assert_eq!(first_batch.post_state_root.0, first.header.state_root);
    let empty = chain.produce_block().unwrap();
    assert_eq!(empty.header.state_root, second.header.state_root);
    let second_batch = chain.get_next_batch().unwrap();
    assert_eq!(second_batch.tx_count, 2);
    assert_eq!(second_batch.block_range, (BlockHeight(2), BlockHeight(3)));
    assert_eq!(second_batch.pre_state_root, first_batch.post_state_root);
    assert_eq!(second_batch.post_state_root.0, empty.header.state_root);
}

#[test]
fn produccion_concurrente_no_reutiliza_alturas_ni_contextos_de_estado() {
    let chain = Arc::new(chain(VerificationMode::Optimistic, 100, 10));
    let workers: Vec<_> = (0..4).map(|_| {
        let chain = Arc::clone(&chain);
        std::thread::spawn(move || {
            (0..10).map(|_| chain.produce_block().unwrap().height().0).collect::<Vec<_>>()
        })
    }).collect();
    let mut heights: Vec<_> = workers.into_iter().flat_map(|w| w.join().unwrap()).collect();
    heights.sort_unstable();
    assert_eq!(heights, (1..=40).collect::<Vec<_>>());
    for height in 1..=40 {
        let block = chain.get_block_by_height(BlockHeight(height)).unwrap();
        let parent = chain.get_block_by_height(BlockHeight(height - 1)).unwrap();
        assert_eq!(block.header.parent_hash, parent.hash());
    }
}

#[test]
fn intervalo_cero_se_rechaza_antes_de_consumir_transacciones() {
    let chain = chain(VerificationMode::Optimistic, 0, 10);
    submit_transaction(&chain);
    assert!(chain.produce_block().is_err());
    assert_eq!(chain.height(), BlockHeight(0));
    assert_eq!(chain.stats().pending_txs, 1);
}
