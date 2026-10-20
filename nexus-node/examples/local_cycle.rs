//! Reproducible local cycle; keys stay with the caller and no network is used.
use nexus_node::{DurableNode, DurableNodeConfig};
use nexus_core::{checkpoint::encode, Address, Amount, ChainId, Nonce, SignatureScheme, Transaction};
use nexus_crypto::{DilithiumKeypair, Signer};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from(std::env::args_os().nth(1)
        .ok_or("Usage: cargo run -p nexus-node --example local_cycle -- <new checkpoint directory>")?);
    let publisher = DilithiumKeypair::generate(SignatureScheme::Dilithium3)?;
    let sender = DilithiumKeypair::generate(SignatureScheme::Dilithium3)?;
    let receiver = Address::new([42; 32]);
    let mut config = DurableNodeConfig::default(); config.active.batch_interval_blocks = 1;
    config.genesis_balances = vec![(sender.address(), Amount::from_units(10))];
    let mut node = DurableNode::create(&path, config.clone(), publisher.clone())?;
    let transfer = sender.sign_transaction(Transaction::transfer(ChainId::LOCAL, Nonce(0), receiver,
        Amount(7), 21000, Amount(1_000_000_000)))?;
    node.submit_transaction(transfer.clone())?; node.produce_block()?;
    let root = node.l2_state_root(); drop(node);
    let mut node = DurableNode::open(&path, config.clone(), publisher.clone())?;
    assert_eq!(node.l2_state_root(), root);
    let tx = node.prepare_l1_submission(node.batch(0).unwrap(), Default::default())?;
    let exact_packet = encode(&tx)?; let hash = tx.hash(); drop(node);
    let mut node = DurableNode::open(&path, config.clone(), publisher.clone())?;
    assert_eq!(encode(&node.signed_packet(0, hash)?)?, exact_packet);
    node.process_l1_transactions(vec![node.signed_packet(0, hash)?], Address::ZERO).await?; drop(node);
    let mut node = DurableNode::open(&path, config.clone(), publisher.clone())?;
    node.confirm_batch(0)?; drop(node);
    let mut node = DurableNode::open(&path, config, publisher)?;
    let confirmation = node.confirmation(0).unwrap();
    let replay_rejected = node.submit_transaction(transfer).is_err();
    let duplicate_confirmation_rejected = node.confirm_batch(0).is_err();
    let packet_preserved = encode(&node.signed_packet(0, hash)?)? == exact_packet;
    assert!(replay_rejected && duplicate_confirmation_rejected && packet_preserved);
    assert_eq!(node.l2_account(&receiver).unwrap().balance, Amount(7));
    assert_eq!(node.l2_account(&sender.address()).unwrap().nonce, Nonce(1));
    assert_eq!(node.l2_state_root(), root);
    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
        "perfil": "nexus-ciclo-local-durable-v1", "reaperturas": 4, "generacion": node.generation(),
        "l1_altura": node.l1_height().0, "l2_altura": node.l2_height().0,
        "raiz_l2": root.0.to_string(), "hash_envio_l1": hash.to_string(),
        "altura_inclusion": confirmation.l1_height.0, "intentos": confirmation.attempts.len(),
        "bytes_paquete": exact_packet.len(), "paquete_identico": packet_preserved,
        "nonce_emisor": node.l2_account(&sender.address()).unwrap().nonce.0,
        "saldo_receptor": "7", "repeticion_rechazada": replay_rejected,
        "confirmacion_duplicada_rechazada": duplicate_confirmation_rejected,
        "claves_privadas_guardadas": false, "emision_red": false, "finalidad_bft_acreditada": false
    }))?);
    Ok(())
}
