//! Recorrido R3 reproducible; las muestras sintéticas no califican una fuente física.
use nexus_core::{NexusError, SignatureScheme};
use nexus_crypto::{KeyManager, KeyRegistry, SentinelSeed};
use rand::{RngCore, SeedableRng};

fn main() -> Result<(), NexusError> {
    let mut samples = vec![0; nexus_crypto::entropy::SOURCE_ASSESSMENT_SAMPLES];
    rand_chacha::ChaCha20Rng::from_seed([7; 32]).fill_bytes(&mut samples);
    let mut manager = KeyManager::with_sentinel(SentinelSeed::new());
    manager.ingest_source(&samples)?;
    let identity = manager.generate_key(SignatureScheme::Dilithium3)?;
    manager.generate_key(SignatureScheme::Dilithium3)?;
    let message = b"NEXUS R3: operacion de demostracion con nonce 1";
    let old_signature = manager.sign(&identity, message)?;
    let old_public = manager.get_key(&identity).ok_or(NexusError::AccountNotFound(identity))?
        .material.public_key.as_bytes().to_vec();
    manager.ingest_source(&[0; 4])?;
    let blocked = manager.sign_default(message).is_err();
    manager.begin_source_recovery()?;
    manager.ingest_source(&samples)?;
    let blocked_before_rotation = manager.sign_default(message).is_err();
    let trusted = manager.rotate_sentinel()?;
    let new_signature = manager.sign(&identity, message)?;
    let changed = old_public != manager.get_key(&identity).ok_or(NexusError::AccountNotFound(identity))?
        .material.public_key.as_bytes();
    let archive = manager.registry().to_bytes()?;
    let rotation_bytes = bincode::serialized_size(manager.registry().records().last()
        .ok_or_else(|| NexusError::Internal("Falta el evento de rotación".into()))?)?;
    if let Some(path) = std::env::args().nth(1) {
        // Archivo público para la evidencia; no contiene claves privadas ni semillas.
        std::fs::write(path, &archive)?;
    }
    drop(manager);
    // El punto confiable se conserva fuera del archivo que se está verificando.
    let recovered = KeyRegistry::from_bytes(&archive, trusted)?;
    let old_current = recovered.verify_current(message, &old_signature)?;
    let old_historical = recovered.verify_historical(message, &old_signature)?;
    let new_current = recovered.verify_current(message, &new_signature)?;
    if !blocked || !blocked_before_rotation || !changed || old_current || !old_historical || !new_current {
        return Err(NexusError::SecurityViolation("No se cumple el recorrido R3".into()));
    }
    println!("identidades=2; epoca=1; registros={}; archivo_bytes={}; rotacion_bytes={}",
        trusted.records, archive.len(), rotation_bytes);
    println!("bloqueo_por_fallo={blocked}; bloqueo_antes_de_rotar={blocked_before_rotation}; claves_cambiadas={changed}");
    println!("firma_anterior_vigente={old_current}; firma_anterior_historica={old_historical}; firma_nueva_vigente={new_current}");
    println!("checkpoint_head={}", trusted.head.to_hex());
    Ok(())
}
