//! Registro público de épocas con autorización de las claves saliente y entrante.
//!
//! El checkpoint debe conservarse en un canal independiente. Este módulo no
//! demuestra consenso, fecha real de una firma ni anclaje en una cadena externa.

use crate::{DilithiumPublicKey, DilithiumSignature, entropy::RotationReason};
use bincode::Options;
use nexus_core::{Address, Hash256, NexusError, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const FORMAT: u16 = 1;
const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;

fn codec() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding()
        .with_limit(MAX_ARCHIVE_BYTES).reject_trailing_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyManager, SentinelSeed};
    use nexus_core::SignatureScheme;
    use rand::{RngCore, SeedableRng};

    fn populated() -> KeyManager {
        let mut manager = KeyManager::with_sentinel(SentinelSeed::new());
        let mut samples = vec![0; crate::entropy::SOURCE_ASSESSMENT_SAMPLES];
        rand_chacha::ChaCha20Rng::from_seed([7; 32]).fill_bytes(&mut samples);
        manager.ingest_source(&samples).unwrap();
        manager.generate_key(SignatureScheme::Dilithium3).unwrap();
        manager.generate_key(SignatureScheme::Dilithium3).unwrap();
        manager.rotate_sentinel().unwrap();
        manager
    }

    fn encode(records: &[RotationRecord]) -> Vec<u8> {
        codec().serialize(&(FORMAT, records)).unwrap()
    }

    #[test]
    fn public_registry_recovers_after_file_roundtrip() {
        let manager = populated();
        let trusted = manager.registry().checkpoint();
        let signed = manager.sign_default(b"persistencia").unwrap();
        let path = std::env::temp_dir().join(format!("nexus-r3-{}-{}.bin",
            std::process::id(), trusted.head.to_hex()));
        let bytes = manager.registry().to_bytes().unwrap();
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
            file.write_all(&bytes).unwrap();
            file.sync_all().unwrap();
        }
        drop(manager);
        let recovered = KeyRegistry::from_bytes(&std::fs::read(&path).unwrap(), trusted).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(recovered.checkpoint(), trusted);
        assert_eq!(recovered.active_count(), 2);
        assert!(recovered.verify_current(b"persistencia", &signed).unwrap());
    }

    #[test]
    fn tampered_metadata_or_authorization_is_rejected() {
        let manager = populated();
        let trusted = manager.registry().checkpoint();
        let mut records = manager.registry().records().to_vec();
        records.last_mut().unwrap().body.timestamp.0 += 1;
        assert!(KeyRegistry::from_bytes(&encode(&records), trusted).is_err());
        records = manager.registry().records().to_vec();
        let auth = &mut records.last_mut().unwrap().authorizations[0];
        let signature = auth.next.as_ref().unwrap();
        let mut corrupted = signature.as_bytes().to_vec();
        corrupted[0] ^= 1;
        auth.next = Some(DilithiumSignature::from_bytes(corrupted, signature.scheme()).unwrap());
        assert!(KeyRegistry::from_bytes(&encode(&records), trusted).is_err());
        records = manager.registry().records().to_vec();
        records.last_mut().unwrap().authorizations[0].previous = None;
        assert!(KeyRegistry::from_bytes(&encode(&records), trusted).is_err());
    }

    #[test]
    fn missing_reordered_or_duplicated_records_are_rejected() {
        let manager = populated();
        let trusted = manager.registry().checkpoint();
        let records = manager.registry().records();
        let mut changed = records.to_vec();
        changed.remove(1);
        assert!(KeyRegistry::from_bytes(&encode(&changed), trusted).is_err());
        changed = records.to_vec();
        changed.swap(0, 1);
        assert!(KeyRegistry::from_bytes(&encode(&changed), trusted).is_err());
        changed = records.to_vec();
        changed.push(records[2].clone());
        assert!(KeyRegistry::from_bytes(&encode(&changed), trusted).is_err());
    }

    #[test]
    fn trusted_checkpoint_detects_valid_prefix_rollback() {
        let manager = populated();
        let records = manager.registry().records();
        let prefix = encode(&records[..2]);
        assert!(KeyRegistry::from_bytes(&prefix, manager.registry().checkpoint()).is_err());
        let old_checkpoint = RegistryCheckpoint { records: 2, head: records[1].hash().unwrap() };
        assert!(KeyRegistry::from_bytes(&manager.registry().to_bytes().unwrap(), old_checkpoint).is_ok());
        let mut wrong = old_checkpoint;
        wrong.head = Hash256::hash(b"checkpoint falso");
        assert!(KeyRegistry::from_bytes(&prefix, wrong).is_err());
        // Un punto confiable antiguo no detecta cambios posteriores a ese punto.
        assert!(KeyRegistry::from_bytes(&prefix, old_checkpoint).is_ok());
    }

    #[test]
    fn foreign_history_and_modified_full_hash_are_rejected() {
        let manager = populated();
        let foreign = populated();
        assert!(KeyRegistry::from_bytes(&foreign.registry().to_bytes().unwrap(),
            manager.registry().checkpoint()).is_err());
        let mut checkpoint = manager.registry().checkpoint();
        checkpoint.head.0[31] ^= 1;
        assert!(KeyRegistry::from_bytes(&manager.registry().to_bytes().unwrap(), checkpoint).is_err());
    }

    #[test]
    fn malformed_truncated_unknown_version_and_trailing_bytes_are_rejected() {
        let manager = populated();
        let trusted = manager.registry().checkpoint();
        let bytes = manager.registry().to_bytes().unwrap();
        for length in [0, 1, bytes.len() / 2, bytes.len() - 1] {
            assert!(KeyRegistry::from_bytes(&bytes[..length], trusted).is_err());
        }
        let mut changed = bytes.clone();
        changed.push(0);
        assert!(KeyRegistry::from_bytes(&changed, trusted).is_err());
        changed = bytes;
        changed[0] = 255;
        assert!(KeyRegistry::from_bytes(&changed, trusted).is_err());
    }

    #[test]
    fn rotation_missing_an_identity_or_new_proof_is_rejected_without_mutation() {
        let manager = populated();
        let records = manager.registry().records();
        let trusted = RegistryCheckpoint { records: 2, head: records[1].hash().unwrap() };
        let mut registry = KeyRegistry::from_bytes(&encode(&records[..2]), trusted).unwrap();
        let mut record = records[2].clone();
        if let RegistryEvent::Rotation { replacements, .. } = &mut record.body.event {
            replacements.pop();
        }
        record.authorizations.pop();
        assert!(registry.append(record).is_err());
        assert_eq!(registry.checkpoint(), trusted);
        let mut record = records[2].clone();
        record.authorizations[1].next = None;
        assert!(registry.append(record).is_err());
        assert_eq!(registry.checkpoint(), trusted);
    }

    #[test]
    fn duplicate_enrollment_and_reenrollment_after_retirement_are_rejected() {
        let mut manager = KeyManager::new();
        let identity = manager.generate_key(SignatureScheme::Dilithium3).unwrap();
        let record = manager.registry().records()[0].clone();
        let mut registry = manager.registry().clone();
        assert!(registry.append(record.clone()).is_err());
        manager.remove_key(&identity).unwrap();
        registry = manager.registry().clone();
        let checkpoint = registry.checkpoint();
        let mut forged = record;
        forged.body.sequence = checkpoint.records;
        forged.body.previous_hash = checkpoint.head;
        assert!(registry.append(forged).is_err());
        assert_eq!(registry.checkpoint(), checkpoint);
    }

    #[test]
    fn skipped_epochs_duplicate_identities_and_reused_keys_are_rejected() {
        let manager = populated();
        let records = manager.registry().records();
        let trusted = RegistryCheckpoint { records: 2, head: records[1].hash().unwrap() };
        let mut registry = KeyRegistry::from_bytes(&encode(&records[..2]), trusted).unwrap();
        for case in 0..3 {
            let mut record = records[2].clone();
            if let RegistryEvent::Rotation { new_epoch, replacements, .. } = &mut record.body.event {
                match case {
                    0 => *new_epoch = 2,
                    1 => replacements[1] = replacements[0].clone(),
                    _ => replacements[0].1 = registry.current(&replacements[0].0).unwrap()
                        .material.public_key.clone(),
                }
            }
            assert!(registry.append(record).is_err());
            assert_eq!(registry.checkpoint(), trusted);
        }
    }
}

fn invalid(message: &str) -> NexusError {
    NexusError::SecurityViolation(message.into())
}

/// Punto de control público; su autenticidad procede del canal que lo custodia.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryCheckpoint {
    pub records: u64,
    pub head: Hash256,
}

/// Material exclusivamente público y compromiso de la semilla, cuando existe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyMaterial {
    pub epoch: u64,
    pub public_key: DilithiumPublicKey,
    pub seed_hash: Option<Hash256>,
}

/// Vigencia por posición del registro: intervalo [valid_from, valid_until).
#[derive(Debug, Clone)]
pub struct PublicKeyVersion {
    pub material: PublicKeyMaterial,
    pub valid_from: u64,
    pub valid_until: Option<u64>,
}

/// La rotación reúne todas las identidades en un único evento indivisible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistryEvent {
    Enrollment { identity: Address, key: PublicKeyMaterial },
    Rotation {
        old_epoch: u64,
        new_epoch: u64,
        old_seed_hash: Hash256,
        new_seed_hash: Hash256,
        reason: RotationReason,
        replacements: Vec<(Address, DilithiumPublicKey)>,
    },
    Retirement { identity: Address },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordBody {
    pub format: u16,
    pub sequence: u64,
    pub previous_hash: Hash256,
    pub timestamp: Timestamp,
    pub event: RegistryEvent,
}

/// Cada transición prueba autorización saliente y posesión de la clave entrante.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordAuthorization {
    pub identity: Address,
    pub previous: Option<DilithiumSignature>,
    pub next: Option<DilithiumSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationRecord {
    pub body: RecordBody,
    pub authorizations: Vec<RecordAuthorization>,
}

impl RecordBody {
    pub(crate) fn signing_bytes(&self) -> Result<Vec<u8>, NexusError> {
        let mut bytes = b"NEXUS_KEY_REGISTRY_EVENT_V1".to_vec();
        bytes.extend(codec().serialize(self)?);
        Ok(bytes)
    }
}

impl RotationRecord {
    pub fn hash(&self) -> Result<Hash256, NexusError> {
        let mut bytes = b"NEXUS_KEY_REGISTRY_RECORD_V1".to_vec();
        bytes.extend(codec().serialize(self)?);
        Ok(Hash256::hash(&bytes))
    }
}

/// Firma de aplicación vinculada a la identidad estable y a la época.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochSignature {
    pub identity: Address,
    pub epoch: u64,
    pub signature: DilithiumSignature,
}

pub(crate) fn operation_bytes(identity: Address, epoch: u64, message: &[u8]) -> Vec<u8> {
    let mut bytes = b"NEXUS_KEY_OPERATION_V1".to_vec();
    bytes.extend(identity.as_bytes());
    bytes.extend(epoch.to_le_bytes());
    bytes.extend((message.len() as u64).to_le_bytes());
    bytes.extend(message);
    bytes
}

/// Índices reconstruidos exclusivamente después de verificar el archivo público.
#[derive(Debug, Clone, Default)]
pub struct KeyRegistry {
    records: Vec<RotationRecord>,
    hashes: Vec<Hash256>,
    current: HashMap<Address, u64>,
    history: HashMap<(Address, u64), PublicKeyVersion>,
    enrolled: HashMap<Address, u64>,
}

impl KeyRegistry {
    pub fn new() -> Self { Self::default() }

    pub fn records(&self) -> &[RotationRecord] { &self.records }

    pub fn checkpoint(&self) -> RegistryCheckpoint {
        RegistryCheckpoint {
            records: self.records.len() as u64,
            head: self.hashes.last().copied().unwrap_or(Hash256::ZERO),
        }
    }

    pub fn current(&self, identity: &Address) -> Option<&PublicKeyVersion> {
        self.current.get(identity).and_then(|epoch| self.history.get(&(*identity, *epoch)))
    }

    pub fn at_epoch(&self, identity: &Address, epoch: u64) -> Option<&PublicKeyVersion> {
        self.history.get(&(*identity, epoch))
    }

    pub fn active_count(&self) -> usize { self.current.len() }

    /// El reloj es metadato; el orden autorizado lo fija la secuencia encadenada.
    pub(crate) fn prepare(&self, event: RegistryEvent) -> RecordBody {
        RecordBody {
            format: FORMAT,
            sequence: self.records.len() as u64,
            previous_hash: self.checkpoint().head,
            timestamp: Timestamp::now(),
            event,
        }
    }

    /// Valida todo antes de cambiar índices. No admite una transición parcial.
    pub(crate) fn append(&mut self, record: RotationRecord) -> Result<(), NexusError> {
        let body = &record.body;
        if body.format != FORMAT || body.sequence != self.records.len() as u64
            || body.previous_hash != self.checkpoint().head {
            return Err(invalid("Formato, secuencia o enlace del registro inválido"));
        }
        let bytes = body.signing_bytes()?;
        let verify = |key: &DilithiumPublicKey, signature: &Option<DilithiumSignature>| {
            match signature {
                Some(signature) if key.verify(&bytes, signature)? => Ok(()),
                _ => Err(invalid("Falta autorización válida de la transición")),
            }
        };
        let mut updates = Vec::new();
        match &body.event {
            RegistryEvent::Enrollment { identity, key } => {
                if self.enrolled.contains_key(identity) || *identity != key.public_key.to_address()
                    || (key.seed_hash.is_none() && key.epoch != 0)
                    || record.authorizations.len() != 1 {
                    return Err(invalid("Alta duplicada o identidad de alta inválida"));
                }
                let auth = &record.authorizations[0];
                if auth.identity != *identity || auth.previous.is_some() {
                    return Err(invalid("Autorización de alta inválida"));
                }
                verify(&key.public_key, &auth.next)?;
                updates.push((*identity, Some(key.clone())));
            }
            RegistryEvent::Rotation { old_epoch, new_epoch, old_seed_hash, new_seed_hash,
                replacements, .. } => {
                if old_epoch.checked_add(1) != Some(*new_epoch) || old_seed_hash == new_seed_hash
                    || replacements.is_empty() || replacements.len() != self.current.len()
                    || record.authorizations.len() != replacements.len() {
                    return Err(invalid("Época o conjunto de rotación inválido"));
                }
                let mut previous_identity: Option<Address> = None;
                for ((identity, public_key), auth) in replacements.iter().zip(&record.authorizations) {
                    if previous_identity.is_some_and(|prior| prior.as_bytes() >= identity.as_bytes())
                        || auth.identity != *identity {
                        return Err(invalid("Identidades duplicadas o fuera de orden"));
                    }
                    previous_identity = Some(*identity);
                    let old = self.current(identity).ok_or_else(|| invalid("Identidad no vigente"))?;
                    if old.material.epoch != *old_epoch || old.material.seed_hash != Some(*old_seed_hash)
                        || old.material.public_key.scheme() != public_key.scheme()
                        || old.material.public_key.as_bytes() == public_key.as_bytes() {
                        return Err(invalid("La rotación no corresponde a la clave vigente"));
                    }
                    verify(&old.material.public_key, &auth.previous)?;
                    verify(public_key, &auth.next)?;
                    updates.push((*identity, Some(PublicKeyMaterial {
                        epoch: *new_epoch, public_key: public_key.clone(), seed_hash: Some(*new_seed_hash),
                    })));
                }
            }
            RegistryEvent::Retirement { identity } => {
                let old = self.current(identity).ok_or_else(|| invalid("Identidad no vigente"))?;
                if record.authorizations.len() != 1 {
                    return Err(invalid("Autorizaciones de retiro inválidas"));
                }
                let auth = &record.authorizations[0];
                if auth.identity != *identity || auth.next.is_some() {
                    return Err(invalid("Autorización de retiro inválida"));
                }
                verify(&old.material.public_key, &auth.previous)?;
                updates.push((*identity, None));
            }
        }
        let hash = record.hash()?;
        for (identity, next) in updates {
            if let Some(epoch) = self.current.remove(&identity) {
                if let Some(old) = self.history.get_mut(&(identity, epoch)) {
                    old.valid_until = Some(body.sequence);
                }
            }
            if let Some(material) = next {
                self.enrolled.entry(identity).or_insert(body.sequence);
                self.current.insert(identity, material.epoch);
                self.history.insert((identity, material.epoch), PublicKeyVersion {
                    material, valid_from: body.sequence, valid_until: None,
                });
            }
        }
        self.hashes.push(hash);
        self.records.push(record);
        Ok(())
    }

    /// Solo acepta la época vigente. La salud local la aplica el gestor al firmar.
    pub fn verify_current(&self, message: &[u8], signed: &EpochSignature) -> Result<bool, NexusError> {
        match self.current(&signed.identity) {
            Some(key) if key.material.epoch == signed.epoch => self.verify_historical(message, signed),
            _ => Ok(false),
        }
    }

    /// Comprueba validez criptográfica histórica; no demuestra cuándo se firmó.
    pub fn verify_historical(&self, message: &[u8], signed: &EpochSignature) -> Result<bool, NexusError> {
        match self.at_epoch(&signed.identity, signed.epoch) {
            Some(key) => key.material.public_key.verify(
                &operation_bytes(signed.identity, signed.epoch, message), &signed.signature),
            None => Ok(false),
        }
    }

    /// El llamante debe obtener la posición de aceptación de evidencia independiente.
    pub fn verify_at_record(&self, message: &[u8], signed: &EpochSignature, position: u64)
        -> Result<bool, NexusError> {
        match self.at_epoch(&signed.identity, signed.epoch) {
            Some(key) if position < self.records.len() as u64 && position >= key.valid_from
                && key.valid_until.is_none_or(|end| position < end) =>
                self.verify_historical(message, signed),
            _ => Ok(false),
        }
    }

    /// Exporta únicamente eventos, claves públicas, compromisos y firmas.
    pub fn to_bytes(&self) -> Result<Vec<u8>, NexusError> {
        Ok(codec().serialize(&(FORMAT, &self.records))?)
    }

    /// Reconstruye el registro y exige conservar el prefijo del checkpoint confiable.
    /// Un checkpoint vacío permite alta inicial, pero no protege frente a rollback.
    pub fn from_bytes(bytes: &[u8], trusted: RegistryCheckpoint) -> Result<Self, NexusError> {
        if bytes.len() as u64 > MAX_ARCHIVE_BYTES {
            return Err(invalid("Archivo de registro demasiado grande"));
        }
        let (format, records): (u16, Vec<RotationRecord>) = codec().deserialize(bytes)?;
        if format != FORMAT { return Err(invalid("Versión de archivo desconocida")); }
        let mut registry = Self::new();
        for record in records { registry.append(record)?; }
        if trusted.records > registry.records.len() as u64 {
            return Err(invalid("Registro truncado respecto del checkpoint"));
        }
        let expected = if trusted.records == 0 { Hash256::ZERO }
            else { registry.hashes[trusted.records as usize - 1] };
        if expected != trusted.head { return Err(invalid("El registro contradice el checkpoint")); }
        Ok(registry)
    }
}
