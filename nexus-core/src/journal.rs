//! Registros inmutables y acotados, publicados mediante renombrado del temporal sincronizado.
//! La recuperación ignora temporales incompletos que nunca se confirmaron.
//! Un hueco o registro publicado corrupto impide abrir el diario; nunca se trunca.
//! Requiere directorio y sistema de archivos confiables. No garantiza resistencia
//! a retrocesos maliciosos. En Unix sincroniza archivo y directorio antes de
//! confirmar; un fallo después del renombrado exige reabrir y reproducir.
//! Otros sistemas conservan la garantía previa de sincronización del archivo.
use crate::{Hash256, NexusError};
use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, path::{Path, PathBuf}};

pub const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"NXSJNL02";
const HEADER: usize = 88;
fn error(message: impl std::fmt::Display) -> NexusError { NexusError::StateError(message.to_string()) }

fn sync_directory(directory: &Path) -> Result<(), NexusError> {
    #[cfg(unix)]
    File::open(directory).and_then(|file| file.sync_all()).map_err(error)?;
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

pub struct JournalStore {
    directory: PathBuf,
    sequence: u64,
    digest: Hash256,
    requires_recovery: bool,
    _writer: File,
}
impl JournalStore {
    pub fn record_name(sequence: u64) -> String { format!("event-{sequence:020}.bin") }
    pub fn exists(directory: &Path) -> Result<bool, NexusError> {
        if !directory.is_dir() { return Ok(false); }
        for entry in fs::read_dir(directory).map_err(error)? {
            let name = entry.map_err(error)?.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("event-") || name.starts_with("checkpoint-") { return Ok(true); }
        }
        Ok(false)
    }
    fn lock(directory: &Path) -> Result<Self, NexusError> {
        let directory = fs::canonicalize(directory).map_err(error)?;
        let writer = OpenOptions::new().read(true).write(true).create(true).truncate(false)
            .open(directory.join("writer.lock")).map_err(error)?;
        writer.try_lock().map_err(|e| error(format!("Journal writer is locked: {e}")))?;
        Ok(Self { directory, sequence: 0, digest: Hash256::ZERO, requires_recovery: false, _writer: writer })
    }
    fn records(&self) -> Result<Vec<(u64, PathBuf)>, NexusError> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.directory).map_err(error)? {
            let entry = entry.map_err(error)?;
            let name = entry.file_name(); let name = name.to_string_lossy();
            if name.starts_with("checkpoint-") {
                return Err(NexusError::ConfigError("Legacy snapshots require an explicit migration; use a new journal directory".into()));
            }
            if name.starts_with("event-") {
                let number = name.strip_prefix("event-").and_then(|s| s.strip_suffix(".bin"))
                    .ok_or_else(|| error("Malformed journal filename"))?;
                if number.len() != 20 || !number.bytes().all(|c| c.is_ascii_digit()) || !entry.file_type().map_err(error)?.is_file() {
                    return Err(error("Invalid published journal record"));
                }
                let sequence = number.parse::<u64>().map_err(error)?;
                if sequence == 0 { return Err(error("Journal sequence zero is reserved")); }
                records.push((sequence, entry.path()));
            }
        }
        records.sort_by_key(|entry| entry.0);
        Ok(records)
    }
    pub fn create(directory: &Path) -> Result<Self, NexusError> {
        fs::create_dir_all(directory).map_err(error)?;
        let store = Self::lock(directory)?;
        if !store.records()?.is_empty() { return Err(error("A journal already exists; open it instead")); }
        // Persist new directory entries too, including ancestors created by create_dir_all.
        for ancestor in store.directory.ancestors() { sync_directory(ancestor)?; }
        Ok(store)
    }
    pub fn open(directory: &Path, mut visit: impl FnMut(u64, &[u8]) -> Result<(), NexusError>) -> Result<Self, NexusError> {
        let mut store = Self::lock(directory)?;
        let records = store.records()?;
        if records.is_empty() { return Err(error("No committed journal genesis record")); }
        for (sequence, path) in records {
            if store.sequence.checked_add(1) != Some(sequence) { return Err(error("Missing journal sequence; refusing rollback")); }
            let mut file = File::open(path).map_err(error)?;
            let mut header = [0; HEADER]; file.read_exact(&mut header).map_err(error)?;
            let mut sequence_bytes = [0; 8]; sequence_bytes.copy_from_slice(&header[8..16]);
            let stored_sequence = u64::from_le_bytes(sequence_bytes);
            let mut length_bytes = [0; 8]; length_bytes.copy_from_slice(&header[16..24]);
            let length = u64::from_le_bytes(length_bytes);
            if &header[..8] != MAGIC || stored_sequence != sequence || length == 0 || length > MAX_RECORD_BYTES as u64
                || file.metadata().map_err(error)?.len() != HEADER as u64 + length
                || &header[24..56] != store.digest.as_bytes() {
                return Err(error("Invalid journal header, length or hash chain"));
            }
            let mut payload = vec![0; length as usize]; file.read_exact(&mut payload).map_err(error)?;
            let mut committed = header[8..56].to_vec(); committed.extend_from_slice(&payload);
            let digest = Hash256::hash(&committed);
            if &header[56..88] != digest.as_bytes() { return Err(error("Journal checksum mismatch; refusing rollback")); }
            visit(sequence, &payload)?;
            store.sequence = sequence; store.digest = digest;
        }
        // A prior writer may have published a record but failed its directory sync.
        sync_directory(&store.directory)?;
        Ok(store)
    }
    pub fn sequence(&self) -> u64 { self.sequence }
    /// A published record could not be confirmed durable; replay before continuing.
    pub fn requires_recovery(&self) -> bool { self.requires_recovery }
    pub fn commit(&mut self, payload: &[u8]) -> Result<(), NexusError> {
        self.commit_with_directory_sync(payload, sync_directory)
    }
    fn commit_with_directory_sync(&mut self, payload: &[u8],
        sync: impl FnOnce(&Path) -> Result<(), NexusError>) -> Result<(), NexusError> {
        if self.requires_recovery { return Err(error("Journal publication is uncertain; reopen for recovery")); }
        if payload.is_empty() || payload.len() > MAX_RECORD_BYTES { return Err(error("Journal record exceeds byte limit")); }
        let sequence = self.sequence.checked_add(1).ok_or_else(|| error("Journal sequence exhausted"))?;
        let target = self.directory.join(Self::record_name(sequence));
        if target.exists() { return Err(error("Journal target already exists")); }
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(error)?.as_nanos();
        let temporary = self.directory.join(format!(".event-{sequence:020}-{}-{stamp}.pending", std::process::id()));
        let mut committed = sequence.to_le_bytes().to_vec();
        committed.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        committed.extend_from_slice(self.digest.as_bytes()); committed.extend_from_slice(payload);
        let digest = Hash256::hash(&committed);
        let result: Result<(), NexusError> = (|| {
            let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary).map_err(error)?;
            file.write_all(MAGIC).map_err(error)?;
            file.write_all(&committed[..48]).map_err(error)?;
            file.write_all(digest.as_bytes()).map_err(error)?;
            file.write_all(payload).map_err(error)?;
            file.sync_all().map_err(error)?;
            drop(file);
            fs::rename(&temporary, &target).map_err(error)?;
            Ok(())
        })();
        if result.is_err() { let _ = fs::remove_file(&temporary); }
        result?;
        // Rename made this record visible. Never roll it back or reuse its sequence,
        // even if syncing the directory fails. The caller must replay before signing.
        self.sequence = sequence; self.digest = digest;
        self.requires_recovery = true;
        sync(&self.directory)?;
        self.requires_recovery = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_directory_sync_keeps_published_record_and_requires_replay() {
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!("nexus-sync-{}-{stamp}", std::process::id()));
        let mut writer = JournalStore::create(&directory).unwrap();
        writer.commit(b"genesis").unwrap();
        let result = writer.commit_with_directory_sync(b"signed vote", |_| Err(error("injected fsync failure")));
        assert!(result.is_err());
        assert!(writer.requires_recovery());
        assert_eq!(writer.sequence(), 2);
        let published = directory.join(JournalStore::record_name(2));
        let exact = fs::read(&published).unwrap();
        assert!(writer.commit(b"conflicting vote").is_err());
        assert_eq!(fs::read(&published).unwrap(), exact);
        assert!(!directory.join(JournalStore::record_name(3)).exists());
        drop(writer);
        let mut replayed = Vec::new();
        let mut recovered = JournalStore::open(&directory, |_, bytes| {
            replayed.push(bytes.to_vec()); Ok(())
        }).unwrap();
        assert_eq!(replayed, vec![b"genesis".to_vec(), b"signed vote".to_vec()]);
        assert!(!recovered.requires_recovery());
        recovered.commit(b"next vote").unwrap();
        assert_eq!(recovered.sequence(), 3);
        drop(recovered);
        fs::remove_dir_all(directory).unwrap();
    }
}
