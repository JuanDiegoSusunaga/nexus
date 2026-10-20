//! Versioned local checkpoints in a trusted directory, not network certificates.
//! One OS file lock per writer; a synced temporary file is renamed before success.
//! Process-crash recovery is supported. Power-loss durability of directory metadata
//! and protection against malicious rollback/replacement require a separate policy.
use crate::{Hash256, NexusError};
use bincode::Options;
use serde::{de::DeserializeOwned, Serialize};
use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, path::{Path, PathBuf}};

pub const MAX_CHECKPOINT_BYTES: u64 = 64 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"NEXUSCP1";
const HEADER: usize = 56;

fn error(message: impl std::fmt::Display) -> NexusError { NexusError::StateError(message.to_string()) }

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, NexusError> {
    bincode::DefaultOptions::new().with_fixint_encoding().with_limit(MAX_CHECKPOINT_BYTES)
        .serialize(value).map_err(Into::into)
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, NexusError> {
    if bytes.len() as u64 > MAX_CHECKPOINT_BYTES { return Err(error("Checkpoint exceeds local size limit")); }
    bincode::DefaultOptions::new().with_fixint_encoding().with_limit(MAX_CHECKPOINT_BYTES)
        .reject_trailing_bytes().deserialize(bytes).map_err(Into::into)
}

/// Structural checks for a trusted local snapshot; does not replay or certify consensus.
pub fn validate_blocks(blocks: &std::collections::HashMap<Hash256, crate::Block>,
    heights: &std::collections::HashMap<crate::BlockHeight, Hash256>, height: crate::BlockHeight,
    genesis: &crate::Block, layer: crate::Layer, state_root: crate::StateRoot) -> Result<(), NexusError> {
    let count = height.0.checked_add(1).and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| error("Invalid checkpoint height"))?;
    if count != blocks.len() || count != heights.len() { return Err(error("Incomplete checkpoint block index")); }
    let mut expected_genesis = crate::Block::genesis(layer);
    expected_genesis.header.state_root = genesis.header.state_root;
    if encode(genesis)? != encode(&expected_genesis)? { return Err(error("Invalid checkpoint genesis")); }
    let mut parent = Hash256::ZERO;
    for number in 0..=height.0 {
        let hash = heights.get(&crate::BlockHeight(number)).ok_or_else(|| error("Missing checkpoint height"))?;
        let block = blocks.get(hash).ok_or_else(|| error("Missing checkpoint block"))?;
        if block.hash() != *hash || block.height().0 != number || block.parent_hash() != parent
            || block.header.layer != layer || block.header.version != crate::PROTOCOL_VERSION
            || (number == 0 && encode(block)? != encode(genesis)?)
            || (number > 0 && crate::MerkleTree::from_leaves(block.transaction_hashes()).root() != block.header.transactions_root) {
            return Err(error("Inconsistent checkpoint block chain"));
        }
        parent = *hash;
    }
    if blocks[&parent].header.state_root != state_root.0 { return Err(error("Checkpoint account root mismatch")); }
    Ok(())
}

pub struct CheckpointStore {
    directory: PathBuf,
    generation: u64,
    _writer: File,
}

impl CheckpointStore {
    pub fn create(directory: &Path) -> Result<Self, NexusError> {
        fs::create_dir_all(directory).map_err(error)?;
        let store = Self::lock(directory)?;
        if store.generation != 0 { return Err(error("A checkpoint already exists; open it instead")); }
        Ok(store)
    }

    pub fn open(directory: &Path) -> Result<Self, NexusError> {
        if !directory.is_dir() { return Err(error("Checkpoint directory does not exist")); }
        let store = Self::lock(directory)?;
        if store.generation == 0 { return Err(error("No committed checkpoint")); }
        Ok(store)
    }

    fn lock(directory: &Path) -> Result<Self, NexusError> {
        let directory = fs::canonicalize(directory).map_err(error)?;
        let writer = OpenOptions::new().read(true).write(true).create(true).truncate(false)
            .open(directory.join("writer.lock")).map_err(error)?;
        writer.try_lock().map_err(|e| error(format!("Checkpoint writer is locked: {e}")))?;
        let mut generation = 0;
        for entry in fs::read_dir(&directory).map_err(error)? {
            let name = entry.map_err(error)?.file_name();
            let name = name.to_string_lossy();
            if let Some(number) = name.strip_prefix("checkpoint-").and_then(|s| s.strip_suffix(".bin")) {
                if number.len() != 20 || !number.bytes().all(|c| c.is_ascii_digit()) {
                    return Err(error("Malformed checkpoint filename"));
                }
                let number = number.parse::<u64>().map_err(error)?;
                if number == 0 { return Err(error("Invalid checkpoint generation")); }
                generation = generation.max(number);
            }
        }
        Ok(Self { directory, generation, _writer: writer })
    }

    pub fn generation(&self) -> u64 { self.generation }

    fn path(&self, generation: u64) -> PathBuf { self.directory.join(format!("checkpoint-{generation:020}.bin")) }

    pub fn read_latest(&self) -> Result<Vec<u8>, NexusError> {
        let mut bytes = Vec::new();
        File::open(self.path(self.generation)).map_err(error)?
            .take(MAX_CHECKPOINT_BYTES + HEADER as u64 + 1).read_to_end(&mut bytes).map_err(error)?;
        if bytes.len() < HEADER || &bytes[..8] != MAGIC { return Err(error("Invalid checkpoint header/version")); }
        let generation = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let length = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        if generation != self.generation || length > MAX_CHECKPOINT_BYTES || length != (bytes.len() - HEADER) as u64 {
            return Err(error("Invalid checkpoint generation or length"));
        }
        let mut committed = bytes[8..24].to_vec(); committed.extend_from_slice(&bytes[HEADER..]);
        if Hash256::hash(&committed).as_bytes() != &bytes[24..HEADER] {
            return Err(error("Checkpoint checksum mismatch; refusing rollback"));
        }
        Ok(bytes[HEADER..].to_vec())
    }

    pub fn commit(&mut self, payload: &[u8]) -> Result<(), NexusError> {
        if payload.len() as u64 > MAX_CHECKPOINT_BYTES { return Err(error("Checkpoint exceeds local size limit")); }
        let generation = self.generation.checked_add(1).ok_or_else(|| error("Checkpoint generations exhausted"))?;
        let target = self.path(generation);
        if target.exists() { return Err(error("Checkpoint target already exists")); }
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(error)?.as_nanos();
        let temporary = self.directory.join(format!(".checkpoint-{generation:020}-{}-{stamp}.pending", std::process::id()));
        let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary).map_err(error)?;
        let result: Result<(), NexusError> = (|| {
            let mut committed = generation.to_le_bytes().to_vec();
            committed.extend_from_slice(&(payload.len() as u64).to_le_bytes()); committed.extend_from_slice(payload);
            file.write_all(MAGIC).map_err(error)?;
            file.write_all(&committed[..16]).map_err(error)?;
            file.write_all(Hash256::hash(&committed).as_bytes()).map_err(error)?;
            file.write_all(payload).map_err(error)?;
            file.sync_all().map_err(error)?;
            drop(file);
            fs::rename(&temporary, &target).map_err(error)?;
            Ok(())
        })();
        if result.is_err() { let _ = fs::remove_file(&temporary); }
        result?;
        // No fallible operation follows publication of the final filename.
        self.generation = generation;
        Ok(())
    }
}
