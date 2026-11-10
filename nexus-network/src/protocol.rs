//! Network protocol definitions

/// Protocol version
pub const PROTOCOL_VERSION: u32 = nexus_core::PROTOCOL_VERSION;

/// Protocol identifier
pub const PROTOCOL_ID: &str = "/nexus/4.0.0"; // legacy local reference

/// Maximum message size (1 MB)
pub const MAX_MESSAGE_SIZE: usize = 1_048_576;

/// Handshake timeout (seconds)
pub const HANDSHAKE_TIMEOUT: u64 = 10;
