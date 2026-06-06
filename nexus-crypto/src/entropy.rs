//! Active Key-Lifecycle Management — Entropy Source Health and Key Rotation
//!
//! This module implements the "Sentinel-Seed" active-security logic on rigorous,
//! standards-based foundations (NEXUS thesis Objective 3, v2):
//!
//! - The security-relevant measure of an entropy SOURCE is its **min-entropy**
//!   `H_inf(X) = -log2(max_x Pr[X=x])`, **not** the Shannon entropy of a derived
//!   seed (which a CSPRNG makes look maximal regardless of the source's secrecy).
//! - The source is monitored online with the **NIST SP 800-90B health tests**
//!   (Repetition Count Test and Adaptive Proportion Test); their failure blocks
//!   key derivation and triggers rotation.
//! - Keys are rotated with **forward secrecy** by policy (use count, age, or a
//!   health-test failure), mixing the old seed into the new one via a one-way hash.
//!
//! NOTE: `EntropyMonitor::shannon_entropy` is retained for diagnostics/analysis
//! only; it is **not** used as a security metric or rotation trigger.

use nexus_core::{Hash256, NexusError, Timestamp};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::VecDeque;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Minimum acceptable **source min-entropy** (bits per byte).
/// 7.5 bits/byte is a demanding bar for a byte-oriented source (max is 8.0).
pub const MIN_ENTROPY_BITS: f64 = 7.5;

/// Maximum entropy (theoretical maximum for bytes).
pub const MAX_ENTROPY_BITS: f64 = 8.0;

/// Default rotation interval (number of derivations before forced rotation).
pub const DEFAULT_ROTATION_INTERVAL: u64 = 100_000;

// ---------------------------------------------------------------------------
// NIST SP 800-90B online health tests
// ---------------------------------------------------------------------------

/// Continuous health tests for an entropy source, per **NIST SP 800-90B §4.4**:
/// the Repetition Count Test (RCT) and the Adaptive Proportion Test (APT).
///
/// Both run on the raw sample stream of the source. A failure marks the source
/// unhealthy, which blocks key derivation and triggers rotation/reseeding.
#[derive(Debug, Clone)]
pub struct HealthMonitor {
    // Repetition Count Test
    rct_cutoff: u64,
    rct_last: Option<u8>,
    rct_run: u64,
    // Adaptive Proportion Test
    apt_window: usize,
    apt_cutoff: u64,
    apt_ref: Option<u8>,
    apt_seen: usize,
    apt_count: u64,
    // Overall status
    failed: bool,
}

impl HealthMonitor {
    /// SP 800-90B health-test false-positive probability: alpha = 2^-20.
    /// Hence -log2(alpha) = 20.
    const NEG_LOG2_ALPHA: f64 = 20.0;
    /// One-sided normal quantile for (1 - alpha) with alpha = 2^-20 (~4.7634),
    /// used in the normal approximation of the APT binomial cutoff.
    const Z_ALPHA: f64 = 4.7634;
    /// APT window size for non-binary (byte) sources.
    const APT_WINDOW: usize = 512;

    /// Build a monitor for a source whose assessed min-entropy is `h_min`
    /// (bits per sample). Cutoffs are derived from `h_min` and alpha = 2^-20.
    pub fn new(h_min: f64) -> Self {
        let h = h_min.clamp(0.01, 8.0);
        // RCT cutoff: C = 1 + ceil(-log2(alpha) / H).
        let rct_cutoff = 1 + (Self::NEG_LOG2_ALPHA / h).ceil() as u64;
        // APT cutoff via normal approximation of Binomial(W, p), p = 2^-H.
        let w = Self::APT_WINDOW as f64;
        let p = 2f64.powf(-h);
        let mean = w * p;
        let sd = (w * p * (1.0 - p)).sqrt();
        let apt_cutoff = (mean + Self::Z_ALPHA * sd).ceil() as u64;
        Self {
            rct_cutoff,
            rct_last: None,
            rct_run: 0,
            apt_window: Self::APT_WINDOW,
            apt_cutoff,
            apt_ref: None,
            apt_seen: 0,
            apt_count: 0,
            failed: false,
        }
    }

    /// Feed one raw source sample to both tests.
    pub fn update(&mut self, sample: u8) {
        // Repetition Count Test
        match self.rct_last {
            Some(prev) if prev == sample => {
                self.rct_run += 1;
                if self.rct_run >= self.rct_cutoff {
                    self.failed = true;
                }
            }
            _ => {
                self.rct_last = Some(sample);
                self.rct_run = 1;
            }
        }
        // Adaptive Proportion Test
        match self.apt_ref {
            None => {
                self.apt_ref = Some(sample);
                self.apt_seen = 1;
                self.apt_count = 1;
            }
            Some(reference) => {
                self.apt_seen += 1;
                if sample == reference {
                    self.apt_count += 1;
                    if self.apt_count >= self.apt_cutoff {
                        self.failed = true;
                    }
                }
                if self.apt_seen >= self.apt_window {
                    // Start a fresh window.
                    self.apt_ref = None;
                    self.apt_seen = 0;
                    self.apt_count = 0;
                }
            }
        }
    }

    /// Feed many samples.
    pub fn update_all(&mut self, samples: &[u8]) {
        for &s in samples {
            self.update(s);
        }
    }

    /// True while neither health test has failed.
    pub fn is_healthy(&self) -> bool {
        !self.failed
    }

    /// RCT / APT cutoffs (for inspection/testing).
    pub fn cutoffs(&self) -> (u64, u64) {
        (self.rct_cutoff, self.apt_cutoff)
    }

    /// Clear test state (e.g., after a successful reseed). Cutoffs are preserved.
    pub fn reset(&mut self) {
        self.rct_last = None;
        self.rct_run = 0;
        self.apt_ref = None;
        self.apt_seen = 0;
        self.apt_count = 0;
        self.failed = false;
    }
}

// ---------------------------------------------------------------------------
// Sentinel-Seed
// ---------------------------------------------------------------------------

/// Sentinel-Seed: a monitored seed with active key-lifecycle management.
#[derive(Clone)]
pub struct SentinelSeed {
    /// Current seed value (zeroized on drop).
    seed: SeedValue,
    /// Current epoch (increments on each rotation).
    epoch: u64,
    /// Number of times the seed has been used to derive a key.
    use_count: u64,
    /// Creation timestamp.
    created_at: Timestamp,
    /// Last rotation timestamp.
    last_rotation: Timestamp,
    /// Estimated min-entropy of the SOURCE (bits/byte) at the last assessment.
    source_min_entropy: f64,
    /// Online health monitor for the source (SP 800-90B).
    health: HealthMonitor,
    /// History of source min-entropy measurements.
    entropy_history: VecDeque<EntropyMeasurement>,
    /// Configuration.
    config: SentinelConfig,
}

/// Internal seed value with zeroization.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct SeedValue {
    bytes: [u8; 32],
}

/// Configuration for the Sentinel-Seed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    /// Minimum acceptable **source min-entropy** (bits/byte).
    pub min_entropy: f64,
    /// Maximum derivations before forced rotation.
    pub max_uses: u64,
    /// Maximum age before forced rotation (milliseconds).
    pub max_age_ms: u64,
    /// Number of entropy measurements to keep.
    pub history_size: usize,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            min_entropy: MIN_ENTROPY_BITS,
            max_uses: DEFAULT_ROTATION_INTERVAL,
            max_age_ms: 86_400_000, // 24 hours
            history_size: 100,
        }
    }
}

/// A single source min-entropy measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyMeasurement {
    /// Estimated source min-entropy (bits/byte).
    pub min_entropy: f64,
    /// Timestamp of measurement.
    pub timestamp: Timestamp,
    /// Use count at measurement time.
    pub use_count: u64,
}

impl SentinelSeed {
    /// Create a new Sentinel-Seed with a random value.
    pub fn new() -> Self {
        Self::with_config(SentinelConfig::default())
    }

    /// Create with custom configuration.
    pub fn with_config(config: SentinelConfig) -> Self {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self::build(bytes, config)
    }

    /// Create from existing seed bytes.
    pub fn from_bytes(bytes: [u8; 32], config: SentinelConfig) -> Self {
        Self::build(bytes, config)
    }

    fn build(bytes: [u8; 32], config: SentinelConfig) -> Self {
        let now = Timestamp::now();
        // The source is assumed to meet its configured min-entropy until an
        // explicit assessment (`ingest_source`) says otherwise. In a deployment
        // this estimate comes from the raw entropy source, never from the seed.
        let source_min_entropy = config.min_entropy;
        let health = HealthMonitor::new(config.min_entropy);
        Self {
            seed: SeedValue { bytes },
            epoch: 0,
            use_count: 0,
            created_at: now,
            last_rotation: now,
            source_min_entropy,
            health,
            entropy_history: VecDeque::with_capacity(config.history_size),
            config,
        }
    }

    /// Current epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Use count.
    pub fn use_count(&self) -> u64 {
        self.use_count
    }

    /// Estimated source min-entropy (bits/byte) — the security-relevant measure.
    pub fn source_min_entropy(&self) -> f64 {
        self.source_min_entropy
    }

    /// Whether the source health tests are currently passing.
    pub fn is_source_healthy(&self) -> bool {
        self.health.is_healthy()
    }

    /// Shannon entropy of the seed bytes — **diagnostic only**, NOT a security
    /// metric (a CSPRNG-derived seed looks near-maximal regardless of secrecy).
    pub fn current_entropy(&self) -> f64 {
        EntropyMonitor::shannon_entropy(&self.seed.bytes)
    }

    /// Feed raw SOURCE samples to the health tests and re-estimate the source
    /// min-entropy. Records a measurement.
    pub fn ingest_source(&mut self, samples: &[u8]) {
        self.health.update_all(samples);
        if !samples.is_empty() {
            self.source_min_entropy = EntropyMonitor::estimate_min_entropy(samples);
            self.record_entropy();
        }
    }

    /// Check whether rotation is needed (by policy or source health).
    pub fn needs_rotation(&self) -> bool {
        // Source health failure (SP 800-90B).
        if !self.health.is_healthy() {
            return true;
        }
        // Source min-entropy below the acceptable bar.
        if self.source_min_entropy < self.config.min_entropy {
            return true;
        }
        // Usage limit.
        if self.use_count >= self.config.max_uses {
            return true;
        }
        // Age limit.
        let age = Timestamp::now().elapsed_since(self.last_rotation);
        age >= self.config.max_age_ms
    }

    /// Reason for rotation, if any.
    pub fn rotation_reason(&self) -> Option<RotationReason> {
        if !self.health.is_healthy() {
            return Some(RotationReason::SourceUnhealthy);
        }
        if self.source_min_entropy < self.config.min_entropy {
            return Some(RotationReason::LowEntropy {
                current: self.source_min_entropy,
                minimum: self.config.min_entropy,
            });
        }
        if self.use_count >= self.config.max_uses {
            return Some(RotationReason::MaxUsesReached {
                uses: self.use_count,
                max: self.config.max_uses,
            });
        }
        let age = Timestamp::now().elapsed_since(self.last_rotation);
        if age >= self.config.max_age_ms {
            return Some(RotationReason::AgeExpired {
                age_ms: age,
                max_ms: self.config.max_age_ms,
            });
        }
        None
    }

    /// Derive a key from the seed (increments use count). Blocks if rotation is
    /// needed (usage/age/source-health), enforcing the active-security policy.
    pub fn derive_key(&mut self, context: &[u8]) -> Result<[u8; 32], NexusError> {
        if self.needs_rotation() {
            return Err(NexusError::KeyRotationRequired);
        }
        Ok(self.derive_key_unchecked(context))
    }

    /// Derive without the rotation check (use with caution).
    pub fn derive_key_unchecked(&mut self, context: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"NEXUS_SENTINEL_DERIVE");
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.use_count.to_le_bytes());
        hasher.update(self.seed.bytes);
        hasher.update(context);

        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);

        self.use_count += 1;
        key
    }

    /// Rotate the seed with forward secrecy and reset the health state.
    pub fn rotate(&mut self) -> RotationResult {
        let old_epoch = self.epoch;
        let old_entropy = self.source_min_entropy;
        let reason = self.rotation_reason();

        // Fresh material mixed with the old seed via a one-way hash → forward
        // secrecy: compromising the new seed does not reveal past seeds.
        let mut rng = ChaCha20Rng::from_entropy();
        let mut new_bytes = [0u8; 32];
        rng.fill_bytes(&mut new_bytes);

        let mut hasher = Sha3_256::new();
        hasher.update(b"NEXUS_SENTINEL_ROTATE");
        hasher.update(self.seed.bytes);
        hasher.update(new_bytes);
        hasher.update(self.epoch.to_le_bytes());
        let mixed = hasher.finalize();

        // Zeroize old seed, install new one.
        self.seed.bytes.zeroize();
        self.seed.bytes.copy_from_slice(&mixed);
        self.epoch += 1;
        self.use_count = 0;
        self.last_rotation = Timestamp::now();

        // Fresh source assessment and health state for the new epoch.
        self.source_min_entropy = self.config.min_entropy;
        self.health.reset();
        self.entropy_history.clear();

        RotationResult {
            old_epoch,
            new_epoch: self.epoch,
            old_entropy,
            new_entropy: self.source_min_entropy,
            reason,
            timestamp: self.last_rotation,
        }
    }

    fn record_entropy(&mut self) {
        let measurement = EntropyMeasurement {
            min_entropy: self.source_min_entropy,
            timestamp: Timestamp::now(),
            use_count: self.use_count,
        };
        if self.entropy_history.len() >= self.config.history_size {
            self.entropy_history.pop_front();
        }
        self.entropy_history.push_back(measurement);
    }

    /// Source min-entropy measurement history.
    pub fn entropy_history(&self) -> &VecDeque<EntropyMeasurement> {
        &self.entropy_history
    }

    /// Average measured source min-entropy.
    pub fn average_entropy(&self) -> Option<f64> {
        if self.entropy_history.is_empty() {
            return None;
        }
        let sum: f64 = self.entropy_history.iter().map(|m| m.min_entropy).sum();
        Some(sum / self.entropy_history.len() as f64)
    }

    /// Seed identifier (a hash, not the seed itself).
    pub fn seed_hash(&self) -> Hash256 {
        let mut hasher = Sha3_256::new();
        hasher.update(b"NEXUS_SENTINEL_ID");
        hasher.update(self.seed.bytes);
        hasher.update(self.epoch.to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Hash256::new(hash)
    }
}

impl Default for SentinelSeed {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SentinelSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SentinelSeed")
            .field("epoch", &self.epoch)
            .field("use_count", &self.use_count)
            .field("source_min_entropy", &self.source_min_entropy)
            .field("source_healthy", &self.health.is_healthy())
            .field("needs_rotation", &self.needs_rotation())
            .field("seed", &"[REDACTED]")
            .finish()
    }
}

/// Reason for key rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RotationReason {
    /// Source min-entropy below the acceptable threshold.
    LowEntropy { current: f64, minimum: f64 },
    /// Source failed an SP 800-90B health test (RCT/APT).
    SourceUnhealthy,
    /// Usage limit reached.
    MaxUsesReached { uses: u64, max: u64 },
    /// Age limit reached.
    AgeExpired { age_ms: u64, max_ms: u64 },
    /// Manual rotation.
    Manual,
}

/// Result of a rotation operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationResult {
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub old_entropy: f64,
    pub new_entropy: f64,
    pub reason: Option<RotationReason>,
    pub timestamp: Timestamp,
}

// ---------------------------------------------------------------------------
// Entropy analysis utilities
// ---------------------------------------------------------------------------

/// Entropy analysis utilities.
pub struct EntropyMonitor;

impl EntropyMonitor {
    /// Shannon entropy of data (bits per byte). **Diagnostic only** — for a
    /// short, derived buffer this does not measure key secrecy. Use
    /// `estimate_min_entropy` on the raw source for security decisions.
    pub fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut frequencies = [0u64; 256];
        for &byte in data {
            frequencies[byte as usize] += 1;
        }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &count in &frequencies {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Min-entropy of data (bits per byte): `H_inf = -log2(max_x p(x))`.
    pub fn min_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut frequencies = [0u64; 256];
        for &byte in data {
            frequencies[byte as usize] += 1;
        }
        let len = data.len() as f64;
        let max_freq = *frequencies.iter().max().unwrap() as f64;
        -(max_freq / len).log2()
    }

    /// Most-Common-Value min-entropy estimate (NIST SP 800-90B §6.3.1, point
    /// estimate). This is the appropriate estimator for an entropy SOURCE.
    pub fn estimate_min_entropy(samples: &[u8]) -> f64 {
        Self::min_entropy(samples)
    }

    /// Whether the source min-entropy estimate meets `min_bits`.
    pub fn is_sufficient(data: &[u8], min_bits: f64) -> bool {
        Self::estimate_min_entropy(data) >= min_bits
    }

    /// Estimated total bits of security in a buffer (min-entropy * length).
    pub fn security_bits(data: &[u8]) -> f64 {
        Self::min_entropy(data) * data.len() as f64
    }

    /// Analyze entropy quality of a (source) buffer.
    pub fn analyze(data: &[u8]) -> EntropyAnalysis {
        let shannon = Self::shannon_entropy(data);
        let min = Self::min_entropy(data);
        let security = Self::security_bits(data);
        let quality = if min >= 7.9 {
            EntropyQuality::Excellent
        } else if min >= 7.5 {
            EntropyQuality::Good
        } else if min >= 6.0 {
            EntropyQuality::Acceptable
        } else if min >= 4.0 {
            EntropyQuality::Poor
        } else {
            EntropyQuality::Insufficient
        };
        EntropyAnalysis {
            shannon_entropy: shannon,
            min_entropy: min,
            security_bits: security,
            quality,
            data_length: data.len(),
        }
    }
}

/// Entropy analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyAnalysis {
    pub shannon_entropy: f64,
    pub min_entropy: f64,
    pub security_bits: f64,
    pub quality: EntropyQuality,
    pub data_length: usize,
}

/// Entropy quality classification (by min-entropy, bits/byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntropyQuality {
    Excellent,    // >= 7.9
    Good,         // >= 7.5
    Acceptable,   // >= 6.0
    Poor,         // >= 4.0
    Insufficient, // < 4.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_uniform() {
        let data = [0u8; 256];
        assert_eq!(EntropyMonitor::shannon_entropy(&data), 0.0);
    }

    #[test]
    fn test_shannon_entropy_two_values() {
        let data: Vec<u8> = (0..256).map(|i| (i % 2) as u8).collect();
        let entropy = EntropyMonitor::shannon_entropy(&data);
        assert!((entropy - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_min_entropy_estimate() {
        // A biased source: one value dominates -> low min-entropy.
        let mut data = vec![7u8; 900];
        data.extend(std::iter::repeat(3u8).take(100));
        let h = EntropyMonitor::estimate_min_entropy(&data);
        // p_max = 0.9 -> H_inf = -log2(0.9) ~ 0.152
        assert!(h < 0.2);
    }

    #[test]
    fn test_sentinel_seed_creation() {
        let seed = SentinelSeed::new();
        assert_eq!(seed.epoch(), 0);
        assert_eq!(seed.use_count(), 0);
        // The source is healthy and meets its configured min-entropy bar.
        assert!(seed.is_source_healthy());
        assert!(seed.source_min_entropy() >= MIN_ENTROPY_BITS);
        // The diagnostic Shannon-of-seed is well-defined but NOT used for security.
        let diag = seed.current_entropy();
        assert!((0.0..=8.0).contains(&diag));
    }

    #[test]
    fn test_sentinel_seed_derive() {
        let mut seed = SentinelSeed::new();
        let key1 = seed.derive_key(b"context1").unwrap();
        let key2 = seed.derive_key(b"context2").unwrap();
        assert_ne!(key1, key2);
        assert_eq!(seed.use_count(), 2);
    }

    #[test]
    fn test_sentinel_seed_rotation_forward_secure() {
        let mut seed = SentinelSeed::new();
        let hash1 = seed.seed_hash();
        let result = seed.rotate();
        assert_eq!(result.old_epoch, 0);
        assert_eq!(result.new_epoch, 1);
        assert_eq!(seed.use_count(), 0);
        assert_ne!(hash1, seed.seed_hash());
    }

    #[test]
    fn test_needs_rotation_uses() {
        let config = SentinelConfig {
            max_uses: 10,
            ..Default::default()
        };
        let mut seed = SentinelSeed::with_config(config);
        for _ in 0..10 {
            let _ = seed.derive_key_unchecked(b"test");
        }
        assert!(seed.needs_rotation());
        assert!(matches!(
            seed.rotation_reason(),
            Some(RotationReason::MaxUsesReached { .. })
        ));
    }

    #[test]
    fn test_health_rct_detects_stuck_source() {
        // RCT cutoff at H=7.5 is 1 + ceil(20/7.5) = 4: a value repeated >= 4
        // times consecutively fails the test.
        let mut hm = HealthMonitor::new(7.5);
        let (rct_cutoff, _) = hm.cutoffs();
        assert_eq!(rct_cutoff, 4);
        for _ in 0..rct_cutoff {
            hm.update(0xAB);
        }
        assert!(!hm.is_healthy());
    }

    #[test]
    fn test_health_passes_on_random() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let mut data = [0u8; 2048];
        rng.fill_bytes(&mut data);
        let mut hm = HealthMonitor::new(7.5);
        hm.update_all(&data);
        assert!(hm.is_healthy());
    }

    #[test]
    fn test_ingest_unhealthy_source_triggers_rotation() {
        let mut seed = SentinelSeed::new();
        assert!(!seed.needs_rotation());
        // A long run of a single byte trips the RCT.
        seed.ingest_source(&[0x00u8; 64]);
        assert!(!seed.is_source_healthy());
        assert!(seed.needs_rotation());
        assert!(matches!(
            seed.rotation_reason(),
            Some(RotationReason::SourceUnhealthy)
        ));
        // Derivation is blocked while the source is unhealthy.
        assert!(seed.derive_key(b"ctx").is_err());
    }
}
