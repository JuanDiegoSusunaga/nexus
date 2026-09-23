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

/// Lote fijo para la frecuencia máxima empírica (Decisión 001).
/// Acumula muestras entre llamadas; no constituye una calificación SP 800-90B.
pub const SOURCE_ASSESSMENT_SAMPLES: usize = 65_536;

/// Estado de la evaluación operativa del flujo suministrado por la aplicación.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceStatus {
    Unassessed,
    Healthy,
    HealthTestFailed,
    LowEntropy,
    Recovering,
    InvalidConfiguration,
}

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
    /// APT window size for non-binary (byte) sources.
    const APT_WINDOW: usize = 512;

    /// Build a monitor for a source whose assessed min-entropy is `h_min`
    /// (bits per sample). Cutoffs are derived from `h_min` and alpha = 2^-20.
    pub fn new(h_min: f64) -> Self {
        match Self::try_new(h_min) {
            Ok(monitor) => monitor,
            Err(_) => Self {
                rct_cutoff: 0, rct_last: None, rct_run: 0,
                apt_window: Self::APT_WINDOW, apt_cutoff: 0,
                apt_ref: None, apt_seen: 0, apt_count: 0, failed: true,
            },
        }
    }

    /// Construcción con error explícito; no corrige silenciosamente parámetros inválidos.
    pub fn try_new(h_min: f64) -> Result<Self, NexusError> {
        if !h_min.is_finite() || !(0.01..=MAX_ENTROPY_BITS).contains(&h_min) {
            return Err(NexusError::ConfigError(
                "La min-entropía por byte debe estar entre 0,01 y 8 bits".into(),
            ));
        }
        let h = h_min;
        // RCT: C = 1 + ceil(-log2(alpha) / H).
        let rct_cutoff = 1 + (Self::NEG_LOG2_ALPHA / h).ceil() as u64;
        let p = 2f64.powf(-h);
        // La referencia ya cuenta: B = 1 + Binomial(W-1, p).
        // Se calcula la menor C con P(B >= C) <= alpha (C=16 para H=7,5).
        let apt_cutoff = Self::binomial_cutoff(p);
        Ok(Self {
            rct_cutoff,
            rct_last: None,
            rct_run: 0,
            apt_window: Self::APT_WINDOW,
            apt_cutoff,
            apt_ref: None,
            apt_seen: 0,
            apt_count: 0,
            failed: false,
        })
    }

    /// Suma binomial con pesos relativos al modo para evitar subdesbordamiento.
    fn binomial_cutoff(p: f64) -> u64 {
        let n = Self::APT_WINDOW - 1;
        let mode = (((n + 1) as f64 * p).floor() as usize).min(n);
        let mut weights = [0.0; Self::APT_WINDOW];
        weights[mode] = 1.0;
        for k in (1..=mode).rev() {
            weights[k-1] = weights[k] * k as f64 / (n-k+1) as f64 * (1.0-p) / p;
        }
        for k in mode..n {
            weights[k+1] = weights[k] * (n-k) as f64 / (k+1) as f64 * p / (1.0-p);
        }
        let total: f64 = weights.iter().sum();
        let alpha = 2f64.powf(-Self::NEG_LOG2_ALPHA);
        let mut tail = 0.0;
        let mut cutoff = (n + 2) as u64;
        for k in (0..=n).rev() {
            tail += weights[k] / total;
            if tail > alpha {
                break;
            }
            cutoff = (k + 1) as u64;
        }
        cutoff
    }

    /// Feed one raw source sample to both tests.
    pub fn update(&mut self, sample: u8) {
        // El fallo queda retenido hasta una reevaluación explícita del consumidor.
        if self.failed { return; }
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

    /// No se han observado fallos. Por sí solo no acredita suficientes muestras.
    pub fn is_healthy(&self) -> bool {
        !self.failed
    }

    /// RCT / APT cutoffs (for inspection/testing).
    pub fn cutoffs(&self) -> (u64, u64) {
        (self.rct_cutoff, self.apt_cutoff)
    }

    /// Reinicia contadores; el consumidor debe exigir nuevas muestras antes de derivar.
    pub fn reset(&mut self) {
        self.rct_last = None;
        self.rct_run = 0;
        self.apt_ref = None;
        self.apt_seen = 0;
        self.apt_count = 0;
        self.failed = self.rct_cutoff == 0 || self.apt_cutoff == 0;
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
    /// Estado independiente de la semilla y de los contadores de rotación.
    source_status: SourceStatus,
    /// Histograma de un lote; no se conservan muestras crudas ni material de semilla.
    source_counts: [u64; 256],
    source_samples: usize,
    /// Un fallo exige recuperar el flujo y renovar la semilla antes de derivar.
    rotation_after_recovery: bool,
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
        // Crear una semilla o asumir una barra no equivale a evaluar la fuente.
        let source_min_entropy = 0.0;
        let health = HealthMonitor::new(config.min_entropy);
        let source_status = if health.is_healthy() {
            SourceStatus::Unassessed
        } else {
            SourceStatus::InvalidConfiguration
        };
        Self {
            seed: SeedValue { bytes },
            epoch: 0,
            use_count: 0,
            created_at: now,
            last_rotation: now,
            source_min_entropy,
            health,
            source_status,
            source_counts: [0; 256],
            source_samples: 0,
            rotation_after_recovery: false,
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

    /// Última frecuencia máxima empírica expresada en bits/byte; cero sin evaluación.
    /// Consultar `source_status` para distinguir ausencia de evaluación y degradación.
    pub fn source_min_entropy(&self) -> f64 {
        self.source_min_entropy
    }

    /// Whether the source health tests are currently passing.
    pub fn is_source_healthy(&self) -> bool {
        self.source_status == SourceStatus::Healthy && self.health.is_healthy()
    }

    pub fn source_status(&self) -> SourceStatus {
        self.source_status
    }

    /// Número de muestras acumuladas en el lote actual, siempre menor que 65.536.
    pub fn pending_source_samples(&self) -> usize {
        self.source_samples
    }

    /// Shannon entropy of the seed bytes — **diagnostic only**, NOT a security
    /// metric (a CSPRNG-derived seed looks near-maximal regardless of secrecy).
    pub fn current_entropy(&self) -> f64 {
        EntropyMonitor::shannon_entropy(&self.seed.bytes)
    }

    /// Evalúa el flujo entregado por la aplicación en lotes fijos de 65.536 bytes.
    /// La aplicación debe vincularlo a la fuente que realmente utiliza y calificarla.
    /// Muestras vacías/parciales no habilitan el arranque; un fallo no se borra
    /// enviando después un lote sano. La recuperación se inicia explícitamente.
    pub fn ingest_source(&mut self, samples: &[u8]) {
        if matches!(self.source_status, SourceStatus::HealthTestFailed
            | SourceStatus::LowEntropy | SourceStatus::InvalidConfiguration) {
            return;
        }
        for &sample in samples {
            self.health.update(sample);
            if !self.health.is_healthy() {
                self.source_status = SourceStatus::HealthTestFailed;
                self.rotation_after_recovery = true;
                return;
            }
            self.source_counts[sample as usize] += 1;
            self.source_samples += 1;
            if self.source_samples == SOURCE_ASSESSMENT_SAMPLES {
                let maximum = self.source_counts.iter().copied().max().unwrap_or(0);
                let p = maximum as f64 / SOURCE_ASSESSMENT_SAMPLES as f64;
                self.source_min_entropy = -p.log2();
                self.record_entropy();
                self.source_counts.fill(0);
                self.source_samples = 0;
                if self.source_min_entropy < self.config.min_entropy {
                    self.source_status = SourceStatus::LowEntropy;
                    self.rotation_after_recovery = true;
                    return;
                }
                self.source_status = SourceStatus::Healthy;
            }
        }
    }

    /// Inicia una evaluación con nuevas muestras tras recuperar la fuente externa.
    /// No obtiene muestras, no declara salud ni modifica la semilla por sí sola.
    pub fn begin_source_recovery(&mut self) -> Result<(), NexusError> {
        let health = HealthMonitor::try_new(self.config.min_entropy)?;
        self.health = health;
        self.source_counts.fill(0);
        self.source_samples = 0;
        self.source_min_entropy = 0.0;
        self.source_status = SourceStatus::Recovering;
        self.rotation_after_recovery = true;
        Ok(())
    }

    /// Check whether rotation is needed (by policy or source health).
    pub fn needs_rotation(&self) -> bool {
        if self.source_status != SourceStatus::Healthy || self.rotation_after_recovery {
            return true;
        }
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
        match self.source_status {
            SourceStatus::InvalidConfiguration => return Some(RotationReason::InvalidConfiguration),
            SourceStatus::Unassessed | SourceStatus::Recovering =>
                return Some(RotationReason::SourceAssessmentRequired),
            SourceStatus::HealthTestFailed => return Some(RotationReason::SourceUnhealthy),
            SourceStatus::LowEntropy | SourceStatus::Healthy => {}
        }
        if !self.health.is_healthy() {
            return Some(RotationReason::SourceUnhealthy);
        }
        if self.source_min_entropy < self.config.min_entropy {
            return Some(RotationReason::LowEntropy {
                current: self.source_min_entropy,
                minimum: self.config.min_entropy,
            });
        }
        if self.rotation_after_recovery {
            return Some(RotationReason::SourceRecovered);
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

    /// Paso interno: la API pública siempre aplica la política de salud y rotación.
    fn derive_key_unchecked(&mut self, context: &[u8]) -> [u8; 32] {
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

    /// Renueva la semilla únicamente después de evaluar la fuente.
    /// Conserva los monitores continuos, la última evaluación y su historial.
    pub fn rotate(&mut self) -> Result<RotationResult, NexusError> {
        if !self.is_source_healthy() {
            return Err(NexusError::SecurityViolation(
                "Rotación bloqueada: la fuente requiere evaluación o recuperación".into(),
            ));
        }
        let new_epoch = self.epoch.checked_add(1).ok_or_else(||
            NexusError::SecurityViolation("Se agotó el contador de épocas".into()))?;
        let old_epoch = self.epoch;
        let old_entropy = self.source_min_entropy;
        let reason = self.rotation_reason();

        // Fresh material mixed with the old seed via a one-way hash → forward
        // secrecy: compromising the new seed does not reveal past seeds.
        let mut new_bytes = [0u8; 32];
        rand::rngs::OsRng.try_fill_bytes(&mut new_bytes).map_err(|_| {
            new_bytes.zeroize();
            NexusError::CryptoError("El generador del sistema operativo no entregó material fresco".into())
        })?;

        let mut hasher = Sha3_256::new();
        hasher.update(b"NEXUS_SENTINEL_ROTATE");
        hasher.update(self.seed.bytes);
        hasher.update(new_bytes);
        hasher.update(self.epoch.to_le_bytes());
        let mut mixed = hasher.finalize();

        // Zeroize old seed, install new one.
        self.seed.bytes.zeroize();
        self.seed.bytes.copy_from_slice(&mixed);
        new_bytes.zeroize();
        mixed.as_mut_slice().zeroize();
        self.epoch = new_epoch;
        self.use_count = 0;
        self.last_rotation = Timestamp::now();

        self.rotation_after_recovery = false;

        Ok(RotationResult {
            old_epoch,
            new_epoch: self.epoch,
            old_entropy,
            new_entropy: self.source_min_entropy,
            reason,
            timestamp: self.last_rotation,
        })
    }

    fn record_entropy(&mut self) {
        if self.config.history_size == 0 { return; }
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
            .field("source_status", &self.source_status)
            .field("source_healthy", &self.is_source_healthy())
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
    /// No existe un lote completo evaluado desde el arranque o la recuperación.
    SourceAssessmentRequired,
    /// Configuración inválida; no se habilita la derivación.
    InvalidConfiguration,
    /// El flujo pasó la reevaluación; todavía debe renovarse la semilla.
    SourceRecovered,
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
        let max_freq = frequencies.iter().copied().max().unwrap_or(0) as f64;
        -(max_freq / len).log2()
    }

    /// Estimación puntual por frecuencia máxima, conservada para la Decisión 001.
    /// No incluye el límite de confianza de SP 800-90B §6.3.1 ni detecta dependencia
    /// temporal. No certifica la entropía de una fuente o de una salida de CSPRNG.
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

    // Flujo sintético determinista: prepara los casos; no califica una fuente real.
    fn evaluation_samples() -> Vec<u8> {
        let mut samples = vec![0u8; SOURCE_ASSESSMENT_SAMPLES];
        ChaCha20Rng::from_seed([7u8; 32]).fill_bytes(&mut samples);
        samples
    }

    fn evaluated_seed() -> SentinelSeed {
        let mut seed = SentinelSeed::from_bytes([42u8; 32], SentinelConfig::default());
        seed.ingest_source(&evaluation_samples());
        assert!(seed.is_source_healthy());
        seed
    }

    #[test]
    fn test_apt_cutoff_matches_conditional_binomial_tail() {
        let (rct, apt) = HealthMonitor::try_new(7.5).unwrap().cutoffs();
        assert_eq!((rct, apt), (4, 16));
        // Cálculo independiente desde P(X=0); la producción normaliza desde el modo.
        let p = 2f64.powf(-7.5);
        let mut mass = (1.0-p).powi(511);
        let mut tail_15 = 0.0;
        let mut tail_16 = 0.0;
        for k in 0..=511 {
            if k >= 14 { tail_15 += mass; }
            if k >= 15 { tail_16 += mass; }
            mass *= (511-k) as f64 / (k+1) as f64 * p / (1.0-p);
        }
        let alpha = 2f64.powi(-20);
        assert!(tail_15 > alpha);
        assert!(tail_16 < alpha);
        assert!((tail_16 - 2.7640953150605826e-7).abs() < 1e-18);
    }

    #[test]
    fn test_apt_counts_reference_and_fails_at_sixteen() {
        let mut health = HealthMonitor::new(7.5);
        health.update(0);
        for _ in 1..15 {
            health.update(1);
            health.update(0);
        }
        assert!(health.is_healthy());
        health.update(1);
        health.update(0);
        assert!(!health.is_healthy());
        health.update_all(&evaluation_samples());
        assert!(!health.is_healthy());
    }

    #[test]
    fn test_apt_resets_reference_at_exact_window_boundary() {
        let mut health = HealthMonitor::new(7.5);
        for _ in 0..3 {
            for i in 0..512 {
                let sample = if i < 30 && i % 2 == 0 { 0 } else { 1 + (i % 251) as u8 };
                health.update(sample);
            }
            assert!(health.is_healthy());
            assert_eq!(health.apt_seen, 0);
            assert_eq!(health.apt_ref, None);
        }
    }

    #[test]
    fn test_rct_continues_across_apt_windows() {
        let mut health = HealthMonitor::new(7.5);
        for i in 0..509 { health.update(1 + (i % 251) as u8); }
        health.update_all(&[254; 3]);
        assert!(health.is_healthy());
        assert_eq!(health.apt_seen, 0);
        health.update(254);
        assert!(!health.is_healthy());
    }

    #[test]
    fn test_invalid_source_parameters_fail_closed_even_after_reset() {
        for h in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 0.0, 0.001, 8.01] {
            assert!(HealthMonitor::try_new(h).is_err());
            let mut monitor = HealthMonitor::new(h);
            monitor.reset();
            assert!(!monitor.is_healthy());
            let config = SentinelConfig { min_entropy: h, ..Default::default() };
            let mut seed = SentinelSeed::from_bytes([42; 32], config);
            assert_eq!(seed.source_status(), SourceStatus::InvalidConfiguration);
            seed.ingest_source(&evaluation_samples());
            assert!(seed.derive_key(b"configuracion").is_err());
            assert!(seed.rotate().is_err());
            assert!(seed.begin_source_recovery().is_err());
        }
        for h in [0.01, 0.5, 1.0, 4.0, 7.5, 8.0] {
            let monitor = HealthMonitor::try_new(h).unwrap();
            assert!(monitor.is_healthy());
            assert!((2..=513).contains(&monitor.cutoffs().1));
        }
    }

    #[test]
    fn test_source_requires_complete_batch_across_calls() {
        let mut seed = SentinelSeed::from_bytes([42; 32], SentinelConfig::default());
        let samples = evaluation_samples();
        let original_hash = seed.seed_hash();
        seed.ingest_source(&[]);
        seed.ingest_source(&samples[..65_535]);
        assert_eq!(seed.source_status(), SourceStatus::Unassessed);
        assert_eq!(seed.pending_source_samples(), 65_535);
        assert!(seed.entropy_history().is_empty());
        assert!(seed.derive_key(b"parcial").is_err());
        assert!(seed.rotate().is_err());
        assert_eq!(seed.seed_hash(), original_hash);
        seed.ingest_source(&samples[65_535..]);
        assert_eq!(seed.source_status(), SourceStatus::Healthy);
        assert_eq!(seed.pending_source_samples(), 0);
        assert_eq!(seed.entropy_history().len(), 1);
        assert!(seed.derive_key(b"completo").is_ok());
    }

    #[test]
    fn test_source_evaluation_is_independent_of_chunk_sizes() {
        let samples = evaluation_samples();
        let mut whole = SentinelSeed::from_bytes([42; 32], SentinelConfig::default());
        let mut chunks = whole.clone();
        whole.ingest_source(&samples);
        for part in samples.chunks(137) { chunks.ingest_source(part); }
        assert_eq!(whole.source_status(), chunks.source_status());
        assert_eq!(whole.source_min_entropy(), chunks.source_min_entropy());
        assert_eq!(whole.health.apt_count, chunks.health.apt_count);
        assert_eq!(whole.health.rct_run, chunks.health.rct_run);
        assert_eq!(whole.entropy_history().len(), chunks.entropy_history().len());
    }

    #[test]
    fn test_low_frequency_entropy_latches_until_explicit_recovery() {
        let mut seed = evaluated_seed();
        // Frecuencia uniforme sobre 128 símbolos: H empírica=7; RCT/APT no fallan.
        let low: Vec<u8> = (0..SOURCE_ASSESSMENT_SAMPLES).map(|i| (i % 128) as u8).collect();
        seed.ingest_source(&low);
        assert!(seed.health.is_healthy());
        assert_eq!(seed.source_status(), SourceStatus::LowEntropy);
        assert_eq!(seed.source_min_entropy(), 7.0);
        seed.ingest_source(&evaluation_samples());
        assert_eq!(seed.source_status(), SourceStatus::LowEntropy);
        assert!(seed.derive_key(b"bloqueado").is_err());
        assert!(seed.rotate().is_err());
    }

    #[test]
    fn test_health_recovery_requires_new_batch_then_rotation() {
        let mut seed = evaluated_seed();
        seed.ingest_source(&[0; 4]);
        assert_eq!(seed.source_status(), SourceStatus::HealthTestFailed);
        let old_hash = seed.seed_hash();
        seed.ingest_source(&evaluation_samples());
        assert_eq!(seed.source_status(), SourceStatus::HealthTestFailed);
        assert!(seed.rotate().is_err());
        assert_eq!(seed.seed_hash(), old_hash);
        assert_eq!(seed.epoch(), 0);
        seed.begin_source_recovery().unwrap();
        seed.ingest_source(&[]);
        let samples = evaluation_samples();
        seed.ingest_source(&samples[..65_535]);
        assert_eq!(seed.source_status(), SourceStatus::Recovering);
        assert!(seed.derive_key(b"reevaluacion").is_err());
        assert!(seed.rotate().is_err());
        seed.ingest_source(&samples[65_535..]);
        assert!(seed.is_source_healthy());
        assert!(matches!(seed.rotation_reason(), Some(RotationReason::SourceRecovered)));
        assert!(seed.derive_key(b"sin-renovar").is_err());
        let result = seed.rotate().unwrap();
        assert_eq!((result.old_epoch, result.new_epoch), (0, 1));
        assert_ne!(seed.seed_hash(), old_hash);
        assert_eq!(seed.entropy_history().len(), 2);
        assert!(seed.derive_key(b"recuperacion-completa").is_ok());
    }

    #[test]
    fn test_rotation_preserves_continuous_health_and_partial_batch() {
        let mut seed = evaluated_seed();
        let next = evaluation_samples()[65_535].wrapping_add(1);
        seed.ingest_source(&[next; 3]);
        let estimate = seed.source_min_entropy();
        let history = seed.entropy_history().len();
        seed.rotate().unwrap();
        assert_eq!(seed.pending_source_samples(), 3);
        assert_eq!(seed.source_min_entropy(), estimate);
        assert_eq!(seed.entropy_history().len(), history);
        seed.ingest_source(&[next]);
        assert_eq!(seed.source_status(), SourceStatus::HealthTestFailed);
    }

    #[test]
    fn test_failure_after_complete_batch_blocks_whole_ingestion() {
        let mut seed = SentinelSeed::from_bytes([42; 32], SentinelConfig::default());
        let mut samples = evaluation_samples();
        samples.extend_from_slice(&[0; 4]);
        seed.ingest_source(&samples);
        assert_eq!(seed.source_status(), SourceStatus::HealthTestFailed);
        assert!(seed.derive_key(b"cola-degradada").is_err());
    }

    #[test]
    fn test_history_zero_and_epoch_overflow_do_not_bypass_policy() {
        let config = SentinelConfig { history_size: 0, ..Default::default() };
        let mut seed = SentinelSeed::from_bytes([42; 32], config);
        seed.ingest_source(&evaluation_samples());
        assert!(seed.is_source_healthy());
        assert!(seed.entropy_history().is_empty());
        seed.epoch = u64::MAX;
        let old_hash = seed.seed_hash();
        assert!(seed.rotate().is_err());
        assert_eq!(seed.seed_hash(), old_hash);
        assert_eq!(seed.epoch(), u64::MAX);
    }

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
        // El arranque carece de una evaluación del flujo suministrado.
        assert_eq!(seed.source_status(), SourceStatus::Unassessed);
        assert!(!seed.is_source_healthy());
        assert_eq!(seed.source_min_entropy(), 0.0);
        // The diagnostic Shannon-of-seed is well-defined but NOT used for security.
        let diag = seed.current_entropy();
        assert!((0.0..=8.0).contains(&diag));
    }

    #[test]
    fn test_sentinel_seed_derive() {
        let mut seed = SentinelSeed::new();
        let mut samples = vec![0u8; SOURCE_ASSESSMENT_SAMPLES];
        ChaCha20Rng::from_seed([7u8; 32]).fill_bytes(&mut samples);
        seed.ingest_source(&samples);
        let key1 = seed.derive_key(b"context1").unwrap();
        let key2 = seed.derive_key(b"context2").unwrap();
        assert_ne!(key1, key2);
        assert_eq!(seed.use_count(), 2);
    }

    #[test]
    fn test_sentinel_seed_rotation_forward_secure() {
        let mut seed = SentinelSeed::new();
        let mut samples = vec![0u8; SOURCE_ASSESSMENT_SAMPLES];
        ChaCha20Rng::from_seed([7u8; 32]).fill_bytes(&mut samples);
        seed.ingest_source(&samples);
        let hash1 = seed.seed_hash();
        let result = seed.rotate().unwrap();
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
        let mut samples = vec![0u8; SOURCE_ASSESSMENT_SAMPLES];
        ChaCha20Rng::from_seed([7u8; 32]).fill_bytes(&mut samples);
        seed.ingest_source(&samples);
        for _ in 0..10 {
            let _ = seed.derive_key(b"test").unwrap();
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
        let mut samples = vec![0u8; SOURCE_ASSESSMENT_SAMPLES];
        ChaCha20Rng::from_seed([7u8; 32]).fill_bytes(&mut samples);
        seed.ingest_source(&samples);
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
