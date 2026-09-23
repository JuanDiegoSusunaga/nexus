//! Barrido empírico de parámetros (W, C) del Adaptive Proportion Test
//! (NIST SP 800-90B §4.4.2) — insumo de la **Decisión 001** (TG2).
//!
//! Ejecutar: `cargo run -p nexus-crypto --example apt_sweep --release`
//!
//! Tres experimentos:
//!
//! 1. **Falsos positivos.** Para fuentes *saludables* (uniforme H=8 y el peor
//!    caso admisible: un valor modal con p = 2^-7.5, el resto uniforme), mide
//!    por simulación masiva la tasa real de disparo por ventana del APT para
//!    dos reglas de corte: la aproximación normal histórica y el cálculo
//!    binomial vigente para B=1+Binomial(W-1,p), ambos con alpha = 2^-20.
//! 2. **Latencia de detección.** Para fuentes degradadas con H_inf conocida,
//!    mide muestras-hasta-bloqueo (APT o RCT, lo que dispare primero) bajo
//!    ambos cortes.
//! 3. **Capa complementaria (estimador MCV).** Tasa de detección de
//!    `EntropyMonitor::estimate_min_entropy` (< barra de 7.5) por lote de
//!    4096 muestras, para degradaciones sutiles que el APT no ve.
//!
//! La simulación replica la semántica exacta de `HealthMonitor::update`
//! (ventanas no solapadas, referencia = primera muestra, conteo incluye la
//! referencia, RCT concurrente) y se verifica contra la implementación real
//! (`check_equivalencia`). RNG determinista (ChaCha8, semillas fijas) para
//! que las tablas sean reproducibles.

use nexus_crypto::entropy::{EntropyMonitor, HealthMonitor};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::thread;
use std::time::Instant;

/// alpha de diseño de los tests de salud (SP 800-90B): 2^-20.
const ALPHA: f64 = 9.5367431640625e-7;
/// Min-entropía evaluada de la fuente objetivo (bits/byte) — la barra del módulo.
const H_ASSESSED: f64 = 7.5;
/// Corte del RCT para H = 7.5: 1 + ceil(20 / 7.5) = 4 (igual a HealthMonitor).
const RCT_CUTOFF: u64 = 4;

// ---------------------------------------------------------------------------
// Fuente simulada
// ---------------------------------------------------------------------------

/// Fuente de bytes con min-entropía controlada. `Biased` es el peor caso para
/// una H_inf dada: el valor 0x00 sale con p_max = 2^-h y el resto de la masa
/// se reparte uniformemente entre los otros 255 símbolos.
#[derive(Clone, Copy)]
enum Source {
    Uniform,
    Biased { thr: u32 },
}

impl Source {
    fn with_h(h: f64) -> Self {
        if h >= 8.0 {
            Source::Uniform
        } else {
            let p = 2f64.powf(-h);
            Source::Biased {
                thr: (p * 4_294_967_296.0) as u32,
            }
        }
    }

    #[inline(always)]
    fn sample(self, rng: &mut ChaCha8Rng) -> u8 {
        let u = rng.next_u64();
        match self {
            Source::Uniform => (u >> 24) as u8,
            Source::Biased { thr } => {
                if (u as u32) < thr {
                    0
                } else {
                    1 + ((u >> 32) % 255) as u8
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cortes: aproximación normal (implementada) vs. binomial exacto (SP 800-90B)
// ---------------------------------------------------------------------------

/// P(X >= k) para X ~ Binomial(n, p), sumando la cola superior de la pmf
/// (estable para las colas pequeñas que interesan aquí).
fn binom_tail_ge(n: u64, p: f64, k: u64) -> f64 {
    if k == 0 {
        return 1.0;
    }
    let q = 1.0 - p;
    let mut pmf = q.powf(n as f64);
    let mut tail = 0.0;
    for i in 0..=n {
        if i >= k {
            tail += pmf;
        }
        if i < n {
            pmf *= ((n - i) as f64 / (i + 1) as f64) * (p / q);
        }
    }
    tail
}

/// Réplica del corte histórico anterior al 22 de septiembre (aproximación
/// normal de Binomial(W, p) con z = 4.7634).
fn normal_cutoff(w: u64, p: f64) -> u64 {
    let wf = w as f64;
    let mean = wf * p;
    let sd = (wf * p * (1.0 - p)).sqrt();
    (mean + 4.7634 * sd).ceil() as u64
}

/// Menor corte C tal que P(apt_count >= C) <= alpha bajo el modelo de
/// SP 800-90B (la muestra de referencia es el valor modal): apt_count =
/// 1 + X con X ~ Binomial(W-1, p). Es la semántica exacta del disparo de
/// `HealthMonitor`. Con CRITBINOM como cuantil de la CDF, C = 2 + CRITBINOM(W-1, p, 1-alpha).
fn exact_cutoff(w: u64, p: f64, alpha: f64) -> u64 {
    let n = w - 1;
    let mut m = 0u64;
    while binom_tail_ge(n, p, m) > alpha {
        m += 1;
    }
    m + 1
}

// ---------------------------------------------------------------------------
// Parte 1 — falsos positivos por ventana en fuentes saludables
// ---------------------------------------------------------------------------

/// Corre `windows_total` ventanas del APT (tamaño `w`) sobre la fuente y
/// devuelve (histograma del conteo final por ventana [cap 64], eventos RCT,
/// muestras totales). El histograma sirve para leer la tasa empírica de
/// cualquier corte C de una sola pasada: alpha_emp(C) = sum(hist[C..]) / N.
fn fp_histogram(src: Source, w: usize, windows_total: u64, seed0: u64) -> (Vec<u64>, u64, u64) {
    let threads = thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
    let per_thread = windows_total.div_ceil(threads as u64);
    let results: Vec<(Vec<u64>, u64)> = thread::scope(|s| {
        (0..threads)
            .map(|t| {
                s.spawn(move || {
                    let mut rng = ChaCha8Rng::seed_from_u64(seed0 ^ (t as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
                    let mut hist = vec![0u64; 64];
                    let mut rct_events = 0u64;
                    let mut rct_last: Option<u8> = None;
                    let mut rct_run = 0u64;
                    for _ in 0..per_thread {
                        let reference = src.sample(&mut rng);
                        // RCT sobre el flujo continuo (cruza ventanas).
                        match rct_last {
                            Some(prev) if prev == reference => {
                                rct_run += 1;
                                if rct_run >= RCT_CUTOFF {
                                    rct_events += 1;
                                    rct_run = 0;
                                    rct_last = None;
                                }
                            }
                            _ => {
                                rct_last = Some(reference);
                                rct_run = 1;
                            }
                        }
                        let mut count = 1u64;
                        for _ in 1..w {
                            let sample = src.sample(&mut rng);
                            match rct_last {
                                Some(prev) if prev == sample => {
                                    rct_run += 1;
                                    if rct_run >= RCT_CUTOFF {
                                        rct_events += 1;
                                        rct_run = 0;
                                        rct_last = None;
                                    }
                                }
                                _ => {
                                    rct_last = Some(sample);
                                    rct_run = 1;
                                }
                            }
                            if sample == reference {
                                count += 1;
                            }
                        }
                        hist[(count as usize).min(63)] += 1;
                    }
                    (hist, rct_events)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect()
    });
    let mut hist = vec![0u64; 64];
    let mut rct_events = 0u64;
    for (h, r) in results {
        for (i, v) in h.iter().enumerate() {
            hist[i] += v;
        }
        rct_events += r;
    }
    let windows = per_thread * threads as u64;
    (hist, rct_events, windows * w as u64)
}

fn emp_alpha(hist: &[u64], windows: u64, cutoff: u64) -> (f64, u64) {
    let events: u64 = hist.iter().skip(cutoff as usize).sum();
    (events as f64 / windows as f64, events)
}

// ---------------------------------------------------------------------------
// Parte 2 — latencia de detección en fuentes degradadas
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Trip {
    Apt,
    Rct,
    Cap,
}

/// Simula el monitor (APT con ventana `w` y corte `c`; RCT con corte 4) sobre
/// una fuente degradada hasta el primer disparo o hasta `cap` muestras.
/// Devuelve (muestras consumidas, qué disparó). Semántica idéntica a
/// `HealthMonitor::update` (RCT primero, luego APT, ventanas no solapadas).
fn run_until_trip(src: Source, w: usize, c: u64, cap: u64, rng: &mut ChaCha8Rng) -> (u64, Trip) {
    let mut rct_last: Option<u8> = None;
    let mut rct_run = 0u64;
    let mut apt_ref: Option<u8> = None;
    let mut apt_seen = 0usize;
    let mut apt_count = 0u64;
    for i in 1..=cap {
        let sample = src.sample(rng);
        match rct_last {
            Some(prev) if prev == sample => {
                rct_run += 1;
                if rct_run >= RCT_CUTOFF {
                    return (i, Trip::Rct);
                }
            }
            _ => {
                rct_last = Some(sample);
                rct_run = 1;
            }
        }
        match apt_ref {
            None => {
                apt_ref = Some(sample);
                apt_seen = 1;
                apt_count = 1;
            }
            Some(reference) => {
                apt_seen += 1;
                if sample == reference {
                    apt_count += 1;
                    if apt_count >= c {
                        return (i, Trip::Apt);
                    }
                }
                if apt_seen >= w {
                    apt_ref = None;
                    apt_seen = 0;
                    apt_count = 0;
                }
            }
        }
    }
    (cap, Trip::Cap)
}

/// Latencia de detección sobre `trials` corridas independientes.
/// Devuelve (latencias de las corridas que detectaron, ordenadas; nº por RCT;
/// nº por APT; nº que llegaron al tope sin detectar).
fn detect_latency(src: Source, w: usize, c: u64, trials: u64, cap: u64, seed0: u64) -> (Vec<u64>, u64, u64, u64) {
    let threads = thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
    let per_thread = trials.div_ceil(threads as u64);
    let results: Vec<(Vec<u64>, u64, u64, u64)> = thread::scope(|s| {
        (0..threads)
            .map(|t| {
                s.spawn(move || {
                    let mut rng = ChaCha8Rng::seed_from_u64(seed0 ^ (t as u64).wrapping_mul(0xD1B5_4A32_D192_ED03));
                    let mut lat = Vec::new();
                    let (mut n_rct, mut n_apt, mut n_cap) = (0u64, 0u64, 0u64);
                    for _ in 0..per_thread {
                        let (n, trip) = run_until_trip(src, w, c, cap, &mut rng);
                        match trip {
                            Trip::Rct => {
                                n_rct += 1;
                                lat.push(n);
                            }
                            Trip::Apt => {
                                n_apt += 1;
                                lat.push(n);
                            }
                            Trip::Cap => n_cap += 1,
                        }
                    }
                    (lat, n_rct, n_apt, n_cap)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect()
    });
    let mut lat = Vec::new();
    let (mut n_rct, mut n_apt, mut n_cap) = (0u64, 0u64, 0u64);
    for (l, r, a, c_) in results {
        lat.extend(l);
        n_rct += r;
        n_apt += a;
        n_cap += c_;
    }
    lat.sort_unstable();
    (lat, n_rct, n_apt, n_cap)
}

// ---------------------------------------------------------------------------
// Parte 3 — estimador MCV por lote (capa complementaria)
// ---------------------------------------------------------------------------

/// Fracción de lotes de `batch` muestras cuya estimación MCV de min-entropía
/// cae por debajo de la barra (dispararía rotación por `LowEntropy`).
fn mcv_detect_rate(h_real: f64, batch: usize, batches: u64, bar: f64, seed0: u64) -> f64 {
    let src = Source::with_h(h_real);
    let threads = thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
    let per_thread = batches.div_ceil(threads as u64);
    let hits: u64 = thread::scope(|s| {
        (0..threads)
            .map(|t| {
                s.spawn(move || {
                    let mut rng = ChaCha8Rng::seed_from_u64(seed0 ^ (t as u64).wrapping_mul(0xA076_1D64_78BD_642F));
                    let mut buf = vec![0u8; batch];
                    let mut hits = 0u64;
                    for _ in 0..per_thread {
                        for b in buf.iter_mut() {
                            *b = src.sample(&mut rng);
                        }
                        if EntropyMonitor::estimate_min_entropy(&buf) < bar {
                            hits += 1;
                        }
                    }
                    hits
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .sum()
    });
    hits as f64 / (per_thread * threads as u64) as f64
}

// ---------------------------------------------------------------------------
// Anclaje: el simulador reproduce a HealthMonitor muestra a muestra
// ---------------------------------------------------------------------------

/// Con los cortes implementados (W=512, C=11, RCT=4), el índice del primer
/// disparo del simulador debe coincidir exactamente con el de HealthMonitor
/// sobre el mismo flujo. Se comprueba en fuentes degradada y atascada.
fn check_equivalencia() {
    let hm_cutoffs = HealthMonitor::new(H_ASSESSED).cutoffs();
    let p = 2f64.powf(-H_ASSESSED);
    assert_eq!(hm_cutoffs.0, RCT_CUTOFF, "corte RCT distinto al implementado");
    assert_eq!(hm_cutoffs.1, exact_cutoff(512, p, ALPHA), "corte APT distinto al implementado");

    for (seed, h_real) in [(11u64, 4.0f64), (12, 5.0), (13, 2.0), (14, 0.0), (15, 6.0)] {
        let src = Source::with_h(h_real.max(0.01));
        let src = if h_real == 0.0 {
            // Fuente atascada: p_max ~ 1 (umbral saturado).
            Source::Biased { thr: u32::MAX }
        } else {
            src
        };
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let (n_sim, _) = run_until_trip(src, 512, hm_cutoffs.1, 10_000_000, &mut rng);

        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let mut hm = HealthMonitor::new(H_ASSESSED);
        let mut n_hm = 0u64;
        while hm.is_healthy() {
            hm.update(src.sample(&mut rng));
            n_hm += 1;
        }
        assert_eq!(n_sim, n_hm, "simulador y HealthMonitor difieren (seed {seed})");
    }
    println!("[ok] simulador == HealthMonitor (cortes ({}, {}) verificados, 5 flujos)\n", hm_cutoffs.0, hm_cutoffs.1);
}

// ---------------------------------------------------------------------------

fn fmt_rate(rate: f64, events: u64) -> String {
    if events == 0 {
        "0 eventos".to_string()
    } else {
        format!("{:.2e} (2^{:.1})", rate, rate.log2())
    }
}

fn main() {
    let t0 = Instant::now();
    let threads = thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
    println!("Barrido de parámetros APT — Decisión 001 (alpha diseño = 2^-20, H evaluada = {H_ASSESSED} bits/byte)");
    println!("Hilos: {threads}\n");

    check_equivalencia();

    let p_limit = 2f64.powf(-H_ASSESSED);

    // ----- Parte 1: cortes y falsos positivos ------------------------------
    println!("== Parte 1: corte histórico (aprox. normal) vs. corte vigente (binomial) ==");
    println!("Modelo SP 800-90B: apt_count = 1 + Binomial(W-1, 2^-H). Cola teórica de cada corte:");
    println!("{:>6} | {:>7} | {:>13} | {:>7} | {:>13}", "W", "C_impl", "cola(C_impl)", "C_exact", "cola(C_exact)");
    println!("{}", "-".repeat(60));
    let ws: [u64; 5] = [256, 512, 1024, 2048, 4096];
    let mut c_exact_512 = 0u64;
    for &w in &ws {
        let c_impl = normal_cutoff(w, p_limit);
        let c_exact = exact_cutoff(w, p_limit, ALPHA);
        if w == 512 {
            c_exact_512 = c_exact;
        }
        println!(
            "{:>6} | {:>7} | {:>13.2e} | {:>7} | {:>13.2e}",
            w,
            c_impl,
            binom_tail_ge(w - 1, p_limit, c_impl - 1),
            c_exact,
            binom_tail_ge(w - 1, p_limit, c_exact - 1),
        );
    }

    println!("\nTasa EMPÍRICA de disparo por ventana (fuentes saludables; el APT no debería disparar):");
    println!(
        "{:>28} | {:>6} | {:>10} | {:>22} | {:>22} | {:>12}",
        "fuente", "W", "ventanas", "alpha_emp(C_impl)", "alpha_emp(C_exact)", "RCT/muestra"
    );
    println!("{}", "-".repeat(115));
    for (label, h, w, windows) in [
        ("uniforme (H=8.0)", 8.0f64, 512u64, 1u64 << 25),
        ("límite (H=7.5, peor caso)", 7.5, 256, 1 << 24),
        ("límite (H=7.5, peor caso)", 7.5, 512, 1 << 26),
        ("límite (H=7.5, peor caso)", 7.5, 1024, 1 << 24),
        ("límite (H=7.5, peor caso)", 7.5, 2048, 1 << 22),
        ("límite (H=7.5, peor caso)", 7.5, 4096, 1 << 22),
    ] {
        let src = Source::with_h(h);
        let (hist, rct_events, samples) = fp_histogram(src, w as usize, windows, 0xC0FFEE ^ w ^ (h as u64) << 32);
        let windows_run = samples / w;
        let c_impl = normal_cutoff(w, p_limit);
        let c_exact = exact_cutoff(w, p_limit, ALPHA);
        let (a_impl, e_impl) = emp_alpha(&hist, windows_run, c_impl);
        let (a_exact, e_exact) = emp_alpha(&hist, windows_run, c_exact);
        println!(
            "{:>28} | {:>6} | {:>10} | {:>22} | {:>22} | {:>12.2e}",
            label,
            w,
            windows_run,
            fmt_rate(a_impl, e_impl),
            fmt_rate(a_exact, e_exact),
            rct_events as f64 / samples as f64,
        );
    }

    // ----- Parte 2: latencia de detección ----------------------------------
    println!("\n== Parte 2: latencia de detección (W=512; RCT=4 concurrente; tope 50M muestras; 200 corridas) ==");
    println!(
        "{:>10} | {:>7} | {:>10} | {:>12} | {:>12} | {:>14}",
        "H_inf real", "corte C", "detecta %", "mediana", "p90", "vía (RCT/APT)"
    );
    println!("{}", "-".repeat(80));
    for &h_real in &[7.0f64, 6.5, 6.0, 5.0, 4.0, 3.0] {
        for &c in &[normal_cutoff(512, p_limit), c_exact_512] {
            let src = Source::with_h(h_real);
            let (lat, n_rct, n_apt, n_cap) = detect_latency(src, 512, c, 200, 50_000_000, 0xDEC1_5100 ^ (h_real * 10.0) as u64 ^ c << 40);
            let total = (n_rct + n_apt + n_cap) as f64;
            let pct = 100.0 * (n_rct + n_apt) as f64 / total;
            let (med, p90) = if lat.is_empty() {
                ("—".to_string(), "—".to_string())
            } else {
                (
                    format!("{}", lat[lat.len() / 2]),
                    format!("{}", lat[((lat.len() as f64 * 0.9) as usize).min(lat.len() - 1)]),
                )
            };
            println!(
                "{:>10} | {:>7} | {:>9.1}% | {:>12} | {:>12} | {:>6}/{:<7}",
                h_real, c, pct, med, p90, n_rct, n_apt
            );
        }
    }
    println!("(fuente atascada, H=0: la detecta el RCT en exactamente {} muestras)", RCT_CUTOFF);

    // ----- Parte 3: estimador MCV por lote ---------------------------------
    println!("\n== Parte 3: capa complementaria — estimador MCV (§6.3.1) por tamaño de lote, barra = {H_ASSESSED} ==");
    println!("(tasa de lotes con estimación < barra; para fuentes SALUDABLES —H >= 7.5— es un FALSO positivo)");
    println!(
        "{:>10} | {:>9} | {:>9} | {:>9} | {:>9}",
        "H_inf real", "N=4096", "N=16384", "N=65536", "N=262144"
    );
    println!("{}", "-".repeat(60));
    for &h_real in &[8.0f64, 7.6, 7.5, 7.2, 7.0, 6.5] {
        let rates: Vec<String> = [(4096usize, 20_000u64), (16_384, 10_000), (65_536, 4_000), (262_144, 1_000)]
            .iter()
            .map(|&(batch, batches)| {
                let rate = mcv_detect_rate(h_real, batch, batches, H_ASSESSED, 0xE57_1D0 ^ (h_real * 100.0) as u64 ^ (batch as u64) << 24);
                format!("{:>8.2}%", rate * 100.0)
            })
            .collect();
        println!("{:>10} | {} | {} | {} | {}", h_real, rates[0], rates[1], rates[2], rates[3]);
    }
    println!("(H=8.0 y H=7.6 son fuentes saludables: su fila mide el falso positivo del estimador;");
    println!(" H=7.5 está exactamente en la barra, sin margen)");

    println!("\nTiempo total: {:.1} s", t0.elapsed().as_secs_f64());
}
