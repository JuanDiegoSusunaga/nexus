# NEXUS Dual-Chain — Modelo de Referencia

**Arquitectura Blockchain Dual Post-Cuántica para Sistemas Bancarios Seguros y Resilientes — Modelo Matemático-Computacional y Prototipo de Referencia**

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PQC](https://img.shields.io/badge/crypto-Post--Quantum-green.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![Estado](https://img.shields.io/badge/estado-prototipo%20de%20investigaci%C3%B3n-yellow.svg)]()

---

> **Naturaleza de este trabajo.** Este repositorio acompaña al trabajo de grado *"Arquitectura Blockchain Dual NEXUS: Un Modelo Matemático-Computacional para Sistemas Bancarios Seguros y Resilientes Post-Cuántico"*. Su objetivo, según la propuesta aprobada, es **diseñar, modelar y validar formalmente** una arquitectura — **no** entregar un sistema de producción listo para despliegue. En consecuencia, el código es un **prototipo de referencia**: algunos componentes están implementados y verificados, otros están **especificados/modelados** a nivel de tipos e interfaces, y otros se documentan explícitamente como **trabajo futuro**. La sección [Estado de implementación](#estado-de-implementación) detalla con precisión qué es qué, para evitar cualquier sobre-afirmación.

---

## Tabla de Contenidos

- [Introducción](#introducción)
- [Estado de implementación](#estado-de-implementación)
- [Arquitectura General (diseño objetivo)](#arquitectura-general-diseño-objetivo)
- [Componentes del Sistema](#componentes-del-sistema)
- [Criptografía Post-Cuántica](#criptografía-post-cuántica)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [Compilación y Uso](#compilación-y-uso)
- [Fundamentos Teóricos y Validación Formal](#fundamentos-teóricos-y-validación-formal)
- [Rendimiento](#rendimiento)
- [Correspondencia con los Objetivos de la Tesis](#correspondencia-con-los-objetivos-de-la-tesis)
- [Limitaciones conocidas y trabajo futuro](#limitaciones-conocidas-y-trabajo-futuro)
- [Referencias](#referencias)

---

## Introducción

NEXUS es un **modelo de arquitectura blockchain de doble capa** diseñado para proteger infraestructura financiera frente a la amenaza de la computación cuántica. El trabajo aborda tres problemas:

1. **El Trilema de la Blockchain**: escalabilidad, seguridad y descentralización.
2. **La amenaza HNDL** (*Harvest Now, Decrypt Later*): datos cifrados hoy con criptografía clásica podrían descifrarse con un computador cuántico futuro.
3. **La vulnerabilidad de RSA/ECC frente al algoritmo de Shor**: se adopta exclusivamente criptografía post-cuántica basada en retículos (NIST PQC).

El aporte central es el **diseño formal** de un sistema *Dual-Chain* —**Anchor Layer (L1)** para consenso y disponibilidad de datos, **Active Layer (L2)** para ejecución verificable— junto con la **validación formal** de su núcleo criptográfico (ver [Validación Formal](#fundamentos-teóricos-y-validación-formal)).

---

## Estado de implementación

Para distinguir con honestidad lo construido de lo modelado, cada componente se etiqueta así:

| Símbolo | Significado |
|:---:|---|
| ✅ **Implementado** | Lógica funcional y verificada con pruebas; usa bibliotecas auditadas donde aplica. |
| 🟡 **Modelado** | Especificado a nivel de tipos/interfaces/algoritmo como abstracción del diseño; **no** es un mecanismo de seguridad operativo completo. |
| 🔭 **Trabajo futuro** | Declarado en el diseño pero **no** implementado (o implementado como *placeholder*). |

| Componente | Crate / archivo | Estado |
|---|---|:---:|
| Firmas post-cuánticas (CRYSTALS-Dilithium 2/3/5) | `nexus-crypto/dilithium.rs`, `signer.rs` | ✅ Implementado |
| Tipos núcleo, aritmética segura, estado de cuentas | `nexus-core/types.rs`, `state.rs` | ✅ Implementado |
| Verificación de firma de transacción (en ejecución) | `nexus-active/execution.rs`, `nexus-anchor/chain.rs` | ✅ Implementado |
| `Sentinel-Seed`: min-entropía + salud de la fuente (NIST SP 800-90B) + rotación | `nexus-crypto/entropy.rs` | 🟡 rotación ✅; métrica a reformular (v2) |
| Núcleo de finalidad por voto ponderado (≥2/3) y *fork-choice* | `nexus-anchor/finality.rs` | 🟡 Modelado (sin verificación de firma de voto) |
| Ejecución de transferencias nativas L2 | `nexus-active/execution.rs` | ✅ Implementado |
| Árbol de Merkle binario (inclusión) | `nexus-core/merkle.rs` | 🟡 Modelado (sin separación de dominio hoja/nodo) |
| Generación **determinística** de claves desde semilla (KDF) | `nexus-crypto/dilithium.rs`, `keypair.rs` | 🔭 Trabajo futuro |
| ~~Extractor Difuso / biometría~~ | `nexus-crypto/fuzzy_extractor.rs` | ❌ **Eliminado del alcance (v2)** — módulo desconectado del build (archivo inerte) |
| Consenso PoS-BFT operativo (verificación de votos, *slashing*, rondas en red) | `nexus-anchor/consensus.rs` | 🔭 Trabajo futuro (andamiaje de referencia) |
| Disponibilidad de datos (erasure coding, DAS, compromiso polinómico) | `nexus-anchor/data_availability.rs` | 🔭 Trabajo futuro |
| Verificación ZK / Nitro Verifier (Groth16) | `nexus-zk/*`, `nexus-active/verifier.rs` | 🔭 Trabajo futuro |
| Red P2P (libp2p: gossipsub, kad, noise) | `nexus-network/*` | 🔭 Trabajo futuro (interfaz modelada) |
| Nodo ejecutable / servidor RPC | `nexus-node/*` | 🔭 Trabajo futuro |
| CLI (`keygen`, `bench crypto`) | `nexus-cli/main.rs` | ✅ Implementado (parcial) |

> **Estado de compilación (junio 2026).** El *workspace* **compila por completo** (`cargo check --workspace`) y **los 70 tests unitarios pasan** (`cargo test --workspace`: core 15, crypto 25, anchor 16, active 14). Los benchmarks de Dilithium del [Rendimiento](#rendimiento) son **mediciones reales**. *(Si el directorio `target/` queda bloqueado por un editor o el antivirus, compilar con `CARGO_TARGET_DIR` apuntando a otra ruta.)*

---

## Arquitectura General (diseño objetivo)

> El siguiente diagrama representa el **diseño objetivo** del sistema. Las anotaciones de estado (✅/🟡/🔭) indican el grado de realización en el prototipo actual.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           NEXUS DUAL-CHAIN (diseño objetivo)                 │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      ACTIVE LAYER (L2)                                │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐   │  │
│  │  │  NEXUS          │  │  NITRO          │  │  EXECUTION          │   │  │
│  │  │  SEQUENCER  🟡  │  │  VERIFIER   🔭  │  │  ENGINE   ✅(transf.)│   │  │
│  │  │ • Mempool       │  │ • Pruebas ZK    │  │ • Procesamiento TX  │   │  │
│  │  │ • Ordenamiento  │  │ • Fraud Proofs  │  │ • Estado / Receipts │   │  │
│  │  └────────┬────────┘  └────────┬────────┘  └──────────┬──────────┘   │  │
│  │           └────────────────────┼──────────────────────┘              │  │
│  │                    ┌───────────▼───────────┐                         │  │
│  │                    │  BATCH BUILDER    🟡   │  (compresión 🔭)        │  │
│  │                    └───────────┬───────────┘                         │  │
│  └────────────────────────────────┼─────────────────────────────────────┘  │
│                                   │ State Commitment / DA Publication  🔭   │
│                                   ▼                                         │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                      ANCHOR LAYER (L1)                                │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐   │  │
│  │  │  CONSENSUS   🔭 │  │  DATA           │  │  FINALITY      🟡    │   │  │
│  │  │  ENGINE         │  │  AVAILABILITY🔭 │  │  GADGET             │   │  │
│  │  │ • PoS BFT       │  │ • Erasure Code  │  │ • Voto ponderado    │   │  │
│  │  │ • Validadores 🟡│  │ • DAS Sampling  │  │ • Fork Choice       │   │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────────┘   │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────────────────┤
│                         SECURITY LAYER                                       │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐  │
│  │ SENTINEL-SEED ✅│  │ ELIMINADO  (v2) │  │      KEY MANAGER        🟡   │  │
│  │ • min-entropía  │  │  (biometría ❌) │  │ • Rotación automática    ✅  │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────────────────┤
│                      CRYPTOGRAPHIC CORE                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │             CRYSTALS-DILITHIUM (PQC)   ✅                            │   │
│  │      Nivel 2 (128-bit) │ Nivel 3 (192-bit) │ Nivel 5 (256-bit)      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐  │
│  │  SHA3-256   ✅   │  │  BLAKE3      ✅  │  │  ZK-SNARKs (Groth16) 🔭  │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Componentes del Sistema

### 1. Anchor Layer (L1)

| Componente | Función (diseño) | Archivo | Estado |
|------------|---------|---------|:---:|
| Consensus Engine | PoS-BFT estilo Tendermint con firmas PQC | `nexus-anchor/src/consensus.rs` | 🔭 |
| Validator Set | Validadores, *staking*, *slashing* | `nexus-anchor/src/validator.rs` | 🟡 |
| Data Availability | DA con *erasure coding* | `nexus-anchor/src/data_availability.rs` | 🔭 |
| Finality Gadget | Finalidad por voto ponderado (estilo GRANDPA) | `nexus-anchor/src/finality.rs` | 🟡 |

> **Nota de honestidad sobre el consenso.** El módulo actual modela el vocabulario y la máquina de estados (Proposal → Prevote → Precommit → Commit), pero **no** constituye aún un protocolo BFT operativo: los votos entrantes no se verifican criptográficamente, no hay deduplicación por validador, el quórum se cuenta por número de votos (no ponderado por *stake*) y no hay difusión en red. Se presenta como **especificación de referencia**; su realización completa es trabajo futuro.

### 2. Active Layer (L2)

| Componente | Función (diseño) | Archivo | Estado |
|------------|---------|---------|:---:|
| Nexus Sequencer | Ordenamiento y *batching* | `nexus-active/src/sequencer.rs` | 🟡 |
| Nitro Verifier | Verificación de transición de estado (ZK / *fraud proofs*) | `nexus-active/src/verifier.rs` | 🔭 |
| Execution Engine | Procesamiento de transacciones | `nexus-active/src/execution.rs` | ✅ (transferencias) |
| Batch Builder | Construcción de *batches* | `nexus-active/src/batch.rs` | 🟡 |

> El **Nitro Verifier** actualmente acepta toda prueba bien formada (es un *placeholder*); la verificación ZK/fraud-proof real es trabajo futuro. La **ejecución de transferencias nativas** sí es real: verifica la firma Dilithium, el *nonce* y el saldo, y aplica el débito/crédito.

### 3. Security Layer

| Componente | Función (diseño) | Archivo | Estado |
|------------|---------|---------|:---:|
| Sentinel-Seed | Monitoreo de entropía y rotación | `nexus-crypto/src/entropy.rs` | ✅ |
| ~~Fuzzy Extractor~~ | Biometría — **eliminada del alcance (v2)** | `nexus-crypto/src/fuzzy_extractor.rs` | ❌ |
| Key Manager | Gestión unificada de claves | `nexus-crypto/src/keypair.rs` | 🟡 |

---

## Criptografía Post-Cuántica

### CRYSTALS-Dilithium (✅ implementado)

NEXUS utiliza CRYSTALS-Dilithium / ML-DSA (NIST FIPS 204) como esquema de firma. La implementación delega en la biblioteca auditada [`fips204`](https://crates.io/crates/fips204) (ML-DSA puro en Rust, *constant-time*): generación de claves (incluida la **`KeyGen` determinística desde semilla**), firma y verificación son llamadas reales a la biblioteca, la verificación propaga el resultado real, y las claves secretas se borran de memoria (`zeroize`).

| Nivel | Seguridad Clásica | Seguridad Cuántica (cota conservadora) | Clave Pública | Firma |
|-------|-------------------|--------------------|--------------:|------:|
| 2 | 128-bit | ~64-bit | 1.312 bytes | 2.420 bytes |
| **3** | **192-bit** | **~96-bit** | **1.952 bytes** | **3.309 bytes** |
| 5 | 256-bit | ~128-bit | 2.592 bytes | 4.627 bytes |

**Recomendado**: Dilithium3.

> **Notas técnicas (importantes para la defensa):**
> 1. **Columna de seguridad cuántica.** Las cifras "mitad de bits" son una **cota conservadora tipo Grover**, no la estimación *core-SVP* basada en *sieving* cuántico (que da una reducción mucho menor, ~0,91× la seguridad clásica). El [Capítulo de Validación Formal](#fundamentos-teóricos-y-validación-formal) reconcilia ambas; cítalas como lo que son.
> 2. **Tamaños de firma.** Los valores son los de **FIPS 204 / ML-DSA** (3.309 B para Dilithium3 / ML-DSA-65; 4.627 B para Dilithium5 / ML-DSA-87), conforme a la biblioteca `fips204` que implementa el código.

#### Fundamento matemático

Dilithium se basa en los problemas **Module-LWE** y **Module-SIS** sobre el anillo $R_q = \mathbb{Z}_q[X]/(X^n+1)$, con $n=256$ y $q=8\,380\,417$. La dureza se reduce, vía reducciones *worst-case → average-case*, a problemas reticulares de peor caso (Mod-SIVP) que se creen difíciles incluso para adversarios cuánticos. El desarrollo formal está en el **[Capítulo de Validación Formal (Obj. 4)](#fundamentos-teóricos-y-validación-formal)**.

### Extractor Difuso / biometría — ❌ eliminado del alcance (v2)

La autenticación biométrica (extractor difuso) **se eliminó del alcance** en la versión v2: un biométrico no es revocable —basar en él una clave de firma es un diseño cuestionable— y el código corrector de errores nunca se implementó. La derivación determinística de claves se hace ahora **desde una semilla de alta entropía vía KDF** (ver Obj. 2), sin biometría. El archivo `nexus-crypto/fuzzy_extractor.rs` permanece pendiente de remover (Plan Maestro, Fase B).

### Sentinel-Seed: salud de la fuente de entropía (Obj. 3)

La métrica de seguridad **no** es la entropía de Shannon de la semilla (que no mide el secreto de una clave y es degenerada para 32 bytes). El modelo v2 usa:

- **min-entropía de la fuente** $H_\infty(X) = -\log_2 \max_x \Pr[X{=}x]$ como medida pertinente del material de clave;
- **pruebas de salud en línea** conforme a **NIST SP 800-90B** (*Repetition Count Test* y *Adaptive Proportion Test*) para detectar degradación del generador;
- **rotación con secrecia hacia adelante** por política (uso > 100.000 derivaciones, antigüedad > 24 h, o **fallo de las pruebas de salud**), con bloqueo de la derivación ante degradación de la fuente.

> **Estado.** La rotación está implementada; la métrica de Shannon del prototipo actual debe **reformularse** a min-entropía + SP 800-90B (Plan Maestro, Fase B). El desarrollo formal de esta distinción está en el **Capítulo de Validación Formal (Obj. 4)**.

---

## Estructura del Proyecto

```
nexus/
├── Cargo.toml                    # Workspace
├── nexus-core/                   # Tipos, traits, bloque, transacción, estado, merkle
├── nexus-crypto/                 # Dilithium, fuzzy extractor, entropía, keypair, signer
├── nexus-anchor/                 # L1: consensus, validator, data_availability, finality, chain
├── nexus-active/                 # L2: sequencer, verifier, execution, batch, chain
├── nexus-sentinel/               # Monitoreo de seguridad (re-exporta primitivas de crypto)
├── nexus-zk/                     # Interfaz ZK (Groth16) — placeholder
├── nexus-network/                # Interfaz P2P (libp2p) — modelada
├── nexus-node/                   # Nodo (esqueleto)
└── nexus-cli/                    # CLI (keygen, bench crypto)
```

### Dependencias entre Crates

```
nexus-cli → nexus-node → {nexus-anchor, nexus-active, nexus-network, nexus-zk, nexus-sentinel}
                              ↓               ↓
                         nexus-crypto → nexus-core
```

---

## Compilación y Uso

### Requisitos
- Rust 1.75 o superior, Cargo.
- (Sin dependencias de C: `fips204` es puro Rust — no requiere OpenSSL ni toolchain de C.)

### Estado del build
El workspace **compila** y **los tests pasan**. *(Si el directorio `target/` queda bloqueado por un editor o antivirus, usar `CARGO_TARGET_DIR=<otra-ruta> cargo build`.)*

### Compilación
```bash
cd nexus
cargo build --release
cargo test --workspace          # ejecuta la batería de pruebas unitarias
cargo bench -p nexus-crypto     # benchmarks Criterion de Dilithium
cargo doc --no-deps --open
```

### CLI
```bash
cargo run --bin nexus -- keygen -l 3 -o ~/.nexus/key.dat   # genera keypair Dilithium3
cargo run --bin nexus -- bench --bench-type crypto         # benchmarks de criptografía
cargo run --bin nexus -- info
```

### Ejemplo: crear y firmar una transacción (✅ funcional)
```rust
use nexus_core::{Transaction, ChainId, Nonce, Address, Amount, SignatureScheme};
use nexus_crypto::{DilithiumKeypair, Signer};

let keypair = DilithiumKeypair::generate(SignatureScheme::Dilithium3)?;
let tx = Transaction::transfer(
    ChainId::MAINNET, Nonce::new(0),
    Address::from_hex("...")?, Amount::from_units(100),
    21_000, Amount(1_000_000),
);
let signed_tx = keypair.sign_transaction(tx)?;   // firma ligada al hash de la tx
assert!(signed_tx.verify());                      // verificación Dilithium real
```

---

## Fundamentos Teóricos y Validación Formal

La validación formal de la seguridad (Objetivo 4 de la tesis) es un **resultado matemático escrito**, desarrollado en el **Capítulo de Validación Formal (Cap. 6 / Obj. 4)** del documento de grado. Comprende:

1. **Prueba de dureza post-cuántica**: reducción de la in-forjabilidad (EUF/sUF-CMA) de Dilithium a **Module-LWE**, **SelfTargetMSIS** y **Module-SIS**, y de éstos —vía reducciones *worst-case → average-case*— a **Mod-SIVP**; con el argumento de no aplicabilidad del algoritmo de Shor.
2. **Análisis de complejidad computacional (notación O)**: costo asintótico de `KeyGen`, `Sign` y `Verify` (dominado por la NTT, $O(n\log n)$ por multiplicación en $R_q$), y el *overhead* del esquema dual.
3. **Validación empírica complementaria**: benchmarks que estiman las constantes ocultas del análisis asintótico (no lo sustituyen).

> El código de este repositorio **ilustra computacionalmente** el modelo (p. ej., demuestra firmas Dilithium reales). La *validación formal* propiamente dicha reside en el capítulo escrito, no en pruebas/benchmarks de software.

### Teoría de Juegos del Secuenciador (modelado, Objetivo 3)
El comportamiento del secuenciador se modela con una matriz de pagos cuyo **Equilibrio de Nash** es la estrategia honesta (la deshonestidad conduce a *slashing* y pérdida de *stake*). El modelo es analítico; el mecanismo de *slashing* que lo haría operativo es trabajo futuro.

---

## Rendimiento

**Valores medidos** (`cargo bench -p nexus-crypto`, harness Criterion, 100 muestras/punto, **medianas**). *Hardware:* Intel Kaby Lake (Familia 6 Modelo 142), 4 hilos lógicos, Windows 11; perfil `release`.

| Operación | Dilithium2 | Dilithium3 | Dilithium5 |
|-----------|----------:|----------:|----------:|
| Generación de claves | 321 µs | 503 µs | 725 µs |
| Firma | 727 µs | 1,21 ms | 1,34 ms |
| Verificación | 166 µs | 279 µs | 436 µs |

**Tamaños (exactos, FIPS 204):** clave pública 1.952 B · firma 3.309 B (Dilithium3 / ML-DSA-65). *Backend:* `fips204` (Rust puro).

**Lecturas clave:** (i) la **verificación tarda cientos de µs** — el cuello de botella post-cuántico es el *tamaño*, no el cómputo; (ii) generación y verificación **escalan con $k\ell$** (consistente con $O(k\ell\,n\log n)$); (iii) la firma es **no monótona** por la varianza del *rejection sampling*. Cifras de un portátil modesto; lo relevante es el orden de magnitud y la forma del escalado. Análisis en el Capítulo de Validación Formal (§6.6).

---

## Correspondencia con los Objetivos de la Tesis

| Objetivo | Entregable | Estado | Ubicación |
|----------|------------|:---:|-----------|
| **Obj 1** — Diseñar la arquitectura Dual-Chain (Nexus Sequencer, Nitro Verifier) | Especificación de capas, tipos, mensajes e interfaces | 🟡 Modelado | `nexus-anchor/`, `nexus-active/` |
| **Obj 2** — Core PQC: Dilithium + derivación determinística (KDF) | Dilithium **implementado**; **KeyGen determinística desde semilla implementada** (`fips204`); biometría **eliminada** | ✅ | `nexus-crypto/dilithium.rs`, `keypair.rs` |
| **Obj 3** — Seguridad activa: min-entropía + salud (SP 800-90B) + rotación | Rotación **implementada**; métrica a reformular | 🟡 Parcial | `nexus-crypto/entropy.rs` |
| **Obj 4** — Validación formal: reducción a Module-LWE + análisis O() | **Capítulo matemático escrito** (no código); complementado con benchmarks | 📄 Documento | *Cap. 4 — Validación Formal* |

> **Corrección importante respecto a versiones previas de este README:** el Objetivo 4 **no** se satisface con "tests + benchmarks". Una reducción de dureza y un análisis de complejidad son artefactos matemáticos demostrativos; los benchmarks son evidencia empírica *complementaria*. Ver el Capítulo de Validación Formal.

---

## Limitaciones conocidas y trabajo futuro

Esta sección lista de forma transparente lo que el prototipo **no** hace todavía, para que el alcance quede inequívoco:

- **Compilación**: requiere las dos correcciones indicadas arriba antes de construir/ejecutar.
- **Generación determinística de claves**: la API `from_seed` ignora actualmente la semilla (la biblioteca PQC usa su propio RNG). Solución prevista: KDF (SHAKE256) → generación determinística parametrizada por la semilla.
- **Biometría / Extractor Difuso**: **eliminado del alcance (v2)**; `fuzzy_extractor.rs` pendiente de remover.
- **Consenso BFT**: falta verificación de firmas de voto, deduplicación por validador, quórum ponderado por *stake* ($\lfloor 2N/3\rfloor+1$), detección de equivocación + *slashing*, y difusión en red.
- **Finalidad**: el núcleo de conteo de votos es real, pero falta verificación de firma del voto y enlace de ascendencia (*ancestry*) entre bloques finalizados.
- **Disponibilidad de datos**: el "erasure coding" actual duplica *chunks* (no es Reed-Solomon); el muestreo DAS y el "compromiso polinómico" son simplificaciones — pendientes de implementación real (código MDS + compromiso KZG/Merkle + muestreo de pares remotos).
- **Capa ZK / Nitro Verifier**: *placeholders* (el verificador acepta toda prueba no vacía; el *prover* devuelve bytes fijos). Pendiente: circuitos R1CS reales con `ark-groth16`, *trusted setup* y verificación por emparejamientos.
- **Red P2P**: `libp2p` está declarado pero no integrado; la capa es un registro de pares en memoria.
- **Nodo/RPC**: el nodo no ejecuta un bucle de eventos ni expone RPC.
- **Merkle**: añadir separación de dominio hoja/nodo (RFC 6962) y revisar el *padding* por duplicación de última hoja.
- **`state.transfer`**: hacer la operación atómica (revertir el débito si el crédito falla).

---

## Referencias

1. Ducas, L., Kiltz, E., Lepoint, T., Lyubashevsky, V., Schwabe, P., Seiler, G., Stehlé, D. (2018). *CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme*. IACR ToCHES.
2. NIST (2024). *FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)*.
3. Lyubashevsky, V. (2012). *Lattice Signatures without Trapdoors* (Fiat-Shamir with Aborts). EUROCRYPT.
4. Langlois, A., Stehlé, D. (2015). *Worst-Case to Average-Case Reductions for Module Lattices*. Designs, Codes and Cryptography.
5. Regev, O. (2009). *On Lattices, Learning with Errors, Random Linear Codes, and Cryptography*. J. ACM.
6. Dodis, Y., Ostrovsky, R., Reyzin, L., Smith, A. (2008). *Fuzzy Extractors: How to Generate Strong Keys from Biometrics and Other Noisy Data*. SIAM J. Comput.
7. Buterin, V. (2021). *An Incomplete Guide to Rollups*.
8. Shannon, C. E. (1948). *A Mathematical Theory of Communication*.
9. Mascelli, J., Rodden, M. (2025). *"Harvest Now Decrypt Later": Examining Post-Quantum Cryptography and the Data Privacy Risks for Distributed Ledger Networks*. Federal Reserve, FEDS 2025-093.

---

## Licencia

MIT License — Ver [LICENSE](LICENSE).

## Autor

**Juan Diego Susunaga Velasquez** — Universidad del Rosario, Escuela de Ciencias e Ingeniería.
Director: **Leonardo Huertas Calle**.

*Parte del trabajo de grado "Arquitectura Blockchain Dual NEXUS: Un Modelo Matemático-Computacional para Sistemas Bancarios Seguros y Resilientes Post-Cuántico".*
