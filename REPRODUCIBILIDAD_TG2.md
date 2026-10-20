# Reproducibilidad de la edición TG2

**Organización:** 23 de septiembre de 2026. Este repositorio contiene el prototipo Rust y las variantes experimentales de TG2. Los documentos se mantienen en `https://github.com/JuanDiegoSusunaga/tesis-nexus`.

## Adaptación al contrato Lean — 20 de octubre de 2026

La ruta de validez usa ahora `nexus-zk/src/stark/linked.rs` y `linked_codec.rs`: doble FRI vinculada, lector LE canónico con EOF estricto, 16–4096 filas, cuarenta consultas y corte de 512 extracciones del selector, incluidos duplicados. El perfil de trabajo esperado (12 o 20 bits) se entrega externamente; no se rebaja según el certificado. Se mantiene el formato del corpus histórico `(TransitionStatement, LinkedProof)`.

En `nexus-active`, usar `LinkedValidityProof` para el PoC y `NitroVerifier::verify_expected(&proof, &expected)` para verificar con un `ExpectedTransition` obtenido del estado confiable del llamante. La entrada antigua `verify(&proof)` rechaza validez e híbrido: ya no acepta por formato ni por tamaño. El modo optimista permanece separado y sus pruebas pendientes no se registran como raíces verificadas antes de finalizar. Un rechazo del contrato no registra una raíz, y una altura ya registrada no se sobrescribe por otra raíz.

Este perfil admite únicamente escalares canónicos de Goldilocks codificados en 32 bytes con los últimos 24 a cero. **No** demuestra validez de raíces SHA3 arbitrarias, firmas ML-DSA dentro del AIR ni ejecución completa de `ActiveChain`. La altura es contexto externo, no parte del enunciado AIR. La integración del llamante con políticas de autorización y antirrepetición es distinta del contrato matemático. `pq_verifier` y los experimentos anteriores se conservan como referencias históricas y no habilitan la aceptación de la ruta nueva. La equivalencia universal de Rust con Lean sigue sin estar demostrada.

Antes de editar Rust pasaron check/test/build globales (197 pruebas) y la compilación/auditoría globales de Lean (2709 declaraciones). Después de la adaptación pasan check/test/build **aislados** de `nexus-zk` y `nexus-active`, con 113 pruebas, incluidas trece nuevas. No se repite el workspace global después de editar. Los catorce certificados históricos de ambos perfiles conservan sus bytes y resultados. La evidencia está en `../Documentos/06-Evidencia-TG2/2026-10-20/Rust-Lean/`; las dependencias no cambian. `adaptacion.json` y `revision-final.json` conservan las instantáneas anteriores al commit; `consolidacion.json` vincula el commit posterior con esas comprobaciones, sin presentarlas como pruebas nuevas. El manifiesto del 19 se conserva como antecedente y la identificación vigente se consulta en el manifiesto documental actualizado.

```powershell
cargo check -p nexus-zk -p nexus-active --all-targets --locked --offline --jobs 4
cargo test -p nexus-zk -p nexus-active --locked --offline --jobs 4
cargo build -p nexus-zk -p nexus-active --locked --offline --jobs 4
```

## Ubicación del código

| Ruta | Función |
|---|---|
| `nexus-crypto/src/entropy.rs` | Monitor R2 y estados de salud |
| `nexus-crypto/src/keypair.rs`, `registry.rs` | Gestor de épocas y registro local R3 |
| `nexus-crypto/tests/` | Regresiones y correspondencia del perfil de firma |
| `nexus-crypto/benches/` | Comparativa de firma, referencia clásica y residencia |
| `nexus-crypto/experiments/` | Ensayo TG2 multinúcleo corregido |
| `nexus-active/experiments/`, `tests/` | Verificador canónico experimental y sus casos |
| `nexus-zk/experiments/`, `tests/` | Contrastes algebraicos, proximidad y FRI vinculada |
| `nexus-zk/src/stark/` | Núcleo heredado y contrato adaptado en `linked.rs`/`linked_codec.rs`, con alcances separados |

Los módulos experimentales se incluyen desde pruebas y ejemplos específicos. Su presencia no significa que estén integrados en todas las rutas de producción del prototipo.

## Comandos desde este repositorio

Entorno registrado: Windows, Rust/Cargo 1.97.1, toolchain MSVC. `Cargo.lock` fija la resolución de dependencias. La primera instalación requiere `cargo fetch --locked`; después se puede trabajar sin red.

```powershell
$env:CARGO_TARGET_DIR = 'C:\tmp\nexus-target'
cargo check --workspace --all-targets --locked --offline
cargo test --workspace --locked --offline
cargo build --workspace --locked --offline
```

El 23 de septiembre pasaron **197 pruebas** del workspace en desarrollo. Las diez pruebas release de FRI vinculada se registraron el día 22. Las advertencias preexistentes quedan en los logs de cada ejecución.

## Relación con la tesis

Para navegar los enlaces locales del README, clonar este repositorio como `Tesis/nexus/` y el documental como `Tesis/`. En el repositorio documental, `Documentos/04-Administrativo-TG2/Entrega-Final/version-tg2.json` fija el commit exacto de código. `python scripts/verificar_version_tg2.py` comprueba ese commit y los archivos de la edición.

La evidencia de cada experimento conserva las fuentes utilizadas en ese momento y sus hashes. Las etapas históricas pueden usar código distinto al actual. Las instrucciones de repetición y las limitaciones están en los informes y en `scripts/README.md` del repositorio documental.
