# Reproducibilidad de la edición TG2

**Organización:** 23 de septiembre de 2026. Este repositorio contiene el prototipo Rust y las variantes experimentales de TG2. Los documentos se mantienen en `https://github.com/JuanDiegoSusunaga/tesis-nexus`.

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
| `nexus-zk/src/stark/` | Implementación heredada conservada como referencia de TG1 |

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
