# Revisión dirigida antes de la testnet pública

**Fecha:** 30 de octubre de 2026. El autor pidió una blockchain pública para validar la tesis y buscar errores y problemas actuales. Se revisaron reglas monetarias, contabilidad de validadores, ejecución, consenso y superficie de red del workspace local. No se publicó ningún servicio ni se modificaron manuscrito o Lean.

## Tres defectos reproducidos y corregidos

1. **Suma de stake saturada al registrar.** `add_validator` aceptaba un depósito nuevo incluso cuando el total excedía `u128::MAX`. El contador se saturaba. Ahora la suma comprobada rechaza el alta antes de modificar miembros o total.
2. **Penalización sin descuento en el total.** `slash` reducía el principal individual y conservaba el total anterior. La prueba con depósitos de 101 y 99, multa de 5 y retiro posterior mostraba el error de contabilidad. Ahora principal, total y estado de penalización se actualizan juntos. El acceso mutable al validador queda interno para evitar modificaciones de stake que eludan esa contabilidad.
3. **Desbordamiento al calcular la multa.** `stake * porcentaje / 100` fallaba en debug con stake máximo, aunque el cociente cabía en `u128`. Se usa la identidad `floor(s*p/100) = floor(s/100)*p + floor((s mod 100)*p/100)`, válida para enteros no negativos. Con `p <= 100`, ambos términos y su suma caben. Las comprobaciones de porcentaje, saldo y plazo preceden a la mutación.

La explotación remota no está demostrada: son APIs locales y la red todavía no funciona. El consenso actual obtiene pesos de validadores activos mediante suma comprobada; no usa este total almacenado como sustituto del quórum. Las correcciones no acreditan seguridad BFT ni reparan automáticamente archivos históricos con contabilidad inconsistente.

## Evidencia reproducible

- [Fuente anterior](validator-before.rs), conservada antes de corregir.
- [Salida anterior: tres pruebas fallan](reproduction-before.log) y [comando/resultado](reproduction-before.json).
- [Tres pruebas de regresión](../../../../nexus/nexus-anchor/tests/validator_accounting.rs).
- [Verificación posterior](verification.json), con comandos, duración y hashes de fuentes/salidas.
- [Chequeo global](cargo-check.log): `cargo check --workspace --all-targets --locked --offline --jobs 4`, correcto.
- [Pruebas globales](cargo-test.log): `cargo test --workspace --locked --offline --jobs 4`, **387 correctas**, sin fallos. Se conserva un helper ignorado que invoca su prueba padre de salida abrupta.

La corrección conserva estructura serializada y versiones de protocolo/checkpoint. Esa compatibilidad de forma no asegura que un snapshot antiguo tenga contabilidad correcta. No se migraron datos. El comando anterior y el posterior usaron cuatro hilos de pruebas; los procesos se lanzaron con ventanas de consola ocultas. Se conservan advertencias del compilador; no se repitió el build separado porque check de todos los targets y las pruebas cubren esta modificación de biblioteca.

## Pendientes de publicación confirmados por inspección

| Componente | Evidencia actual | Trabajo pendiente |
|---|---|---|
| Transporte y API | `nexus-network/src/lib.rs` declara mensajes/configuración; `nexus-node/src/lib.rs::start` solo registra inicio; `rpc.rs` es un placeholder. | Transporte real, límites de recursos y acceso de clientes. |
| Consenso | `nexus-anchor/src/consensus.rs` conserva una máquina local autenticada, sin cambio de ronda ni bloqueo entre rondas y sin diario durable de firma. | Protocolo distribuido con dominio de génesis/despliegue, recuperación y certificados verificables. |
| Moneda | `chain.rs::stage_block` acredita la recompensa configurable por bloque; predeterminado 2 NXS. Gas reservado, sin comisión debitada ni quema implementada. | Suministro/genésis, emisión acotada y contadores, distribución, tarifas y reglas de quema si se adoptan. |
| L2 | `execution.rs` usa el reloj local para vigencia. | Contexto de ejecución reproducible entre réplicas, recepción/sincronización de bloques y autorización coherente entre capas. |
| Matemática y PQ | Quórum estricto y modelos propios conservados; ML-DSA operativo. AIR/FRI mantiene su alcance ROM clásico finito y relación escalar. | Composición de seguridad del despliegue; distinguir pruebas del modelo de evidencia del ejecutable y la red. |

Estos puntos son funciones ausentes o límites declarados del prototipo, no seis ataques remotos demostrados. Los porcentajes de distribución, el suministro máximo y el mecanismo definitivo de quema siguen sin seleccionarse. La testnet pública tendrá NXS de prueba; un comité inicial fijo no implica incorporación abierta de validadores.

Fuentes externas, incidentes y propuesta monetaria se conservan en las secciones 14 y 15 de [documentacion.md](../../../../documentacion.md). La fecha de un incidente, su informe y el estado actual de un servicio se distinguen explícitamente.
