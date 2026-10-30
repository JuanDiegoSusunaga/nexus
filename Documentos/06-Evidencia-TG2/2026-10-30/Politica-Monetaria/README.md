# Perfil monetario local para la futura testnet pública

**Fecha:** 30 de octubre de 2026. Implementación posterior a la auditoría de contabilidad. La red pública continúa pendiente: estas pruebas validan transiciones y almacenamiento locales, no comunicación ni consenso entre operadores.

## Resultado

`AnchorChain::new_monetary` aplica asignaciones de génesis comprobadas, máximo de emisión histórica, subsidio por altura con reducción a la mitad por intervalos, gas que incluye bytes del sobre firmado, precio mínimo y reparto de comisión entre quema y proponente. Cada bloque comprueba `suma de saldos = emisión acumulada − quema acumulada`. La raíz compromete cuentas, contadores y dominio monetario.

La quema no permite reutilizar el cupo de emisión. Los parámetros son obligatorios y configurables; no se ha elegido una oferta o reparto de producción. Las cantidades pequeñas de las pruebas son fixtures en unidades mínimas. En el perfil monetario se permiten transferencias y `BatchSubmit` firmado; no staking, contratos generales ni emisión entre capas.

`Transaction::network_domain` queda dentro de los bytes firmados. Se exige el compromiso del génesis monetario/configuración esperados; otro despliegue con el mismo número de cadena no acepta la operación. La validación de aplicación usa el tiempo del bloque. El futuro consenso debe añadir el comité, certificados y validación temporal de propuestas en vivo.

`DurableNodeConfig::anchor_monetary` selecciona el perfil y exige que las asignaciones experimentales L2 estén vacías. Se evita crear el mismo NXS de forma independiente en dos libros; el puente de valor sigue sin implementarse. Si falla el checkpoint, el nodo restaura el estado anterior; tras una salida abrupta, recarga el último estado reconocido como persistente.

La recarga monetaria exige el génesis esperado y reproduce todos los bloques. Una prueba altera balances o contadores, recalcula la raíz archivada y modifica el índice del bloque para que coincida: la recarga aun así rechaza la unidad inventada porque la ejecución no la justifica. Los metadatos auxiliares se reconstruyen mediante replay. Esto no impide que un propietario malicioso del almacenamiento sustituya todo por un prefijo válido antiguo.

## Verificación

[verification.json](verification.json) contiene comandos, duraciones, hashes de salidas y huellas de todas las fuentes/configuraciones Rust seleccionadas.

| Etapa | Resultado | Registro |
|---|---|---|
| `cargo check --workspace --all-targets --locked --offline --jobs 4` | Correcto | [cargo-check.log](cargo-check.log) |
| `cargo test --workspace --locked --offline --jobs 4` | **403 correctas**, sin fallos; un helper ignorado invocado por su prueba padre | [cargo-test.log](cargo-test.log) |
| `cargo build --workspace --locked --offline --jobs 4` | Correcto | [cargo-build.log](cargo-build.log) |

Se añaden dieciséis pruebas: once de integración L1, una de recarga con archivo falsificado y cuatro de nodo persistente. Incluyen génesis canónico y límites inválidos, alturas exactas de subsidios, último subsidio al alcanzar el tope, quema sin reapertura de cupo, extremos de `u128`, cobro real y aliases entre remitente/receptor/proponente, medición de bytes, dominios distintos, errores atómicos, anclaje firmado de datos L2 con cobro y reconstrucción tras replay, cuatro almacenes locales, rechazo de doble asignación L1/L2, escritura fallida y proceso que termina sin ejecutar `Drop` después del reconocimiento durable.

Fuentes principales:

- [Política y contadores](../../../../nexus/nexus-anchor/src/monetary.rs).
- [Integración en L1 y replay](../../../../nexus/nexus-anchor/src/chain.rs).
- [Pruebas monetarias](../../../../nexus/nexus-anchor/tests/monetary_profile.rs).
- [Nodo persistente](../../../../nexus/nexus-node/src/durable.rs) y [pruebas de persistencia](../../../../nexus/nexus-node/tests/monetary_durable.rs).
- [Transacción con dominio](../../../../nexus/nexus-core/src/transaction.rs).

Se usaron cuatro trabajos/hilos y procesos auxiliares con ventanas ocultas en Windows. Se conservan advertencias del compilador. `rustfmt` no está disponible en el toolchain instalado; no se afirma una comprobación automática de formato.

## Versiones y límites

Protocolo **3**, ruta `/nexus/3.0.0`, checkpoint L1 **3** y L2/nodo **4**. El cambio de transacción firmada altera los bytes de firma y el formato de archivos; no se ofrece migración automática. El perfil legado sigue usando reserva de gas sin comisión debitada y recompensa configurable sin esta política; la testnet deberá seleccionar explícitamente el perfil monetario.

El procesamiento de un bloque aún no es finalidad BFT. No se han implementado ni publicado transporte, sincronización, cambio de ronda o diario durable de votos. Cuatro réplicas y cuatro directorios no son cuatro operadores independientes. Los checkpoints actuales guardan la historia completa y tienen un límite de 64 MiB; el almacenamiento deberá evolucionar antes de una operación pública sostenida. Las pruebas de persistencia cubren salida de proceso, no durabilidad de metadatos ante pérdida eléctrica. La prueba no demuestra resistencia poscuántica integral, seguridad económica ni rendimiento bancario. Manuscrito, Lean y evidencia histórica no se regeneran ni se presentan como prueba de estas nuevas reglas.
