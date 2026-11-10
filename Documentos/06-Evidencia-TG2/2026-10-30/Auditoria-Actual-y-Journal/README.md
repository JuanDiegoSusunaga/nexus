# Auditoría actual de NEXUS y diario incremental — 30 de octubre de 2026

Revisión del workspace local a solicitud del autor: «Busca errores actuales y problemas actuales». Se revisaron persistencia BFT, arranque CLI, pruebas Merkle, transporte y límites de la ruta experimental de testnet. Esta revisión y las pruebas no constituyen una auditoría externa ni acreditan ausencia de otros errores.

## Fallos encontrados y corregidos

| Hallazgo | Efecto observado | Corrección y evidencia |
|---|---|---|
| Compilación rota durante la sustitución del almacenamiento | `cargo check --workspace --all-targets` encontraba ocho errores: la prueba privada todavía usaba `Snapshot`, `snapshot()` y `restore()` eliminados. | Se sustituyó por pruebas de replay, firmas y certificados. [Log anterior](audit-check.log), [log actual](cargo-check.log). |
| El arranque CLI solo reconocía `checkpoint-*` | Con un diario `event-*` existente, intentaría crear el nodo de nuevo y fallaría en lugar de recuperarlo. | La detección usa `JournalStore::exists`, propagando errores de lectura y reconociendo ambos formatos. El formato antiguo se rechaza explícitamente. La prueba TCP reinicia validadores y verifica sincronización. [CLI](../../../../nexus/nexus-cli/src/testnet.rs), [prueba entre procesos](../../../../nexus/nexus-cli/tests/testnet_processes.rs). |
| La prueba Merkle ignoraba `leaf_index` | Tres controles aceptaban posiciones alteradas, incluso un índice fuera de la profundidad y un índice no nulo para una única hoja. | Se verifica que cada dirección coincida con el bit correspondiente del índice y que no sobren bits al terminar. [Tres fallos antes](audit-merkle-before.log), [tres casos correctos después](audit-merkle-after.log), [regresiones](../../../../nexus/nexus-core/tests/merkle_position.rs). |
| Cada cambio BFT copiaba la historia completa | El costo de almacenamiento por voto crecía con la historia y un snapshot completo estaba limitado a 64 MiB. | Diario incremental v2: registra entrada, salidas exactas, huella del estado y raíz monetaria. No vuelve a serializar todos los bloques. [Nodo](../../../../nexus/nexus-node/src/bft.rs), [almacén](../../../../nexus/nexus-core/src/journal.rs). |

El fallo Merkle afecta al contrato de esa API. No se encontró que el consenso TCP actual utilizara ese verificador para admitir transferencias. La corrección no cambia las raíces ni el formato de las pruebas: restringe verificaciones que antes aceptaban posiciones inconsistentes. No acredita el número original de hojas, que debe comprobar el consumidor con contexto confiable cuando exista relleno; la raíz esperada también debe proceder de una fuente confiable.

## Recuperación incremental

Cada registro publicado tiene secuencia, longitud, hash anterior y checksum; admite hasta 8 MiB. Se escribe un temporal exclusivo, se sincroniza y se renombra antes de devolver los mensajes. Un fallo de escritura no publica las firmas ni asigna el estado propuesto en memoria. Un archivo temporal incompleto puede ignorarse; corrupción, huecos intermedios, archivos publicados malformados o rechazo semántico impiden abrir el diario. No se borra historia publicada para recuperar un estado anterior.

Al abrir, se reproducen las transiciones usando un firmante que solo devuelve las firmas guardadas para los mismos bytes y en el mismo orden. La recuperación no genera firmas nuevas. Se verifican salidas, certificados, huella del estado, identidad, configuración, versión y raíz. Si una decisión durable no puede aplicarse por un error inesperado, el nodo deja de producir salidas y requiere recuperación.

Las pruebas incluyen exclusión de escritor, continuidad al reabrir, corrupción/truncamiento/huecos/empalmes, rechazo semántico, publicación fallida y reintento, salida abrupta de otro proceso con un temporal parcial y una historia genérica de **75.000.000 bytes** repartida entre diez registros válidos. Esta última prueba corresponde al almacén genérico, no a una cadena NEXUS de ese tamaño.

En el nodo real se aplican y recuperan **24 bloques certificados**: el primer y último registro de commit tienen el mismo tamaño. Los tamaños medidos están en `verification.json`. También se conservan las pruebas de salida abrupta tras firmar una propuesta y de fallo de persistencia antes de aplicar una recompensa, que comprueban conservación del bloqueo y ausencia de doble aplicación.

El protocolo TCP sigue en **4**; el diario BFT pasa a **2**. Los snapshots BFT v1 no se migran automáticamente. Para un laboratorio nuevo se genera un génesis nuevo y claves nuevas en otra carpeta; no se borra el diario ni se reutiliza una clave de validador con un diario vacío para el mismo génesis.

## Problemas que siguen abiertos

| Prioridad | Problema actual y consecuencia | Evidencia o frontera |
|---|---|---|
| Alta antes de publicar | Las claves de `init` se guardan sin cifrar; Windows hereda permisos del directorio. Falta custodia y configuración de acceso del despliegue. | `write_new` y generación en [CLI](../../../../nexus/nexus-cli/src/testnet.rs). Son claves de laboratorio. |
| Alta antes de operación sostenida | Bloques, cuentas y certificados siguen en RAM; replay de arranque y número de archivos crecen con la historia. No hay poda, índice de disco ni recuperación acelerada validada. | Campos de `BftNode`, `AnchorChain` y `JournalStore::open`. El diario elimina la copia completa por evento, no estos costos. |
| Alta para mantener la hipótesis de validador honesto | El dueño del almacenamiento puede borrar un sufijo entero, restaurar una copia antigua o duplicar clave y diario en otra máquina. El bloqueo de archivo solo evita dos escritores locales sobre ese directorio. | Modelo de directorio confiable; sin contador externo contra rollback ni garantía de metadatos ante pérdida eléctrica. |
| Alta antes de Internet | TCP no cifra el tráfico y los límites de conexiones/colas/IP no prueban resistencia DDoS. Solo se verificó loopback entre procesos, sin latencia, particiones y caídas de máquinas externas. | [Transporte](../../../../nexus/nexus-network/src/testnet.rs), [runtime](../../../../nexus/nexus-node/src/testnet.rs), [ensayo actual](network-run.json). |
| Límite de diseño | Cuatro validadores fijos, finalidad con tres y tolerancia prevista de uno bizantino. No hay incorporación abierta ni cambio de comité validado. El saldo consultado depende de la atestación de un validador; `pending` es volátil. | [Consenso](../../../../nexus/nexus-anchor/src/bft.rs) y guía de testnet. La emisión está acotada, pero los parámetros de laboratorio no validan incentivos de producción. |
| Límite científico | No existe refinamiento formal completo Rust/Lean, prueba de ejecución general L2 mediante AIR/FRI ni garantía poscuántica integral de la dualblockchain. El puente de valor y la coordinación de ambas capas en la red pública siguen pendientes. | Se conserva el alcance matemático de la tesis y QROM AIR/FRI como trabajo futuro. Usar ML-DSA no elimina estas obligaciones. |

## Verificación

**Resultado:** check de todos los targets, **436 pruebas correctas**, cero fallos y build correcto. Un helper ignorado en la suite ordinaria se invoca desde su prueba padre. Los registros del primer y último commit del ensayo de 24 bloques miden **27.832 bytes**; sus 24 registros suman **667.968 bytes**, aparte del génesis.

El [ensayo adicional del lanzador](launcher-smoke.json) ejecuta dos veces `python scripts/run_testnet_lab.py --seconds 6` con el mismo laboratorio: los cuatro nodos arrancan primero desde altura 0 y vuelven a abrir desde altura 3. Ambas ejecuciones terminan correctamente y las cuatro escuchas quedan cerradas. No se publican las claves del laboratorio.

[Registro de comandos, resultados y huellas de fuentes](verification.json). Se ejecutan `cargo check --workspace --all-targets`, `cargo test --workspace` y `cargo build --workspace`, con `--locked --offline --jobs 4`. El test de red inicia cuatro ejecutables ocultos en Windows, apaga y reinicia participantes, verifica transferencias y reproduce la historia certificada desde un observador. Solo se conservan [génesis público](genesis-lab.json), resultados y logs; no claves privadas.

Los logs anteriores de Merkle prueban la reproducción negativa; la suite global corresponde al código corregido. La evidencia TCP de la carpeta hermana conserva su carácter histórico. Esta revisión no modifica el manuscrito ni las demostraciones Lean, no publica endpoints y no realiza commit ni push.
