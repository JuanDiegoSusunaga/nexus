# Testnet TCP: cuatro ejecutables, transferencias y recuperación

**Fecha:** 30 de octubre de 2026. Se añaden transporte, runtime y CLI reales al motor BFT y perfil monetario. La comprobación se realiza en loopback del mismo ordenador; no es una publicación en Internet ni independencia de operadores.

## Experimento

La [prueba de procesos](../../../../nexus/nexus-cli/tests/testnet_processes.rs) utiliza el ejecutable `nexus`, crea un laboratorio y lanza cuatro procesos con sus propias claves y directorios. Los consulta mediante TCP y verifica firmas de respuesta y certificados. Después:

1. Confirma bloques en los cuatro nodos y envía 2,5 NXS desde el faucet.
2. Rechaza una operación con clave pública alterada y una cabecera TCP con longitud excesiva, manteniendo el servicio.
3. Termina un proceso y comprueba progreso de los otros tres.
4. Termina un segundo proceso, envía otra transferencia de 1 NXS y comprueba que los dos restantes no la finalizan.
5. Reinicia el tercero con su clave/diario y comprueba inclusión de la transferencia pendiente.
6. Reinicia el cuarto y comprueba recuperación y acuerdo sobre un bloque común.
7. Un verificador sin clave descarga certificados secuenciales, reproduce todo el estado monetario y comprueba saldo final de 3,5 NXS, emisión y quema. Al terminar se cierran solo los procesos creados por la prueba.

[network-run.json](network-run.json) conserva génesis, dominio, alturas, raíz verificada, hashes de transferencias y contadores. [genesis-lab.json](genesis-lab.json) contiene el archivo público de ese experimento. No incluye claves privadas. Los cuatro logs son [nodo 0](node-0.log), [nodo 1](node-1.log), [nodo 2](node-2.log) y [nodo 3](node-3.log).

El laboratorio usa cantidades y parámetros ilustrativos: no es una propuesta de oferta o reparto de producción. La duración total del ensayo incluye cortes y esperas; no se presenta como medida de TPS o latencia productiva.

## Verificación y correcciones

[verification.json](verification.json) conserva comandos, resultados, tiempos y hashes de registros/fuentes. El alcance incluye chequeo global de todos los targets, pruebas del workspace y build, con dependencias locked/offline y cuatro trabajos/hilos. El helper ignorado de checkpoint se ejecuta desde su prueba padre.

| Comprobación | Resultado | Registro |
|---|---|---|
| `cargo check --workspace --all-targets --locked --offline --jobs 4` | Correcto | [cargo-check.log](cargo-check.log) |
| `cargo test --workspace --locked --offline --jobs 4` | **424 correctas**, sin fallos; un helper ignorado invocado por su prueba padre | [cargo-test.log](cargo-test.log) |
| `cargo build --workspace --locked --offline --jobs 4` | Correcto | [cargo-build.log](cargo-build.log) |

Son ocho pruebas nuevas frente al incremento BFT: cuatro de protocolo/atestación, dos de temporizadores/génesis, una de importes CLI y una de procesos TCP. La corrida conservada verificó seis bloques, alturas iniciales 2/2/2/2 y progreso 5/5/5 con un nodo apagado. Después de la recuperación, el verificador confirmó 3,5 NXS en el receptor y quema positiva. Es un resultado concreto, no un mínimo de rendimiento garantizado.

Las nuevas pruebas cubren tramas y límites, nonce/contexto/respuesta firmada, imposibilidad de inventar un tip finalizado mediante una sola atestación, identificador que compromete el sobre público completo, temporizadores crecientes, génesis con versión/compromisos fijados y enteros grandes, importes decimales exactos y el ciclo de cuatro procesos.

La primera prueba real reveló un desbordamiento de pila del cliente en Windows; se corrigió usando un hilo interno de 8 MiB para el runtime principal, sin crear ventanas de terminal. También se eliminó el aplanado de configuración JSON que impedía leer `u128` correctamente y se añadió recarga tipada con cantidades grandes. El identificador público ahora incorpora remitente, clave y esquema; cambia el protocolo general a **4** y la cabecera TCP a `NXSNET04`, sin migrar archivos anteriores.

## Contrato y límites

El [runtime](../../../../nexus/nexus-node/src/testnet.rs) posee el nodo de forma exclusiva y mantiene límites de conexiones, solicitudes/IP, eventos, tamaño y pool. Los temporizadores y consultas a pares se ejecutan realmente. El [cliente/tramas](../../../../nexus/nexus-network/src/testnet.rs) verifica contexto, nonce y respuestas atestadas. Los certificados siguen requiriendo tres firmas ML-DSA distintas; los pares no pueden forzar una altura solo declarándola.

Un saldo consultado es una atestación del validador que responde, no una prueba de pertenencia al estado. La prueba de procesos verifica saldos independientemente reproduciendo la historia. Una respuesta `pending` significa cola en memoria, no inclusión ni persistencia de la operación antes de finalizarla. Los observadores sin clave pueden sincronizar certificados, pero no emitir atestaciones de validador.

El TCP es público en claro, sin garantía de confidencialidad. La autenticación por mensaje no elimina cortes, censura de red o DDoS. Los límites son experimentales y el almacenamiento todavía conserva snapshots completos y generaciones, con máximo de 64 MiB por checkpoint. Tampoco se prueban aquí custodia de producción, rollback malicioso, admisión abierta o resiliencia poscuántica integral.

La [guía de laboratorio](../../../../nexus/TESTNET.md) y el [lanzador](../../../../nexus/scripts/run_testnet_lab.py) permiten reproducir el arranque sin consolas adicionales en Windows. El lanzador conserva los diarios, rechaza puertos ocupados y termina únicamente sus propios hijos. Fue revisado y comprobado sintácticamente; el ciclo funcional de CLI/TCP está cubierto por la prueba de integración, no por una segunda ejecución del lanzador.
