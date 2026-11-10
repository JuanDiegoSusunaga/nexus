# Consenso experimental de cuatro validadores y firma durable

**Fecha:** 30 de octubre de 2026. Incremento posterior al perfil monetario. No es un despliegue público ni una auditoría independiente. Los runtimes intercambian mensajes con un planificador de pruebas dentro del mismo proceso; existe además una prueba de salida abrupta en otro proceso.

## Contrato implementado

El [motor BFT](../../../../nexus/nexus-anchor/src/bft.rs) fija cuatro claves ML-DSA-65 con igual peso y quórum de tres votos distintos. Firma contexto, altura, ronda, fase, valor e identidad. La propuesta vincula el bloque completo y, cuando corresponde, un certificado de prevotos de una ronda anterior. El hash de bloque de consenso incluye todo el cuerpo: no reutiliza solo el hash de cabecera como compromiso de los sobres completos.

La base matemática propia es [QuorumIncentivos.lean](../../../../formalizacion/Nexus/Modelos/QuorumIncentivos.lean), en particular `quorum_estricto_interseca_honestos`. Con pesos 1/4, tres firmantes superan 2/3 y a lo sumo un validador defectuoso queda por debajo de 1/3. El modelo de intersección no demuestra por sí solo seguridad de las transiciones o disponibilidad.

Las fases y el bloqueo se orientan por [The latest gossip on BFT consensus, v3](https://arxiv.org/abs/1807.04938v3). Se conservan valores preparados entre rondas; una prueba de prevotos suficientemente nueva puede autorizar un voto y una antigua no borra un bloqueo más reciente. La implementación incorpora certificados explícitos ML-DSA y límites de memoria; no es una traducción formalmente verificada del artículo.

Los anuncios de ronda exigen dos emisores distintos para adelantarla. Los mensajes ordinarios se limitan a ocho rondas futuras y dos pasadas. Un certificado compacto de dos anuncios permite saltar a una ronda lejana conservando el bloqueo, para que el límite de memoria no deje sin recuperación a un nodo desconectado durante muchas rondas. Los tokens de temporizador son específicos de altura/ronda/fase; el runtime de red aún deberá programar demoras crecientes y retransmisiones.

El [nodo persistente BFT](../../../../nexus/nexus-node/src/bft.rs) deriva el dominio monetario del génesis/configuración y del comité. Cambiar claves o tolerancia temporal cambia también el dominio de las transacciones. La clave privada se suministra al proceso y no se incluye en el checkpoint.

Votos, fases, bloqueo y mensajes para retransmisión se persisten antes de que la API los devuelva para envío. Al decidir, certificado, aplicación monetaria y estado de la altura siguiente se guardan juntos. Si falla la escritura, la API devuelve error y restaura el estado anterior. La recarga reproduce la historia monetaria, valida certificados de todas las alturas y verifica el diario. Un observador sin clave de validador puede reconstruir el libro mediante certificados secuenciales, sin firmar.

## Verificación

[verification.json](verification.json) conserva comandos, tiempos, hashes de registros y huellas de todas las fuentes/configuraciones Rust seleccionadas.

| Etapa | Resultado | Registro |
|---|---|---|
| `cargo check --workspace --all-targets --locked --offline --jobs 4` | Correcto | [cargo-check.log](cargo-check.log) |
| `cargo test --workspace --locked --offline --jobs 4` | **416 correctas**, sin fallos; un helper ignorado invocado por su prueba padre | [cargo-test.log](cargo-test.log) |
| `cargo build --workspace --locked --offline --jobs 4` | Correcto | [cargo-build.log](cargo-build.log) |

Trece pruebas nuevas:

- [Cuatro pruebas de núcleo](../../../../nexus/nexus-anchor/tests/bft_rounds.rs): contextos y fases firmadas, compromiso del cuerpo, repetición sin quórum, conflicto de voto sin mutación, bloqueo restaurado, prueba nueva frente a prueba obsoleta, adelanto con dos anuncios y recuperación de ronda lejana con prueba acotada.
- [Ocho pruebas de runtimes](../../../../nexus/nexus-node/tests/bft_durable.rs): dos bloques con transferencias, cuatro almacenes y observador; líder ausente; detención con dos nodos y recuperación con tres; propuesta durable; fallo de escritura al decidir; reloj/comité alterados; líder único que envía propuestas contradictorias; proceso que termina sin ejecutar `Drop` tras persistir su propuesta.
- Una prueba interna de archivos alterados: certificados ausentes o con firmantes repetidos y fase reiniciada frente a votos ya firmados se rechazan.

Los casos de líder equivocado y cambios de ronda son escenarios concretos. No cubren todos los calendarios adversarios ni constituyen prueba universal de seguridad o terminación. Algunas pruebas de pruebas obsoletas firman deliberadamente historias incompatibles con las claves de fixture para ejercitar el rechazo; no afirman que esas historias puedan darse bajo el supuesto de un único fallo.

Se usaron cuatro trabajos/hilos y procesos auxiliares con ventanas ocultas en Windows. Se conservan advertencias existentes. `rustfmt` no está disponible en el toolchain instalado; no se afirma una revisión automática de formato.

## Versiones y trabajo pendiente

Protocolo general **3**; formato propio de checkpoint `BftNode` **1**. El diario conserva toda la historia de certificados y el snapshot monetario; es un formato distinto del nodo local anterior. No se migran ni sustituyen archivos previos.

Antes de publicar faltan transporte y límites de recursos, temporizadores/retransmisión reales, recuperación por red, almacenamiento incremental y pruebas entre procesos/redes. La historia se copia en snapshots, hay un límite de 64 MiB por archivo y se conservan generaciones: todavía no es almacenamiento adecuado para operación pública sostenida. La garantía de persistencia probada cubre salida de proceso; no pérdida de alimentación ni rollback deliberado del almacenamiento.

La seguridad supone a lo sumo una clave bizantina, criptografía no falsificada y un solo diario activo por clave. Copiar una clave a otro diario o restaurar un diario antiguo puede invalidar el supuesto de validador honesto. No hay admisión abierta de validadores, rotación del comité en marcha ni PoS ponderado por NXS; la selección inicial es fija. Tampoco se acredita composición poscuántica integral, confidencialidad de transporte, ejecución general mediante AIR/FRI ni seguridad económica de una moneda con valor real.
