# Reproducibilidad de la edición TG2

## Publicación desde Docker y repositorio exclusivo — 30 de octubre de 2026

Por decisión del autor, los avances de la testnet se guardan exclusivamente en `JuanDiegoSusunaga/nexus`. Se incluyen documentación, corpus público y evidencia sin claves ni datos operativos. Las dos pruebas que leían corpus desde la carpeta contigua del repositorio académico ahora lo leen dentro de este clon; Docker construye desde esta raíz. La lógica Rust de producción no cambia por esa reubicación.

La [guía operativa](deploy/PUBLICAR_DOCKER.md) registra cuatro validadores, pasarela y túnel públicos desde un solo computador. Diecisiete pruebas Python pasan. Se verifica una transferencia por HTTPS y un cliente Linux descargado que valida cuatro identidades y raíz certificada común; una sonda HTTP de otra red recibe 200. Las transferencias y la validación criptográfica se originan en el mismo computador físico del servidor. [Evidencia](Documentos/06-Evidencia-TG2/2026-10-30/Docker-Publico/README.md).

Los nodos conservan la imagen nativa verificada anterior y sus diarios; la reconstrucción independiente del paquete no reemplaza los contenedores activos. Siguen pendientes operadores y máquinas independientes, custodia, retención de historia y refinamiento universal Rust/Lean. El enlace es temporal; NXS es de prueba y no tiene precio establecido para este génesis. Las secciones siguientes conservan el estado de las etapas anteriores.

**Acceso unificado, 29 de octubre de 2026:** [tesis, matemáticas, Rust y evidencias](https://github.com/JuanDiegoSusunaga/tesis-nexus). El workspace se incluye también en la carpeta `nexus/` de ese repositorio.

**Organización histórica:** 23 de septiembre de 2026. Este repositorio contiene el prototipo Rust y las variantes experimentales de TG2. Los documentos se mantienen en `https://github.com/JuanDiegoSusunaga/tesis-nexus`.

## Límite de 512 MiB para la prueba inicial — 30 de octubre de 2026

El generador y el helper de contenedores admiten `--memory-limit 512m`, manteniendo `1g` como predeterminado. El manifiesto y los cuatro servicios reflejan el límite. Ocho pruebas Python pasan y se repite el ensayo de transferencias, cortes y recreación, comprobando el límite efectivo de 536.870.912 bytes por contenedor; los cuatro reabren en altura 8 con 2 NXS de saldo receptor. No se altera la imagen ni Rust/Cargo; las 436 pruebas y build de la imagen se conservan como evidencia anterior, sin presentarlos como una ejecución nueva.

[Resultados y huellas](Documentos/06-Evidencia-TG2/2026-10-30/Perfil-512MiB/README.md). Este ensayo local respalda evaluar cuatro VPS de 1 GiB por US$24/mes de base, antes de impuestos y extras. No reproduce el sistema operativo completo de esos VPS ni carga sostenida. Se mantienen pendientes presupuesto, cuenta, hosts y publicación externa.

## Despliegue Linux preparado — 30 de octubre de 2026

La imagen Linux amd64 se construye con Rust 1.97.1 y bases fijadas por digest. Check de todos los targets, **436 pruebas** y build release de `nexus-cli` correctos; siete pruebas Python del generador también pasan. El contexto incluye veinte artefactos públicos de regresión que necesitan las pruebas, sin claves ni manuscrito. El runtime no contiene fuentes ni Cargo. Los 132 archivos de la auditoría anterior conservan sus huellas.

Un cliente Windows verifica cuatro identidades y una raíz certificada común de cuatro contenedores Linux. El ensayo incluye transferencias de 1,25 y 0,75 NXS, avance con tres, detención con dos, reinicios por SIGKILL y recreación de contenedores con diarios conservados; los cuatro reabren en altura 9 con saldo de 2 NXS. Se verifican UID, raíz solo lectura, capacidades eliminadas y una clave de solo lectura por nodo. Se cierran contenedores y red propios y se conservan volúmenes.

[Paquete y guía](deploy/README.md) · [Propuesta de alojamiento](deploy/ALOJAMIENTO.md) · [Imagen, consultas, logs y huellas](Documentos/06-Evidencia-TG2/2026-10-30/Despliegue-Linux/README.md). Esta prueba usa una sola máquina y loopback, sin publicación en Internet. Faltan proveedor/cuenta, presupuesto y destinos autorizados. No se modifican matemáticas ni Rust y no se afirma custodia de producción o composición poscuántica integral.

## Auditoría actual y diario incremental — 30 de octubre de 2026

Se corrigen ocho errores de compilación de una prueba que todavía usaba snapshots eliminados, la detección de diarios al reiniciar desde CLI y la aceptación de posiciones alteradas en `MerkleProof`. Tres regresiones reproducen el fallo Merkle antes de corregirlo; la raíz y el formato no cambian. El consumidor debe seguir comprobando una raíz confiable y, cuando corresponda, el número original de hojas.

`BftNode` usa diario **v2**: persiste entradas, salidas firmadas exactas, huellas y raíces en registros acotados de hasta 8 MiB. Al abrir reproduce transiciones con las firmas registradas, sin generar otras. Publica el temporal sincronizado antes de devolver mensajes; corrupción, huecos intermedios o diferencias semánticas impiden recuperar. El protocolo de red permanece en **4**. No se migra automáticamente el snapshot BFT v1 ni deben reutilizarse claves con un diario vacío para el mismo génesis.

Pasan check de todos los targets, **436 pruebas** y build, con doce pruebas netas adicionales respecto del incremento TCP. Incluyen historia genérica de 75.000.000 bytes, crecimiento de 24 bloques certificados con registros inicial/final de 27.832 bytes, corrupción, firmas faltantes/reordenadas y salida abrupta. El ensayo TCP de cuatro procesos vuelve a pasar. Un helper ignorado por la suite ordinaria se invoca desde su prueba padre.

[Hallazgos, logs y huellas](Documentos/06-Evidencia-TG2/2026-10-30/Auditoria-Actual-y-Journal/README.md). Persisten historia/certificados en RAM y replay creciente, confianza en el almacenamiento, claves sin cifrar de laboratorio y falta de publicación/pruebas entre redes. No se modifica el manuscrito ni Lean y no se afirma composición poscuántica integral. Las secciones siguientes registran etapas históricas.

## Testnet TCP — 30 de octubre de 2026

`nexus testnet init/run/status/account/transfer` habilita laboratorio, procesos, consultas y envío real por TCP. `PublicGenesis` fija protocolo y compromisos de génesis, red y comité, conservando enteros monetarios de 128 bits. El runtime consulta pares, verifica certificados secuenciales, retransmite mensajes persistidos, difunde una cola acotada y programa plazos crecientes por ronda. Las respuestas de validadores vinculan nonce, petición y cuerpo con ML-DSA; un saldo consultado es una atestación, no una prueba independiente de pertenencia.

El protocolo pasa a **4**: el identificador de transacciones públicas compromete el sobre completo, incluidos remitente, clave y esquema; TCP usa `NXSNET04` y la ruta declarada es `/nexus/4.0.0`. Los formatos de checkpoint que no cambian mantienen sus versiones y rechazan contextos/protocolos anteriores. No hay migración automática.

Pasan check de todos los targets, **424 pruebas** y build, con ocho nuevas. La prueba de cuatro ejecutables sobre TCP verifica transferencias, rechazo de un sobre alterado, tres participantes operativos, operación pendiente con solo dos, reinicios y replay independiente de seis bloques con saldo final de 3,5 NXS. Se corrigieron pila insuficiente del cliente Windows y configuración JSON aplanada que impedía leer `u128`. [Evidencia](Documentos/06-Evidencia-TG2/2026-10-30/Testnet-TCP/README.md) · [Guía y lanzador](TESTNET.md).

No se mantienen procesos de prueba activos al finalizar ni se publica un endpoint externo. TCP es público en claro y las claves generadas por `init` son de laboratorio, sin cifrar. La cola es volátil; `pending` no significa finalidad. Faltan almacenamiento incremental, gestión operativa y operadores/máquinas externos antes de Internet. Las secciones siguientes conservan estados de incrementos anteriores.

## Consenso BFT experimental — 30 de octubre de 2026

`BftNode` y `BftNodeConfig` implementan un runtime persistente de comité fijo: cuatro claves ML-DSA-65 con igual peso, quórum exacto de tres, propuestas/prevotos/precommits, bloqueos entre rondas y certificados. El dominio monetario también incorpora comité y política temporal. Cada voto vincula contexto, altura, ronda, fase y hash del bloque completo. La referencia matemática propia es la intersección honesta de quórums; el esquema de fases sigue el antecedente Tendermint, sin afirmar un refinamiento formal del programa.

La API persiste antes de devolver mensajes para envío y guarda decisión, transición monetaria y altura siguiente de forma conjunta. Tras reinicio retransmite lo registrado y conserva fase/bloqueo. Un fallo de escritura restaura el estado anterior. Recargar exige el mismo contexto, historia certificada y diario válido. Un observador sin clave de validador puede aplicar certificados secuenciales.

El planificador de pruebas comprueba líder ausente, conflicto de un líder bizantino, detención con dos participantes, recuperación con tres, pruebas antiguas de bloqueo, salto de ronda con dos anuncios, salida abrupta y errores de archivo/escritura. Pasan check global, **416 pruebas** y build; trece pruebas nuevas. [Contrato, fuentes y evidencia](Documentos/06-Evidencia-TG2/2026-10-30/Consenso-BFT/README.md).

Protocolo general **3**, checkpoint propio de `BftNode` **1**. No se migran formatos anteriores. El nodo BFT es una ruta distinta del nodo local L1/L2 conservado. Faltan transporte, límites de red, temporizadores crecientes y retransmisión reales, almacenamiento incremental y pruebas entre procesos/redes. Se requiere almacenamiento confiable y un diario activo por clave. El motor es experimental y no implica una testnet pública ya publicada, PoS abierto o seguridad poscuántica integral.

## Perfil monetario — 30 de octubre de 2026

`AnchorChain::new_monetary(config, genesis)` habilita `MonetaryGenesis` y `MonetaryPolicy`: asignaciones comprobadas en orden canónico, tope de emisión histórica, subsidios por altura con reducción por intervalos, precio mínimo, gas por bytes del sobre y reparto entre quema y proponente. Los valores pequeños de las pruebas no fijan suministro ni porcentajes de producción. Deben deshabilitarse recompensa y metadato de tarifas legados al seleccionar este perfil.

Cada bloque exige conservación entre saldos, emisión y quema. La quema no reabre la emisión acumulada. El perfil permite transferencias y `BatchSubmit` con ML-DSA-65; no staking, contratos generales ni emisión de representaciones entre capas. Las transacciones incluyen el `network_domain` esperado dentro de los bytes firmados. La raíz de estado vincula cuentas, contadores y dominio monetario; no debe confundirse con la relación escalar AIR/FRI.

`DurableNodeConfig::anchor_monetary` selecciona el perfil. Las asignaciones experimentales L2 deben quedar vacías para evitar crear NXS independientemente en ambas capas. La recarga monetaria recibe el génesis esperado y reproduce los bloques, rechazando contadores o balances inventados aun con raíces archivadas recalculadas. La escritura fallida revierte el cambio antes de devolver error. El almacenamiento local sigue siendo confiable y no impide un rollback malicioso a un prefijo válido.

Protocolo **3**, ruta `/nexus/3.0.0`, checkpoint L1 **3** y L2/nodo **4**. No hay migración automática del formato anterior. Pasan check global de todos los targets, **403 pruebas** y build, con dieciséis pruebas nuevas. [Contrato detallado y evidencia](Documentos/06-Evidencia-TG2/2026-10-30/Politica-Monetaria/README.md).

La aplicación de bloques todavía no acredita finalidad BFT, transporte ni una testnet pública. Las reglas de propuestas en vivo, comité y diario de votos siguen pendientes. Las secciones siguientes conservan el estado y las versiones de incrementos anteriores; la comprobación actual es la enlazada arriba.

## Contabilidad de validadores — 30 de octubre de 2026

La revisión para la futura testnet pública reproduce y corrige tres fallos en `ValidatorSet::add_validator` y `ValidatorRegistry::slash`: suma saturada de stake, total que no disminuía al penalizar y producto desbordado al calcular la multa. Las actualizaciones validan antes de mutar y el acceso mutable directo a un validador pasa a ser interno. Check global de todos los targets y 387 pruebas correctas, incluidas tres nuevas. [Reproducción anterior, corrección y alcance](Documentos/06-Evidencia-TG2/2026-10-30/Auditoria-Red-Publica/README.md).

La estructura serializada y las versiones se conservan; no se migran ni reparan snapshots anteriores. No se implementan todavía red pública, tope de emisión, tarifas debitadas ni quema. La contabilidad del registro no equivale a una prueba de seguridad económica del consenso.

## Bloqueo de emergencia L2 — 30 de octubre de 2026

`ActiveChainConfig::recovery` fija antes de operar un `RecoveryPolicy` con un identificador de despliegue no nulo y una clave pública de recuperación por identidad protegida. La configuración es inmutable durante la ejecución. Su constructor y deserializador rechazan identidades repetidas y la reutilización de claves operativas protegidas como autoridades. Admisión y ejecución también rechazan transacciones firmadas con cualquiera de las claves de recuperación configuradas, aunque su dirección tenga saldo; el registro operativo no admite esas claves.

`EmergencyFreezeRequest::sign(chain_id, deployment, identity, issued_at, expires_at, &guardian)` produce una orden con dominio exclusivo de bloqueo L2. La autoridad se obtiene de la configuración confiable, nunca de la orden. Se comprueban firma, versión, cadena, despliegue e intervalo temporal. La API `apply_emergency_freeze(request)` está disponible en `ActiveChain`, `DurableNode` y el motor independiente. No exige la firma ni la disponibilidad de la clave operativa. `emergency_freeze_status(&identity)` devuelve la orden aceptada y su fecha local de aceptación.

El bloqueo es permanente en este perfil: impide emitir operaciones desde la identidad, cancela su pool y sus reservas externas y no se elimina al rotar, retirar o volver a presentar eventos operativos. Las órdenes repetidas, incluso con otra firma válida para la misma identidad, se rechazan. Esta protección usa el estado monótono de bloqueo; no hay un contador de desbloqueos ni una API para desbloquear, sustituir la clave o recuperar fondos. El bloqueo no mueve saldos, consume nonces ni revierte operaciones previas; tampoco impide recibir transferencias.

El cambio se serializa con producción y admisión. Una reserva externa de la identidad no puede bloquear la emergencia. `DurableNode` persiste la orden y la cancelación del pool juntas antes de devolver éxito; si falla la escritura, restaura ambas. La recarga verifica la firma de cada orden a su fecha de aceptación guardada: vencer el plazo para presentar la orden no desactiva un bloqueo ya aceptado. La configuración esperada debe coincidir, de modo que abrir con autoridades distintas o con la recuperación deshabilitada falla.

La verificación de este incremento pasó `cargo check --workspace --all-targets`, 384 pruebas y `cargo build --workspace`, con dependencias locked/offline. Incluye catorce pruebas nuevas de firmas, contextos, separación de claves, bloqueo tras rotación, concurrencia, recibos alterados, persistencia, fallo de escritura y salida abrupta de otro proceso. [Evidencia y hashes](Documentos/06-Evidencia-TG2/2026-10-30/Bloqueo-Emergencia-L2/verification.json).

**Alcance vigente:** protocolo de bloques/red v2; checkpoints de `ActiveChain` y `DurableNode` v3 y de `AnchorChain` v2. No hay migración automática de checkpoints anteriores. Las claves de recuperación deben custodiarse fuera del firmador operativo; este cambio no implementa esa custodia ni prueba independencia física. La política y los bloqueos son locales y no están anclados en L1. La protección contra un propietario malicioso del almacenamiento o la restauración de una copia antigua sigue pendiente. Un identificador de despliegue reutilizado en otra instancia con las mismas autoridades permite reutilizar órdenes entre ambas; debe elegirse uno distinto por despliegue. La evidencia anterior conserva su corte y sus hashes.

## Autorización local de claves L2 — 30 de octubre de 2026

`KeyManager::sign_transaction(&identity, transaction)` firma para una identidad estable y su época vigente. La firma incluye un dominio específico de transacciones L2, además de los campos de la operación, la identidad y la época. `SignedTransaction::authorization_epoch = Some(epoch)` selecciona este contrato; su hash compromete la envoltura completa. Las firmas sin época conservan el contrato de dirección derivada de la clave, pero se rechazan para cualquier identidad que ya figure en el registro, incluso después de su retiro. El verificador sin registro y L1 rechazan explícitamente las envolturas con época.

`ActiveChain::apply_key_record(record)` y `DurableNode::apply_key_record(record)` reciben un evento del historial público de `KeyManager`. Verifican secuencia, enlace y autorizaciones antes de instalarlo. Se aplican los eventos en orden: el registro existente es un único historial autorizado, no una mezcla de historiales independientes de varios gestores. La rotación conserva las reglas del registro, incluidas las autorizaciones de todas las identidades activas. No se acepta un registro adjunto a una transacción ni se reemplaza el historial con una instantánea arbitraria.

Admisión y ejecución comparten el mismo registro. Un cambio de política se serializa con la producción de bloques y retira del pool las transacciones cuya clave dejó de estar vigente, liberando sus reservas de nonce. Si un consumidor externo tiene trabajo del secuenciador reservado, el cambio se rechaza antes de modificar el registro. Tras una rotación, la clave nueva opera sobre la cuenta original, conservando su saldo y nonce. El retiro impide nuevas operaciones; no revierte operaciones ejecutadas previamente. `key_registry_checkpoint()` entrega el número de eventos y el hash de cabecera locales.

El coordinador durable publica registro y pool en una misma generación. Un fallo de escritura restaura ambos y no devuelve éxito. Al abrir, reconstruye y verifica las autorizaciones del historial y vuelve a conectar admisión y ejecución con una sola política. La recarga comprueba las firmas y vigencia del pool sin aplicar el reloj actual al vencimiento histórico; la selección y la ejecución posteriores sí aplican sus controles de vencimiento normales.

Uso sobre un nodo ya creado y una identidad de un gestor configurado:

```rust,ignore
// Entregar cada evento nuevo exactamente una vez, en el orden del historial.
node.apply_key_record(manager.registry().records()[0].clone())?;
let signed = manager.sign_transaction(&identity, transaction)?;
node.submit_transaction(signed)?;
// Después de rotar o retirar en manager, entregar también el evento siguiente.
```

Las pruebas de `nexus-active/tests/key_authorization.rs` y `nexus-node/tests/key_authorization.rs` cubren identidad estable, firmas alteradas, separación de mensajes, retiro, acceso directo al motor, concurrencia, reinicios, registros inválidos y fallos de persistencia. Los resultados de esta ejecución se conservan en la [verificación del 30 de octubre](Documentos/06-Evidencia-TG2/2026-10-30/Autorizacion-Claves-L2/verification.json).

**Corte de este primer incremento:** protocolo y checkpoints v2; el bloqueo de emergencia descrito arriba eleva los checkpoints L2/nodo a v3. La codificación binaria de transacciones añade la época opcional. No hay migración de checkpoints anteriores. La política se incorpora mediante una API administrativa local confiable y no está anclada en L1 ni comprometida por la raíz de cuentas. Los controles de salud de entropía no detectan intrusiones. La tesis, sus resultados Lean y el manifiesto de la edición conservada mantienen su alcance histórico; las nuevas fuentes se identifican en la evidencia de cada ejecución.

## Ciclo local persistente y ejecución soportada — 20 de octubre de 2026

`nexus_node::DurableNode` es un coordinador local que posee L1 y L2 de forma exclusiva. Las instancias directas de `ActiveChain` y `AnchorChain` mantienen su operación en memoria. El coordinador guarda una nueva generación completa antes de devolver éxito de admisión, producción, registro de envío, procesamiento L1, recuperación o confirmación. `prepare_l1_submission` y `prepare_l1_retry` preparan y registran juntos: los bytes exactos quedan guardados antes de devolver el paquete al llamante. No realizan transmisión de red.

Los checkpoints conservan cuentas/código/storage, bloques e índices, pool y nonces confirmados, lote en construcción, contextos de lotes conocidos, cola, intentos con paquetes y fechas, confirmaciones, raíces verificadas y pruebas optimistas pendientes, DA y metadatos locales de validadores/finalidad. Se exportan bajo los bloqueos correspondientes; el coordinador no expone las cadenas mutables. El publicador entrega la misma clave al reabrir; no se serializa la clave privada. Identidad, configuración L1/L2 y asignación inicial deben coincidir con el contexto esperado. La restauración comprueba versión, límites, estructura de bloques, raíz de cuentas, pool y coherencia DA. Es restauración de estado local confiable, sin repetir la admisión al reloj actual de paquetes históricos.

`ActiveChain::with_genesis_balances` permite una asignación experimental explícita y rechaza direcciones repetidas. Su raíz se incorpora al génesis L2 de esa instancia. No añade un método de emisión después del génesis ni cambia el génesis por defecto. La API no convierte esta configuración local en una identidad de red certificada.

El almacenamiento admite un escritor mediante bloqueo de archivo del sistema operativo. Cada generación contiene cabecera/versionado `NEXUSCP1`, número, longitud y checksum SHA3. Los bytes se escriben a un archivo temporal nuevo, se sincronizan y después se publican mediante renombrado. Los temporales incompletos se ignoran al abrir; un último archivo comprometido corrupto se rechaza, sin volver silenciosamente a una generación anterior. Un error previo a la publicación revierte el estado en memoria; si la restauración falla, el nodo exige reapertura. Se conservan todas las generaciones. El payload máximo es 64 MiB; no hay migración automática de formato ni retención/poda implementada.

El contrato de ejecución L2 rechaza `Call` y `Deploy` con resultado fallido, cero gas de ejecución y sin cambios, logs o retorno simulados, después de los controles normales de admisión. La transferencia soportada conserva su contrato de balances, nonce y reserva de costo. No se implementan comisiones ni intérprete de contratos. Se reprodujeron los dos éxitos ficticios antes de la corrección.

Ejemplo ejecutable (directorio nuevo, clave mantenida por el ejemplo solo durante su ejecución):

```powershell
cargo run -p nexus-node --example local_cycle --locked --offline -- target/mi-ciclo-local
```

El ejemplo ejecuta una transferencia financiada en el génesis experimental, reabre tras ejecución, registro del paquete, inclusión y confirmación, contrasta raíz y bytes, y rechaza repetición y confirmación duplicada. Emite JSON sin secretos. Las pruebas adicionales usan cinco procesos independientes terminados sin ejecutar `Drop`, fuerzan fallos de escritura en cuatro fases y comprueban pool, lote parcial, límite de reintentos, claves/políticas incompatibles, corrupción, vencimiento histórico y un certificado escalar sintético. La [evidencia del ciclo local](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/06-Evidencia-TG2/2026-10-20/Ciclo-Local-Durable/verificacion.json) conserva comandos, resultados y ejemplo.

**Límites:** directorio y checkpoints locales confiables; el checksum detecta corrupción, pero no autentica al escritor ni evita que alguien restaure maliciosamente archivos antiguos. Se ensaya recuperación ante salida de procesos; la durabilidad frente a corte eléctrico, metadatos del directorio y sistemas de archivos remotos requiere una política adicional. La custodia durable de claves sigue fuera de este componente. No se acredita finalidad BFT, disponibilidad remota, rendimiento de producción ni ejecución L2 mediante el AIR escalar. Las fuentes Lean, manuscrito, primitivas y núcleo/lector AIR-FRI se preservan; no se agrega un resultado matemático.

## Recuperación de un reintento omitido — 20 de octubre de 2026

`recover_l1_retry(index, expected_hash, &transaction, &l1)` recupera el registro de un reemplazo que la instancia L1 confiable ya procesó. Exige que el lote tenga un envío pendiente cuyo hash vigente sea `expected_hash`, que el nuevo hash no esté reservado por ningún intento presente o histórico, y que quede capacidad dentro del límite común de tres reintentos. Compara publicador, raíz, cantidad y datos con el lote conocido y reutiliza la comprobación de envoltura completa e inclusión canónica de `validate_processed_batch_submission`. El nonce consumido y el vencimiento actual no invalidan esa inclusión histórica. `retry_l1_submission` conserva su admisión actual previa al procesamiento.

La operación conserva íntegros el lote, el certificado aceptado y los intentos anteriores, incluidos sus bytes y fechas. Añade un intento con los bytes firmados exactos y devuelve un `ConfirmedBatch` con la ubicación original del reemplazo; la fecha del intento corresponde al registro local de la recuperación. El control del hash vigente, las reservas, el límite y el estado pendiente se comprueban antes de modificar el historial. El registro y la confirmación ocurren bajo el mismo bloqueo, sin publicar un reemplazo pendiente intermedio. Las llamadas concurrentes de recuperación o reintento normal solo permiten una transición desde el hash esperado.

La confirmación identifica explícitamente el paquete recuperado, aunque otro intento también esté incluido. `mark_batch_confirmed` conserva su selección del primer intento registrado cuya inclusión coincida. Un paquete ya registrado se confirma por esa API: la recuperación no duplica su hash ni rellena retroactivamente los bytes de una intención por hash. Un lote confirmado, un hash obsoleto, un hash reservado incluso por un lote confirmado o un cuarto reintento se rechazan sin cambios. El límite también se aplica si L1 ya procesó ese cuarto paquete; esta API no lo adopta.

La [evidencia de recuperación de reintentos](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/06-Evidencia-TG2/2026-10-20/Recuperacion-Reintentos-L1/verificacion.json) conserva ocho pruebas externas y una interna. Cubren paquetes exactos y alterados, vencimiento histórico, fuentes sin inclusión, lote/publicador distintos, hashes obsoletos o reservados, ausencias, límite, múltiples inclusiones y concurrencia. El ensayo interno con certificado escalar válido comprueba que el lote y su certificado aceptado permanecen iguales durante el rechazo y la recuperación; no se presenta como autenticación de ejecución general L2.

**Alcance:** requiere el lote y su intento previo todavía en memoria y una instancia L1 confiable seleccionada por la integración. No restaura procesos tras reiniciar, no emite transacciones ni acredita finalidad BFT. La recuperación preserva la decisión L2 anterior y no registra una raíz nueva; el modo optimista sigue provisional. Lean, manuscrito, primitivas y formatos firmados/AIR-FRI permanecen intactos; el resultado matemático sigue limitado al perfil escalar documentado.

## Recuperación de un registro inicial omitido — 20 de octubre de 2026

`recover_l1_submission(batch, &transaction, &l1)` atiende el caso en que L1 ya procesó el paquete, pero L2 no registró el primer envío. Exige una instantánea local conocida sin intentos anteriores; consulta la instancia L1 confiable, comprueba publicador, raíz, cantidad y datos del lote y aplica las mismas reglas de certificado y reserva única de hashes del registro inicial. Devuelve un `ConfirmedBatch` con el bloque y altura originales, aunque L1 haya avanzado. Conserva los bytes firmados y registra una sola observación confirmada, sin un envío pendiente intermedio ni una nueva firma.

`AnchorChain::validate_processed_batch_submission` consulta bloque canónico, registro de lote y reconstrucción DA bajo un único bloqueo de lectura. Además de comprobar su coherencia, compara la serialización completa del paquete recibido con la transacción almacenada: el hash actual no cubre remitente, clave pública ni esquema de firma. La inclusión histórica procede de un bloque que L1 validó al procesarlo; no se vuelve a someter su nonce consumido o su vencimiento al estado/reloj actuales. `validate_batch_submission`, `register_l1_submission` y `retry_l1_submission` conservan su admisión actual y siguen rechazando paquetes ya consumidos.

La recuperación no acepta candidatos preparados, bloques rechazados, registros del helper DA ni recibos aportados por el llamante. Todos los pasos que pueden rechazar la operación preceden al registro de raíces o confirmaciones. Un intento anterior, incluso por hash, conserva su historial: se confirma mediante `mark_batch_confirmed` y no se sobrescribe por esta API. Las llamadas de recuperación concurrentes solo registran una confirmación. Esta API conserva su alcance inicial; los reemplazos omitidos se atienden por la ruta separada `recover_l1_retry` descrita arriba.

La [evidencia de recuperación procesada](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/06-Evidencia-TG2/2026-10-20/Recuperacion-Procesada-L1/verificacion.json) registra ocho pruebas externas y dos internas. Cubren inclusión histórica con vencimiento pasado, ubicación original del bloque, envolturas distintas con igual hash, fuentes sin inclusión, payload/publicador distintos, identidad local, historiales previos, concurrencia, políticas de validez/híbrido y corrupción DA. El caso interno con certificado escalar válido comprueba que una inclusión ausente, una envoltura alterada o un certificado inválido no registran su raíz.

**Alcance:** la fuente L1 la selecciona la integración y es confiable; el historial y los lotes conocidos siguen en memoria. Esta recuperación no restaura el proceso tras reiniciar, no emite transacciones y no acredita finalidad BFT. El modo optimista conserva su carácter provisional; en validez/híbrido la inclusión no sustituye al certificado. El AIR escalar sigue sin autenticar los bytes DA como ejecución general L2. Se preservan las fuentes Lean, el manuscrito, las primitivas criptográficas y los formatos firmados/AIR-FRI; no se añade un teorema.

## Registro validado de transacciones firmadas — 20 de octubre de 2026

`register_l1_submission(batch, &transaction, &l1)` deriva el hash del paquete firmado recibido. Exige coincidencia con el publicador, raíz posterior, cantidad y bytes del lote local, y llama a `AnchorChain::validate_batch_submission` para comprobar firma, cadena, nonce, fecha, vencimiento, gas, saldo y envoltura completa bajo la política L1. Después registra el lote mediante las mismas reglas de certificado, unicidad y estado del registro anterior. La validación de L1 y la serialización ocurren antes de registrar raíces o intentos.

`retry_l1_submission(index, expected_hash, &transaction, &l1)` aplica la misma comprobación al reemplazo y conserva el control de hash vigente, las reservas históricas y el límite de tres reintentos. Un rechazo conserva contador, fechas, paquetes e historial. Ambas rutas usan los mismos pasos de contabilidad que las API por hash, con un único bloqueo del contexto local; evitan adquirir otra vez ese bloqueo dentro del registro.

`SubmissionAttempt::transaction_bytes` contiene los bytes `bincode` exactos de la transacción firmada validada. `get_l1_submission_transaction(index, hash)` permite recuperarla sin generar otra firma y conserva su identidad antes y después de confirmar. Los bytes devueltos son una copia del registro. Los intentos creados mediante `mark_batch_submitted` o `retry_batch_submission` mantienen `None`: esas API solo registran intenciones por hash y no acreditan la validez del paquete L1. Es posible pasar de un intento por hash a un reintento validado sin perder esa distinción.

La [evidencia de registro validado](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/06-Evidencia-TG2/2026-10-20/Registro-Firmado-L1/verificacion.json) registra ocho pruebas externas y una interna: recuperación exacta de paquetes, datos/remitente distintos con firmas válidas, envolturas y políticas inválidas, campos no incluidos en el hash alterados, reintentos, límite, intenciones por hash y concurrencia. El caso interno usa un certificado escalar sintético válido y comprueba que un rechazo de admisión L1 no registra su raíz; no se presenta como prueba de ejecución general L2.

**Alcance:** es un registro previo al procesamiento contra la admisión actual de la instancia L1 confiable. No reserva el nonce ni garantiza que el estado posterior sea compatible; un paquete cuyo nonce ya fue consumido se rechaza por esta ruta. Guardar los bytes no realiza un envío de red ni acredita entrega, inclusión o finalidad BFT. El historial sigue en memoria. El formato firmado y el certificado AIR/FRI no cambian, y el perfil escalar no autentica los bytes DA como ejecución general. Lean, tesis y primitivas criptográficas quedan preservados.

## Preparación de transacciones L1 — 20 de octubre de 2026

`ActiveChain::prepare_l1_submission(&batch, &l1, &publisher, options)` devuelve una transacción firmada `BatchSubmit` a partir de un lote conocido. Comprueba los campos de la instantánea local, la identidad del secuenciador y que el lote no esté confirmado. En validez/híbrido exige el certificado del perfil escalar con contexto local; usa un verificador temporal y conserva las raíces y pruebas pendientes del verificador de la cadena. El modo optimista mantiene su admisión provisional. La preparación no registra el envío ni consume la cola de trabajo.

`L1SubmissionOptions` permite fijar gas, precio y vencimiento; por defecto usa 21 000, cero y ausencia de vencimiento. `AnchorChain::prepare_batch_submission` toma de una instantánea L1 la cadena configurada, el nonce del publicador y una fecha igual al máximo entre el reloj y la fecha del padre. Firma con la clave prestada por el llamante, comprueba costo representable y reutiliza validación y ejecución sobre una copia. Exige firma, gas, saldo, nonce, vencimiento y límites DA; contrasta el tamaño del candidato L1 completo con la transacción firmada. Un lote que cabe en el límite L2 puede exceder ese tamaño al añadir su envoltura L1 y se rechaza sin registrar efectos.

El flujo local se puede expresar así:

```rust,ignore
let tx = active.prepare_l1_submission(&batch, &l1, &publisher, L1SubmissionOptions::default())?;
active.register_l1_submission(batch.clone(), &tx, &l1)?;
let block = l1.prepare_block(vec![tx], proposer)?;
l1.process_block(block).await?;
let confirmation = active.mark_batch_confirmed(batch.index, &l1)?;
```

Preparar conserva el nonce real, cuentas, DA, alturas, bloques, raíces verificadas e historial de intentos. Si otra transacción consume el nonce antes del procesamiento, L1 rechaza la preparación antigua y se puede construir otra para el reintento explícito. Se comprueba admisión individual en una envoltura L1 mínima; la recompensa del proponente, otras transacciones o metadatos añadidos al bloque pueden introducir nuevos rechazos. El método no reagrupa lotes ni ajusta el límite L2 automáticamente.

La [evidencia del preparador](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/06-Evidencia-TG2/2026-10-20/Preparacion-L1/verificacion.json) registra ocho pruebas externas y una interna: flujo firmado hasta confirmación, dominios L1/L2 distintos, nonce y fecha derivados, rechazo de contexto/firmante, certificados inválidos, gas/costo/vencimiento/saldo, envoltura demasiado grande, preparación obsoleta y recompensa desbordada. El caso interno verifica que un certificado escalar sintético válido no registra una raíz por el mero hecho de preparar la transacción.

**Alcance:** la instancia L1 y la clave publicadora proceden de la integración confiable; el método construye una transacción y la integración decide su emisión. No reserva nonces, no garantiza que el estado futuro mantenga su admisibilidad y no acredita finalidad BFT. La transacción L1 conserva el formato actual de raíz, cantidad y bytes; no transporta una prueba de ejecución general L2. El chequeo escalar permanece en L2 y no autentica esos bytes dentro del AIR. Se conservan fuentes Lean y de tesis, certificados, formatos firmados y núcleo/lector AIR-FRI, sin extender el resultado matemático.

## Recuperación de envíos pendientes — 20 de octubre de 2026

El primer hash registrado dejaba bloqueado un lote si el envío no aparecía en L1: repetir `mark_batch_submitted` se rechazaba por duplicado y la confirmación seguía pendiente. Se conserva un escenario de referencia de esa limitación y se añade `retry_batch_submission(index, expected_hash, next_hash)`. Esta API registra una nueva intención sobre el mismo lote ya admitido, sin volver a ejecutar transacciones ni sustituir su certificado o contexto local.

`expected_hash` debe coincidir con el intento vigente. El siguiente hash debe ser no vacío y no haber sido reservado por ningún lote de la instancia, incluyendo intentos anteriores y lotes confirmados. El gestor permite el envío inicial y tres reintentos; rechaza un cuarto, los cambios desactualizados, los lotes sin envío y los ya confirmados. Todo rechazo conserva el contador, las fechas, el historial y las reservas existentes. El bloqueo del contexto local serializa el reintento con otros reintentos y con la confirmación.

`get_batch_submission(index)` devuelve el lote pendiente con su hash actual, contador e historial de `SubmissionAttempt`. Tras la confirmación, el historial queda en `ConfirmedBatch::attempts`, consultable por `get_batch_confirmation`. La confirmación recorre los intentos en orden de registro y usa la primera inclusión encontrada que coincide con el publicador y el lote. Esto admite un intento original incluido después de registrar un reemplazo; también permite saltar una transacción procesada cuyos campos no coincidan. `AnchorChain::find_processed_batch_inclusion` distingue ausencia (`Ok(None)`) de un error de integridad local, que se propaga.

La [evidencia de recuperación](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/06-Evidencia-TG2/2026-10-20/Reintentos-L1/verificacion.json) incluye ocho pruebas externas y una interna: recuperación desde un hash erróneo, reservas históricas, cambios desactualizados, límite, inclusión tardía, varias inclusiones, campos incorrectos y carreras de reintento/confirmación. El caso interno usa un certificado escalar sintético válido para comprobar que permanecen idénticos el lote certificado y su contexto, sin presentarlo como prueba de ejecución general L2.

**Alcance:** se registran intenciones locales; la integración sigue emitiendo las transacciones y seleccionando la instancia L1 confiable. Registrar un reemplazo no demuestra que un intento anterior haya sido cancelado ni evita varias inclusiones en L1. La garantía es una sola confirmación local del lote, con trazabilidad de sus intentos. No hay temporizadores, recuperación durable ni unicidad entre instancias o reinicios. Se preservan las fuentes Lean y de tesis, los formatos firmados y el núcleo/lector AIR-FRI; no se amplía el alcance matemático ni se acredita finalidad BFT o validez L2 general.

## Confirmación local de inclusión L1 — 20 de octubre de 2026

`mark_batch_submitted(batch, l1_hash)` registra la intención de envío después de verificar el contrato local del lote. Rechaza el hash vacío y la asignación del mismo hash a otro lote, incluso después de confirmar el primero, dentro de esta instancia en memoria. La integración conserva la responsabilidad de emitir la transacción firmada.

`mark_batch_confirmed(index, &l1)` sustituye la API anterior por índice y devuelve `Result<ConfirmedBatch, NexusError>`. Consulta directamente una instancia `AnchorChain` confiable aportada por la integración; no acepta un recibo externo como autoridad. Exige el hash de envío registrado, un `BatchSubmit` en un bloque procesado canónico, el remitente igual a la dirección del secuenciador y coincidencia exacta de raíz posterior, número de transacciones y bytes del lote. La identidad publicadora de este perfil es la del secuenciador; no hay delegación de publicación configurada.

`AnchorChain::get_processed_batch_inclusion` lee bloque, registro y datos DA bajo una única instantánea local. `L2BatchRecord::l1_tx_hash` solo se establece mediante la ejecución de una transacción firmada; el helper local de registro conserva `None`. Preparar un bloque o registrar sus bytes en el helper no permite confirmar el envío. Un bloque rechazado tampoco publica ese origen. La confirmación guarda el lote, el hash de transacción, el hash de bloque y la altura L1, consultables mediante `get_batch_confirmation`. La transición pendiente→confirmado ocurre una vez, también bajo llamadas concurrentes.

`nexus-active` añade una dependencia local de `nexus-anchor`, sin nuevas bibliotecas externas ni cambios de versiones resueltas. El método auxiliar de contabilidad `BatchSubmitter::mark_confirmed` pasa a ser interno del crate. Se reproducen dos fallos anteriores y se añaden ocho pruebas: hash inventado, hash compartido, hash vacío, recorrido completo con rechazo y reintento, campos o remitente distintos, helper local, tipo de transacción equivocado y confirmación concurrente. La [evidencia de confirmación local](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/06-Evidencia-TG2/2026-10-20/Confirmacion-L1/verificacion.json) registra las comprobaciones; la prueba optimista anterior se adapta para exigir el rechazo de un envío ficticio.

**Límite de confianza:** el llamante debe seleccionar la instancia L1 autorizada. La consulta observa procesamiento local, no verifica finalidad BFT ni una prueba remota de inclusión. El formato actual `BatchSubmit` transporta raíz posterior, cantidad y bytes; el índice, rango L2 y preestado se mantienen en el contexto local, sin un compromiso nuevo de esos campos en L1. La unicidad del hash es local y no persiste entre reinicios ni impide reutilización entre otras instancias. Confirmar inclusión no promueve raíces optimistas a verificadas. Se conservan las fuentes Lean, el teorema de intersección con peso estricto >2/3, el AIR escalar, sus certificados y los límites de la tesis; no se deduce de esta conexión una prueba de validez L2 ni finalidad de consenso.

## Almacenamiento local DA — 20 de octubre de 2026

Se corrigen tres regresiones del registro de datos: los envíos a una misma altura sobrescribían fragmentos, se admitían datos vacíos que podían provocar módulo por cero al muestrear y las pruebas de fragmentos no correspondían al compromiso guardado. El perfil local conserva bytes opacos de entre 1 y `MAX_DA_DATA_SIZE` (1 MiB), divididos en fragmentos de 256 bytes; el último conserva su longitud exacta. No duplica fragmentos ni simula paridad. `coding_params = (chunk_count, chunk_count)` indica que se necesitan todos los originales.

`DACommitment::from_data(data)` devuelve `Result` y construye un recibo local con `encoding_version = 1`. `commitment` conserva SHA3 de los bytes completos; `chunk_root` es otra raíz, construida con las hojas ordenadas `SHA3("NEXUS/LOCAL-DA/CHUNK/V1" || hash_contenido || tamaño_u64_LE || cantidad_u32_LE || índice_u32_LE || bytes_fragmento)`. El árbol reutiliza la construcción Merkle de `nexus-core`, incluida su extensión a potencia de dos repitiendo la última hoja. La prueba exige metadatos válidos, índice dentro del número original de hojas, longitud exacta y profundidad canónica, y vincula también el hash del contenido. Los recibos anteriores sin versión no son un formato admitido; no cambia el formato de transacciones firmadas ni el certificado AIR/FRI.

Los fragmentos se guardan por `(altura, índice_local_de_lote, índice_de_fragmento)`. `reconstruct_batch` y `generate_batch_proof` reciben ese índice local; las API anteriores `reconstruct_data` y `generate_proof` solo aceptan alturas con un único lote y rechazan la ambigüedad. La reconstrucción contrasta bytes, metadatos, hash y raíz. El nombre heredado `sample` comprueba determinísticamente la integridad de todos los lotes locales de esa altura: no consulta pares ni acredita disponibilidad de red.

`L2BatchRecord::da_batch_index` conserva la posición local, independiente del índice global del lote. `AnchorChain::get_l2_batch_data` recupera los bytes y vuelve a comprobar su hash. Las dos vías de registro —transacción L1 y helper local— usan ese selector; los efectos siguen sujetos al rechazo atómico del bloque. El hash retornado por el helper sigue siendo SHA3 de los bytes completos.

La [evidencia del almacenamiento DA local](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/06-Evidencia-TG2/2026-10-20/DA-Local/verificacion.json) conserva tres reproducciones previas y trece pruebas nuevas: nueve externas de fragmentos, dos de integración L1 y dos internas de corrupción, además de reforzar la prueba anterior que generaba una ruta sin verificarla. Un oráculo independiente de dos hojas comprueba la raíz y el orden de hermanos.

**Límite:** el recibo debe proceder de un contexto confiable; una raíz aportada por quien envía la prueba no se convierte por ello en un compromiso de consenso. Este perfil no prueba inclusión del recibo en L1, disponibilidad remota, Reed–Solomon, recuperación con fragmentos perdidos ni ejecución válida L2. La raíz de cuentas L1 sigue sin comprometer integralmente estas estructuras auxiliares. El formato de hojas DA es independiente del AIR escalar y de su modelo Lean; no se añade un teorema ni se amplía el resultado matemático. Se conservan las fuentes de la tesis y el núcleo/lector AIR-FRI.

## Dominio local de transacciones L2 — 20 de octubre de 2026

`SequencerConfig::chain_id` fija el identificador firmado esperado (por defecto `ChainId::LOCAL`). El secuenciador rechaza otro identificador antes de reservar el nonce o añadirlo al pool. `ActiveChain` construye su motor con esa misma configuración, sin una segunda política que pueda divergir. El motor también comprueba el dominio en la ejecución directa; `execute_batch` convierte ese rechazo en un resultado fallido sin cambios de estado, consumo de gas ni avance del nonce para esa entrada. Las entradas válidas del lote continúan bajo las reglas existentes.

`ExecutionEngine::new()` y `with_state(state)` conservan `LOCAL`. Para otro identificador se usan `for_chain(chain_id)` o `with_state_for_chain(state, chain_id)`. El identificador es política confiable del llamante: la raíz SHA3 de cuentas no lo codifica ni permite recuperarlo. Cambiar la etiqueta de una transacción firmada no sustituye su firma. La configuración deserializada por campos que omite `chain_id` usa el valor por defecto; no se promete compatibilidad binaria con configuraciones serializadas anteriores.

Siete pruebas externas y una de producción integrada cubren rechazo en las tres entradas públicas, reserva de nonce, firma alterada, restauración con dominio explícito, lotes mixtos y operaciones de contrato de otra cadena. La prueba integrada configura `TESTNET`, ejecuta una transferencia con saldo de prueba, contrasta raíz y balances, comprueba el avance de nonce y el contexto del lote. Tres regresiones se reprodujeron antes de la corrección. La [evidencia de dominio L2](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/06-Evidencia-TG2/2026-10-20/Politicas-L2/verificacion.json) registra el corte y las comprobaciones.

Esta política no modifica los bytes firmados, las cabeceras, el génesis, los votos ni el certificado AIR/FRI. Si L1 y L2 comparten identificador, esta comprobación no las separa por capa. Se conserva el alcance escalar Lean y no se acredita aislamiento completo entre redes, un nuevo teorema ni una prueba de ejecución general L2. El presupuesto de gas de L2 conserva su política previa, distinta de la reserva agregada de L1.

## Contrato local de estado L1 — 20 de octubre de 2026

### Políticas locales de dominio y gas

`AnchorChainConfig::chain_id` fija el identificador esperado de las transacciones firmadas (por defecto `ChainId::LOCAL`). Firmar un identificador no basta: tanto `prepare_block` como `process_block` lo comparan con esta política. Cambiarlo exige una firma nueva. La corrección L1 no añade un dominio de red al génesis, a las cabeceras o a los votos; la extensión posterior a las transacciones L2 se describe arriba. No se presenta como aislamiento completo entre redes.

`AnchorChainConfig::block_gas_limit` limita la suma de los `gas_limit` declarados, con 30 000 000 por defecto. Se resta cada reserva de un presupuesto restante después de comprobar que cabe; así se rechaza también una suma no representable en `u64`. La igualdad con el presupuesto es válida y un límite cero permite bloques vacíos. Se reserva el gas declarado, aunque el gas intrínseco sea menor o su precio sea cero. No se cobran comisiones y las réplicas deben compartir la misma política local.

Las ocho pruebas de `nexus-anchor/tests/block_policy.rs` cubren firmas válidas de otra cadena, cambios de etiqueta sin volver a firmar, recepción de bloques con raíz correcta pero política incompatible, rechazo sin efectos y reintento, presupuesto exacto, cero y `u64::MAX`. Dos regresiones se reprodujeron antes de corregir el procesador. La [evidencia de políticas L1](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/06-Evidencia-TG2/2026-10-20/Politicas-L1/verificacion.json) registra las comprobaciones de este corte; la evidencia de 264 pruebas enlazada más abajo corresponde al corte anterior.

### Ejecución y raíz de cuentas

`AnchorChain::process_block` vuelve a ejecutar el bloque sobre una copia del estado local y compara la raíz calculada con `header.state_root` antes de publicar cualquier efecto. Una diferencia devuelve `InvalidStateRoot` y conserva cuentas, nonces, validadores, DA, lotes, altura, almacenamiento de bloques y finalidad. No se acepta una raíz vacía como sustituto de la calculada.

`prepare_block(transactions, proposer)` permite construir un candidato honesto desde el padre y la política locales. Calcula la raíz sin guardar el bloque ni aplicar sus efectos; al recibirlo, `process_block` ejecuta de nuevo la validación. Preparar un candidato no firma un certificado de consenso ni autoriza un envío L2.

El perfil conserva las siguientes reglas de ejecución:

- Cada transacción debe tener firma ML-DSA válida, nonce igual al de su cuenta, gas suficiente y saldo que cubra `gas_limit * gas_price + valor` (o el depósito para un alta de validador), con aritmética comprobada. En este perfil el gas es una reserva de admisión: no se debita una comisión y `fee_percentage` continúa como metadato reservado.
- Se aplican las transferencias en orden, manteniendo el saldo en las autotransferencias; las altas descuentan el depósito y registran su clave autorizada; los envíos de lotes actualizan el registro y la DA locales. Cada operación aceptada incrementa exactamente una vez el nonce del remitente. Los tipos L1 no implementados se rechazan.
- La recompensa fija del proponente se acredita después de todas las transacciones y antes de calcular la raíz. Para un bloque de solo transferencias, la suma de saldos aumenta únicamente en esa recompensa. Si cualquier operación o la recompensa desborda, se rechaza todo el bloque.
- La raíz conserva el formato de `InMemoryState`: SHA3-256 de las cuentas ordenadas por dirección y su codificación `bincode`; el conjunto vacío usa la raíz vacía canónica. Esta raíz de cuentas no se presenta como un compromiso integral del registro de validadores, la DA o el almacenamiento de contratos.
- Los vencimientos se comprueban con la fecha de la cabecera: una transacción creada después de esa fecha o vencida antes de ella se rechaza. La fecha del bloque no puede retroceder respecto del padre. El constructor usa el reloj para proponer una fecha; la verificación de la transición usa el contexto explícito del bloque.
- Se exigen versión, capa, padre y raíz de transacciones coherentes. El perfil aún no implementa recibos L1 y solo admite `receipts_root = ZERO`, sin certificar recibos ficticios.

`nexus-anchor/tests/state_root_contract.rs` contrasta las raíces con balances y nonces calculados por un oráculo de prueba independiente del constructor. Cubre bloques honestos, recompensas, autotransferencias, replay histórico, políticas locales distintas y rechazo de raíces alteradas con efectos auxiliares válidos preparados. Se conservan las nueve regresiones de este contrato junto con las correcciones anteriores.

Esta validación de una raíz SHA3 de cuentas no aplica a ella la relación escalar AIR/FRI de la sección 6.7.9 ni el teorema de intersección de quórums. Las fuentes Lean y el formato del certificado vinculado se conservan; el refinamiento universal y una L1/L2 operativa completa mantienen sus límites.

[Evidencia y consolidación del contrato L1](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/06-Evidencia-TG2/2026-10-20/Estado-L1/verificacion.json): pasan 264 pruebas globales, check/build del workspace y catorce casos dirigidos en release. El manifiesto documental identifica el commit local y conserva el corte anterior.

## Integración de ActiveChain — 20 de octubre de 2026

### Correcciones de autenticidad, estado y quórum — revisión posterior

La revisión Rust posterior a `637e77c` corrige el rechazo explícito de firmas falsas en L1, el registro único de bloques y la publicación atómica del estado, registro de validadores, disponibilidad local y lotes. La altura del procesador L1 representa el último bloque procesado. Este procesamiento local se distingue de un certificado de consenso y no demuestra la implementación operativa completa descrita como trabajo futuro en la tesis.

La política de votos sigue `Nexus.Modelos.Quorum.quorum_estricto_interseca_honestos`, en `formalizacion/Nexus/Modelos/QuorumIncentivos.lean`, y las secciones 3.9–3.10 del manuscrito: peso estrictamente mayor que dos tercios del conjunto confiable. Se autentican claves, firmas, fase, altura, ronda y objetivo; cada identidad contribuye una sola vez. Se usan sumas enteras comprobadas y el umbral `W - floor((W-1)/3)` para `W>0`, sin cocientes flotantes. El campo heredado `bft_threshold` admite los valores de compatibilidad 0.667 o 2/3; cualquier otra política se rechaza. Esto aplica el requisito de quórum, sin demostrar por sí solo seguridad y vivacidad BFT ni las reglas completas de bloqueo y comunicación.

El gadget de finalidad requiere una instantánea de validadores suministrada por el llamante confiable y fijada al añadir cada bloque. Comprueba firmas, peso y ascendencia hasta el ancla. `FinalityVote.weight`, `FinalityJustification.total_weight` y `threshold` usan `u128` en unidades mínimas; el total aportado al verificar debe coincidir con la instantánea. `vote_signing_bytes` y `finality_signing_bytes` separan sus dominios. Las propuestas de consenso incluyen la firma del proponente sobre la cabecera. Estos formatos de aplicación se distinguen del certificado AIR/FRI conservado.

El secuenciador autentica antes de reservar nonces, rechaza transacciones que no caben en un lote vacío y prioriza por gas solo entre las cabezas ejecutables de cada remitente. Construir un lote reserva trabajo; únicamente los resultados de ejecución local en `ActiveChain` avanzan el nonce confirmado. Los fallos liberan el nonce y conservan las dependencias futuras pendientes. Un rechazo por saldo o gas no crea cuentas ni altera la raíz. Los costos y nonces agotados se rechazan con aritmética comprobada; `max_cost` conserva una estimación saturada para compatibilidad y `checked_max_cost` se usa en validación.

El verificador de fraude optimista aún carece de preestado autenticado, inclusión y reejecución vinculados. Por ello devuelve rechazo ante trazas aportadas y `finalize_proof` devuelve `NotImplemented` al agotarse el plazo: no se promueve una raíz optimista a verificada. La aceptación provisional y la confirmación local de un envío permanecen separadas. No se presenta esa carencia como una prueba de fraude implementada.

Las fuentes Lean, los capítulos de la tesis, el núcleo AIR/FRI, su lector, los perfiles 12/20, las cuarenta consultas y el corte 512 se conservan. Las nuevas pruebas en `nexus-core/tests/state_safety.rs`, `nexus-active/tests/execution_safety.rs` y `nexus-anchor/tests/` cubren los contraejemplos, ejecuciones válidas y fronteras del quórum. No se deduce de ellas refinamiento universal Rust/Lean, validez de raíces SHA3 dentro del AIR escalar ni cierre de los pendientes matemáticos externos.

[Evidencia de las correcciones y sus límites](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/06-Evidencia-TG2/2026-10-20/Correcciones-Rust/verification.json): 255 pruebas globales, check de todos los targets y cuatro regresiones numéricas en release. Las fuentes protegidas se cotejan por SHA-256, sin recompilar Lean ni regenerar el manuscrito.

`ActiveChain` obtiene el contexto de una instantánea privada del lote construido localmente, no del sobre recibido. `ActiveChainConfig::validity_profile` fija filas y trabajo mediante `LinkedValidityProfile`; no se leen como política del certificado. Solo se puede añadir la prueba al lote: cambiar índice, rango, raíces, transacciones, cantidad, fecha o firma respecto de la instantánea causa rechazo.

`create_state_proof(&batch)` devuelve ahora `Result<StateProof, NexusError>` y completa las entradas públicas. En validez/híbrido exige prueba presente y de tamaño acotado. `verify_state_proof(&batch, &proof)` llama a `verify_expected` con contexto local; `mark_batch_submitted(batch, l1_hash)` devuelve `Result` y verifica antes de registrar el envío. El modo optimista mantiene aceptación provisional separada, sin acreditar el contrato Lean ni finalizar raíces al marcar confirmación L1. `get_next_batch` entrega trabajo al probador, no una autorización; `get_known_batch(index)` permite recuperar el lote después de un rechazo. El registro local impide envíos repetidos del mismo índice, incluso concurrentes; no es persistencia ni antirrepetición de consenso entre reinicios.

Se captura la raíz inicial antes de ejecutar. Los bloques se incorporan completos o no se incorporan al lote; la rotación ocurre entre bloques y conserva la frontera de estado. Los límites del lote en `ActiveChain` usan los de su secuenciador y cuentan el prefijo de longitud serializado. Los bloques vacíos conservan la raíz y pueden cerrar un lote pendiente. Se serializa la producción para no reutilizar alturas en llamadas concurrentes.

**Límite operativo:** el motor de transacciones usa raíces SHA3 generales y el AIR sigue siendo una recurrencia escalar. No se recortan hashes, no se genera una prueba de recurrencia para presentarla como prueba de transacciones y no se habilita fallback. Un lote con raíces fuera del modelo no puede registrarse como enviado en validez/híbrido; ampliar el AIR para validarlo no forma parte de esta integración. Los casos positivos de cableado usan instantáneas escalares sintéticas solo en pruebas internas. Esta conexión no convierte el PoC en una L2 completa.

La evidencia de esta integración se conserva en `Documentos/06-Evidencia-TG2/2026-10-20/ActiveChain/`. `integracion.json` conserva la instantánea previa al commit; `consolidacion.json` identifica el commit posterior y enlaza el check/build y las 55 pruebas aisladas (trece nuevas), sin repetirlos para consolidar. El commit `3e40e28` y su manifiesto quedan como antecedentes de la adaptación anterior; el manifiesto documental vigente identifica el commit de integración. Permanecen los límites operativos descritos arriba.

## Adaptación al contrato Lean — 20 de octubre de 2026

La ruta de validez usa ahora `nexus-zk/src/stark/linked.rs` y `linked_codec.rs`: doble FRI vinculada, lector LE canónico con EOF estricto, 16–4096 filas, cuarenta consultas y corte de 512 extracciones del selector, incluidos duplicados. El perfil de trabajo esperado (12 o 20 bits) se entrega externamente; no se rebaja según el certificado. Se mantiene el formato del corpus histórico `(TransitionStatement, LinkedProof)`.

En `nexus-active`, usar `LinkedValidityProof` para el PoC y `NitroVerifier::verify_expected(&proof, &expected)` para verificar con un `ExpectedTransition` obtenido del estado confiable del llamante. La entrada antigua `verify(&proof)` rechaza validez e híbrido: ya no acepta por formato ni por tamaño. El modo optimista permanece separado y sus pruebas pendientes no se registran como raíces verificadas antes de finalizar. Un rechazo del contrato no registra una raíz, y una altura ya registrada no se sobrescribe por otra raíz.

Este perfil admite únicamente escalares canónicos de Goldilocks codificados en 32 bytes con los últimos 24 a cero. **No** demuestra validez de raíces SHA3 arbitrarias, firmas ML-DSA dentro del AIR ni ejecución completa de `ActiveChain`. La altura es contexto externo, no parte del enunciado AIR. La integración del llamante con políticas de autorización y antirrepetición es distinta del contrato matemático. `pq_verifier` y los experimentos anteriores se conservan como referencias históricas y no habilitan la aceptación de la ruta nueva. La equivalencia universal de Rust con Lean sigue sin estar demostrada.

Antes de editar Rust pasaron check/test/build globales (197 pruebas) y la compilación/auditoría globales de Lean (2709 declaraciones). Después de la adaptación pasan check/test/build **aislados** de `nexus-zk` y `nexus-active`, con 113 pruebas, incluidas trece nuevas. No se repite el workspace global después de editar. Los catorce certificados históricos de ambos perfiles conservan sus bytes y resultados. La evidencia está en `Documentos/06-Evidencia-TG2/2026-10-20/Rust-Lean/`; las dependencias no cambian. `adaptacion.json` y `revision-final.json` conservan las instantáneas anteriores al commit; `consolidacion.json` vincula el commit posterior con esas comprobaciones, sin presentarlas como pruebas nuevas. El manifiesto del 19 se conserva como antecedente y la identificación vigente se consulta en el manifiesto documental actualizado.

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

La [edición unificada](https://github.com/JuanDiegoSusunaga/tesis-nexus) contiene documentos, matemáticas y este workspace en un solo clon. Desde su raíz, `python scripts/verificar_version_tg2.py` comprueba los archivos integrados mediante el manifiesto de esquema 2. El commit que contiene el manifiesto identifica el conjunto; el commit Rust de origen conserva la procedencia de la importación. Los enlaces a la evidencia también funcionan al consultar este repositorio Rust por separado.

La evidencia de cada experimento conserva las fuentes utilizadas en ese momento y sus hashes. Las etapas históricas pueden usar código distinto al actual. Las instrucciones de repetición y las limitaciones están en los informes y en `scripts/README.md` del repositorio documental.
