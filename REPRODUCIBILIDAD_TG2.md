# Reproducibilidad de la edición TG2

**Organización:** 23 de septiembre de 2026. Este repositorio contiene el prototipo Rust y las variantes experimentales de TG2. Los documentos se mantienen en `https://github.com/JuanDiegoSusunaga/tesis-nexus`.

## Recuperación de un reintento omitido — 20 de octubre de 2026

`recover_l1_retry(index, expected_hash, &transaction, &l1)` recupera el registro de un reemplazo que la instancia L1 confiable ya procesó. Exige que el lote tenga un envío pendiente cuyo hash vigente sea `expected_hash`, que el nuevo hash no esté reservado por ningún intento presente o histórico, y que quede capacidad dentro del límite común de tres reintentos. Compara publicador, raíz, cantidad y datos con el lote conocido y reutiliza la comprobación de envoltura completa e inclusión canónica de `validate_processed_batch_submission`. El nonce consumido y el vencimiento actual no invalidan esa inclusión histórica. `retry_l1_submission` conserva su admisión actual previa al procesamiento.

La operación conserva íntegros el lote, el certificado aceptado y los intentos anteriores, incluidos sus bytes y fechas. Añade un intento con los bytes firmados exactos y devuelve un `ConfirmedBatch` con la ubicación original del reemplazo; la fecha del intento corresponde al registro local de la recuperación. El control del hash vigente, las reservas, el límite y el estado pendiente se comprueban antes de modificar el historial. El registro y la confirmación ocurren bajo el mismo bloqueo, sin publicar un reemplazo pendiente intermedio. Las llamadas concurrentes de recuperación o reintento normal solo permiten una transición desde el hash esperado.

La confirmación identifica explícitamente el paquete recuperado, aunque otro intento también esté incluido. `mark_batch_confirmed` conserva su selección del primer intento registrado cuya inclusión coincida. Un paquete ya registrado se confirma por esa API: la recuperación no duplica su hash ni rellena retroactivamente los bytes de una intención por hash. Un lote confirmado, un hash obsoleto, un hash reservado incluso por un lote confirmado o un cuarto reintento se rechazan sin cambios. El límite también se aplica si L1 ya procesó ese cuarto paquete; esta API no lo adopta.

La [evidencia de recuperación de reintentos](../Documentos/06-Evidencia-TG2/2026-10-20/Recuperacion-Reintentos-L1/verificacion.json) conserva ocho pruebas externas y una interna. Cubren paquetes exactos y alterados, vencimiento histórico, fuentes sin inclusión, lote/publicador distintos, hashes obsoletos o reservados, ausencias, límite, múltiples inclusiones y concurrencia. El ensayo interno con certificado escalar válido comprueba que el lote y su certificado aceptado permanecen iguales durante el rechazo y la recuperación; no se presenta como autenticación de ejecución general L2.

**Alcance:** requiere el lote y su intento previo todavía en memoria y una instancia L1 confiable seleccionada por la integración. No restaura procesos tras reiniciar, no emite transacciones ni acredita finalidad BFT. La recuperación preserva la decisión L2 anterior y no registra una raíz nueva; el modo optimista sigue provisional. Lean, manuscrito, primitivas y formatos firmados/AIR-FRI permanecen intactos; el resultado matemático sigue limitado al perfil escalar documentado.

## Recuperación de un registro inicial omitido — 20 de octubre de 2026

`recover_l1_submission(batch, &transaction, &l1)` atiende el caso en que L1 ya procesó el paquete, pero L2 no registró el primer envío. Exige una instantánea local conocida sin intentos anteriores; consulta la instancia L1 confiable, comprueba publicador, raíz, cantidad y datos del lote y aplica las mismas reglas de certificado y reserva única de hashes del registro inicial. Devuelve un `ConfirmedBatch` con el bloque y altura originales, aunque L1 haya avanzado. Conserva los bytes firmados y registra una sola observación confirmada, sin un envío pendiente intermedio ni una nueva firma.

`AnchorChain::validate_processed_batch_submission` consulta bloque canónico, registro de lote y reconstrucción DA bajo un único bloqueo de lectura. Además de comprobar su coherencia, compara la serialización completa del paquete recibido con la transacción almacenada: el hash actual no cubre remitente, clave pública ni esquema de firma. La inclusión histórica procede de un bloque que L1 validó al procesarlo; no se vuelve a someter su nonce consumido o su vencimiento al estado/reloj actuales. `validate_batch_submission`, `register_l1_submission` y `retry_l1_submission` conservan su admisión actual y siguen rechazando paquetes ya consumidos.

La recuperación no acepta candidatos preparados, bloques rechazados, registros del helper DA ni recibos aportados por el llamante. Todos los pasos que pueden rechazar la operación preceden al registro de raíces o confirmaciones. Un intento anterior, incluso por hash, conserva su historial: se confirma mediante `mark_batch_confirmed` y no se sobrescribe por esta API. Las llamadas de recuperación concurrentes solo registran una confirmación. Esta API conserva su alcance inicial; los reemplazos omitidos se atienden por la ruta separada `recover_l1_retry` descrita arriba.

La [evidencia de recuperación procesada](../Documentos/06-Evidencia-TG2/2026-10-20/Recuperacion-Procesada-L1/verificacion.json) registra ocho pruebas externas y dos internas. Cubren inclusión histórica con vencimiento pasado, ubicación original del bloque, envolturas distintas con igual hash, fuentes sin inclusión, payload/publicador distintos, identidad local, historiales previos, concurrencia, políticas de validez/híbrido y corrupción DA. El caso interno con certificado escalar válido comprueba que una inclusión ausente, una envoltura alterada o un certificado inválido no registran su raíz.

**Alcance:** la fuente L1 la selecciona la integración y es confiable; el historial y los lotes conocidos siguen en memoria. Esta recuperación no restaura el proceso tras reiniciar, no emite transacciones y no acredita finalidad BFT. El modo optimista conserva su carácter provisional; en validez/híbrido la inclusión no sustituye al certificado. El AIR escalar sigue sin autenticar los bytes DA como ejecución general L2. Se preservan las fuentes Lean, el manuscrito, las primitivas criptográficas y los formatos firmados/AIR-FRI; no se añade un teorema.

## Registro validado de transacciones firmadas — 20 de octubre de 2026

`register_l1_submission(batch, &transaction, &l1)` deriva el hash del paquete firmado recibido. Exige coincidencia con el publicador, raíz posterior, cantidad y bytes del lote local, y llama a `AnchorChain::validate_batch_submission` para comprobar firma, cadena, nonce, fecha, vencimiento, gas, saldo y envoltura completa bajo la política L1. Después registra el lote mediante las mismas reglas de certificado, unicidad y estado del registro anterior. La validación de L1 y la serialización ocurren antes de registrar raíces o intentos.

`retry_l1_submission(index, expected_hash, &transaction, &l1)` aplica la misma comprobación al reemplazo y conserva el control de hash vigente, las reservas históricas y el límite de tres reintentos. Un rechazo conserva contador, fechas, paquetes e historial. Ambas rutas usan los mismos pasos de contabilidad que las API por hash, con un único bloqueo del contexto local; evitan adquirir otra vez ese bloqueo dentro del registro.

`SubmissionAttempt::transaction_bytes` contiene los bytes `bincode` exactos de la transacción firmada validada. `get_l1_submission_transaction(index, hash)` permite recuperarla sin generar otra firma y conserva su identidad antes y después de confirmar. Los bytes devueltos son una copia del registro. Los intentos creados mediante `mark_batch_submitted` o `retry_batch_submission` mantienen `None`: esas API solo registran intenciones por hash y no acreditan la validez del paquete L1. Es posible pasar de un intento por hash a un reintento validado sin perder esa distinción.

La [evidencia de registro validado](../Documentos/06-Evidencia-TG2/2026-10-20/Registro-Firmado-L1/verificacion.json) registra ocho pruebas externas y una interna: recuperación exacta de paquetes, datos/remitente distintos con firmas válidas, envolturas y políticas inválidas, campos no incluidos en el hash alterados, reintentos, límite, intenciones por hash y concurrencia. El caso interno usa un certificado escalar sintético válido y comprueba que un rechazo de admisión L1 no registra su raíz; no se presenta como prueba de ejecución general L2.

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

La [evidencia del preparador](../Documentos/06-Evidencia-TG2/2026-10-20/Preparacion-L1/verificacion.json) registra ocho pruebas externas y una interna: flujo firmado hasta confirmación, dominios L1/L2 distintos, nonce y fecha derivados, rechazo de contexto/firmante, certificados inválidos, gas/costo/vencimiento/saldo, envoltura demasiado grande, preparación obsoleta y recompensa desbordada. El caso interno verifica que un certificado escalar sintético válido no registra una raíz por el mero hecho de preparar la transacción.

**Alcance:** la instancia L1 y la clave publicadora proceden de la integración confiable; el método construye una transacción y la integración decide su emisión. No reserva nonces, no garantiza que el estado futuro mantenga su admisibilidad y no acredita finalidad BFT. La transacción L1 conserva el formato actual de raíz, cantidad y bytes; no transporta una prueba de ejecución general L2. El chequeo escalar permanece en L2 y no autentica esos bytes dentro del AIR. Se conservan fuentes Lean y de tesis, certificados, formatos firmados y núcleo/lector AIR-FRI, sin extender el resultado matemático.

## Recuperación de envíos pendientes — 20 de octubre de 2026

El primer hash registrado dejaba bloqueado un lote si el envío no aparecía en L1: repetir `mark_batch_submitted` se rechazaba por duplicado y la confirmación seguía pendiente. Se conserva un escenario de referencia de esa limitación y se añade `retry_batch_submission(index, expected_hash, next_hash)`. Esta API registra una nueva intención sobre el mismo lote ya admitido, sin volver a ejecutar transacciones ni sustituir su certificado o contexto local.

`expected_hash` debe coincidir con el intento vigente. El siguiente hash debe ser no vacío y no haber sido reservado por ningún lote de la instancia, incluyendo intentos anteriores y lotes confirmados. El gestor permite el envío inicial y tres reintentos; rechaza un cuarto, los cambios desactualizados, los lotes sin envío y los ya confirmados. Todo rechazo conserva el contador, las fechas, el historial y las reservas existentes. El bloqueo del contexto local serializa el reintento con otros reintentos y con la confirmación.

`get_batch_submission(index)` devuelve el lote pendiente con su hash actual, contador e historial de `SubmissionAttempt`. Tras la confirmación, el historial queda en `ConfirmedBatch::attempts`, consultable por `get_batch_confirmation`. La confirmación recorre los intentos en orden de registro y usa la primera inclusión encontrada que coincide con el publicador y el lote. Esto admite un intento original incluido después de registrar un reemplazo; también permite saltar una transacción procesada cuyos campos no coincidan. `AnchorChain::find_processed_batch_inclusion` distingue ausencia (`Ok(None)`) de un error de integridad local, que se propaga.

La [evidencia de recuperación](../Documentos/06-Evidencia-TG2/2026-10-20/Reintentos-L1/verificacion.json) incluye ocho pruebas externas y una interna: recuperación desde un hash erróneo, reservas históricas, cambios desactualizados, límite, inclusión tardía, varias inclusiones, campos incorrectos y carreras de reintento/confirmación. El caso interno usa un certificado escalar sintético válido para comprobar que permanecen idénticos el lote certificado y su contexto, sin presentarlo como prueba de ejecución general L2.

**Alcance:** se registran intenciones locales; la integración sigue emitiendo las transacciones y seleccionando la instancia L1 confiable. Registrar un reemplazo no demuestra que un intento anterior haya sido cancelado ni evita varias inclusiones en L1. La garantía es una sola confirmación local del lote, con trazabilidad de sus intentos. No hay temporizadores, recuperación durable ni unicidad entre instancias o reinicios. Se preservan las fuentes Lean y de tesis, los formatos firmados y el núcleo/lector AIR-FRI; no se amplía el alcance matemático ni se acredita finalidad BFT o validez L2 general.

## Confirmación local de inclusión L1 — 20 de octubre de 2026

`mark_batch_submitted(batch, l1_hash)` registra la intención de envío después de verificar el contrato local del lote. Rechaza el hash vacío y la asignación del mismo hash a otro lote, incluso después de confirmar el primero, dentro de esta instancia en memoria. La integración conserva la responsabilidad de emitir la transacción firmada.

`mark_batch_confirmed(index, &l1)` sustituye la API anterior por índice y devuelve `Result<ConfirmedBatch, NexusError>`. Consulta directamente una instancia `AnchorChain` confiable aportada por la integración; no acepta un recibo externo como autoridad. Exige el hash de envío registrado, un `BatchSubmit` en un bloque procesado canónico, el remitente igual a la dirección del secuenciador y coincidencia exacta de raíz posterior, número de transacciones y bytes del lote. La identidad publicadora de este perfil es la del secuenciador; no hay delegación de publicación configurada.

`AnchorChain::get_processed_batch_inclusion` lee bloque, registro y datos DA bajo una única instantánea local. `L2BatchRecord::l1_tx_hash` solo se establece mediante la ejecución de una transacción firmada; el helper local de registro conserva `None`. Preparar un bloque o registrar sus bytes en el helper no permite confirmar el envío. Un bloque rechazado tampoco publica ese origen. La confirmación guarda el lote, el hash de transacción, el hash de bloque y la altura L1, consultables mediante `get_batch_confirmation`. La transición pendiente→confirmado ocurre una vez, también bajo llamadas concurrentes.

`nexus-active` añade una dependencia local de `nexus-anchor`, sin nuevas bibliotecas externas ni cambios de versiones resueltas. El método auxiliar de contabilidad `BatchSubmitter::mark_confirmed` pasa a ser interno del crate. Se reproducen dos fallos anteriores y se añaden ocho pruebas: hash inventado, hash compartido, hash vacío, recorrido completo con rechazo y reintento, campos o remitente distintos, helper local, tipo de transacción equivocado y confirmación concurrente. La [evidencia de confirmación local](../Documentos/06-Evidencia-TG2/2026-10-20/Confirmacion-L1/verificacion.json) registra las comprobaciones; la prueba optimista anterior se adapta para exigir el rechazo de un envío ficticio.

**Límite de confianza:** el llamante debe seleccionar la instancia L1 autorizada. La consulta observa procesamiento local, no verifica finalidad BFT ni una prueba remota de inclusión. El formato actual `BatchSubmit` transporta raíz posterior, cantidad y bytes; el índice, rango L2 y preestado se mantienen en el contexto local, sin un compromiso nuevo de esos campos en L1. La unicidad del hash es local y no persiste entre reinicios ni impide reutilización entre otras instancias. Confirmar inclusión no promueve raíces optimistas a verificadas. Se conservan las fuentes Lean, el teorema de intersección con peso estricto >2/3, el AIR escalar, sus certificados y los límites de la tesis; no se deduce de esta conexión una prueba de validez L2 ni finalidad de consenso.

## Almacenamiento local DA — 20 de octubre de 2026

Se corrigen tres regresiones del registro de datos: los envíos a una misma altura sobrescribían fragmentos, se admitían datos vacíos que podían provocar módulo por cero al muestrear y las pruebas de fragmentos no correspondían al compromiso guardado. El perfil local conserva bytes opacos de entre 1 y `MAX_DA_DATA_SIZE` (1 MiB), divididos en fragmentos de 256 bytes; el último conserva su longitud exacta. No duplica fragmentos ni simula paridad. `coding_params = (chunk_count, chunk_count)` indica que se necesitan todos los originales.

`DACommitment::from_data(data)` devuelve `Result` y construye un recibo local con `encoding_version = 1`. `commitment` conserva SHA3 de los bytes completos; `chunk_root` es otra raíz, construida con las hojas ordenadas `SHA3("NEXUS/LOCAL-DA/CHUNK/V1" || hash_contenido || tamaño_u64_LE || cantidad_u32_LE || índice_u32_LE || bytes_fragmento)`. El árbol reutiliza la construcción Merkle de `nexus-core`, incluida su extensión a potencia de dos repitiendo la última hoja. La prueba exige metadatos válidos, índice dentro del número original de hojas, longitud exacta y profundidad canónica, y vincula también el hash del contenido. Los recibos anteriores sin versión no son un formato admitido; no cambia el formato de transacciones firmadas ni el certificado AIR/FRI.

Los fragmentos se guardan por `(altura, índice_local_de_lote, índice_de_fragmento)`. `reconstruct_batch` y `generate_batch_proof` reciben ese índice local; las API anteriores `reconstruct_data` y `generate_proof` solo aceptan alturas con un único lote y rechazan la ambigüedad. La reconstrucción contrasta bytes, metadatos, hash y raíz. El nombre heredado `sample` comprueba determinísticamente la integridad de todos los lotes locales de esa altura: no consulta pares ni acredita disponibilidad de red.

`L2BatchRecord::da_batch_index` conserva la posición local, independiente del índice global del lote. `AnchorChain::get_l2_batch_data` recupera los bytes y vuelve a comprobar su hash. Las dos vías de registro —transacción L1 y helper local— usan ese selector; los efectos siguen sujetos al rechazo atómico del bloque. El hash retornado por el helper sigue siendo SHA3 de los bytes completos.

La [evidencia del almacenamiento DA local](../Documentos/06-Evidencia-TG2/2026-10-20/DA-Local/verificacion.json) conserva tres reproducciones previas y trece pruebas nuevas: nueve externas de fragmentos, dos de integración L1 y dos internas de corrupción, además de reforzar la prueba anterior que generaba una ruta sin verificarla. Un oráculo independiente de dos hojas comprueba la raíz y el orden de hermanos.

**Límite:** el recibo debe proceder de un contexto confiable; una raíz aportada por quien envía la prueba no se convierte por ello en un compromiso de consenso. Este perfil no prueba inclusión del recibo en L1, disponibilidad remota, Reed–Solomon, recuperación con fragmentos perdidos ni ejecución válida L2. La raíz de cuentas L1 sigue sin comprometer integralmente estas estructuras auxiliares. El formato de hojas DA es independiente del AIR escalar y de su modelo Lean; no se añade un teorema ni se amplía el resultado matemático. Se conservan las fuentes de la tesis y el núcleo/lector AIR-FRI.

## Dominio local de transacciones L2 — 20 de octubre de 2026

`SequencerConfig::chain_id` fija el identificador firmado esperado (por defecto `ChainId::LOCAL`). El secuenciador rechaza otro identificador antes de reservar el nonce o añadirlo al pool. `ActiveChain` construye su motor con esa misma configuración, sin una segunda política que pueda divergir. El motor también comprueba el dominio en la ejecución directa; `execute_batch` convierte ese rechazo en un resultado fallido sin cambios de estado, consumo de gas ni avance del nonce para esa entrada. Las entradas válidas del lote continúan bajo las reglas existentes.

`ExecutionEngine::new()` y `with_state(state)` conservan `LOCAL`. Para otro identificador se usan `for_chain(chain_id)` o `with_state_for_chain(state, chain_id)`. El identificador es política confiable del llamante: la raíz SHA3 de cuentas no lo codifica ni permite recuperarlo. Cambiar la etiqueta de una transacción firmada no sustituye su firma. La configuración deserializada por campos que omite `chain_id` usa el valor por defecto; no se promete compatibilidad binaria con configuraciones serializadas anteriores.

Siete pruebas externas y una de producción integrada cubren rechazo en las tres entradas públicas, reserva de nonce, firma alterada, restauración con dominio explícito, lotes mixtos y operaciones de contrato de otra cadena. La prueba integrada configura `TESTNET`, ejecuta una transferencia con saldo de prueba, contrasta raíz y balances, comprueba el avance de nonce y el contexto del lote. Tres regresiones se reprodujeron antes de la corrección. La [evidencia de dominio L2](../Documentos/06-Evidencia-TG2/2026-10-20/Politicas-L2/verificacion.json) registra el corte y las comprobaciones.

Esta política no modifica los bytes firmados, las cabeceras, el génesis, los votos ni el certificado AIR/FRI. Si L1 y L2 comparten identificador, esta comprobación no las separa por capa. Se conserva el alcance escalar Lean y no se acredita aislamiento completo entre redes, un nuevo teorema ni una prueba de ejecución general L2. El presupuesto de gas de L2 conserva su política previa, distinta de la reserva agregada de L1.

## Contrato local de estado L1 — 20 de octubre de 2026

### Políticas locales de dominio y gas

`AnchorChainConfig::chain_id` fija el identificador esperado de las transacciones firmadas (por defecto `ChainId::LOCAL`). Firmar un identificador no basta: tanto `prepare_block` como `process_block` lo comparan con esta política. Cambiarlo exige una firma nueva. La corrección L1 no añade un dominio de red al génesis, a las cabeceras o a los votos; la extensión posterior a las transacciones L2 se describe arriba. No se presenta como aislamiento completo entre redes.

`AnchorChainConfig::block_gas_limit` limita la suma de los `gas_limit` declarados, con 30 000 000 por defecto. Se resta cada reserva de un presupuesto restante después de comprobar que cabe; así se rechaza también una suma no representable en `u64`. La igualdad con el presupuesto es válida y un límite cero permite bloques vacíos. Se reserva el gas declarado, aunque el gas intrínseco sea menor o su precio sea cero. No se cobran comisiones y las réplicas deben compartir la misma política local.

Las ocho pruebas de `nexus-anchor/tests/block_policy.rs` cubren firmas válidas de otra cadena, cambios de etiqueta sin volver a firmar, recepción de bloques con raíz correcta pero política incompatible, rechazo sin efectos y reintento, presupuesto exacto, cero y `u64::MAX`. Dos regresiones se reprodujeron antes de corregir el procesador. La [evidencia de políticas L1](../Documentos/06-Evidencia-TG2/2026-10-20/Politicas-L1/verificacion.json) registra las comprobaciones de este corte; la evidencia de 264 pruebas enlazada más abajo corresponde al corte anterior.

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

[Evidencia y consolidación del contrato L1](../Documentos/06-Evidencia-TG2/2026-10-20/Estado-L1/verificacion.json): pasan 264 pruebas globales, check/build del workspace y catorce casos dirigidos en release. El manifiesto documental identifica el commit local y conserva el corte anterior.

## Integración de ActiveChain — 20 de octubre de 2026

### Correcciones de autenticidad, estado y quórum — revisión posterior

La revisión Rust posterior a `637e77c` corrige el rechazo explícito de firmas falsas en L1, el registro único de bloques y la publicación atómica del estado, registro de validadores, disponibilidad local y lotes. La altura del procesador L1 representa el último bloque procesado. Este procesamiento local se distingue de un certificado de consenso y no demuestra la implementación operativa completa descrita como trabajo futuro en la tesis.

La política de votos sigue `Nexus.Modelos.Quorum.quorum_estricto_interseca_honestos`, en `formalizacion/Nexus/Modelos/QuorumIncentivos.lean`, y las secciones 3.9–3.10 del manuscrito: peso estrictamente mayor que dos tercios del conjunto confiable. Se autentican claves, firmas, fase, altura, ronda y objetivo; cada identidad contribuye una sola vez. Se usan sumas enteras comprobadas y el umbral `W - floor((W-1)/3)` para `W>0`, sin cocientes flotantes. El campo heredado `bft_threshold` admite los valores de compatibilidad 0.667 o 2/3; cualquier otra política se rechaza. Esto aplica el requisito de quórum, sin demostrar por sí solo seguridad y vivacidad BFT ni las reglas completas de bloqueo y comunicación.

El gadget de finalidad requiere una instantánea de validadores suministrada por el llamante confiable y fijada al añadir cada bloque. Comprueba firmas, peso y ascendencia hasta el ancla. `FinalityVote.weight`, `FinalityJustification.total_weight` y `threshold` usan `u128` en unidades mínimas; el total aportado al verificar debe coincidir con la instantánea. `vote_signing_bytes` y `finality_signing_bytes` separan sus dominios. Las propuestas de consenso incluyen la firma del proponente sobre la cabecera. Estos formatos de aplicación se distinguen del certificado AIR/FRI conservado.

El secuenciador autentica antes de reservar nonces, rechaza transacciones que no caben en un lote vacío y prioriza por gas solo entre las cabezas ejecutables de cada remitente. Construir un lote reserva trabajo; únicamente los resultados de ejecución local en `ActiveChain` avanzan el nonce confirmado. Los fallos liberan el nonce y conservan las dependencias futuras pendientes. Un rechazo por saldo o gas no crea cuentas ni altera la raíz. Los costos y nonces agotados se rechazan con aritmética comprobada; `max_cost` conserva una estimación saturada para compatibilidad y `checked_max_cost` se usa en validación.

El verificador de fraude optimista aún carece de preestado autenticado, inclusión y reejecución vinculados. Por ello devuelve rechazo ante trazas aportadas y `finalize_proof` devuelve `NotImplemented` al agotarse el plazo: no se promueve una raíz optimista a verificada. La aceptación provisional y la confirmación local de un envío permanecen separadas. No se presenta esa carencia como una prueba de fraude implementada.

Las fuentes Lean, los capítulos de la tesis, el núcleo AIR/FRI, su lector, los perfiles 12/20, las cuarenta consultas y el corte 512 se conservan. Las nuevas pruebas en `nexus-core/tests/state_safety.rs`, `nexus-active/tests/execution_safety.rs` y `nexus-anchor/tests/` cubren los contraejemplos, ejecuciones válidas y fronteras del quórum. No se deduce de ellas refinamiento universal Rust/Lean, validez de raíces SHA3 dentro del AIR escalar ni cierre de los pendientes matemáticos externos.

[Evidencia de las correcciones y sus límites](../Documentos/06-Evidencia-TG2/2026-10-20/Correcciones-Rust/verification.json): 255 pruebas globales, check de todos los targets y cuatro regresiones numéricas en release. Las fuentes protegidas se cotejan por SHA-256, sin recompilar Lean ni regenerar el manuscrito.

`ActiveChain` obtiene el contexto de una instantánea privada del lote construido localmente, no del sobre recibido. `ActiveChainConfig::validity_profile` fija filas y trabajo mediante `LinkedValidityProfile`; no se leen como política del certificado. Solo se puede añadir la prueba al lote: cambiar índice, rango, raíces, transacciones, cantidad, fecha o firma respecto de la instantánea causa rechazo.

`create_state_proof(&batch)` devuelve ahora `Result<StateProof, NexusError>` y completa las entradas públicas. En validez/híbrido exige prueba presente y de tamaño acotado. `verify_state_proof(&batch, &proof)` llama a `verify_expected` con contexto local; `mark_batch_submitted(batch, l1_hash)` devuelve `Result` y verifica antes de registrar el envío. El modo optimista mantiene aceptación provisional separada, sin acreditar el contrato Lean ni finalizar raíces al marcar confirmación L1. `get_next_batch` entrega trabajo al probador, no una autorización; `get_known_batch(index)` permite recuperar el lote después de un rechazo. El registro local impide envíos repetidos del mismo índice, incluso concurrentes; no es persistencia ni antirrepetición de consenso entre reinicios.

Se captura la raíz inicial antes de ejecutar. Los bloques se incorporan completos o no se incorporan al lote; la rotación ocurre entre bloques y conserva la frontera de estado. Los límites del lote en `ActiveChain` usan los de su secuenciador y cuentan el prefijo de longitud serializado. Los bloques vacíos conservan la raíz y pueden cerrar un lote pendiente. Se serializa la producción para no reutilizar alturas en llamadas concurrentes.

**Límite operativo:** el motor de transacciones usa raíces SHA3 generales y el AIR sigue siendo una recurrencia escalar. No se recortan hashes, no se genera una prueba de recurrencia para presentarla como prueba de transacciones y no se habilita fallback. Un lote con raíces fuera del modelo no puede registrarse como enviado en validez/híbrido; ampliar el AIR para validarlo no forma parte de esta integración. Los casos positivos de cableado usan instantáneas escalares sintéticas solo en pruebas internas. Esta conexión no convierte el PoC en una L2 completa.

La evidencia de esta integración se conserva en `../Documentos/06-Evidencia-TG2/2026-10-20/ActiveChain/`. `integracion.json` conserva la instantánea previa al commit; `consolidacion.json` identifica el commit posterior y enlaza el check/build y las 55 pruebas aisladas (trece nuevas), sin repetirlos para consolidar. El commit `3e40e28` y su manifiesto quedan como antecedentes de la adaptación anterior; el manifiesto documental vigente identifica el commit de integración. Permanecen los límites operativos descritos arriba.

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
