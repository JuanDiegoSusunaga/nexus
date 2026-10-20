# Reproducibilidad de la edición TG2

**Organización:** 23 de septiembre de 2026. Este repositorio contiene el prototipo Rust y las variantes experimentales de TG2. Los documentos se mantienen en `https://github.com/JuanDiegoSusunaga/tesis-nexus`.

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
