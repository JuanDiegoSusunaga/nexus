# Documentación y repositorios para NEXUS

**Consulta web:** 30 de octubre de 2026. **Objetivo vigente:** testnet pública para validar experimentalmente aportes de la tesis, con NXS de prueba y cuatro validadores iniciales. El autor eligió publicar desde su Docker: existe acceso público temporal, descrito en la sección 22. Los cuatro nodos comparten un computador; no se acredita independencia física ni seguridad poscuántica integral. Este desarrollo se conserva exclusivamente en `JuanDiegoSusunaga/nexus`. Las secciones anteriores registran las etapas y fuentes de diseño.

Este archivo reúne fuentes primarias, documentación oficial y código de referencia. La columna «Aplicación a NEXUS» expresa una evaluación de diseño; no afirma que la tecnología ya esté integrada. Los enlaces apuntan a las fuentes consultadas, no a resultados de buscadores. No se han instalado ni actualizado dependencias como parte de esta recopilación.

Lecturas directas: [matemática propia](#1-la-matemática-de-la-tesis-dirige-la-implementación), [requisito poscuántico](#2-requisito-transversal-resiliencia-poscuántica), [20 criptomonedas y arquitecturas](#11-veinte-criptomonedas-principales-sin-memecoins) e [hipótesis de innovación](#12-qué-podría-ser-innovador-en-la-dual-blockchain-de-nexus).

## 1. La matemática de la tesis dirige la implementación

Los repositorios externos sirven para estudiar protocolos, transporte, almacenamiento y pruebas. No sustituyen los modelos ni los resultados propios de NEXUS. Cada decisión de la testnet debe vincularse con el modelo correspondiente y declarar sus hipótesis.

| Base propia | Fuente local | Aplicación a la testnet y límite |
|---|---|---|
| Firmas reticulares ML-DSA y derivación de claves | [Núcleo criptográfico](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/01-Manuscrito/Capitulos/Cap4-Nucleo-Criptografico.md) · [Análisis de seguridad](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/01-Manuscrito/Capitulos/Cap6-Validacion-Formal.md) | Autenticar transacciones, propuestas, votos y órdenes administrativas. Conservar las obligaciones R1 sobre la correspondencia entre las reducciones y el backend. |
| Intersección honesta de quórums | [QuorumIncentivos.lean](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/formalizacion/Nexus/Modelos/QuorumIncentivos.lean), teoremas `interseccion_cota` y `quorum_estricto_interseca_honestos` | Peso firmado estrictamente superior a 2/3, calculado con enteros. Para cuatro validadores de igual peso hacen falta tres. El lema no demuestra por sí solo bloqueos entre rondas, persistencia del voto ni vivacidad. |
| Arquitectura dual y amortización | [Capítulo 3](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/01-Manuscrito/Capitulos/Cap3-Diseno-Arquitectura.md) · [AmortizacionVariable.lean](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/formalizacion/Nexus/Modelos/AmortizacionVariable.lean) | Conservar ejecución L2 y anclaje L1. Medir `d + (c + pi(M))/M`; el límite hacia `d` exige crecimiento sublineal de la prueba y las condiciones de disponibilidad y ejecución del modelo. |
| Cota de aceptación falsa con presupuesto adversario | [CotaTrabajoFinal.lean](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/formalizacion/Nexus/Verificador/CotaTrabajoFinal.lean) · [Ejemplos certificados](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/formalizacion/Nexus/Verificador/CotaTrabajoNumerica.lean) | Conservar perfiles y presupuestos declarados al evaluar el verificador AIR/FRI. El resultado corresponde al modelo ROM clásico finito; no acredita QROM completo, ejecución L2 general ni equivalencia universal con Rust. |
| Rotación, revocación y custodia | [Capítulo 5](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/01-Manuscrito/Capitulos/Cap5-Gestion-Claves.md) · [Contrato Rust vigente](REPRODUCIBILIDAD_TG2.md) | Validar identidad, época, dominios y bloqueos antes de aceptar operaciones. La autoridad de emergencia debe custodiarse separadamente; la independencia física todavía requiere implementación y evaluación. |
| Residencia de secretos | [ResidenciaIntegral.lean](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/formalizacion/Nexus/Modelos/ResidenciaIntegral.lean) | Usar el inventario de copias y la integral de bytes por tiempo para estudiar exposición. No convertir esa métrica en probabilidad de compromiso sin las hipótesis adicionales del modelo. |
| Incentivos y disponibilidad | [QuorumIncentivos.lean](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/formalizacion/Nexus/Modelos/QuorumIncentivos.lean) | Separar el juego de pagos y las hipótesis de reconstrucción de una economía real y una red DA operativa. No deducir resistencia a participantes maliciosos de recompensas elegidas sin validación. |

La [guía de formalización](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/formalizacion/README.md) y la [matriz de obligaciones](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/formalizacion/REVISION-MANUSCRITO.md) fijan el alcance de los resultados. En el código, [consensus.rs](nexus-anchor/src/consensus.rs) ya contiene el umbral entero estricto; su cabecera reconoce que todavía no demuestra seguridad/vivacidad BFT completa ni integración de red.

## 2. Requisito transversal: resiliencia poscuántica

«Usar ML-DSA para transferencias» es una parte del requisito. Debemos inventariar todas las raíces de confianza de la testnet y comprobar que ninguna ruta crítica pueda eludir la política poscuántica.

| Superficie | Requisito para NEXUS | Fuente primaria |
|---|---|---|
| Transacciones y validadores | ML-DSA para operaciones, propuestas, votos, certificados y autorización de cambios; separación de dominios por red, capa, altura, ronda, fase y contenido. | [FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) |
| Claves de sesión y confidencialidad | Estudiar ML-KEM o un transporte híbrido estandarizado si el perfil exige cifrado poscuántico. Un KEM establece secretos; no sustituye la autorización de nodos. | [FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) |
| TLS híbrido | Evaluar un transporte existente que implemente los grupos y combinadores definidos; comprobar también la autenticación, sin atribuirle garantías de firmas por el solo intercambio híbrido. | [RFC 10024 — grupos PQ/T de TLS 1.3](https://www.ietf.org/ietf-ftp/rfc/rfc10024.html) · [RFC 9954 — diseño híbrido, informativo](https://datatracker.ietf.org/doc/rfc9954/) |
| Hashes y transcripciones | Documentar algoritmo, tamaño de salida y propiedad requerida: preimagen, colisión o aleatoriedad del modelo. El número de bits del digest no es automáticamente el nivel de seguridad cuántica. | [FIPS 202 — SHA-3 y SHAKE](https://csrc.nist.gov/pubs/fips/202/final) · [Panorama PQC del NIST](https://www.nist.gov/pqc) |
| Custodia y recuperación | Separar claves operativas, claves de validación y autoridades de emergencia; definir generación, almacenamiento, rotación, retiro y recuperación. | [NIST SP 800-57 Parte 1, revisión 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) |
| Capa AIR/FRI | Respetar el modelo de la tesis y mantener abierta la transferencia cuántica completa. Las decisiones de consenso no deben apoyarse en una garantía de ejecución general que la PoC aún no acredita. | [Alcance de la validación NEXUS](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/01-Manuscrito/Capitulos/Cap6-Validacion-Formal.md) |

FIPS 204 tiene una nota de posibles actualizaciones publicada el 31 de julio de 2026 en su página oficial; revisar esa nota al fijar el perfil. RFC 10024 figura como documento Standards Track de agosto de 2026, mientras RFC 9954 es informativo. Son estados de las fuentes consultadas, no una certificación de nuestro código.

**Punto de atención de transporte:** el workspace declara `libp2p` con Noise. Antes de usarlo como canal de la testnet debe revisarse su construcción: el perfil Noise de libp2p documenta componentes clásicos. No etiquetar el canal completo como poscuántico por añadir firmas ML-DSA a las transacciones. Fuentes: [especificación Noise de libp2p](https://github.com/libp2p/specs/blob/master/noise/README.md) y [Noise Protocol Framework](https://noiseprotocol.org/noise.html).

## 3. Fundamentos de blockchain y ejecución

| Recurso | Documentación o repositorio | Aplicación a NEXUS |
|---|---|---|
| Bitcoin: diseño original | [White paper de Satoshi Nakamoto](https://bitcoin.org/bitcoin.pdf) | Estudiar doble gasto, bloques, propagación e incentivos. Su PoW es una referencia histórica, no una decisión de consenso para NEXUS. |
| Bitcoin: guías de desarrollo | [Developer Guides](https://developer.bitcoin.org/devguide/) · [Bitcoin Core](https://github.com/bitcoin/bitcoin) | Contrastar validación, mempool, sincronización y pruebas funcionales. El modelo UTXO difiere de nuestras cuentas. |
| Ethereum: conceptos de ejecución | [Documentación para desarrolladores](https://ethereum.org/developers/docs/) | Revisar cuentas, transacciones, bloques, gas, nodos y separación de responsabilidades. |
| Ethereum: especificaciones ejecutables | [Execution specs](https://github.com/ethereum/execution-specs) · [Consensus specs](https://github.com/ethereum/consensus-specs) | Referencias sobre especificar transiciones y separar ejecución de consenso. No implican compatibilidad EVM ni seguridad poscuántica para NEXUS. |
| Framework de cadenas en Rust | [Polkadot SDK](https://github.com/paritytech/polkadot-sdk) | Comparar organización de runtime, cliente y servicios. Es una alternativa arquitectónica para estudiar, no una migración aprobada del prototipo. |

## 4. Consenso y arranque de la testnet

| Recurso | Documentación o repositorio | Modelo y uso propuesto |
|---|---|---|
| Tendermint: artículo del protocolo | [The latest gossip on BFT consensus](https://arxiv.org/abs/1807.04938) | Fuente para rondas, propuestas, prevotos, precompromisos y condiciones de seguridad/vivacidad. Contrastar su máquina completa con nuestro modelo. |
| CometBFT | [Documentación oficial](https://docs.cosmos.network/cometbft/latest/docs/README) · [Repositorio](https://github.com/cometbft/cometbft) | Referencia de replicación determinista BFT. Evaluar integración y tipos criptográficos antes de adoptar componentes. |
| Separación aplicación/consenso | [ABCI](https://docs.cosmos.network/cometbft/latest/spec/abci/Overview) | Estudiar la frontera entre decidir el orden y ejecutar/verificar operaciones. No confundir consenso con validez de la aplicación. |
| Despliegue de varios validadores | [Red de CometBFT con Docker Compose](https://docs.cosmos.network/cometbft/latest/docs/networks/Docker-Compose) | Referencia operativa para génesis compartido, identidades y procesos separados. |
| BFT escrito en Rust | [Malachite, repositorio actual](https://github.com/circlefin/malachite) · [Arquitectura](https://github.com/circlefin/malachite/blob/main/ARCHITECTURE.md) · [Especificaciones](https://github.com/circlefin/malachite/tree/main/specs) | Estudiar máquina de consenso, almacenamiento del voto y sincronización. La página actual contiene crates `arc-malachitebft-*`; no mezclar ejemplos de versiones o forks anteriores. |
| Raft: artículo original | [In Search of an Understandable Consensus Algorithm](https://raft.github.io/raft.pdf) | Referencia para fallos por caída, elección de líder y log durable. Su modelo no sustituye un protocolo BFT frente a validadores maliciosos. |
| Raft en Rust | [OpenRaft](https://github.com/databendlabs/openraft) · [API y guías](https://docs.rs/openraft/latest/openraft/) | Alternativa para un laboratorio CFT explícito. La documentación advierte de cambios incompatibles antes de 1.0; fijar versión y revisar formato persistente. |

**Criterio derivado para cuatro nodos:** con pesos iguales y umbral estricto superior a 2/3, un certificado requiere tres validadores distintos. Dos conjuntos de tres se intersectan en al menos dos; con a lo sumo un validador malicioso existe un miembro honesto en la intersección. Para convertir esto en seguridad del protocolo, ese miembro debe cumplir reglas de voto y bloqueo persistentes. La aritmética sola no garantiza avance tras cambiar de líder ni bajo particiones. Esta interpretación se apoya en el [modelo de quórums de la tesis](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/formalizacion/Nexus/Modelos/QuorumIncentivos.lean) y el [artículo de Tendermint](https://arxiv.org/abs/1807.04938).

La antigua descripción Markdown de consenso de CometBFT debe contrastarse con el artículo, la versión del código elegida y las especificaciones vigentes. No copiar una transición aislada y asumir que se ha implementado el protocolo completo.

## 5. Redes e infraestructura Rust

| Recurso | Documentación o repositorio | Aplicación a NEXUS |
|---|---|---|
| libp2p para Rust | [Repositorio](https://github.com/libp2p/rust-libp2p) · [Inicio](https://libp2p.io/guides/getting-started-rust/) · [API 0.53.2](https://docs.rs/libp2p/0.53.2/libp2p/) | Descubrimiento, difusión, solicitudes y límites de pares. La referencia de API debe corresponder a `Cargo.lock`; el transporte poscuántico requiere evaluación aparte. |
| Tokio | [Tutorial oficial](https://tokio.rs/tokio/tutorial) · [Repositorio](https://github.com/tokio-rs/tokio) | Conexiones, canales acotados, temporizadores y cierre ordenado. La concurrencia no resuelve el orden de consenso. |
| Despliegues reproducibles | [Docker Compose](https://docs.docker.com/compose/) | Referencia para cuatro servicios y volúmenes separados. También se puede ensayar con procesos independientes; compartir proceso o memoria no demostraría replicación entre nodos. |

## 6. NXS: saldos, emisión y comisiones

En una cadena propia, NXS puede definirse como unidad nativa del estado. Las reglas deben implementarse y verificarse de forma idéntica por todos los nodos. La existencia del nombre en el código no fija suministro, inflación ni valor económico.

| Referencia | Fuente | Qué estudiar |
|---|---|---|
| Saldos y suministro | [Cosmos SDK: módulo bank](https://github.com/cosmos/cosmos-sdk/tree/main/x/bank) | Separación entre transferir, contabilizar suministro y autorizar creación/destrucción. |
| Emisión | [Cosmos SDK: módulo mint](https://github.com/cosmos/cosmos-sdk/tree/main/x/mint) | Parámetros de emisión y su aplicación determinista; no copiar parámetros económicos. |
| Cuentas y autenticación | [Cosmos SDK: módulo auth](https://github.com/cosmos/cosmos-sdk/tree/main/x/auth) | Secuencia de cuentas, autenticación y relación con el procesamiento de comisiones. |

**Perfil inicial propuesto, todavía por implementar:** asignación de NXS de prueba en génesis, conjunto de validadores cerrado y reglas explícitas de comisiones/recompensas. Para cada cambio debe comprobarse la ecuación de conservación: suministro posterior = suministro anterior + emisión autorizada − quema autorizada. Las transferencias redistribuyen saldos. El modelo de incentivos de la tesis debe guiar cualquier extensión posterior; no se introduce una economía pública mediante este documento.

## 7. Persistencia, recuperación y pruebas de fallos

| Recurso | Fuente | Aplicación a NEXUS |
|---|---|---|
| Almacenamiento local | [Wiki oficial de RocksDB](https://github.com/meta/rocksdb/wiki) · [Wrapper Rust](https://github.com/rust-rocksdb/rust-rocksdb) | Estudiar lotes de escritura, WAL y recuperación. Cambiar el motor no resuelve por sí mismo rollback malicioso ni sincronización de consenso. |
| Pruebas distribuidas | [Maelstrom, de Jepsen](https://github.com/jepsen-io/maelstrom) | Banco de experimentación para sistemas distribuidos; requiere adaptar el protocolo y los oráculos de NEXUS. |
| Intercalaciones de concurrencia | [Loom](https://github.com/tokio-rs/loom) | Explorar órdenes de ejecución en componentes de estado/voto; necesita instrumentación específica. |
| Pruebas por propiedades | [Proptest](https://github.com/proptest-rs/proptest) | Generar secuencias de operaciones y comprobar suministro, nonce, duplicados y determinismo. |
| Entradas adversarias | [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) · [Guía oficial](https://rust-fuzz.github.io/book/cargo-fuzz.html) | Someter lectores de mensajes, certificados y checkpoints a entradas malformadas y límites de tamaño. |

## 8. Implementaciones criptográficas de referencia

| Recurso | Fuente | Uso y estado en NEXUS |
|---|---|---|
| ML-DSA en Rust | [integritychain/fips204](https://github.com/integritychain/fips204) | Backend de firmas ya utilizado por el prototipo. El uso de la biblioteca no certifica la integración, la custodia ni la reducción concreta de seguridad del ejecutable. |
| ML-KEM en Rust | [integritychain/fips203](https://github.com/integritychain/fips203) | Candidato para evaluar encapsulación; no está incorporado por esta recopilación. Revisar API, pruebas, mantenimiento y modelo de canal antes de usarlo. |
| Interfaces criptográficas | [RustCrypto/traits](https://github.com/RustCrypto/traits) | Referencia de interfaces y separación de primitivas; no sustituye estándares ni análisis de composición. |

## 9. Criterios de aceptación del hito de cuatro nodos

Estos son criterios de trabajo derivados de la tesis y de las fuentes anteriores; no resultados ya alcanzados.

1. Cuatro procesos con identidades distintas, almacenamiento separado y un génesis/red compartidos; autenticación poscuántica sin ruta de aceptación exclusivamente clásica.
2. Propuestas, votos y certificados ML-DSA vinculados a red, capa, altura, ronda y fase; rechazo de firmas falsas, validadores repetidos y mensajes de otro despliegue.
3. Aplicación exacta del umbral de la tesis; votos y bloqueos durables antes de publicarlos. Documentar el mecanismo de cambio de ronda/líder y sus condiciones.
4. Ejecución determinista de transferencias NXS de prueba y coincidencia de altura, hash y raíz de estado en los cuatro nodos. Rechazo de doble gasto y conservación del suministro del perfil.
5. Recuperación y sincronización verificadas al reiniciar un nodo; rechazo de historias incompatibles y de certificados insuficientes.
6. Ensayos con un nodo caído, mensajes duplicados/reordenados y propuestas inválidas; el perfil BFT deberá cubrir además equivocación y cambio de ronda. Sin quórum, el comportamiento seguro es no finalizar.
7. Medir bytes y latencias de las firmas, votos y lotes usando los modelos de costo/amortización de la tesis. No trasladar benchmarks de repositorios externos a NEXUS.
8. Publicar comandos, configuración, semillas de ensayo no secretas, logs, hashes y límites. Conservar aparte lo demostrado en Lean, lo observado en pruebas y lo aún pendiente de demostración.

## 10. Cómo ampliar esta base documental

Para cada incorporación registrar: fuente primaria, fecha de consulta, versión/commit cuando vaya a usarse, módulo matemático de NEXUS relacionado, decisión que informa y evidencia que falta. Revisar licencia y mantenimiento antes de copiar código o fijar una dependencia. Las URLs `main`, `latest` y las páginas de documentación pueden cambiar; una implementación reproducible debe fijar revisiones.

Punto de partida local: [README](README.md), [contrato del prototipo](REPRODUCIBILIDAD_TG2.md), [balance de objetivos](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/04-Administrativo-TG2/Entrega-Final/Balance-Objetivos-TG2.md) y [pendientes](PENDIENTES.md).

## 11. Veinte criptomonedas principales, sin memecoins

### Método de selección

Se consultó la [clasificación por capitalización de CoinGecko](https://www.coingecko.com/) mediante su [API de mercados](https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&order=market_cap_desc&per_page=100&page=1&sparkline=false), ordenada por capitalización descendente. La selección toma los primeros veinte activos después de excluir memecoins. En la captura del 30 de octubre, esto corresponde a los puestos 1–21, omitiendo Dogecoin, en el puesto 12. La [captura reproducible](Documentos/06-Evidencia-TG2/2026-10-30/Investigacion-Arquitecturas/market-selection.json) conserva identificadores, símbolos, puestos y fecha de consulta.

Se incluyen stablecoins y activos tokenizados porque también aparecen en esa clasificación. Por eso la lista contiene **veinte activos, no veinte blockchains independientes**. El puesto es el de ese proveedor en esa fecha; no mide innovación, descentralización ni madurez técnica. En activos tokenizados, la definición y disponibilidad del suministro pueden producir diferencias importantes entre proveedores.

### Comparación de arquitectura y fuentes

| Puesto de la captura | Activo | Arquitectura y mecanismo de acuerdo | Documentación técnica primaria | Código o implementación verificable |
|---|---|---|---|---|
| 1 | **Bitcoin — BTC** | L1 de pagos, estado UTXO, scripts y cadena con PoW; la selección depende del trabajo acumulado. | [Diseño original](https://bitcoin.org/bitcoin.pdf) · [Guía del protocolo](https://developer.bitcoin.org/devguide/) | [bitcoin/bitcoin](https://github.com/bitcoin/bitcoin), cliente Bitcoin Core. |
| 2 | **Ethereum — ETH** | L1 con cuentas y EVM; ejecución y consenso PoS tienen especificaciones separadas. Los rollups se relacionan con L1 mediante publicación y liquidación. | [Documentación de desarrollo](https://ethereum.org/developers/docs/) | [execution-specs](https://github.com/ethereum/execution-specs) · [consensus-specs](https://github.com/ethereum/consensus-specs). |
| 3 | **Tether — USDT** | Stablecoin emitida sobre varias redes. Hereda el consenso de la red anfitriona; emisión, redención y controles del emisor son una capa distinta. | [Protocolos e integración oficiales](https://tether.to/en/supported-protocols/) | Contratos y despliegues enlazados por red en el portal oficial. No se identificó aquí un repositorio único que represente todas sus implementaciones. |
| 4 | **BNB — BNB** | En BNB Smart Chain: L1 compatible con EVM, cliente derivado de Geth y consenso PoSA/Parlia. opBNB es otro componente del ecosistema, no el mismo mecanismo de BSC. | [Validadores y PoSA](https://docs.bnbchain.org/bnb-smart-chain/validator/overview/) | [bnb-chain/bsc](https://github.com/bnb-chain/bsc). |
| 5 | **XRP — XRP** | XRP Ledger: cuentas, pagos y operaciones de ledger; acuerdo entre validadores con listas de confianza UNL. Sus condiciones no son las de PoW ni las de un comité PoS genérico. | [Protocolo de consenso XRPL](https://xrpl.org/docs/concepts/consensus-protocol) | [XRPLF/rippled](https://github.com/XRPLF/rippled), cliente en C++. |
| 6 | **USDC — USDC** | Stablecoin respaldada en dólares, con contratos en múltiples redes. Cada despliegue hereda el consenso anfitrión; la política de emisión pertenece al emisor. | [Redes y contratos oficiales](https://developers.circle.com/stablecoins/usdc-contract-addresses) | [circlefin/stablecoin-evm](https://github.com/circlefin/stablecoin-evm), contratos EVM; no representa por sí solo todas las redes. |
| 7 | **Solana — SOL** | L1 PoS con cuentas y ejecución paralela. La documentación actual de Anza describe el cambio de TowerBFT a Alpenglow/Votor y la formación de certificados de finalidad. | [Conceptos y desarrollo](https://solana.com/docs) · [Alpenglow, fuente de Anza](https://www.anza.xyz/alpenglow) | [anza-xyz/agave](https://github.com/anza-xyz/agave), cliente validador; fijar versión y activaciones. |
| 8 | **TRON — TRX** | L1 de cuentas y contratos, con DPoS y 27 Super Representatives electos. La documentación distingue producción de bloques y solidificación por participación de representantes distintos. | [Consenso y DPoS](https://developers.tron.network/docs/concensus) | [tronprotocol/java-tron](https://github.com/tronprotocol/java-tron). |
| 9 | **Figure Heloc — FIGR_HELOC** | Activo de crédito tokenizado del ecosistema Figure, asociado a infraestructura Provenance. No es la moneda de consenso de una L1 nueva; la moneda nativa de Provenance es HASH. | [Arquitectura del negocio Figure y uso de Provenance](https://www.figure.com/about/) · [Documentación Provenance](https://docs.provenance.io/) | [provenance-io/provenance](https://github.com/provenance-io/provenance), infraestructura anfitriona PoS. No se identificó aquí un cliente independiente «FIGR_HELOC». |
| 10 | **Hyperliquid — HYPE** | L1 con HyperBFT, inspirado en HotStuff. HyperCore ejecuta el mercado/libro de órdenes y HyperEVM ofrece ejecución EVM bajo el mismo consenso. | [Arquitectura oficial](https://hyperliquid.gitbook.io/hyperliquid-docs) · [HyperEVM](https://hyperliquid.gitbook.io/hyperliquid-docs/hyperevm) | [hyperliquid-dex/node](https://github.com/hyperliquid-dex/node), distribución y operación de nodos; no asumir que contiene todo el código fuente del consenso. |
| 11 | **Zcash — ZEC** | L1 con PoW Equihash, transacciones transparentes y transferencias protegidas mediante pruebas de conocimiento cero. Distinguir los pools y las actualizaciones del protocolo. | [Especificación del protocolo](https://zips.z.cash/protocol/protocol.pdf), documento vivo con versión y fecha. | [ZcashFoundation/zebra](https://github.com/zcashfoundation/zebra), nodo en Rust. |
| 13 | **Monero — XMR** | L1 PoW RandomX, con mecanismos de privacidad de origen, destinatario e importe. El consenso y las pruebas criptográficas de privacidad son componentes diferentes. | [Especificación técnica](https://docs.getmonero.org/technical-specs/) · [Moneropedia](https://www.getmonero.org/resources/moneropedia/) | [monero-project/monero](https://github.com/monero-project/monero). |
| 14 | **USDS — USDS** | Stablecoin del protocolo Sky; su contrato EVM es ERC-20, con `permit`, validación EIP-1271 y actualización UUPS/ERC-1967. No tiene consenso propio independiente de la red anfitriona. | [Contrato y despliegues USDS](https://developers.skyeco.com/protocol/tokens/usds/) | [sky-ecosystem/usds](https://github.com/sky-ecosystem/usds). |
| 15 | **WhiteBIT Coin — WBT** | La documentación actual de Whitechain la presenta como L2 EVM basada en OP Stack, con liquidación en Ethereum y WBT como gas nativo. Fuentes históricas describen una arquitectura PoA diferente. | [Introducción actual de Whitechain](https://docs.whitechain.io/learn/introduction) | [Whitechain Labs](https://github.com/whitechain-labs), organización enlazada desde la documentación. Verificar el componente y versión concreta antes de reutilizar código. |
| 16 | **UNUS SED LEO — LEO** | Token de utilidad del ecosistema Bitfinex. Las redes de transporte documentadas son Ethereum/ERC-20 y Vaulta; el token no aporta un protocolo propio de consenso. | [Ficha técnica del emisor](https://support.bitfinex.com/hc/en-us/articles/360023342674-Unus-Sed-LEO-LEO) · [White paper original](https://www.bitfinex.com/wp-2019-05.pdf) | La ficha oficial enlaza los contratos Ethereum y Vaulta. No se identificó un cliente de consenso independiente para LEO. |
| 17 | **Chainlink — LINK** | Infraestructura de redes de oráculos descentralizados: nodos obtienen/agregan datos y publican resultados en contratos de redes anfitrionas. LINK es un token del sistema, no una L1 general equivalente a BTC/ETH. | [Modelo de datos y DON](https://docs.chain.link/architecture-overview/architecture-decentralized-model) | [smartcontractkit/chainlink](https://github.com/smartcontractkit/chainlink). |
| 18 | **Cardano — ADA** | L1 PoS de la familia Ouroboros, con modelo Extended UTXO y reglas de ejecución/costos específicas. Revisar la variante y era del protocolo que se estudia. | [Consenso, EUTXO y determinismo](https://docs.cardano.org/about-cardano/learn/consensus-explained) | [IntersectMBO/cardano-node](https://github.com/IntersectMBO/cardano-node). |
| 19 | **Stellar — XLM** | Ledger de cuentas y activos; SCP implementa acuerdo bizantino federado mediante conjuntos/slices de quórum elegidos por participantes. No trasladar sus umbrales a un comité fijo sin revisar las hipótesis. | [Stellar Consensus Protocol](https://developers.stellar.org/docs/learn/fundamentals/stellar-consensus-protocol) | [stellar/stellar-core](https://github.com/stellar/stellar-core). |
| 20 | **Bitcoin Cash — BCH** | L1 de pagos con UTXO, scripts y PoW. Estudiar reglas de validación, tamaño de bloques y recursos del cliente por separado de las reglas de Bitcoin. | [Documentación Bitcoin Cash Node](https://docs.bitcoincashnode.org/) | [Repositorio principal BCHN en GitLab](https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node) · [Espejo GitHub](https://github.com/bitcoin-cash-node/bitcoin-cash-node). |
| 21 | **NEAR Protocol — NEAR** | L1 PoS con sharding Nightshade. El diseño divide estado y procesamiento entre shards e incluye validación sin estado en su evolución documentada. | [Artículos oficiales y Nightshade](https://www.near.org/papers) | [near/nearcore](https://github.com/near/nearcore), cliente de referencia. |

### Qué aprender de esta comparación para NEXUS

- **Ethereum y Whitechain:** estudiar compromisos entre capas, disponibilidad, liquidación y qué datos/pruebas debe verificar L1. No asumir que la existencia de L1/L2 es una novedad por sí misma.
- **Hyperliquid y Solana:** distinguir ejecución especializada/paralela del protocolo que ordena y finaliza. Dos entornos de ejecución bajo un consenso no son automáticamente dos blockchains.
- **Cardano, Stellar y XRP:** declarar exactamente el modelo de estado, la selección de validadores y las hipótesis de quórum. Una demostración para un modelo no se transfiere cambiando nombres de componentes.
- **Bitcoin, BCH y Monero:** revisar validación independiente, reglas monetarias, sincronización y comportamiento ante reorganizaciones. No sustituir reglas deterministas por confianza en un líder.
- **USDT, USDC, USDS y LEO:** separar autorización administrativa, contratos, emisión y consenso anfitrión. Para NXS nativo, esas funciones deben definirse en el estado/protocolo de NEXUS, no suponerse resueltas por un estándar de token.
- **Zcash y NEAR:** contrastar el costo y los supuestos de pruebas/fragmentación. Privacidad, solidez, disponibilidad y consenso son garantías distintas.
- **Figure:** distinguir un registro o activo de aplicación de la moneda nativa y de la infraestructura que lo sostiene.

Estas conclusiones son una lectura de diseño para NEXUS basada en las fuentes de cada fila. No son mediciones comparativas de rendimiento ni una recomendación financiera.

### Lectura poscuántica de las veinte arquitecturas

Esta recopilación **no acredita resiliencia poscuántica integral de ninguno de los veinte activos**. Para cada candidato hay que inventariar firmas de usuario, votos/certificados, compromisos, pruebas, transporte, puentes y administración. PoW, PoS, «BFT», «ZK» o «dos capas» no especifican por sí solos la seguridad criptográfica de esos componentes.

Para NEXUS, la comparación guía arquitectura e infraestructura; los mecanismos críticos seguirán el requisito de la sección 2 y la matemática de la tesis. No se importarán como garantía poscuántica firmas o pruebas basadas en curvas clásicas. En especial, el diseño de Alpenglow descrito por Anza utiliza certificados/votos que deben evaluarse por su propia criptografía antes de tomarlo como modelo de autenticación para NEXUS; su umbral no reemplaza nuestro teorema de quórums.

**Estado de fuentes que cambian:** se consultó la página oficial de Anza, que describe Alpenglow y marca la migración mainnet-beta como completada. Es una declaración del implementador, no una medición independiente de esta investigación. En Whitechain se priorizó la documentación vigente de OP Stack frente al white paper PoA histórico. En LEO se conservó Vaulta, que la documentación del emisor presenta como la denominación posterior a EOS. Las versiones deben fijarse antes de implementar comparaciones reproducibles.

## 12. Qué podría ser innovador en la dual blockchain de NEXUS

Son **hipótesis de investigación**, no afirmaciones de prioridad ni garantías ya demostradas del sistema completo. El aporte debe formularse como propiedad concreta, enlazarse con la matemática propia y compararse con antecedentes.

| Línea propuesta | Propiedad o pregunta concreta | Base matemática NEXUS | Evidencia necesaria |
|---|---|---|---|
| **Revocación poscuántica coherente entre L2 y L1** | Una vez finalizada en L1 la revocación de una clave, ningún lote posterior aceptado puede autorizar operaciones con esa clave retirada, conservando la identidad estable. | Modelo de claves por épocas, autorización y quórum estricto. | Especificar el orden de corte, la finalidad y qué significa «posterior»; comprometer el registro en el lote; demostrar rechazo de referencias obsoletas y probar retrasos, concurrencia, reorganización y reinicio bajo las hipótesis elegidas. |
| **Lotes adaptados al costo con restricciones de seguridad** | Elegir tamaño de lote y perfil antes de la transcripción adversaria para reducir bytes por operación sin exceder latencia, disponibilidad y presupuesto de aceptación falsa declarados. | `AmortizacionVariable.lean`, modelos de costos y cotas del verificador. | Derivar el criterio de elección, conservar sus hipótesis y medir datos/probador/verificador. La cota ROM actual no se convierte automáticamente en una cota cuántica al hacer adaptativos los parámetros. |
| **Certificado verificable de autorización y procedencia entre capas** | Vincular lote, identidad/época, punto de control L1, reglas de quórum y perfil de verificación, de modo que un tercero pueda comprobar qué se aceptó y bajo qué política. | Separación de dominios, compromisos, modelos de quórum y contrato del verificador. | Fijar bytes y versiones, verificar la procedencia del contexto y distinguir certificación de autorización de prueba de ejecución. El AIR escalar actual no certifica transacciones generales. |

### Antecedentes que impiden reclamar novedad sin comparación

- [ERC-4337](https://ercs.ethereum.org/ERCS/erc-4337) ya estudia cuentas con lógica de validación propia; [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) trata delegación de código en cuentas externas. La mera separación entre identidad y clave o la programación de validadores no establece novedad.
- [Deeper dive on cross-L2 reading for wallets and other use cases](https://vitalik.eth.limo/general/2023/06/20/deeperdive.html), de Vitalik Buterin, ya discute separación de activos y keystore y actualización de claves entre capas. NEXUS debe diferenciar su modelo poscuántico, propiedad formal y costo concreto.
- [Reactive Key-Loss Protection in Blockchains](https://eprint.iacr.org/2021/289.pdf) estudia recuperación tras pérdida de claves y una implementación en Diem. Debe contrastarse con la autoridad independiente y el bloqueo permanente de nuestro perfil.
- [ZK-ACE](https://arxiv.org/abs/2603.07974) propone autorización ligada a identidad y estados contra repetición para sistemas poscuánticos. Comparar supuestos, composición y resultados; la referencia a una primitiva ideal no equivale a disponer de su implementación segura.
- [Securing Edge & Physical AI: Post-Quantum IoT Blockchain for Mission-Critical Cyber-Physical Agents](https://arxiv.org/abs/2610.33862) incluye épocas, revocación, políticas y puntos de recuperación en un ledger de seguridad. Es un preprint reciente del 24 de octubre de 2026; está identificado para una lectura crítica, no validado como solución por esta recopilación.

**Candidato prioritario:** comenzar por especificar y comprobar la revocación entre capas. Conecta el gestor ya implementado con el anclaje que sigue pendiente y permite formular un resultado verificable. El carácter novedoso tendría que residir en una diferencia demostrable frente a esos antecedentes y en la integración/cuantificación propia, no en afirmar que se inventaron las firmas poscuánticas, los rollups o la rotación de claves.

## 13. Viabilidad financiera, utilidad para personas y participación bancaria

Consulta de fuentes: **30 de octubre de 2026**. Las propuestas para NEXUS son hipótesis de producto y negocio; no constituyen ingresos existentes, acuerdos bancarios ni una autorización regulatoria. NEXUS sigue siendo un prototipo local; la testnet de cuatro nodos está pendiente. No hay una estimación fundamentada de precio o rentabilidad de NXS.

### Separar tres economías

| Elemento | Función propuesta | Cómo se sostiene o evalúa |
|---|---|---|
| Proveedor de tecnología NEXUS | Desarrollar e integrar el software, ofrecer soporte y operar servicios contratados. | Ingresos por integración, mantenimiento y servicios; restar personal, infraestructura, auditorías, atención e integración. Que el protocolo sea abierto no impide cobrar esos servicios. |
| Red y operadores | Ordenar, verificar, conservar datos y prestar disponibilidad. | Comisiones y, si se define, emisión protocolaria. Separar lo que recibe cada operador de lo que ingresa el proveedor. Medir costos y concentración; la emisión redistribuye participación y no sustituye demanda externa. |
| NXS y activos de aplicación | NXS podría servir para comisiones y garantías económicas del protocolo; un depósito tokenizado representaría una obligación distinta de su emisor. | Definir suministro, emisión, reglas de tarifas, penalizaciones y custodia. NXS no es automáticamente estable, un depósito bancario, una acción del proyecto ni un derecho sobre sus ingresos. |

Modelo de planificación: `resultado del proveedor = contratos + servicios cobrados − costos del proveedor`. Por separado: `resultado del operador = comisiones recibidas + recompensas realizables − costos de operación − penalizaciones`. No sumar como ingreso del proveedor todas las comisiones de la red ni valorar emisión como si fuera dinero externo recibido. Un eventual pago de gas por un intermediario permitiría que el usuario viera la tarifa en moneda conocida; ese mecanismo aún no está implementado.

**Ejemplo exclusivamente aritmético:** 100.000 operaciones mensuales con una tarifa de USD 0,01 producirían USD 1.000 de comisiones brutas de red, antes de distribución y costos. No es una previsión de volumen, precio ni demanda. La sostenibilidad exige medir la combinación real de contratos, volumen, tarifa y costo total. El valor negociado de NXS no se deduce de esa multiplicación.

### Por qué alguien lo usaría

| Participante | Beneficio que habría que demostrar | Métrica o validación |
|---|---|---|
| Persona que paga o recibe | Tarifa comprensible, confirmación fiable, aplicación sencilla y control ante compromiso de claves. | Costo total, tiempo hasta finalidad, operaciones fallidas y pruebas de comprensión. El bloqueo actual es permanente: no equivale a recuperar fondos ni a revertir un fraude. |
| Comercio o empresa | Menos conciliación manual y pagos condicionados a eventos verificables. | Horas y errores de conciliación, disponibilidad y costo frente al proceso actual. Requiere implementar la lógica de aplicación correspondiente. |
| Banco o proveedor de pagos | Autorización auditable, coordinación entre entidades y transición criptográfica con impacto medido. | Integración con sistemas existentes, pruebas de continuidad, gestión de claves, privacidad, cumplimiento y costo de migración. |

«Dos blockchains» y «poscuántico» describen componentes. La propuesta comercial debe traducirlos en resultados comprobables. La criptografía no impide por sí sola estafas, instrucciones fraudulentas autorizadas o fallos de custodia. Tampoco se ha medido que NEXUS sea más barato o rápido que las alternativas.

### Cómo podrían participar bancos

Como diseño futuro, una entidad podría usar APIs, operar un nodo bajo reglas de admisión explícitas o emitir un activo que represente una obligación bancaria cuando el marco aplicable lo permita. El activo del cliente mantendría su emisor, moneda, condiciones de redención y tratamiento jurídico propios. El uso de NEXUS no convierte automáticamente a NXS en dinero bancario ni exige ofrecerlo como inversión al cliente.

Una posible distribución de funciones sería **L2 para procesar operaciones y L1 para finalizar compromisos y políticas de autorización**. Antes de adoptarla hay que resolver qué verifica L1, disponibilidad, permisos, censura, salida ante fallos y revocación entre capas. Comprometer un dato no establece por sí solo privacidad: se necesita diseñar protección frente a filtraciones de metadatos y diccionarios. Identidades y documentación de clientes no deben suponerse aptas para publicación en un ledger público. Esta arquitectura institucional todavía no está implementada ni seleccionada como configuración definitiva.

Referencias que acreditan interés técnico institucional, sin acreditar adopción de NEXUS:

- [Project Agorá, BIS](https://www.bis.org/project/agora): prototipo de pagos mayoristas transfronterizos que combina depósitos de bancos comerciales y reservas de bancos centrales tokenizados. Estudia liquidación, interoperabilidad y condiciones legales; no implica que cualquier token o red pública sea adecuado para bancos.
- [Project Leap, BIS](https://www.bis.org/project/leap): experimentos de criptografía poscuántica para comunicaciones y firmas en sistemas de pagos. Es un antecedente para evaluar migración e integración, no una validación del protocolo NEXUS.
- [elHub de la Superintendencia Financiera de Colombia](https://www.superfinanciera.gov.co/publicaciones/10103299/innovasfcelhub-10103299/), página modificada el 15 de septiembre de 2026: declara que no ha autorizado a sus vigiladas a custodiar, invertir, intermediar u operar con criptoactivos. No debe equipararse un piloto tecnológico con una autorización para ofrecer NXS. El alcance de cualquier servicio bancario, incluida una representación tokenizada de depósitos, requiere evaluación concreta de la actividad y su régimen.

### Qué aporta la matemática de la tesis al caso de negocio

- **Amortización variable:** sirve para formular y medir la relación entre tamaño de lote y costo por operación, respetando las hipótesis del modelo. Un menor costo de datos no demuestra por sí solo un menor costo bancario total.
- **Quórums e incentivos:** permite expresar condiciones de intersección y de utilidad de participar honestamente. Faltan elección y aplicación de garantías, observabilidad de faltas, penalización verificable y análisis del valor protegido. No se obtiene seguridad económica real solo asignando una recompensa en NXS.
- **Autorización por épocas:** permite buscar una propiedad de revocación verificable entre capas y una traza útil para auditoría. El gestor y bloqueo local no acreditan todavía esa propiedad distribuida.
- **Cotas del verificador:** delimitan la afirmación demostrada y sus parámetros. No son una prueba de rentabilidad, privacidad bancaria o seguridad poscuántica integral de toda la plataforma.

**Primer experimento comercial propuesto:** dos organizaciones simuladas intercambian activos de prueba y concilian sus registros sobre la futura testnet de cuatro nodos. Medir costo completo, finalidad, recuperación tras fallos y rechazo de claves retiradas; comparar con una solución convencional. Validar después si existe una entidad dispuesta a pagar por el resultado. Antes de dinero real siguen pendientes el protocolo distribuido, seguridad, operación y evaluación jurídica del caso específico.

## 14. Distribución, emisión, suministro y quema de NXS

**Estado:** los mecanismos de emisión, tarifas y quema ya tienen una implementación local opcional descrita en la sección 16. Todavía no se ha elegido un suministro máximo ni porcentajes de distribución para la red que se publicará. Las reglas de la testnet deberán quedar en un génesis público y verificarse en cada réplica. NXS de prueba no implica convertibilidad ni derechos sobre una futura moneda de producción.

Separar las magnitudes evita confundir distribución con creación:

- **Emisión:** crea unidades nuevas conforme a una regla de consenso. Un tope de emisión acumulada limita cuántas unidades pueden crearse en toda la historia.
- **Distribución:** transfiere unidades existentes, por ejemplo desde una cuenta faucet hacia participantes. Un faucet financiado en el génesis no necesita emitir de nuevo con cada solicitud.
- **Desbloqueo:** convierte una asignación previamente bloqueada en saldo gastable. Puede aumentar la oferta disponible sin crear unidades nuevas; necesita un calendario explícito si se utiliza.
- **Quema:** retira unidades del suministro por una regla verificable. Transferirlas a una cuenta ordinaria no demuestra que sean irrecuperables.

Invariantes propuestos, con enteros comprobados en unidades mínimas:

```text
emitido_acumulado_nuevo = emitido_acumulado_anterior + emisión_del_bloque
emitido_acumulado_nuevo <= máximo_emisible
suministro_nuevo = suministro_anterior + emisión_del_bloque - quema_del_bloque
saldo_emisor_de_tx_disminuye = importe_transferido + comisión_cobrada
comisión_cobrada = parte_del_operador + parte_del_tesoro + parte_quemada
```

El tope de emisión acumulada y el tope del suministro vivo son políticas diferentes: si la quema libera espacio para volver a emitir, puede haber más emisión histórica que el máximo de unidades simultáneas. La especificación debe escoger el significado. El balance global también debe incluir depósitos bloqueados, stake y reservas cuando existan; no basta con sumar cuentas líquidas.

La **inflación del suministro** en un periodo es `(emisión − quema) / suministro_inicial`, cuando este último es positivo. No equivale a inflación de precios ni determina el precio negociado de NXS. Si se emiten 100 unidades y se queman 30, el suministro aumenta en 70. Con poco uso puede haber poca quema; quemar todo lo recaudado también deja sin esa fuente de ingresos a los operadores.

[EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) especifica la quema de la tarifa base de Ethereum y distingue esa parte de la remuneración del productor. La propia propuesta explica que el signo de la variación del suministro depende de emisión y quema. Se estudia como antecedente de mecanismo; no se propone copiar su perfil criptográfico ni todas sus reglas a NEXUS.

**Diseño inicial para evaluar:** asignaciones de prueba visibles en el génesis; faucet que reparte desde una reserva identificable; emisión por altura con límite comprobable si se habilita; tarifas explícitas que financien a operadores; quema opcional con proporción acotada y contadores auditables. Antes de fijar números hay que medir costos y necesidades de pruebas. Un reinicio de la testnet debe identificarse como un nuevo génesis/despliegue, sin reutilizar firmas o estado del anterior.

La distribución del stake afecta las hipótesis de quórum de la tesis. Cuatro procesos controlados por una persona no constituyen cuatro operadores independientes. Una distribución por dirección tampoco evita identidades múltiples: hacen falta reglas de participación y análisis de concentración. Las recompensas en monedas de prueba permiten verificar contabilidad y comportamiento, pero no demuestran incentivos económicos frente a pérdidas reales.

## 15. Errores encontrados y problemas actuales para la red pública

Revisión dirigida del código del 30 de octubre de 2026 y fuentes primarias consultadas ese día. Es una revisión parcial con reproducciones, no una auditoría completa ni una certificación para producción. [Evidencia y alcance](Documentos/06-Evidencia-TG2/2026-10-30/Auditoria-Red-Publica/README.md).

### Defectos reproducidos en la contabilidad de validadores

| Defecto observado antes de corregir | Consecuencia | Corrección local |
|---|---|---|
| Alta con suma de stake superior a `u128::MAX`: la suma saturaba y el alta se aceptaba. | El total almacenado no representaba la suma de los depósitos registrados. | Rechazo mediante suma comprobada antes de modificar total o miembros. |
| Penalización reducía el stake individual sin actualizar el total del conjunto. | Con 200 unidades totales y multa de 5, el contador permanecía en 200 en lugar de 195; quitar después al validador dejaba un remanente ficticio en el contador. | Actualización conjunta de principal, total y estado de penalización; mutador directo del validador pasa a ser interno. |
| Cálculo `stake * porcentaje / 100` desbordaba para importes extremos. | La prueba debug con stake máximo terminaba con pánico, aunque el resultado final de la división sí era representable. | Cálculo exacto mediante cociente y resto; controles previos sobre porcentaje, saldo y plazo. |

Son fallos de las APIs locales de registro/penalización: no se ha demostrado un ataque remoto ni emisión explotable a través de una red NEXUS existente. Los quórums actuales recalculan el stake activo con suma comprobada; no se deduce de estos fallos que un atacante haya obtenido finalidad. La corrección no repara automáticamente snapshots históricos inconsistentes.

### Pendientes que bloquean la publicación

1. **Red y RPC:** los módulos legados siguen siendo referencias locales. La ruta `nexus testnet` de la sección 18 ya ejecuta TCP, consultas firmadas, temporizadores y recuperación; se ha probado en loopback entre procesos. Todavía no hay una cadena publicada en Internet.
2. **Consenso distribuido:** el módulo legado `consensus.rs` conserva su alcance local. El nuevo motor de la sección 17 incorpora cambios de ronda, bloqueos, dominios y diario durable, probado con un planificador de mensajes local. Faltan transporte, temporizadores reales y comprobaciones entre procesos para operarlo como red pública. Las firmas ML-DSA no resuelven esas propiedades por sí solas.
3. **Reglas monetarias:** el perfil legado de L1 acredita 2 NXS por bloque de forma predeterminada y usa gas como reserva de admisión. El nuevo perfil opcional de la sección 16 incorpora tope de emisión, calendario, cobro y quema; falta seleccionar parámetros de despliegue e integrarlo en el consenso público. No debe arrancarse la testnet pública suponiendo que el perfil legado ya aplica esas reglas.
4. **Distribución y autoridad:** faltan génesis público de asignaciones, faucet limitado, reglas de admisión de validadores y política de cambios. Un comité inicial fijo tiene permisos de validación aunque consulta y envío se abran al público.
5. **Reproducción distribuida de L2:** la ejecución local evalúa vigencia en el reloj del proceso. Replicar bloques exige fijar el contexto temporal y de autorización compartido, más sincronización y verificación de bloques recibidos. El bloqueo de emergencia local aún no está anclado en L1.
6. **Composición poscuántica:** ML-DSA ya está en el prototipo; no está demostrado un transporte, administración y composición completa poscuánticos. La cota AIR/FRI conservada es ROM clásico finito, y el AIR escalar no prueba ejecución general de transferencias. Estos límites de la tesis siguen vigentes.

### Incidentes recientes y lecciones verificables

- **Binance, comunicado del 30 de octubre de 2026:** su [actualización oficial](https://www.binance.com/en-IN/support/announcement/detail/c5a8729a97ac486d963784d96c5642d7) describe una investigación preliminar sobre acceso no autorizado a infraestructura y retiros. No es un informe final de causa raíz. **Aplicación a NEXUS:** delimitar autoridades, credenciales y revocación; una firma resistente a ataques cuánticos no impide que un servicio comprometido use permisos válidos.
- **ICON, incidente del 27 de agosto de 2026 e informe del 30 de agosto:** la [fundación documentó la repetición de mensajes de retiro previamente firmados](https://www.icon.foundation/blog/2026/icon-network-replay-exploit-post-mortem), liberaciones no autorizadas y una respuesta operativa que no contuvo inmediatamente el movimiento. El informe describe corrección y reanudación, no una vulnerabilidad afirmada como abierta hoy. **Aplicación:** verificar consumo único, nonce, dominio, persistencia y respuesta efectiva ante alarmas, incluidos los puentes entre capas.
- **Emisión frente a quema:** [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) permite identificar el error de diseño de prometer deflación solo por incluir quema. En NEXUS habría que comprobar por bloque los contadores y la conservación descritos en la sección 14.
- **Disponibilidad:** la [página oficial de Solana](https://status.solana.com/) mostraba todos los sistemas operativos y ningún incidente reportado el 30 de octubre al consultar. No se toma una caída histórica ni un texto de buscador como evidencia de una caída actual. NEXUS debe aportar sus propias pruebas de partición, reinicio y recuperación.

**Orden de trabajo:** génesis y contabilidad monetaria deterministas; consenso con contexto, bloqueos y votos durables; transporte y sincronización; pruebas entre procesos con fallos; después publicación de la testnet y recogida de evidencia externa. La validación de la tesis debe distinguir propiedades demostradas, pruebas experimentales y garantías que continúan pendientes.

## 16. Implementación local del perfil monetario

Desarrollo del 30 de octubre de 2026, posterior a la revisión de la sección 15. El módulo [monetary.rs](nexus-anchor/src/monetary.rs) y `AnchorChain::new_monetary` implementan una política explícita, que también puede seleccionarse mediante `DurableNodeConfig::anchor_monetary`. Los parámetros de las pruebas usan unidades mínimas pequeñas y no fijan la oferta de una moneda de producción.

| Regla implementada | Comportamiento verificable |
|---|---|
| Distribución inicial | Asignaciones ordenadas por dirección, sin duplicados ni valores nulos; suma comprobada y limitada por el máximo emitible. El génesis compromete distribución y parámetros L1. |
| Emisión | Subsidio por altura, reducción entera a la mitad cada intervalo y ajuste del último subsidio al saldo restante del tope. Cuando se agota el tope de emisión histórica, la quema no lo reabre. |
| Comisiones | Precio mínimo explícito y gas de `21.000 + 16 × bytes del sobre firmado` para transferencias y `BatchSubmit`. Se comprueba el máximo autorizado y se cobra el uso real; firmas y claves ML-DSA cuentan como bytes. No es un mercado de tarifas EIP-1559. |
| Quema | Fracción de la comisión en puntos básicos, entre 0 y 10.000. El resto se acredita al proponente del bloque. La quema se registra en un contador y se retira de los saldos; no consiste en mandar monedas a una dirección supuestamente inaccesible. |
| Conservación | Contadores de emisión, quema y comisiones acumuladas. Cada transición exige que la suma de saldos sea igual a emisión menos quema; en este perfil no hay staking/escrow. |
| Compromiso de estado | La raíz vincula saldos/cuentas, contadores monetarios y dominio de red. La validez de aplicación se comprueba antes de publicar un bloque. |
| Reinicio de la testnet | `Transaction::network_domain` se firma y debe coincidir con el compromiso monetario esperado. Otro despliegue, otra política o una alteración de ese campo invalida su uso, incluso con el mismo `ChainId`. |
| Persistencia | La recarga exige el génesis esperado y reproduce las operaciones de todos los bloques. Rechaza balances o contadores inventados aunque el archivo incluya una raíz alterada que coincida con ellos. El nodo revierte el cambio si falla la escritura. |

El perfil acepta ML-DSA-65 para transacciones y verifica la firma con el tiempo declarado por el bloque. El futuro consenso debe comprobar también las reglas de reloj para propuestas en vivo, el comité y la finalidad. Ni `process_block` ni `validate_candidate` constituyen por sí solos un certificado de consenso.

El nodo impide asignar NXS experimental en L2 de forma independiente cuando se habilita el perfil monetario L1. La transferencia de valor entre capas requerirá un protocolo de bloqueo/emisión o representación que conserve el total y será una etapa posterior; hoy no está implementado. También se rechaza la vía de registro DA local sin transacción firmada en el perfil monetario.

**Versiones:** protocolo 3 y ruta `/nexus/3.0.0`; checkpoints L1 3 y L2/nodo 4. No hay migración automática de transacciones o checkpoints anteriores. Las pruebas y el manifiesto de la edición académica conservada siguen siendo históricos.

[Evidencia del incremento](Documentos/06-Evidencia-TG2/2026-10-30/Politica-Monetaria/README.md): incluye cuatro réplicas/almacenes locales con las mismas transiciones, límite tras quema, redondeos extremos, cambio de dominio, rechazo atómico, recarga, fallo de escritura y salida abrupta de otro proceso. Es evidencia de ejecución y persistencia; todavía no hay transporte entre esas réplicas ni una testnet publicada.

La política monetaria no se presenta como un teorema nuevo de Lean. La conexión con los quórums, incentivos y costos propios de la tesis sigue requiriendo el protocolo distribuido y mediciones del despliegue. Una vez integrado, los resultados deberán separar propiedades del modelo matemático, comportamiento observado y supuestos de seguridad de sus primitivas.

## 17. Motor BFT experimental y diario durable

Desarrollo local posterior al perfil monetario del 30 de octubre de 2026. [Motor](nexus-anchor/src/bft.rs) y [nodo persistente](nexus-node/src/bft.rs). Este incremento se probó inicialmente con un planificador local; la conexión TCP posterior se describe en la sección 18. La implementación sigue siendo experimental y no está publicada en Internet.

**Base propia:** `quorum_estricto_interseca_honestos` en [QuorumIncentivos.lean](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/formalizacion/Nexus/Modelos/QuorumIncentivos.lean). El arranque asigna peso 1/4 a cada uno de cuatro validadores y exige tres firmantes distintos. Con a lo sumo un validador bizantino se cumple la hipótesis de intersección honesta. El teorema no acredita por sí solo las transiciones Rust, persistencia o terminación de la red.

**Antecedente de protocolo:** [The latest gossip on BFT consensus, versión 3](https://arxiv.org/abs/1807.04938v3), de Buchman, Kwon y Milosevic, orienta las fases de propuesta, prevoto, precommit y conservación de bloqueos. NEXUS utiliza firmas ML-DSA-65, certificados explícitos de prevotos y su perfil monetario. No se afirma un refinamiento formal de esa publicación ni se atribuye a la tesis la invención del protocolo de consenso.

| Mecanismo implementado | Contrato y límite |
|---|---|
| Comité inicial | Cuatro claves distintas ML-DSA-65, ordenadas canónicamente, con igual peso. No es admisión abierta de validadores ni PoS ponderado por saldos de NXS. |
| Génesis y dominio | El despliegue monetario efectivo incorpora el dominio de la política/asignaciones, claves de validadores y tolerancia temporal. El contexto de consenso incorpora además el hash de génesis y versión. Cambiar el comité también cambia el dominio de transacciones. |
| Compromiso de bloque | Propuesta y votos vinculan un hash del bloque completo, no solo su cabecera. Los certificados de tres votos distintos verifican contexto, altura, ronda, fase y valor. |
| Bloqueo entre rondas | Un quórum de prevotos conserva bloque y prueba. Un conflicto sin prueba suficiente recibe prevoto nulo; una prueba anterior al bloqueo no lo sustituye. Los votos nulos y los cambios de ronda no borran el bloqueo. |
| Recuperación de ronda | Un único emisor no adelanta la ronda. Dos anuncios firmados distintos permiten actualizarla. Se limita la memoria de rondas futuras; una prueba compacta de dos anuncios permite recuperar tras una desconexión larga sin asignar un registro por cada ronda omitida. |
| Temporizadores | El motor devuelve un token elegible por altura/ronda/fase y descarta tokens obsoletos. Prevote/precommit requieren quórum observado para habilitar su temporizador. El transporte/runtime deberá programar tiempos crecientes y retransmisión; las pruebas actuales disparan esos eventos explícitamente. |
| Firma durable | `BftNode` persiste voto, fase, bloqueo y mensajes locales antes de devolverlos para emisión. Tras reinicio retransmite los bytes registrados; no abre de nuevo una fase ya votada para elegir otro valor. |
| Decisión y dinero | Certificado, transición monetaria y estado de la altura siguiente se guardan juntos. Un fallo de escritura restaura el estado anterior y no devuelve mensajes nuevos para envío. |
| Recarga | Se reproduce la historia monetaria, se verifican certificados de cada altura y se valida el diario de fase, firmas, bloqueo y contexto. Un archivo sin certificados o con fase reiniciada artificialmente se rechaza. |
| Observadores | Un nodo sin clave de validador acepta certificados secuenciales y reconstruye el mismo libro; no firma votos ni propuestas. Esto es la base para sincronización abierta, aún sin API/transporte públicos. |

**Pruebas concretas:** transferencias entre cuatro runtimes con directorios propios, observador que recupera certificados, líder ausente, detención con dos participantes, recuperación al volver un tercero, líder que propone dos bloques a distintos nodos honestos, prueba de bloqueo antigua, contextos y firmas alterados, escritura fallida al finalizar, salida abrupta y archivos inconsistentes. Los mensajes se intercambian mediante un planificador dentro del proceso de pruebas. No equivalen a operadores independientes ni a una prueba de todos los comportamientos bizantinos.

[Evidencia del incremento](Documentos/06-Evidencia-TG2/2026-10-30/Consenso-BFT/README.md). El formato del checkpoint de `BftNode` es 1; el protocolo general permanece en 3 y los formatos de los perfiles anteriores mantienen sus versiones. Las claves secretas no se guardan en ese checkpoint; el operador debe suministrar la misma clave y usar un único diario activo por clave.

**Trabajo necesario para publicar:** transporte con límites y autenticación del contexto, planificador de tiempos y retransmisión, recuperación por certificados, almacenamiento que no copie toda la historia en cada voto, pruebas entre procesos/redes y configuración de operadores externos. Se conserva el límite de 64 MiB por checkpoint y el supuesto de almacenamiento local confiable; un propietario que copie claves o sustituya un diario por uno antiguo puede invalidar las hipótesis del validador honesto. Tampoco se acredita aquí confidencialidad del transporte, composición poscuántica integral o seguridad económica del NXS de producción.

## 18. TCP real, comandos de laboratorio y recuperación entre procesos

Se implementaron [tramas y cliente TCP](nexus-network/src/testnet.rs), [runtime de red](nexus-node/src/testnet.rs) y [comandos CLI](nexus-cli/src/testnet.rs). La [guía de arranque](TESTNET.md) y el [lanzador de cuatro procesos sin ventanas adicionales](scripts/run_testnet_lab.py) permiten reproducir el laboratorio. No se ha publicado todavía en Internet ni se han incorporado operadores externos.

- **Red:** cada nodo consulta periódicamente sus pares configurados. Recupera el certificado de la siguiente altura y mensajes de consenso persistidos, sin aceptar un salto de altura basado solo en una cifra declarada por el par. Los votos y bloques conservan su autenticación ML-DSA y el contexto BFT.
- **Temporizadores:** se programan por altura/ronda/fase, crecen con la ronda y se habilitan conforme al motor. La pausa de bloques vacíos se coordina con el plazo de propuesta; las retransmisiones y los saltos de ronda certificados permiten recuperar participantes.
- **Consultas públicas:** las respuestas de validadores firman contexto, nonce de la consulta, hash de petición y hash de respuesta. El cliente comprueba esos vínculos. La altura/raíz declarada por `status` debe concordar con génesis o con un certificado de bloque de tres firmantes. Un saldo atestado sigue siendo la declaración de un validador: no es por sí solo una prueba independiente de pertenencia al estado.
- **Transferencias:** se verifica el sobre, dominio, saldo, nonce y gas antes de admitirlo; la cola limita operaciones y bytes. Se difunden transacciones a otros pares. El reconocimiento `pending` es volátil; la finalidad requiere inclusión certificada. Cada dirección tiene como máximo una operación pendiente por nonce en este perfil.
- **Límites:** tramas de hasta 8 MiB, 16 conexiones simultáneas, 64 solicitudes por IP/segundo, 64 eventos en cola, plazos de conexión/lectura/escritura y pool de hasta 512 operaciones/4 MiB. Una operación enviada por esta API admite hasta 256 KiB; la difusión de cada respuesta limita cantidad y bytes. Son límites experimentales, no una prueba de disponibilidad frente a todo DDoS.
- **Génesis distribuible:** el JSON público fija versión de protocolo y los compromisos de génesis, red y comité. El cargador comprueba los valores calculados; no reinterpreta un archivo antiguo silenciosamente al cambiar de protocolo. Los enteros monetarios se conservan como `u128`, sin conversión a coma flotante.

**Protocolo 4:** las transacciones con dominio público ahora identifican el sobre completo, incluidos remitente, clave y esquema. El hash legado solo incluía contenido de la transacción y bytes de firma; no se reutiliza ese identificador para el perfil público. La nueva ruta es `/nexus/4.0.0` y la cabecera TCP `NXSNET04`. Las versiones de formatos que no cambiaron se mantienen; los compromisos y verificadores rechazan el protocolo anterior, sin migración automática.

**Experimento reproducido:** cuatro ejecutables con claves y directorios distintos, unidos por TCP loopback, acuerdan bloques y ejecutan una transferencia de 2,5 NXS. Con un nodo apagado siguen finalizando. Con solo dos, una segunda transferencia de 1 NXS permanece pendiente. Tras reiniciar un tercero se incluye y, al reiniciar el cuarto, recupera los certificados atrasados. Un verificador adicional sin clave reproduce la historia descargada, compara el bloque común de los cuatro y comprueba saldo final de 3,5 NXS, emisión y quema. También se rechazan un sobre con clave alterada y una cabecera de longitud excesiva. [Prueba](nexus-cli/tests/testnet_processes.rs) · [Evidencia](Documentos/06-Evidencia-TG2/2026-10-30/Testnet-TCP/README.md).

Las pruebas revelaron y corrigieron un desbordamiento de pila del cliente debug en Windows y la pérdida del tratamiento de `u128` al aplanar la configuración JSON; el ejecutable usa un hilo interno con pila explícita y el génesis mantiene configuración tipada. Los procesos auxiliares se ejecutan ocultos; no se abren consolas externas.

**Alcance de este incremento:** el ensayo TCP inicial usaba snapshots completos. La sección 19 describe su sustitución por un diario incremental y la auditoría posterior. El tráfico sigue en claro, las claves de laboratorio no están cifradas y los parámetros son ilustrativos. La matemática propia mantiene sus hipótesis y no se transforma esta prueba de procesos en una garantía universal del sistema.

## 19. Auditoría actual y recuperación incremental

La [auditoría del 30 de octubre](Documentos/06-Evidencia-TG2/2026-10-30/Auditoria-Actual-y-Journal/README.md) registra problemas reproducidos, correcciones y riesgos abiertos. Se corrigieron las referencias a la API de snapshots eliminada que rompían la compilación, la detección de diarios al reiniciar desde CLI y un fallo en `MerkleProof`: cambiar `leaf_index` no invalidaba la prueba. Tres regresiones reproducen esa aceptación indebida antes de corregirla; ahora el camino debe coincidir con los bits del índice y su profundidad. Esta API no acredita por sí sola el número de hojas originales ni la procedencia de la raíz esperada.

El almacenamiento BFT ahora usa registros inmutables `event-*` de hasta 8 MiB. Cada uno conserva entrada, salidas firmadas exactas, huella del estado y raíz monetaria. Se publica mediante temporal sincronizado y renombrado antes de devolver mensajes; no se copia la historia completa por evento. La recuperación reproduce transiciones usando solo las firmas registradas, sin generar firmas nuevas. Corrupción o huecos intermedios publicados causan rechazo, sin truncar ni volver a una versión anterior.

Se comprueban fallos de escritura, exclusión de escritor, corrupción, salida abrupta, temporales incompletos, certificados y orden de firmas. La prueba del almacén genérico supera 64 MiB acumulados; la del nodo aplica y recupera 24 bloques certificados con igual tamaño del primer y último registro. La suite también vuelve a ejecutar el ensayo de cuatro procesos TCP con transferencias y reinicios. Los comandos, resultados, tamaños y huellas están en [verification.json](Documentos/06-Evidencia-TG2/2026-10-30/Auditoria-Actual-y-Journal/verification.json).

**Verificación actual:** check de todos los targets, **436 pruebas** y build correctos. Los registros inicial y final del ensayo de 24 bloques miden **27.832 bytes** cada uno.

**Compatibilidad:** protocolo de red 4, diario BFT 2. No hay migración automática del snapshot BFT 1. La [guía](TESTNET.md) usa otra carpeta para crear un laboratorio con génesis y claves nuevos; no debe vaciarse un diario conservando las mismas claves y génesis.

**Pendiente:** publicación y pruebas entre máquinas/redes, custodia de claves, protección de infraestructura, retención de historia en RAM y recuperación creciente. El diario no impide que el propietario restaure una copia antigua o duplique una clave. El comité sigue fijo; un saldo atestado no es una prueba independiente de pertenencia. AIR/FRI aún no prueba la ejecución general de L2 ni existe un refinamiento formal del ejecutable a Lean o una garantía poscuántica integral. Los resultados nuevos se mantienen separados del manuscrito académico conservado.


## 20. Preparación del despliegue Linux y alojamiento

Se añade un [paquete de despliegue](deploy/README.md) con imagen Linux amd64 de bases fijadas por digest, generador de configuraciones públicas y verificador de consultas. La construcción ejecuta check de todos los targets, **436 pruebas** y build release CLI; siete pruebas Python validan el generador. El contexto incluye únicamente las fuentes Rust y veinte artefactos públicos de regresión necesarios. La imagen final no incorpora fuentes, Cargo ni corpus.

La [evidencia del ensayo](Documentos/06-Evidencia-TG2/2026-10-30/Despliegue-Linux/README.md) muestra cuatro contenedores con UID 10001, raíz solo lectura, capacidades eliminadas, una clave por nodo y volúmenes distintos. Desde Windows se comprueban las cuatro identidades y certificados, transferencias por 2 NXS en total, avance con tres, detención con dos y recreación con diarios conservados. La imagen se exporta con huella para instalarla en los futuros hosts. El ensayo sigue siendo local y no valida una red publicada en Internet.

El autor indicó que aún no ha pensado el alojamiento. La [propuesta con precios oficiales](deploy/ALOJAMIENTO.md) compara AWS Lightsail y DigitalOcean: cuatro planes de referencia de US$12 suman **US$48/mes de base**, antes de impuestos y extras. Proveedor, cuenta, presupuesto, direcciones y acceso administrativo aún no están elegidos. No se contratan servidores en esta etapa.

Los paquetes contienen configuración pública; cada clave se instala aparte únicamente en su nodo y el faucet permanece separado. Se rechazan salidas existentes e imágenes sin fijar por contenido. La identidad del proyecto/volumen se deriva del hash de génesis para que reformatear el JSON no seleccione otro diario. No se debe vaciar un diario ni duplicar la misma clave entre hosts.

La publicación requiere desplegar esos paquetes en destinos autorizados y verificar desde otra red consultas, transferencias, recuperación y recursos. El verificador de consultas utiliza la validación criptográfica de CLI, exige cuatro identidades y una raíz certificada común, pero no reproduce toda la historia ni acredita por sí solo un origen externo. Permanecen los límites de RAM, custodia, DDoS, comité fijo y composición poscuántica; los modelos y pruebas de la tesis no se sustituyen por herramientas de despliegue.


## 21. Alternativa de menor costo y límite de memoria

La [propuesta actualizada](deploy/ALOJAMIENTO.md) incorpora una primera prueba acotada con cuatro VPS de 1 GiB. La [tarifa oficial de DigitalOcean](https://www.digitalocean.com/pricing/droplets) indica US$6 por VPS: cuatro suman **US$24/mes de base**, antes de impuestos y extras. Se conserva la opción de cuatro VPS de 2 GB/GiB por US$48 de base. No se elige proveedor, cuenta o presupuesto ni se contratan recursos.

El generador y el helper aceptan `--memory-limit 512m`, que se propaga al manifiesto y a los cuatro nodos; el valor predeterminado sigue siendo `1g`. Ocho pruebas Python pasan. La [evidencia del ensayo](Documentos/06-Evidencia-TG2/2026-10-30/Perfil-512MiB/README.md) comprueba el límite efectivo, transferencias, avance con tres, detención con dos y recuperación/recreación conservando los diarios y el saldo. La imagen, Rust y las matemáticas no cambian. Las 436 pruebas y build de la imagen se conservan como evidencia anterior.

Este resultado mide contenedores en una máquina local; no simula el consumo completo de un VPS de 1 GiB ni garantiza capacidad bajo carga sostenida. Es una alternativa para empezar con una ventana acotada y seguimiento de memoria, disco y sincronización. La elección posterior de Docker local y túnel temporal se registra en la sección siguiente; no se contratan VPS.

## 22. Publicación desde Docker y valor de NXS

El autor eligió su propio Docker y no confirmó acceso administrativo al router. La [guía de operación](deploy/PUBLICAR_DOCKER.md) conserva el enlace temporal, comandos de arranque/detención, descargas y huellas del cliente. La [evidencia pública](Documentos/06-Evidencia-TG2/2026-10-30/Docker-Publico/README.md) separa consulta HTTP desde otra red, transferencia por HTTPS y validación criptográfica del cliente descargado en un contenedor aislado del mismo computador.

Se implementan cuatro validadores ML-DSA-65 con diarios/volúmenes separados, una pasarela HTTP sin claves y un túnel saliente. Los puertos del host se ligan a loopback; solo se sirven génesis público y tres archivos del cliente. El adaptador transporta las tramas originales por HTTPS y la CLI conserva las comprobaciones de firmas, contexto, nonce y certificados BFT. No se expone el daemon Docker ni se instala una autoridad que firme por los usuarios.

[Quick Tunnels de Cloudflare](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/) ofrece una URL temporal sin cuenta ni dominio, para desarrollo y pruebas, sin garantía de disponibilidad y con nombre variable al recrearlo. [Publicación de puertos Docker](https://docs.docker.com/engine/network/port-publishing/) explica la vinculación a `127.0.0.1`. Estos componentes aportan conectividad; no demuestran seguridad poscuántica integral ni sustituyen los modelos matemáticos propios.

NXS es aquí moneda de prueba del génesis publicado. No tiene cotización de mercado establecida ni conversión garantizada a pesos o dólares. El máximo histórico de emisión y la quema controlan contabilidad/suministro, sin fijar precio ni prometer apreciación. No se confunde este activo experimental con otros proyectos que puedan usar un símbolo similar.

El comité conserva cuatro claves fijas bajo un operador; sigue pendiente integrar el ciclo completo Sentinel en sus claves. Quedan pendientes separar dominios de fallo, custodia y operación sostenida, poda/retención y replay creciente, ejecución L2 general acreditada por AIR/FRI y refinamiento universal Rust/Lean. QROM completo sigue como trabajo futuro. El despliegue y los resultados empíricos no equivalen a dictamen académico.
