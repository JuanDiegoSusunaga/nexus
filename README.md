# NEXUS — prototipo de referencia en Rust

**Juan Diego Susunaga Velasquez · Universidad del Rosario**

Documentación organizada para revisión: **29 de octubre de 2026**.

Este workspace acompaña la tesis NEXUS sobre firmas poscuánticas, gestión de claves y registros verificables en una arquitectura de dos capas. Incluye las implementaciones, pruebas y experimentos del prototipo.

**Destino exclusivo de este desarrollo:** [JuanDiegoSusunaga/nexus](https://github.com/JuanDiegoSusunaga/nexus). Código, [documentación de tecnologías](documentacion.md), corpus público y evidencia de la testnet se conservan aquí. La publicación no asigna precio a NXS ni valida integralmente la tesis.

**Publicación experimental desde Docker, 30 de octubre:** [abrir NEXUS](https://dreams-humanities-shelter-utilities.trycloudflare.com). Cuatro validadores en un computador y enlace temporal. NXS de prueba sin cotización establecida. Pasan 17 pruebas Python; se verifican firmas/certificados, transferencia por HTTPS y cliente descargado, con sonda HTTP adicional desde otra red. [Guía operativa](deploy/PUBLICAR_DOCKER.md) · [Evidencia y alcance](Documentos/06-Evidencia-TG2/2026-10-30/Docker-Publico/README.md). La imagen Rust se reutiliza sin cambios.

**Base Rust del 30 de octubre de 2026:** autorización/emergencia L2, perfil monetario y BFT/TCP experimental, ahora con diario incremental y recuperación sin volver a generar firmas. La auditoría corrige compilación, detección del diario CLI y posición Merkle. Check, **436 pruebas** y build correctos, incluido un ensayo de cuatro ejecutables con cortes/reinicios. Protocolo v4, diario `BftNode` v2, sin migración automática. Siguen pendientes custodia y retención de historia en RAM. [Arranque](TESTNET.md) · [Contrato actual](REPRODUCIBILIDAD_TG2.md#auditoría-actual-y-diario-incremental--30-de-octubre-de-2026) · [Hallazgos y evidencia](Documentos/06-Evidencia-TG2/2026-10-30/Auditoria-Actual-y-Journal/README.md).

**Preparación Linux anterior a la publicación:** imagen amd64, check y **436 pruebas** en Linux, build release y siete pruebas Python correctos. Ensayo entre cuatro contenedores: transferencias, avance con tres, detención con dos y recreación conservando diarios. [Paquete y alojamiento](deploy/README.md) · [Evidencia](Documentos/06-Evidencia-TG2/2026-10-30/Despliegue-Linux/README.md). El ensayo público posterior utiliza el Docker del autor.

**Perfil de 512 MiB:** ocho pruebas de configuración y un nuevo ensayo de cuatro contenedores pasan con ese límite efectivo, empleado también en la publicación desde Docker. La alternativa VPS permanece para una etapa entre máquinas independientes. [Resultados](Documentos/06-Evidencia-TG2/2026-10-30/Perfil-512MiB/README.md) · [Alojamiento](deploy/ALOJAMIENTO.md).

Los incrementos previos y sus pruebas se conservan en la documentación de reproducción. Este desarrollo es posterior al código de la edición documental de la tesis; no modifica el manuscrito ni Lean.

La edición académica anterior se conserva en [tesis-nexus](https://github.com/JuanDiegoSusunaga/tesis-nexus). Los avances de esta testnet se guardan exclusivamente en este repositorio `nexus`; no se actualiza el repositorio académico al publicarlos.

Para construir el código y ejecutar su suite desde un solo clon, con Docker y Compose:

```powershell
git clone https://github.com/JuanDiegoSusunaga/nexus.git
Set-Location nexus
docker compose --progress plain -f deploy/compose.build.yaml build
python -m unittest discover -s deploy -p 'test_*.py'
```

La construcción ejecuta check, pruebas Rust y build release. Incluye veinte archivos públicos de regresión, sin descargar el repositorio académico. Para operar la instancia publicada, consultar la guía Docker enlazada arriba.

## Por dónde empezar

| Consulta | Acceso |
|---|---|
| Contratos, reproducción y límites | [REPRODUCIBILIDAD_TG2.md](REPRODUCIBILIDAD_TG2.md) |
| Recorrido local completo | [Ejemplo local_cycle](nexus-node/examples/local_cycle.rs) · [Pruebas del ciclo durable](nexus-node/tests/durable_cycle.rs) |
| Ejecución y lotes L2 | [nexus-active](nexus-active/) |
| Procesamiento y confirmación L1 | [nexus-anchor](nexus-anchor/) |
| Firmas y gestión de claves | [nexus-crypto](nexus-crypto/) · [nexus-sentinel](nexus-sentinel/) |
| Verificador AIR/FRI | [nexus-zk](nexus-zk/) · [Pruebas del contrato Lean](nexus-zk/tests/lean_contract.rs) |
| Demostraciones matemáticas | [Formalización Lean](https://github.com/JuanDiegoSusunaga/tesis-nexus/tree/main/formalizacion) |

## Estado de la implementación

La revisión local del 30 de octubre añade rechazo explícito de las APIs Groth16 genéricas no implementadas y sincronización del directorio del diario en Unix. Un fallo posterior al renombrado exige recuperación antes de seguir firmando. Pasan **439 pruebas Rust**, con un caso auxiliar reservado al proceso hijo ignorado por el ejecutor principal. Esto no amplía el AIR escalar a ejecución L2 general ni completa las obligaciones de reducción de seguridad de ML-DSA. [Pruebas del rechazo genérico](nexus-zk/tests/generic_verifier_rejection.rs) · [Contrato del diario](nexus-core/src/journal.rs) · [Límites operativos](TESTNET.md).

El ensayo cloud del 31 de octubre confirma **498 transferencias medidas** con concurrencias 1, 8 y 32, en tres repeticiones por perfil. El perfil 32 observa 2,67 TPS dentro de las ventanas de oferta y 2,87 TPS incluyendo el vaciado, con latencia p95 de 11,47 s. Los cuatro nodos convergen con colas vacías. Son transferencias L1 en un host compartido; no se deduce capacidad máxima de producción ni ventaja integral L1/L2. [Método, datos y límites](Documentos/06-Evidencia-TG2/2026-10-31/Endurecimiento-y-Carga/README.md).

El ciclo local permite admitir transferencias L2, ejecutarlas, construir lotes, preparar paquetes firmados L1, observar su inclusión y confirmar el lote. `DurableNode` guarda las transiciones antes de devolver éxito y recupera el estado al reabrir. Las llamadas y despliegues de contratos se rechazan explícitamente porque este perfil no implementa un intérprete.

El [registro del 20 de octubre](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/06-Evidencia-TG2/2026-10-20/Ciclo-Local-Durable/verificacion.json), sobre el código `b16688c`, conserva 360 pruebas del workspace y 13 pruebas dirigidas en release, además de check/build. Son comprobaciones previas; la preparación de esta documentación no vuelve a ejecutarlas ni cambia las fuentes Rust.

El prototipo conserva límites explícitos: el AIR escalar comprueba su relación numérica, la confirmación L1 observa procesamiento local y la persistencia usa almacenamiento local confiable. Siguen fuera de esos resultados la validez general de ejecución L2, el consenso BFT en red, la disponibilidad remota y el refinamiento universal entre Rust y Lean. Las garantías de seguridad y obligaciones matemáticas se contrastan en el [balance de la tesis](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/04-Administrativo-TG2/Entrega-Final/Balance-Objetivos-TG2.md).

## Reproducción

El desarrollo actual se reproduce desde este repositorio:

```powershell
git clone -c core.longpaths=true https://github.com/JuanDiegoSusunaga/nexus.git
Set-Location nexus
```

Para compilar se necesitan Rust/Cargo, las herramientas de plataforma y las dependencias de `Cargo.lock`. La [guía de reproducción](REPRODUCIBILIDAD_TG2.md#comandos-desde-este-repositorio) explica los comandos y el uso de la caché; `--offline` requiere dependencias descargadas previamente.

## Estructura

| Crate | Función |
|---|---|
| `nexus-core` | Tipos, cuentas, estado y checkpoints |
| `nexus-crypto`, `nexus-sentinel` | Firmas, monitor y gestión de claves |
| `nexus-active` | Admisión, ejecución y lotes L2 |
| `nexus-anchor` | Procesamiento L1, inclusión local y finalidad experimental |
| `nexus-zk` | Verificador AIR/FRI y variantes experimentales |
| `nexus-node` | Coordinación del ciclo durable y ejemplo ejecutable |
| `nexus-network`, `nexus-cli` | Interfaces de red y herramientas de línea de comandos |

[Antecedentes técnicos y mediciones](ANTECEDENTES_TECNICOS.md) · [Tesis y evidencia](https://github.com/JuanDiegoSusunaga/tesis-nexus) · [Código de la formalización](https://github.com/JuanDiegoSusunaga/tesis-nexus/tree/main/formalizacion).
