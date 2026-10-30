# Laboratorio TCP de NEXUS

Esta guía reproduce el laboratorio local de cuatro validadores con NXS de prueba. La [publicación posterior desde Docker](deploy/PUBLICAR_DOCKER.md) agrega acceso público mediante un túnel temporal. El diario incremental BFT v2 persiste entradas y firmas en registros de hasta 8 MiB, sin copiar toda la historia por voto. La historia y los certificados aún se conservan en memoria; el arranque y el número de archivos crecen con la actividad.

## Arranque local sin ventanas adicionales

Desde `nexus/`, compilar y ejecutar el lanzador:

```powershell
cargo build --workspace --locked
python scripts/run_testnet_lab.py --seconds 30
```

El lanzador comprueba los cuatro puertos, crea el laboratorio solo si falta su génesis y abre cuatro procesos con consolas ocultas en Windows. Usa `target/testnet-journal-lab`, puertos 19001–19004 y logs por nodo. Al terminar el plazo o recibir Ctrl+C cierra únicamente sus propios procesos. `--seconds 0` mantiene el laboratorio activo y `--base-port 20001` elige otro rango. Si un puerto está ocupado, el lanzador no mata ni reemplaza el servicio existente.

El snapshot BFT v1 no se migra automáticamente al diario v2. La carpeta predeterminada nueva genera otro génesis y otras claves sin tocar el laboratorio anterior. No borres un diario ni reutilices claves de validador con un diario vacío para el mismo génesis: podrías volver a firmar decisiones incompatibles con las anteriores. Un directorio antiguo se rechaza explícitamente; un error de recuperación nunca autoriza crear una cadena alternativa.

Los valores iniciales del comando `init` son una plantilla de laboratorio: un millón de NXS asignados al faucet, máximo histórico de dos millones, subsidio inicial de un NXS, intervalo de reducción de un millón de bloques y quema del 25% de las comisiones. No fijan la economía de una red de producción. El programa acepta parámetros explícitos mediante `nexus testnet init --help`.

## Consultar y transferir

Mientras el laboratorio está activo, estas llamadas verifican respuestas firmadas por un miembro del comité:

```powershell
.\target\debug\nexus.exe testnet status --genesis target/testnet-journal-lab/genesis-data/genesis.json --node 127.0.0.1:19001
.\target\debug\nexus.exe testnet account --genesis target/testnet-journal-lab/genesis-data/genesis.json --node 127.0.0.1:19001 --address DIRECCION_HEXADECIMAL
.\target\debug\nexus.exe testnet transfer --genesis target/testnet-journal-lab/genesis-data/genesis.json --node 127.0.0.1:19001 --key target/testnet-journal-lab/genesis-data/faucet.key --to DIRECCION_HEXADECIMAL --amount 1.25
```

Sustituir `DIRECCION_HEXADECIMAL` por una dirección real de 32 bytes. Los importes decimales se convierten de forma exacta a unidades mínimas, con hasta 18 decimales. La respuesta de transferencia indica **pending**: la cola es volátil y el reconocimiento de recepción no implica finalidad. La inclusión se acredita con el bloque y sus tres firmas; el cliente debe retransmitir si una operación pendiente se pierde antes de ser incluida.

El archivo público `genesis.json` fija protocolo, hash de génesis, dominio de red y contexto del comité. Una versión o compromiso que no coincida se rechaza. Los archivos `validator-*.key` y `faucet.key` son secretos **sin cifrar**, generados exclusivamente para este laboratorio. No se imprimen sus bytes ni se incluyen en el archivo público. El lanzador no los regenera si faltan en un despliegue existente.

## Un nodo individual y observadores

`nexus testnet run --help` describe `--genesis`, `--data-dir`, `--key`, `--listen`, múltiples `--peer`, `--poll-ms` y `--run-for-seconds`. Al reiniciar conserva el mismo directorio y clave; si encuentra un diario lo abre y valida, sin crear una cadena nueva como alternativa a un error. La recuperación utiliza las firmas guardadas y no vuelve a generarlas. Un temporal interrumpido se ignora; corrupción o huecos intermedios en registros publicados impiden abrir. Cada validador debe tener una clave y un único diario activo.

Sin `--key` el proceso es observador: verifica y aplica certificados, sin votar. Puede servir datos y certificados para sincronizar. Los clientes rechazan por defecto consultas de saldo sin atestación de validador; un saldo atestado es la declaración autenticada de ese validador, no una prueba independiente de pertenencia al estado. Para verificarlo independientemente hay que reproducir la historia, como hace la prueba de integración.

El transporte es TCP público en claro. ML-DSA autentica consenso y respuestas a consultas, con nonce y contexto; no aporta confidencialidad. Hay límites de tramas, conexiones, solicitudes por IP, cola y bytes pendientes. No se presenta como defensa completa ante DDoS.

## Antes de Internet

La publicación experimental usa la pasarela/túnel de la guía Docker; separar los validadores requiere máquinas y operación adicionales. La operación sostenida requiere resolver la retención de historia en RAM y la recuperación creciente. `--listen` admite una dirección externa, pero este laboratorio escucha solo en loopback. Cuatro procesos de un mismo ordenador no prueban independencia de máquinas ni de operadores. No hay migración automática del protocolo anterior ni admisión abierta de validadores. El diario presupone almacenamiento confiable: no evita rollback por el propietario, duplicación de claves ni pérdida de metadatos ante un corte eléctrico.

[Auditoría actual y diario incremental](../Documentos/06-Evidencia-TG2/2026-10-30/Auditoria-Actual-y-Journal/README.md) · [Evidencia TCP anterior](../Documentos/06-Evidencia-TG2/2026-10-30/Testnet-TCP/README.md) · [Documentación de arquitectura](../documentacion.md).
