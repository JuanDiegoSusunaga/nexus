# Bitácora del prototipo NEXUS — TG2

## Separación del alcance en la rama principal — 10 de noviembre de 2026

El autor considera que el trabajo del 30 de octubre se aproxima demasiado a un producto de criptomoneda y solicita separarlo. Antes de modificar se vuelve a ejecutar la suite sobre `dd46a0f`: 436 pruebas aprobadas, ninguna fallida. Ese estado se conserva sin cambios en la rama [`testnet-experimental`](https://github.com/JuanDiegoSusunaga/nexus/tree/testnet-experimental).

En `main` se revierte ese commit y se reincorpora únicamente lo ligado a los objetivos de la tesis: verificación de posición en `MerkleProof`, contabilidad de validadores, autorización de claves L2 por épocas, bloqueo de emergencia, motor BFT con ML-DSA-65 y diario incremental, junto con el corpus público que permite probar desde un solo clon. Se retiran el perfil monetario NXS, el transporte TCP y sus comandos, los paquetes Docker, la propuesta de alojamiento, la publicación mediante túnel y el documento de tecnologías con comparación de criptomonedas y análisis financiero.

El motor BFT dependía del génesis monetario para obtener su dominio. Se sustituye por un génesis ligado a un identificador de despliegue con saldos experimentales explícitos, sin emisión, comisiones ni quema. Las pruebas de transferencias certificadas, líder ausente, detención sin quórum, líder equívoco, recuperación del diario y salida abrupta se conservan adaptadas. No se añade funcionalidad nueva.

Pasan `cargo check --workspace --all-targets`, `cargo build --workspace` y **412 pruebas**, con una ignorada, locked/offline y rustc 1.97.1. Cambian las versiones de checkpoint de `AnchorChain` (4) y `DurableNode` (5) y del diario BFT (3); el protocolo permanece en 4. La evidencia del 30 de octubre que se conserva identifica las fuentes de `dd46a0f` y se mantiene como registro histórico.

El enlace público temporal del 30 de octubre ya no está activo. No se modifica manuscrito ni Lean. [Contrato vigente](REPRODUCIBILIDAD_TG2.md#alcance-de-la-rama-principal--10-de-noviembre-de-2026) · [Pendientes](PENDIENTES.md).

## Docker público y conservación exclusiva — 30 de octubre de 2026

El autor solicita publicar desde su Docker y no confirma acceso al router. Se prepara una instancia nueva de cuatro validadores con claves y diarios separados, pasarela HTTP de cuatro destinos fijos y Cloudflare Quick Tunnel saliente. Se conservan firmas y certificados de la CLI nativa; no se exponen la API Docker, claves, faucet o exploración de directorios. El conjunto queda activo con puertos del host ligados a loopback. No se configuran router o firewall ni se contratan servidores.

Pasan 17 pruebas Python. El cliente Windows verifica cuatro identidades y una transferencia de 1,25 NXS por el enlace HTTPS público. Una sonda HTTP de Los Ángeles obtiene 200. Otro contenedor, sin claves ni acceso a la red de los servidores, descarga y comprueba hashes del génesis/cliente/scripts antes de ejecutarlos y verifica cuatro identidades con raíz certificada común en altura 157. Ambos clientes criptográficos comparten el computador físico del operador; la sonda externa comprueba solo accesibilidad HTTP. La guía conserva esa distinción.

El autor pide guardar exclusivamente en `https://github.com/JuanDiegoSusunaga/nexus`. Se incluyen documentación y evidencia pública en ese repositorio. Veinte archivos binarios de regresión conservan sus bytes y dos pruebas cambian solo la ruta para encontrarlos dentro del clon. Se adapta el contexto Docker a la raíz de este repositorio y se verifica la construcción independiente; no se reemplaza la imagen de los nodos activos ni sus diarios. Las versiones siguen en protocolo 4 y diario 2.

NXS es una unidad de prueba sin precio establecido ni conversión garantizada; publicación, quema o suministro limitado no asignan precio. Persisten un único dominio físico de fallo, comité fijo, claves sin cifrar en el host, historia creciente en RAM/disco y ausencia de composición poscuántica integral. Se conservan las hipótesis de la tesis y el pendiente de refinamiento Rust/Lean; AIR/FRI no acredita ejecución general L2 y QROM completo permanece como trabajo futuro. No se modifica TG1, manuscrito ni Lean.

La guía, los scripts y la evidencia de esta etapa se conservan en la rama [`testnet-experimental`](https://github.com/JuanDiegoSusunaga/nexus/tree/testnet-experimental).
