# Bitácora del prototipo NEXUS — TG2

## Docker público y conservación exclusiva — 30 de octubre de 2026

El autor solicita publicar desde su Docker y no confirma acceso al router. Se prepara una instancia nueva de cuatro validadores con claves y diarios separados, pasarela HTTP de cuatro destinos fijos y Cloudflare Quick Tunnel saliente. Se conservan firmas y certificados de la CLI nativa; no se exponen la API Docker, claves, faucet o exploración de directorios. El conjunto queda activo con puertos del host ligados a loopback. No se configuran router o firewall ni se contratan servidores.

Pasan 17 pruebas Python. El cliente Windows verifica cuatro identidades y una transferencia de 1,25 NXS por el enlace HTTPS público. Una sonda HTTP de Los Ángeles obtiene 200. Otro contenedor, sin claves ni acceso a la red de los servidores, descarga y comprueba hashes del génesis/cliente/scripts antes de ejecutarlos y verifica cuatro identidades con raíz certificada común en altura 157. Ambos clientes criptográficos comparten el computador físico del operador; la sonda externa comprueba solo accesibilidad HTTP. La guía conserva esa distinción.

El autor pide guardar exclusivamente en `https://github.com/JuanDiegoSusunaga/nexus`. Se incluyen documentación y evidencia pública en ese repositorio. Veinte archivos binarios de regresión conservan sus bytes y dos pruebas cambian solo la ruta para encontrarlos dentro del clon. Se adapta el contexto Docker a la raíz de este repositorio y se verifica la construcción independiente; no se reemplaza la imagen de los nodos activos ni sus diarios. Las versiones siguen en protocolo 4 y diario 2.

NXS es una unidad de prueba sin precio establecido ni conversión garantizada; publicación, quema o suministro limitado no asignan precio. Persisten un único dominio físico de fallo, comité fijo, claves sin cifrar en el host, historia creciente en RAM/disco y ausencia de composición poscuántica integral. Se conservan las hipótesis de la tesis y el pendiente de refinamiento Rust/Lean; AIR/FRI no acredita ejecución general L2 y QROM completo permanece como trabajo futuro. No se modifica TG1, manuscrito ni Lean.

[Guía](deploy/PUBLICAR_DOCKER.md) · [Evidencia y resultados exactos](Documentos/06-Evidencia-TG2/2026-10-30/Docker-Publico/README.md) · [Pendientes](PENDIENTES.md).
