# Publicación experimental desde Docker — 30 de octubre de 2026

El autor eligió su propio Docker para publicar NEXUS y respondió que no tenía acceso al router o no estaba seguro. Se implementó una pasarela HTTP de destinos fijos y un Cloudflare Quick Tunnel saliente, sin configurar router/firewall ni contratar servidores. [Guía operativa](../../../../deploy/PUBLICAR_DOCKER.md). Este incremento se conserva exclusivamente en `JuanDiegoSusunaga/nexus` por indicación del autor.

**URL del ensayo:** <https://dreams-humanities-shelter-utilities.trycloudflare.com>. Cuatro validadores y una pasarela/túnel en un mismo computador; comité fijo bajo un operador. La consulta y presentación de transacciones son públicas, con firmas y certificados ML-DSA-65 verificados por la CLI original. La URL es temporal y puede dejar de estar disponible tras cerrar o recrear el túnel. [Límites oficiales de Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/).

## Comprobaciones conservadas

| Archivo | Comprobación | Alcance |
|---|---|---|
| `python-tests.log` | 17 pruebas correctas: ocho del generador y nueve de pasarela/adaptador | Límites, tramas, destinos fijos, rutas públicas y roundtrip HTTP local |
| `python-compile.log` | Compilación sintáctica de scripts de despliegue | Python; no recompila Rust |
| `gateway-build.log` | Construcción real de la imagen Python + CLI nativa | Base Python fijada por digest; contexto sin claves |
| `http-local-check.json` | Cuatro identidades, raíz certificada común en altura 13 y transferencia de 1,25 NXS | Adaptador HTTP loopback; mismo host |
| `https-public-check.json` | Cuatro identidades, raíz común en altura 35 y transferencia de 1,25 NXS incluida en los cuatro nodos | Túnel HTTPS público; cliente en el mismo host |
| `downloaded-client-check.json` | Descarga pública de génesis, dos scripts y binario Linux; huellas verificadas antes de ejecutarlos; cuatro identidades y raíz común en altura 157 | Contenedor cliente aislado, sin claves ni pertenencia a la red de servidores; mismo computador físico |
| `external-http-request.json`, `external-http-result.json` | HTTP 200 desde la sonda `us1.node.check-host.net`, Los Ángeles, EE. UU. | Accesibilidad desde otra red; la sonda no verifica firmas BFT ni envía una transferencia |
| `runtime.json`, `live-status.json` | Seis servicios activos, límites y montajes filtrados; estados en el momento de captura | Fotografía operativa, sin claves ni garantía de disponibilidad futura |
| `verification.json` | Hashes de fuentes y artefactos, imagen, génesis y límites | Trazabilidad de esta etapa |

[Reporte externo de Check-Host](https://check-host.net/check-report/548564eakd6f), petición `548564eakd6f`. El archivo del resultado conserva el código 200 y la respuesta OK de esa sonda. La descarga/validación completa del cliente y las transferencias conservadas tuvieron origen en el mismo computador físico del servidor. No se afirma que una máquina física externa haya validado criptográficamente una transferencia.

La transferencia por HTTPS tiene identificador `214d41f0585a6d4eb6b0b65cc6a1d6a83957714b7b4c7537ccdd4057374e284e`. La raíz certificada observada por el cliente descargado en altura 157 es `1111b65832ca8f9c351fc358e7d38adae7ed752339a432906e3c020d0dff7f51`. Se conservan los informes completos de las consultas; las alturas posteriores siguen creciendo.

## Identidad y aislamiento

- Protocolo 4; diario BFT 2. Génesis: `fd0b8883c82078d6911b4eeb28dd5b3af59de27d0810c90f7ed3a6b364a0780a`.
- SHA-256 del JSON público: `d5152429cc9642039795bd1ff8ea2df14ecc357c71750cf6fd9a96d3348c4f74`.
- Imagen nativa: `sha256:9a116eec1e0e5b2e1adb018ed843eb4719eb1c707c4b5cdf175aab9f9da28557`. Binario Linux: `0fc54744a574792092497b643f38f405c018a5f9db3455ba746eb08140767a40`.
- La imagen de pasarela efectiva y el digest oficial de cloudflared se registran en el manifiesto. Cada nodo tiene una clave montada como lectura y un volumen propio; pasarela y túnel no montan claves ni socket Docker.
- Puertos del host ligados a `127.0.0.1`; el acceso externo usa el túnel HTTP. No se publican directorios ni secretos. Solo se sirven génesis público y tres archivos de cliente expresamente permitidos.

La imagen nativa activa conserva las **436 pruebas Rust**, check y build de la [etapa Linux anterior](../Despliegue-Linux/verification.json). Los 160 archivos de la [línea base de 512 MiB](../Perfil-512MiB/verification.json) se comparan por hash, identificando por separado los cambios de empaquetado: contexto/Dockerfile y rutas de corpus de dos pruebas. No cambia el código Rust de producción. Además se construye una imagen independiente desde el repositorio completo para comprobar check, pruebas y build con el corpus incluido; sus resultados exactos constan en `standalone-build.log` y el manifiesto, sin reemplazar los nodos activos.

## Límites y siguiente etapa

Se deja el conjunto publicado y activo por solicitud del autor. El túnel no ofrece nombre estable ni garantía de disponibilidad. Los cuatro validadores comparten energía, host y conectividad, por lo que el ensayo no demuestra tolerancia a la pérdida de un computador ni custodia distribuida. Continúan pendientes operadores independientes, retención/poda de historia en RAM/disco, recuperación creciente y capacidad sostenida. Los topes de conexiones y memoria no constituyen una garantía general contra DDoS.

Las claves del comité son fijas: el ciclo completo de fuente de entropía y rotación Sentinel todavía no está integrado en ellas. La prueba de quórum de la tesis conserva sus hipótesis; el despliegue no establece un refinamiento universal Rust/Lean, ejecución general L2 probada por AIR/FRI ni composición poscuántica integral. QROM completo permanece como trabajo futuro. Manuscrito, TG1 y Lean se conservan.

NXS se utiliza exclusivamente como unidad de prueba de este génesis, sin cotización de mercado establecida o conversión garantizada. La publicación no crea un precio, respaldo en moneda fiduciaria ni validación académica adicional. El código y esta documentación se guardan únicamente en el repositorio indicado por el autor; no se contratan recursos ni se envían comunicaciones a terceros.
