# NEXUS pública desde Docker — ensayo del 30 de octubre de 2026

La testnet experimental está publicada en <https://dreams-humanities-shelter-utilities.trycloudflare.com>. Ejecuta cuatro validadores ML-DSA-65 en Docker Desktop, en un solo computador. NXS identifica aquí monedas de prueba de este génesis: no existe un precio de mercado establecido para ellas ni conversión garantizada a pesos o dólares.

## Acceso y alcance

| Recurso | Dirección |
|---|---|
| Descripción y descargas | <https://dreams-humanities-shelter-utilities.trycloudflare.com/> |
| Estado del primer nodo | <https://dreams-humanities-shelter-utilities.trycloudflare.com/status/0> |
| Otros estados | Misma URL con `/status/1`, `/status/2` y `/status/3` |
| Génesis público | Misma URL con `/genesis.json` |
| RPC binario de cada nodo | POST a `/rpc/0` hasta `/rpc/3`, mediante el adaptador descrito abajo |

El túnel establece conexiones salientes; no se configuraron el router, reglas entrantes de Windows ni la API de Docker. Los cinco puertos publicados en el host están ligados a `127.0.0.1`: gateway 18080 y nodos 19001–19004. [Documentación de publicación de puertos Docker](https://docs.docker.com/engine/network/port-publishing/).

Cloudflare Quick Tunnel permite este enlace temporal sin cuenta ni dominio. El nombre cambia al crear otro túnel y no hay garantía de disponibilidad; requiere computador, Docker y conexión activos. Es un servicio para desarrollo y pruebas. [Condiciones y límites oficiales](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/).

La pasarela recibe únicamente tramas NXSNET04 de longitud acotada y las transmite a cuatro destinos fijos. El cliente nativo sigue verificando nonces, contexto, firmas y certificados BFT; HTTPS no reemplaza esa validación. `/status/N` presenta el resultado que verificó la CLI dentro de la pasarela. Para verificarlo desde el cliente se utiliza `/rpc/N`. La pasarela no tiene claves privadas, endpoint para firmar con el faucet, explorador de archivos ni socket Docker.

## Operar la instancia que ya existe

Desde `nexus/`, con Docker Desktop iniciado:

```powershell
python deploy/home.py status
```

Para volver a iniciarla tras una detención y publicar el túnel:

```powershell
python deploy/home.py publish
```

El comando imprime la URL vigente. `python deploy/home.py start` inicia solo el conjunto local si aún no hay túnel activo. La publicación usa el perfil Compose `internet`. Para detener los seis servicios propios conservando los volúmenes:

```powershell
python deploy/home.py stop
```

Los archivos operativos están en `target/home-testnet/`; las claves, en su subdirectorio `keys/`. Conservar génesis, claves y diarios; no ejecutar `prepare` sobre esta instancia, borrar volúmenes, usar `down -v`, duplicar claves en diarios distintos ni restaurar un diario antiguo mientras la misma clave sigue activa. El comando `prepare` rechaza una salida existente. Las claves de este ensayo están sin cifrar en el host; cada validador monta solo la suya como lectura y el faucet permanece fuera de los contenedores.

Para revisar consumo y disco, sin modificar otros proyectos Docker:

```powershell
docker compose -f target/home-testnet/compose.json --profile internet ps
docker stats --no-stream nexus-home-fd0b8883c82078d6-node-0-1 nexus-home-fd0b8883c82078d6-node-1-1 nexus-home-fd0b8883c82078d6-node-2-1 nexus-home-fd0b8883c82078d6-node-3-1
docker exec nexus-home-fd0b8883c82078d6-node-0-1 du -sh /var/lib/nexus
```

Comprobar alturas y retraso en los cuatro estados además de `healthy`. Cada nodo tiene límite de 512 MiB; pasarela y túnel, 256 MiB cada uno. Los diarios crecen y el nodo conserva historia en RAM; todavía no hay poda ni recuperación de costo acotado. Usar ventanas de ensayo con seguimiento de recursos. Los límites no prueban resistencia a DDoS ni operación indefinida.

## Conectarse desde otro equipo

Se ofrece el cliente nativo Linux amd64 ya utilizado por los nodos, junto con un adaptador Python 3 sin dependencias externas. La descarga aislada, validación de huellas y verificación criptográfica de los cuatro nodos se ejecutaron en otro contenedor, sin claves ni pertenencia a la red Docker de los servidores. Ese cliente comparte el computador físico del operador.

Descargar en un directorio nuevo estos cuatro recursos de la URL vigente:

| Ruta | Archivo | SHA-256 fijado para este ensayo |
|---|---|---|
| `/genesis.json` | `genesis.json` | `d5152429cc9642039795bd1ff8ea2df14ecc357c71750cf6fd9a96d3348c4f74` |
| `/client/home_connect.py` | `home_connect.py` | `093b8b46ed0c41a962790a086854784fb0e57a9f5dbb3de8b953ccd70a6f4479` |
| `/client/home_transport.py` | `home_transport.py` | `fb05158183eacfe73f05649889f0cad2bb80eb727b1fe507ad00d329d5a6f18e` |
| `/client/nexus-linux-amd64` | `nexus-linux-amd64` | `0fc54744a574792092497b643f38f405c018a5f9db3455ba746eb08140767a40` |

Comparar las huellas antes de importar o ejecutar lo descargado. La referencia de confianza debe provenir de la copia revisada de esta guía/manifiesto, obtenida por un canal confiable; las huellas anunciadas por la misma pasarela no bastan para establecer confianza inicial. El hash de bloque génesis es `fd0b8883c82078d6911b4eeb28dd5b3af59de27d0810c90f7ed3a6b364a0780a`, distinto del SHA-256 del archivo JSON.

Ejemplo en Linux, sustituyendo la URL si el túnel fue recreado:

```bash
export NEXUS_URL=https://dreams-humanities-shelter-utilities.trycloudflare.com
curl -fSs "$NEXUS_URL/genesis.json" -o genesis.json
curl -fSs "$NEXUS_URL/client/home_connect.py" -o home_connect.py
curl -fSs "$NEXUS_URL/client/home_transport.py" -o home_transport.py
curl -fSs "$NEXUS_URL/client/nexus-linux-amd64" -o nexus-linux-amd64
sha256sum genesis.json home_connect.py home_transport.py nexus-linux-amd64
```

Una vez comprobadas las cuatro huellas:

```bash
chmod u+x nexus-linux-amd64
python3 home_connect.py --url "$NEXUS_URL"
```

El adaptador queda activo y escucha únicamente en `127.0.0.1:19901–19904`. Desde otra sesión del cliente:

```bash
./nexus-linux-amd64 testnet status --genesis genesis.json --node 127.0.0.1:19901
./nexus-linux-amd64 testnet status --genesis genesis.json --node 127.0.0.1:19902
./nexus-linux-amd64 testnet status --genesis genesis.json --node 127.0.0.1:19903
./nexus-linux-amd64 testnet status --genesis genesis.json --node 127.0.0.1:19904
```

La CLI verifica las respuestas y el certificado de altura. Como las consultas son sucesivas, las alturas pueden diferir mientras avanza la cadena. El cliente Windows ya compilado en el repositorio puede usar el mismo adaptador; la descarga pública del binario preparada aquí es Linux amd64. No se distribuyen claves del faucet ni de validadores.

## Evidencia y pendientes

[Registro completo](../Documentos/06-Evidencia-TG2/2026-10-30/Docker-Publico/README.md): 17 pruebas Python correctas; transferencia de 1,25 NXS por HTTPS verificada en los cuatro nodos; cliente descargado que verifica cuatro identidades y una raíz certificada común en altura 157. Una sonda HTTP independiente en Los Ángeles obtiene 200 de `/status/0`. La sonda comprueba accesibilidad; la verificación criptográfica y las transferencias se hicieron desde clientes en el mismo computador físico. No se afirma una transferencia criptográficamente verificada desde otro equipo físico.

El comité tiene cuatro claves fijas bajo un operador y exige tres votos. Los cuatro procesos comparten energía, almacenamiento y conectividad. Sigue pendiente repartirlos entre dominios de fallo y operadores independientes, integrar el ciclo completo Sentinel/rotación en las claves del comité, custodia robusta y operación sostenida. La apertura es de consulta y envío de transacciones, no de ingreso libre al comité.

La tesis aporta firmas y modelos matemáticos con sus hipótesis; no se acredita por este despliegue una prueba integral de seguridad poscuántica. AIR/FRI aún no prueba la ejecución general de L2; falta refinamiento universal Rust/Lean. QROM completo permanece como trabajo futuro según la decisión del autor. Manuscrito, TG1 y Lean no se modifican.

El perfil monetario de prueba fija 1.000.000 NXS iniciales en el faucet, máximo histórico emitido de 2.000.000 NXS, subsidio inicial de 1 NXS por bloque y reducción a la mitad cada 1.000.000 bloques. Se quema el 25 % de la comisión cobrada. Son parámetros experimentales, sin vinculación con una moneda fiduciaria, promesa de rentabilidad o asignación de precio. La quema no aumenta el máximo histórico permitido ni establece un precio.
