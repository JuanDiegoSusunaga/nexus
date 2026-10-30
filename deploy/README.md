# Despliegue Linux de la testnet NEXUS

El paquete prepara cuatro validadores con NXS de prueba. El autor eligió publicar inicialmente desde su propio Docker: [guía y enlace temporal](PUBLICAR_DOCKER.md), con [evidencia de acceso público](../Documentos/06-Evidencia-TG2/2026-10-30/Docker-Publico/README.md). Los cuatro validadores comparten un computador. La [propuesta de alojamiento](ALOJAMIENTO.md) permanece como alternativa para separarlos entre máquinas; no se contratan servidores.

## Imagen verificable

Desde la raíz de este repositorio `nexus`, con Docker Engine y Compose disponibles:

```powershell
docker compose --progress plain -f deploy/compose.build.yaml build
docker image inspect nexus-testnet:protocol4-journal2 --format '{{.Id}}'
```

El Dockerfile fija las imágenes base por digest, conserva `Cargo.lock`, ejecuta check de todos los targets, la suite completa y el build release de `nexus-cli`. El contexto se limita a fuentes Rust y veinte artefactos públicos de regresión: catorce certificados y seis contraejemplos. No incorpora claves, diarios, `.git`, dependencias locales ni manuscrito. El corpus solo se usa durante el build. La imagen final contiene el binario y el sistema base, sin fuentes ni corpus de pruebas.

El runtime usa UID/GID **10001**, sistema de archivos raíz de solo lectura, capacidades eliminadas y `no-new-privileges`. Cada nodo tiene un único archivo de clave montado como solo lectura y su volumen de datos independiente. El paquete fija el **ID completo de la imagen** y desactiva pulls implícitos; debe cargarse exactamente esa imagen en cada máquina. [Construcción por etapas](https://docs.docker.com/build/building/multi-stage/) y [atributos oficiales de Compose](https://docs.docker.com/reference/compose-file/services/).

## Prueba entre contenedores

Con el cliente nativo Windows ya compilado, desde `nexus/`:

```powershell
python -m unittest discover -s deploy -p test_prepare.py -v
python deploy/test_containers.py
```

Para probar el límite de 512 MiB por nodo: `python deploy/test_containers.py --memory-limit 512m`. El generador admite también `--memory-limit 512m` para trasladar ese límite a los cuatro paquetes y al manifiesto; el valor predeterminado sigue siendo `1g`. El ensayo local con 512 MiB pasa, pero no acredita el rendimiento sostenido de un VPS completo de 1 GiB. [Resultados del perfil](../Documentos/06-Evidencia-TG2/2026-10-30/Perfil-512MiB/README.md).

La prueba usa un proyecto Compose único, cuatro direcciones de una subred bridge libre y puertos aleatorios publicados solo en loopback. Consulta las subredes de Docker y elige una `/24` sin solapamientos dentro de `10.240.0.0/16`; si ninguna está libre, falla sin modificar redes ajenas. El ensayo verifica identidades distintas, consultas firmadas, aislamiento, transferencias de 1,25 y 0,75 NXS, avance con tres, detención con dos, recuperación tras SIGKILL y recreación de contenedores conservando volúmenes. Al terminar elimina únicamente sus contenedores/red; conserva volúmenes y artefactos en `target/container-process-tests/` para revisar fallos. No usar `down -v` para limpiar un validador activo.

La consulta de salud comprueba que el proceso responde con una atestación válida; un nodo atrasado también puede responder. Hay que vigilar **altura y retraso**, además de `healthy`.

## Preparar un génesis y paquetes públicos

Crear un génesis nuevo exclusivamente para la futura red. En Windows, desde `nexus/`, con el cliente compilado:

```powershell
.\target\debug\nexus.exe testnet init --out target/public-bootstrap-01 --block-time-ms 5000
$nexusImage = docker image inspect nexus-testnet:protocol4-journal2 --format '{{.Id}}'
python deploy/prepare.py --genesis target/public-bootstrap-01/genesis.json --out target/public-bundle-01 --image-id $nexusImage --endpoint IP_NODO_0:19001 --endpoint IP_NODO_1:19001 --endpoint IP_NODO_2:19001 --endpoint IP_NODO_3:19001
docker image save --output target/nexus-testnet-linux.tar nexus-testnet:protocol4-journal2
Get-FileHash target/nexus-testnet-linux.tar -Algorithm SHA256
```

Sustituir las cuatro IP por direcciones globales reales de los hosts autorizados; el generador rechaza nombres de shell, puertos reservados, direcciones no globales y endpoints duplicados. `--allow-nonpublic` sirve para plantillas documentales o ensayos y no demuestra publicación. La comprobación criptográfica completa del génesis la realiza el cargador nativo de NEXUS al arrancar.

`init` genera cuatro claves de validador y un faucet **sin cifrar**; se conservan fuera del paquete público y no deben versionarse. Cada `node-N/` del paquete contiene únicamente su `compose.json` y el génesis público. El manifiesto identifica la clave pública esperada y el archivo de origen correspondiente. Instalar **solo** `validator-N.key`, renombrado a `validator.key`, en el directorio de ese nodo; no copiar el conjunto ni `faucet.key` a los servidores. La fase inicial mantiene al equipo como custodio de esas claves de prueba; no ofrece custodia distribuida ni HSM.

El directorio de salida debe ser nuevo. El nombre del proyecto/volumen se deriva del hash de génesis, no de los espacios del JSON. No crear otra instancia o vaciar/restaurar un volumen con la misma clave y el mismo génesis: el bloqueo de archivo no coordina diarios copiados en otros hosts. Para reiniciar se conserva siempre el diario. No existe migración automática del snapshot BFT v1.

## Arranque en cada servidor elegido

Requisitos: Linux amd64, Docker Engine y Compose instalados, reloj sincronizado y acceso administrativo autorizado. [Instalación oficial en Debian](https://docs.docker.com/engine/install/debian/). La imagen debe compilarse previamente; no es necesario instalar Rust en cada VPS.

Transferir por el canal administrativo la imagen y las configuraciones públicas. Comprobar su SHA-256 contra la huella registrada en la estación de preparación antes de cargarla. Instalar la clave de ese nodo aparte, sin incluir sus bytes en comandos, logs ni variables de entorno. En un directorio que contenga `compose.json`, `genesis.json` y `validator.key`, preparado para el nodo correspondiente:

```bash
sudo chown 10001:10001 validator.key
sudo chmod 0400 validator.key
sudo chmod 0700 .
docker image load --input /ruta/nexus-testnet-linux.tar
docker image inspect nexus-testnet:protocol4-journal2 --format '{{.Id}}'
docker compose -f compose.json config --quiet
docker compose -f compose.json up -d
docker compose -f compose.json ps
docker compose -f compose.json logs --tail 50
```

El ID inspeccionado debe coincidir con `manifest.json` y `compose.json`. El directorio del nodo debe pertenecer a su administrador y tener acceso restringido; la clave debe pertenecer a UID 10001 para que el contenedor pueda leerla. Compose usa un bind mount de archivo: no se confía en remapeos declarativos de propietario para ese secreto. [Limitación documentada de Compose](https://docs.docker.com/reference/compose-file/services/#secrets).

El volumen persistente se inicializa a partir del directorio de datos de la imagen, propiedad de UID 10001. No se monta el socket Docker dentro del nodo. El firewall de nube permite el puerto NEXUS y restringe SSH al origen administrativo. Revisar el filtrado de puertos publicados: Docker puede eludir reglas UFW; véanse las [limitaciones oficiales](https://docs.docker.com/engine/install/debian/#firewall-limitations).

## Validación desde otra red

Distribuir el mismo `genesis.json` público y usar `nexus testnet status`, `account` y `transfer` contra las cuatro IP. Desde `nexus/`, el siguiente comando registra consultas autenticadas y exige cuatro identidades distintas y una altura certificada común con la misma raíz:

```powershell
python deploy/verify_public.py --binary target/debug/nexus.exe --genesis target/public-bootstrap-01/genesis.json --endpoint IP_NODO_0:19001 --endpoint IP_NODO_1:19001 --endpoint IP_NODO_2:19001 --endpoint IP_NODO_3:19001 --out target/verificacion-externa-01.json
```

El script verifica las respuestas mediante el cliente nativo; no reproduce toda la historia ni deduce por sí solo que el equipo de origen esté fuera de los servidores. Registrar también esa procedencia con evidencia del entorno de ejecución. Probar una transferencia desde el faucet, caída de un nodo, recuperación y convergencia. Registrar hora, alturas, hashes, certificados y recursos. Una respuesta `pending` no acredita inclusión: la cola es volátil.

La publicación se considera pendiente hasta que los endpoints y el génesis definitivos estén disponibles y estas verificaciones se ejecuten **desde fuera** de los servidores. No se exige un operador humano externo para iniciar la testnet, pero se declara quién controla los nodos y sus dominios de fallo. La composición poscuántica integral y la ejecución general L2 mediante AIR/FRI siguen fuera de lo demostrado por este paquete.
