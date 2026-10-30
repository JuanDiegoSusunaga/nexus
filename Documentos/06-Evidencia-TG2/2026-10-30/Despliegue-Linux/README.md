# Preparación del despliegue Linux — 30 de octubre de 2026

Se prepara el siguiente paso hacia la testnet pública: imagen Linux amd64, paquetes de cuatro nodos, validación de consultas y procedimiento de instalación. El autor indicó que todavía no ha pensado el alojamiento. **No hay servidores contratados ni endpoints públicos desplegados.** La [propuesta de alojamiento](../../../../nexus/deploy/ALOJAMIENTO.md) y la [guía de despliegue](../../../../nexus/deploy/README.md) quedan listas para revisión.

## Verificación realizada

| Comprobación | Resultado |
|---|---|
| Linux, Rust 1.97.1, Debian bookworm | Check de todos los targets, **436 pruebas correctas** y build release de `nexus-cli` |
| Helper de pruebas | Uno ignorado en la ejecución ordinaria, invocado desde su prueba padre |
| Generación de paquetes | **7 pruebas Python correctas**: secreto separado, imagen fijada por contenido, rechazo de endpoints inválidos/duplicados, archivos no sobrescritos, proyecto estable ante cambios de espacios en JSON |
| Red entre cuatro contenedores | Cliente Windows verifica consultas firmadas, cuatro identidades distintas y certificados de raíz común en altura 2 |
| Transferencias y fallos | 1,25 NXS; avance con tres hasta altura 6; 0,75 NXS pendiente con dos; recuperación y saldo final de 2 NXS en los cuatro |
| Recreación conservando datos | Los cuatro vuelven a abrir en altura 9 y conservan el saldo esperado |
| Aislamiento comprobado | UID 10001, raíz solo lectura, capacidades eliminadas, sin nuevos privilegios, una clave de solo lectura por contenedor; sin fuentes ni Cargo en runtime |
| Cierre | Cero contenedores propios restantes; red de ensayo retirada y volúmenes conservados |

[Resultados del ensayo](containers-run.json), [testigo de consultas](verified-queries.json), [logs de contenedores](containers.log), [build completo](public-deploy-build.log), [pruebas Python](python-tests.log) y [metadatos, huellas y límites](verification.json). Los 132 archivos registrados en la auditoría anterior conservan sus huellas; esta etapa no cambia fuentes Rust, manuscrito ni Lean.

La imagen final tiene ID `sha256:9a116eec1e0e5b2e1adb018ed843eb4719eb1c707c4b5cdf175aab9f9da28557`. El archivo exportado local mide **29.945.344 bytes** y tiene SHA-256 `0b5977735e5840cf71c91c5e6c55eb50f6cc12b7b0bae8336e5047ce5bc6fdc6`. Su ubicación local está registrada en `verification.json`; el archivo grande no se incorpora al repositorio. No se afirma que compilar en otro entorno produzca idénticos bytes.

Una medición puntual al final del ensayo registra aproximadamente **5,8–7,0 MiB** de memoria por proceso dentro del límite de 1 GiB del contenedor. Es una observación con pocos bloques y sin carga sostenida; no permite dimensionar una red pública de larga duración ni elimina el crecimiento del historial en RAM.

## Correcciones del empaquetado

La primera construcción omitía el corpus externo de pruebas: [cuatro casos de contrato no podían abrir sus archivos](public-deploy-missing-corpus.log). Al incluir esos catorce certificados apareció otra dependencia: [una prueba requería los contraejemplos de proximidad](public-deploy-missing-counterexamples.log). El contexto definitivo incorpora exactamente los veinte artefactos públicos necesarios, con hashes registrados, sin omitir esas pruebas ni cambiar las matemáticas. Los logs UTF-16 de PowerShell se normalizan a UTF-8; se conservan sus hashes originales.

La primera red bridge propuesta estaba ocupada por otra red de Docker. El helper ahora consulta las subredes existentes y elige una `/24` libre, sin eliminar redes ajenas. El ensayo correcto usa `10.240.0.0/24`, cuatro IP distintas y puertos de host solo en loopback. Las redes especiales `host` y `none`, sin configuración IPAM, se tratan como tales.

## Paquetes públicos y pendientes

La [plantilla de manifiesto](template/manifest.json) y los cuatro `compose.json` contienen solo configuración pública. Utilizan direcciones reservadas para documentación y se generan con `allow-nonpublic`; no representan servidores disponibles. Cada nodo recibirá únicamente su clave, instalada por separado. No se copian archivos privados en esta evidencia ni se montan claves de otros validadores o del faucet en el contenedor.

Faltan elegir proveedor, cuenta y presupuesto; disponer de máquinas, direcciones y acceso administrativo; instalar la imagen y una clave por host; publicar el génesis definitivo y verificar transferencias, fallos y sincronización desde otra red. Los precios consultados son orientativos: cuatro planes de referencia de US$12 suman **US$48/mes de base**, antes de impuestos y extras. La elección y el gasto permanecen pendientes de decisión del autor.

La prueba usa cuatro contenedores **en una sola máquina**. No acredita independencia de máquinas u operadores, disponibilidad frente a caída de una región, resistencia DDoS, custodia de producción ni composición poscuántica integral. El verificador de consultas comprueba firmas y certificados mediante CLI; no reproduce toda la historia y no deduce el origen externo de la comprobación. Se mantiene la intersección de quórums de la matemática propia bajo sus hipótesis, sin afirmar un refinamiento completo Rust/Lean o ejecución general L2 mediante AIR/FRI.
