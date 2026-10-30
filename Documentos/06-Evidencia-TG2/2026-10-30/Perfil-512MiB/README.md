# Ensayo del despliegue con límite de 512 MiB — 30 de octubre de 2026

Se añade una alternativa de menor costo que conserva los cuatro nodos y la misma imagen Linux. La [tarifa oficial de DigitalOcean Basic Regular](https://www.digitalocean.com/pricing/droplets) publica VPS de 1 GiB a US$6/mes: cuatro suman **US$24/mes de base**, antes de impuestos y extras. La [propuesta actualizada](../../../../nexus/deploy/ALOJAMIENTO.md) mantiene también cuatro VPS de 2 GB/GiB por US$48 de base. No se han contratado recursos ni elegido cuenta, región o presupuesto.

## Qué se probó

`prepare.py` y el helper de contenedores aceptan `--memory-limit 512m`; el valor predeterminado sigue siendo `1g`. El manifiesto y los cuatro `compose.json` registran el límite elegido. Se rechazan valores no admitidos antes de crear la salida. **Ocho pruebas Python pasan**, incluida la propagación del perfil a los cuatro nodos.

Se repite el ensayo completo con cuatro contenedores y se comprueba mediante inspección de Docker que cada uno tiene un límite efectivo de **536.870.912 bytes**. Se verifican cuatro identidades, una raíz certificada común, transferencias de 1,25 y 0,75 NXS, progreso con tres, detención con dos, recuperación tras cortes SIGKILL y recreación conservando los volúmenes y el saldo de 2 NXS. Los contenedores y la red propios se retiran al finalizar; sus volúmenes se conservan.

[Resultados](containers-run.json) · [Consultas certificadas](verified-queries.json) · [Logs](containers.log) · [Pruebas Python](python-tests.log) · [Huellas y metadatos](verification.json). La plantilla de cuatro nodos no contiene archivos de claves privadas y emplea direcciones reservadas para documentación, sin endpoints públicos reales.

El ID de la imagen sigue siendo `sha256:9a116eec1e0e5b2e1adb018ed843eb4719eb1c707c4b5cdf175aab9f9da28557`. No se modifican Rust, Cargo, el binario, el manuscrito ni Lean. El check, las 436 pruebas Rust y el build release de esa imagen se conservan en la [evidencia Linux anterior](../Despliegue-Linux/README.md); no se presentan como una nueva ejecución en esta etapa. Solo cambian los scripts de configuración/prueba del límite de memoria.

## Límites y decisión pendiente

El ensayo limita contenedores dentro de Docker Desktop: no simula todo el consumo de un VPS de 1 GiB, no prueba una carga sostenida ni elimina el crecimiento del historial. Es evidencia para una primera prueba acotada, con observación de memoria, disco y sincronización, no una garantía de capacidad de producción.

El despliegue público continúa pendiente de la decisión de alojamiento y presupuesto, de hosts autorizados y de pruebas desde otra red. La nueva alternativa de costo no reduce el número de validadores ni modifica reglas monetarias o firmas. Se conservan las hipótesis de quórum y los límites de custodia, almacenamiento y composición poscuántica de las etapas anteriores.
