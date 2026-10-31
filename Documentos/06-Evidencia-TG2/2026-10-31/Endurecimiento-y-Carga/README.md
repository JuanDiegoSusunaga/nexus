# Endurecimiento del diario y medición de carga — 31 de octubre de 2026

El código revisado rechaza las APIs Groth16 genéricas no implementadas y sincroniza el directorio del diario en Unix. Si falla la sincronización después del renombrado, el registro publicado se conserva y el nodo exige recuperación antes de volver a firmar. No cambia el formato de protocolo v4 ni el diario v2. La actualización secuencial conserva el génesis y los cuatro volúmenes existentes.

## Verificación de las correcciones

- [439 pruebas Rust correctas](rust-tests-summary.json), cero fallos; un auxiliar de proceso hijo aparece ignorado en el ejecutor principal. [Registro completo](cargo-test.log).
- [Check del endurecimiento](cargo-check-hardening.log), [build release](cargo-build-release.log) y [check de todos los targets de la rama con el generador añadido](cargo-check-pr.log) correctos.
- [19 pruebas Python](python-tests.log), incluidas unidades de memoria Docker y separación entre oferta y vaciado; [build release del generador](cargo-build-load.log) correcto.
- [Actualización de los cuatro validadores](deployment.json) y [transferencia posterior de 1,25 NXS](transfer-after-deployment.json) correctas. Es evidencia previa a la medición del 31 de octubre.

El fallo de sincronización se inyecta en una prueba; no se simuló un corte eléctrico físico. La garantía depende del sistema de archivos y del almacenamiento. Otras plataformas conservan la sincronización del archivo sin afirmar persistencia del directorio. La ruta AIR/FRI escalar conserva su alcance; no se completa la reducción de seguridad de ML-DSA ni la prueba general de ejecución L2.

## Método de carga

Se utilizó la testnet existente: cuatro contenedores ML-DSA-65 en **un host cloud**, un CPU y 512 MiB de límite por validador, bloques configurados a 5.000 ms y límite del runtime de 16 transacciones candidatas por bloque. El entorno reporta cinco CPU lógicas y cuota cgroup de cuatro CPU; no se atribuyen cuatro máquinas u operadores independientes. Cliente y muestreador comparten recursos con los validadores.

El cliente financió 32 cuentas efímeras con un NXS de prueba cada una. Las **32 transferencias de preparación están excluidas** de los resultados de carga. Después ejecutó tres repeticiones de 30 s por concurrencia, rotando el orden de 1, 8 y 32 cuentas, con una operación pendiente por cuenta. Cada transferencia medida envía 0,000001 NXS, con gas límite 200.000 y el precio mínimo del génesis. Las claves efímeras no se guardan en archivos.

La confirmación exige el hash exacto de la operación dentro de un bloque con certificado de quórum verificado. Se comprueba continuidad de padres desde el tip inicial; no se reproduce toda la ejecución del estado. La latencia incluye firma del cliente, transporte, verificación y sondeo de 200 ms. Las admisiones rechazadas o errores de transporte abortan el ensayo y conservan evidencia parcial; esta ejecución terminó correctamente.

## Resultados observados

| Cuentas concurrentes | Confirmadas medidas | TPS en ventanas de oferta | TPS incluyendo vaciado | Latencia p50 | Latencia p95 | Latencia p99 |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 18 | 0,167 | 0,182 | 5,49 s | 5,71 s | 5,71 s |
| 8 | 144 | 1,333 | 1,454 | 5,50 s | 5,72 s | 5,72 s |
| 32 | 336 | 2,667 | 2,867 | 11,06 s | 11,47 s | 11,49 s |

Total: **498 transferencias medidas**, en nueve fases. Cada concurrencia acumula 90 s de oferta. Los denominadores con vaciado son 98,77 s, 99,06 s y 117,21 s respectivamente. Son tasas agregadas por tiempo, no promedios sin ponderar. La ventana fija excluye las confirmaciones posteriores al corte; la tasa con vaciado cuenta todas las operaciones de cada fase y todo el tiempo hasta confirmarlas.

En el perfil 32 se observaron CPU media de 6,04 % y pico de 13,52 % por validador entre las muestras contenidas en las fases; 100 % equivale a un CPU según Docker. El máximo de RAM observado entre todos los perfiles fue **204,5 MiB en un nodo**. Estos máximos incluyen la historia ya acumulada antes del ensayo y no miden solamente el costo marginal de las transferencias.

Se recogieron 82 muestras de recursos. Entre la primera y la última, el diario de cada nodo creció aproximadamente **13,2–14,2 MiB asignados**, incluyendo preparación, bloques de fondo y carga. Los intervalos que abarcan fases se conservan por separado en `summary.json`; pueden extenderse más allá de sus límites, por lo que ese crecimiento no se atribuye exclusivamente a las operaciones medidas. RAM e historia siguen creciendo: falta retención/poda y evaluación prolongada.

Los cuatro validadores terminaron en la altura **5283**, con la misma raíz de estado y **cero operaciones pendientes**. Las 498 operaciones medidas tienen hashes distintos y pares cuenta/nonce distintos. El límite de 16 candidatos y los 5 s configurados implican un techo ideal de configuración de 3,2 transacciones/s, antes de otros tiempos; **no es una capacidad garantizada**. La ejecución no caracteriza saturación de CPU ni máximo de ML-DSA.

## Datos y reproducción

- [Recibos y fases](load.json), [resumen JSON](summary.json), [tabla CSV](summary.csv), [recursos crudos](resources.jsonl) y [progreso](load.log).
- [Metadatos](metadata.json): génesis, imágenes, límites, binario y hashes de fuentes sobre la base `dd46a0f`. El árbol modificado se conserva en este PR; la base por sí sola no contiene las correcciones.
- [Génesis público](genesis.json). No se incluyen claves de validadores, faucet, semillas ni configuración de túneles.

Desde un clon con Rust 1.97.1, dependencias de `Cargo.lock`, Docker y un laboratorio preparado siguiendo `deploy/README.md` / `deploy/PUBLICAR_DOCKER.md`:

```bash
cargo build --release -p nexus-cli --example testnet_load --locked
python deploy/measure_testnet.py --root target/home-testnet --load-binary target/release/examples/testnet_load --out target/load-01 --phase-seconds 30 --repetitions 3
```

La salida debe ser nueva. Cada reproducción debe usar sus propias claves de laboratorio; no reutilizar identidades con diarios vacíos para el mismo génesis. El script requiere los cuatro endpoints de loopback publicados por `home.py` y el faucet local; la operación usa fondos de prueba.

Este es un ensayo breve de carga cerrada de **transferencias monetarias L1**. No mide generación de pruebas L2, superioridad de dos capas sobre una, rendimiento de operadores distribuidos ni capacidad sostenida de producción. Los cuantiles son empíricos y especialmente limitados por las 18 muestras del perfil 1. No se ofrecen intervalos de confianza ni garantías de seguridad a partir de estas tasas.
