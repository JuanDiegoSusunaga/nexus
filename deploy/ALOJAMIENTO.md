# Propuesta de alojamiento para la testnet NEXUS

Consulta de precios: **30 de octubre de 2026**. El autor eligió después [su Docker con túnel temporal](PUBLICAR_DOCKER.md) para el primer ensayo público. Esta propuesta queda como alternativa para separar máquinas; no contrata recursos ni establece una economía de producción para NXS.

## Propuesta inicial

Usar **cuatro máquinas virtuales Linux amd64**, una por validador, con IPv4 pública y disco persistente. Hay dos perfiles: 1 GiB por VPS para una primera prueba acotada, con límite de 512 MiB en el contenedor; o 2 GB/GiB por VPS y límite de 1 GiB para mayor margen. Compilar la imagen previamente, fuera de esas máquinas pequeñas. Los cuatro validadores pueden ser administrados inicialmente por el equipo de la tesis; esto permite probar fallos entre máquinas, pero no acredita independencia de operadores ni descentralización social.

| Opción | Recursos de referencia por nodo | Precio base por nodo/mes | Cuatro nodos/mes |
|---|---|---:|---:|
| DigitalOcean Basic Regular, prueba inicial acotada | 1 GiB RAM, 1 vCPU, 25 GiB SSD, 1.000 GiB de transferencia incluida | US$6 | **US$24** |
| AWS Lightsail Linux/Unix con IPv4 | 2 GB RAM, 2 vCPU, 60 GB SSD, 3 TB de transferencia incluida | US$12 | **US$48** |
| DigitalOcean Basic Regular | 2 GiB RAM, 1 vCPU, 50 GiB SSD, 2.000 GiB de transferencia incluida | US$12 | **US$48** |
| Laboratorio actual en este ordenador | Cuatro procesos o contenedores locales | Sin alquiler de VPS adicional | Sigue siendo un laboratorio local |

Fuentes: [tarifas oficiales de Lightsail](https://aws.amazon.com/lightsail/pricing/) y [tarifas oficiales de Droplets](https://www.digitalocean.com/pricing/droplets). Son referencias de planes publicados, sujetas a región y disponibilidad; el importe final debe confirmarse en la cuenta antes de crear máquinas. Impuestos, copias adicionales, exceso de tráfico, almacenamiento extra y otros servicios pueden aumentar el total. No se presupone una promoción gratuita ni una conversión fija a pesos colombianos.

**Opción de menor costo:** para una primera prueba acotada, cuatro VPS de 1 GiB suman **US$24 mensuales de infraestructura base**. El ensayo local con límite de 512 MiB por contenedor pasó transferencias, cortes y recuperación, usando la misma imagen. Se conserva la opción de **US$48 de base** para cuatro VPS de 2 GB/GiB. La cifra previa de US$60 era una reserva orientativa para esa segunda opción, no un mínimo ni un límite de facturación del proveedor. No hace falta contratar dominio, balanceador, Kubernetes ni base de datos administrada para este primer ensayo TCP.

Ninguna de estas selecciones garantiza capacidad para tráfico arbitrario. El ensayo Docker de 512 MiB limita la memoria del proceso; no reproduce un VPS completo de 1 GiB ni valida su carga sostenida. La historia y los certificados crecen en RAM; también crecen los archivos del diario. Empezar con bloques cada cinco segundos, una ventana experimental acotada y seguimiento de RAM, disco, altura y retraso de sincronización. Ajustar recursos con mediciones reales antes de prolongar la operación. [Evidencia del perfil de 512 MiB](../../Documentos/06-Evidencia-TG2/2026-10-30/Perfil-512MiB/README.md).

## Qué se publicará

- El génesis público, sus huellas y cuatro endpoints TCP accesibles para consultar y enviar NXS de prueba.
- El binario/imagen de contenido fijado y las instrucciones para ejecutar un observador.
- Evidencia de transferencias, caída de un nodo, detención con dos, recuperación y coincidencia de estados certificados.
- La correspondencia del quórum con `formalizacion/Nexus/Modelos/QuorumIncentivos.lean`: cuatro pesos iguales, quórum tres e hipótesis de a lo sumo uno bizantino. Las reglas implementadas de fases y bloqueos no se presentan como un refinamiento formal completo.

La protección de claves requiere una clave por nodo, sin compartir el faucet con los validadores, permisos del sistema de archivos y protección de las copias. El paquete generado por `prepare.py` contiene configuraciones públicas: la clave correspondiente se instala aparte en su propio host. El inicializador actual genera claves de prueba sin cifrar; no sustituye una custodia de producción ni impide que un administrador duplique claves. La admisión del comité sigue siendo fija.

El firewall del proveedor debe limitar SSH a las direcciones de administración y permitir el puerto TCP elegido para NEXUS. No se abrirá ninguna API del motor Docker a Internet. La publicación de puertos de Docker requiere revisar también sus reglas de red; no se presupone que una regla UFW aislada proteja esos puertos. [Limitaciones oficiales de Docker y firewalls](https://docs.docker.com/engine/install/debian/#firewall-limitations).

## Qué falta para contratar y desplegar

Elegir proveedor, cuenta, región y presupuesto; disponer de acceso administrativo autorizado y de cuatro direcciones. Con esos datos se pueden generar los paquetes definitivos, instalar una clave por host, transferir la imagen verificada y ejecutar la validación desde fuera de la red de servidores. El desembolso y el destino deben quedar definidos antes de crear recursos facturables.

La preparación local y las pruebas entre contenedores no prueban accesibilidad desde Internet. Tampoco acreditan resistencia DDoS, disponibilidad frente a la caída de toda una región o seguridad poscuántica integral de ambas capas. Los límites de la tesis y de AIR/FRI se mantienen.
