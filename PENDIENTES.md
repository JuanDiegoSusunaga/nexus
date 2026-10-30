# Pendientes del prototipo NEXUS — 30 de octubre de 2026

- [x] Autorización, rotación/retiro por épocas y bloqueo de emergencia L2 en el prototipo local, con persistencia y pruebas.
- [x] Perfil monetario experimental: génesis, máximo de emisión histórica, subsidios, comisiones y quema.
- [x] Cuatro validadores ML-DSA-65, quórum tres, transporte TCP, consultas autenticadas, certificados y diario incremental recuperable.
- [x] Imagen Linux comprobada y ensayos con transferencias, tres/dos participantes y recuperación conservando diarios.
- [x] Publicación experimental desde Docker mediante túnel temporal, consulta HTTP desde otra red y validación criptográfica desde clientes del host, incluido cliente descargado aislado. [Alcance y evidencia](Documentos/06-Evidencia-TG2/2026-10-30/Docker-Publico/README.md).
- [x] Conservar este incremento exclusivamente en `JuanDiegoSusunaga/nexus`, con corpus público y construcción desde un clon.
- [ ] Validar transferencia y replay desde otro computador físico y mantener evidencia independiente.
- [ ] Separar validadores entre dominios de fallo y operadores independientes; definir ingreso/cambio de comité.
- [ ] Integrar Sentinel y la rotación de claves en el comité BFT; mejorar custodia y recuperación de secretos.
- [ ] Implementar retención/poda y recuperación escalable; medir capacidad y disponibilidad sostenidas.
- [ ] Completar protocolo de conservación de valor entre L1 y L2 y prueba de ejecución general L2; el AIR/FRI escalar actual no la acredita.
- [ ] Completar correspondencia universal Rust/Lean y obligaciones de revisión matemática/criptográfica. QROM completo sigue como trabajo futuro por decisión del autor.

NXS es de prueba, sin cotización establecida ni conversión garantizada. Quema y suministro no fijan un precio. La publicación no equivale a dictamen académico o garantía integral poscuántica.
