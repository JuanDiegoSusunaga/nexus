# Pendientes del prototipo NEXUS — 10 de noviembre de 2026

- [x] Autorización, rotación y retiro de claves L2 por épocas, y bloqueo de emergencia, con persistencia y pruebas.
- [x] Verificación de posición en `MerkleProof` y tres correcciones de contabilidad de validadores, con regresiones.
- [x] Banco de pruebas BFT: cuatro validadores ML-DSA-65, quórum tres, certificados y diario incremental recuperable. Sin transporte de red.
- [x] Separar de `main` el perfil monetario NXS, el transporte TCP y la publicación desde Docker. Se conservan en [`testnet-experimental`](https://github.com/JuanDiegoSusunaga/nexus/tree/testnet-experimental) y no forman parte de las afirmaciones de la tesis. Check, build y 412 pruebas correctos tras la separación.
- [x] Incorporar del pull request 1 el rechazo de las APIs Groth16 incompletas y el refuerzo del diario en Unix. Check, build y 415 pruebas correctos. Su medición de carga queda en la rama experimental. [Verificación](Documentos/06-Evidencia-TG2/2026-11-10/Correcciones-Verificador-Diario/verification.json).
- [ ] Integrar Sentinel y la rotación de claves en el comité BFT; mejorar custodia y recuperación de secretos.
- [ ] Implementar retención o poda del diario y medir la recuperación con historias largas.
- [ ] Completar el protocolo de conservación de valor entre L1 y L2 y la prueba de ejecución general L2; el AIR/FRI escalar actual no la acredita.
- [ ] Completar la correspondencia universal Rust/Lean y las obligaciones de revisión matemática y criptográfica. QROM completo sigue como trabajo futuro por decisión del autor.

El banco BFT usa un comité fijo en un solo proceso de pruebas. No acredita operación entre máquinas, independencia de operadores ni una garantía poscuántica integral.
