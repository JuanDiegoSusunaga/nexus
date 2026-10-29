# NEXUS — prototipo de referencia en Rust

**Juan Diego Susunaga Velasquez · Universidad del Rosario**

Documentación organizada para revisión: **29 de octubre de 2026**.

Este workspace acompaña la tesis NEXUS sobre firmas poscuánticas, gestión de claves y registros verificables en una arquitectura de dos capas. Incluye las implementaciones, pruebas y experimentos del prototipo.

**Acceso único para el director: [tesis, matemáticas y Rust en tesis-nexus](https://github.com/JuanDiegoSusunaga/tesis-nexus).** El workspace también está incluido allí en `nexus/`, como archivos normales. Este repositorio conserva la procedencia y el historial de la implementación.

## Por dónde empezar

| Consulta | Acceso |
|---|---|
| Contratos, reproducción y límites | [REPRODUCIBILIDAD_TG2.md](REPRODUCIBILIDAD_TG2.md) |
| Recorrido local completo | [Ejemplo local_cycle](nexus-node/examples/local_cycle.rs) · [Pruebas del ciclo durable](nexus-node/tests/durable_cycle.rs) |
| Ejecución y lotes L2 | [nexus-active](nexus-active/) |
| Procesamiento y confirmación L1 | [nexus-anchor](nexus-anchor/) |
| Firmas y gestión de claves | [nexus-crypto](nexus-crypto/) · [nexus-sentinel](nexus-sentinel/) |
| Verificador AIR/FRI | [nexus-zk](nexus-zk/) · [Pruebas del contrato Lean](nexus-zk/tests/lean_contract.rs) |
| Demostraciones matemáticas | [Formalización Lean](https://github.com/JuanDiegoSusunaga/tesis-nexus/tree/main/formalizacion) |

## Estado de la implementación

El ciclo local permite admitir transferencias L2, ejecutarlas, construir lotes, preparar paquetes firmados L1, observar su inclusión y confirmar el lote. `DurableNode` guarda las transiciones antes de devolver éxito y recupera el estado al reabrir. Las llamadas y despliegues de contratos se rechazan explícitamente porque este perfil no implementa un intérprete.

El [registro del 20 de octubre](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/06-Evidencia-TG2/2026-10-20/Ciclo-Local-Durable/verificacion.json), sobre el código `b16688c`, conserva 360 pruebas del workspace y 13 pruebas dirigidas en release, además de check/build. Son comprobaciones previas; la preparación de esta documentación no vuelve a ejecutarlas ni cambia las fuentes Rust.

El prototipo conserva límites explícitos: el AIR escalar comprueba su relación numérica, la confirmación L1 observa procesamiento local y la persistencia usa almacenamiento local confiable. Siguen fuera de esos resultados la validez general de ejecución L2, el consenso BFT en red, la disponibilidad remota y el refinamiento universal entre Rust y Lean. Las garantías de seguridad y obligaciones matemáticas se contrastan en el [balance de la tesis](https://github.com/JuanDiegoSusunaga/tesis-nexus/blob/main/Documentos/04-Administrativo-TG2/Entrega-Final/Balance-Objetivos-TG2.md).

## Reproducción

El acceso recomendado reúne todas las partes:

```powershell
git clone https://github.com/JuanDiegoSusunaga/tesis-nexus.git
Set-Location tesis-nexus
python scripts/verificar_version_tg2.py
Set-Location nexus
```

Para compilar se necesitan Rust/Cargo, las herramientas de plataforma y las dependencias de `Cargo.lock`. La [guía de reproducción](REPRODUCIBILIDAD_TG2.md#comandos-desde-este-repositorio) explica los comandos y el uso de la caché; `--offline` requiere dependencias descargadas previamente.

## Estructura

| Crate | Función |
|---|---|
| `nexus-core` | Tipos, cuentas, estado y checkpoints |
| `nexus-crypto`, `nexus-sentinel` | Firmas, monitor y gestión de claves |
| `nexus-active` | Admisión, ejecución y lotes L2 |
| `nexus-anchor` | Procesamiento L1, inclusión local y finalidad experimental |
| `nexus-zk` | Verificador AIR/FRI y variantes experimentales |
| `nexus-node` | Coordinación del ciclo durable y ejemplo ejecutable |
| `nexus-network`, `nexus-cli` | Interfaces de red y herramientas de línea de comandos |

[Antecedentes técnicos y mediciones](ANTECEDENTES_TECNICOS.md) · [Tesis y evidencia](https://github.com/JuanDiegoSusunaga/tesis-nexus) · [Código de la formalización](https://github.com/JuanDiegoSusunaga/tesis-nexus/tree/main/formalizacion).
