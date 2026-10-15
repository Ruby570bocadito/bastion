# Documentación de Bastion

| # | Documento | Contenido |
|---|---|---|
| 01 | [Visión y propuesta de valor](01-vision.md) | Qué problema resuelve, para quién, diferenciadores y principios |
| 02 | [Arquitectura](02-arquitectura.md) | Componentes, modos de uso (standalone y flota), flujos de datos y estructura del código |
| 03 | [Suite de herramientas](03-herramientas.md) | Las 16 herramientas (Evaluar, Endurecer, Defender, Gobernar) en detalle |
| 04 | [Motor de reglas](04-motor-de-reglas.md) | Formato de reglas y perfiles, probes, operadores y cómo escribir reglas |
| 05 | [Remediación segura](05-remediacion-segura.md) | Diseño de `harden`: plan, instantánea, verificación, rollback y dead-man switch |
| 06 | [Catálogo de controles](06-catalogo-de-controles.md) | Controles implementados (generado) y catálogo objetivo |
| 07 | [UI y diseño](07-ui-y-diseno.md) | Sistema de diseño, pantallas, informe HTML y futura UI web |
| 08 | [Seguridad de la plataforma](08-seguridad-de-la-plataforma.md) | Modelo de amenazas y controles de la propia herramienta |
| 09 | [Instalación](09-instalacion.md) | Instaladores de una línea, opciones, sin conexión, espejos y desinstalación |
| 10 | [Guía de uso](10-guia-de-uso.md) | Referencia de la CLI, informes, códigos de salida y ejemplos |
| 11 | [Desarrollo](11-desarrollo.md) | Entorno, estructura, añadir probes y reglas, releases |
| 12 | [Pruebas y laboratorio](12-pruebas-y-laboratorio.md) | Estrategia de tests, CI y laboratorio de máquinas virtuales |
| 13 | [Hoja de ruta](13-hoja-de-ruta.md) | Fases, entregables y criterios de "terminado" |
| 14 | [Marcos normativos y licencias](14-marcos-y-licencias.md) | CIS, STIG, NIST, ENS, ISO 27001, NIS2 y consideraciones de licencia |
| — | [Decisiones de arquitectura (ADR)](adr/) | Por qué Go, reglas declarativas, standalone primero, etc. |

## Convenciones

- ✅ implementado · 🚧 en curso · 🔜 planificado.
- Los ejemplos de comandos usan `bastion` instalado en el PATH. En Linux, anteponer `sudo` para leer todos los controles.
- El repositorio de ejemplo es `tu-usuario/bastion`. Cámbialo una sola vez con `make set-repo REPO=usuario/bastion`.
