# 13 · Hoja de ruta

| Fase | Estado | Objetivo |
|---|---|---|
| 0 · Fundaciones | ✅ | Base técnica y de producto |
| 1 · Auditoría | 🚧 | Auditoría completa y creíble en las tres plataformas |
| 2 · Hardening | 🚧 | Aplicar cambios con seguridad |
| 3 · Flota | 🔜 | Gestión centralizada con consola web |
| 4 · Defensa | 🔜 | Visibilidad, caza y contención |
| 5 · Enterprise | 🔜 | Active Directory, escala e integraciones |

## Fase 0 · Fundaciones ✅

- [x] Monorepo Go, módulo único, binario estático para Linux y Windows (amd64/arm64).
- [x] Formato de reglas y perfiles con validación estricta y JSON Schema.
- [x] Motor: evaluación paralela, 19 operadores, compuestas, `default`/`on_missing`/`each`, puntuación ponderada.
- [x] 15 probes de solo lectura (3 comunes, 7 Linux, 5 Windows) con caché por escaneo.
- [x] Detección de plataforma y rol (estación, servidor miembro, DC, distro).
- [x] 131 reglas reales (66 Linux, 65 Windows/Server/DC) y 7 perfiles.
- [x] CLI: `scan`, `info`, `rules list|show|lint|doc`, `profiles`, `update`, `init`, `version`.
- [x] Informes: consola, JSON `bastion.report/v1` y HTML autocontenido (claro/oscuro, ATT&CK, evidencias).
- [x] Auto-actualización verificada (SHA-256) y espejos internos.
- [x] Instaladores de una línea (bash y PowerShell): instalar, actualizar, preparar, escanear y desinstalar.
- [x] CI (Linux + Windows, escaneo real), release con GoReleaser + SBOM.
- [x] Documentación completa y ADRs.

## Fase 1 · Auditoría 🚧

- [ ] Ampliar el catálogo: unas 350 reglas Windows y 300 Linux ([catálogo objetivo](06-catalogo-de-controles.md#2-catálogo-objetivo-)).
- [ ] Mapeo verificado a CIS, STIG y ENS por versión de benchmark ([14](14-marcos-y-licencias.md)).
- [ ] Probes nuevos: `userrights` (SIDs legibles), `rsop`/`gpo` (quién gestiona cada valor), `listening` (puertos), `auditd_rules`, `pam`.
- [x] Estado `skipped`: controles sin evaluar por falta de privilegios, fuera de la puntuación.
- [x] Excepciones con motivo, responsable y caducidad (`bastion exceptions`, estado `exception`).
- [ ] Estado `manual` (controles que requieren revisión humana).
- [x] `bastion surface` v1: puertos con proceso, catálogo de servicios de riesgo, recursos compartidos, administradores y puntuación de exposición (también en `bastion ui`).
- [x] `surface`: evaluar el Firewall de Windows (perfiles, acción por defecto, reglas de permiso y bloqueo).
- [ ] `surface`: firewall de Linux (ufw, firewalld, nftables) y firma de los binarios.
- [ ] Firma de releases (cosign) y Authenticode.
- [ ] Prueba de los instaladores de punta a punta en CI (espejo local).
- [x] UI local: `bastion ui` (127.0.0.1 con token): postura, tendencia, plan por olas, historial de escaneos y cambios, excepciones ([ADR-0008](adr/0008-consola-local.md)).

**Terminado cuando:** un auditor puede llevar el binario en un USB, auditar Windows 11, Server 2022 (miembro y DC) y Ubuntu 24.04 y entregar un informe defendible sin falsos positivos conocidos.

## Fase 2 · Hardening 🚧

- [x] Acciones de remediación tipadas en las reglas (13 tipos, 100 controles automáticos) ([05](05-remediacion-segura.md)).
- [x] `harden` con plan, diff, instantánea con registro previo, verificación y rollback automático; `history` y `rollback`.
- [x] *Dead-man switch* para el acceso remoto (proceso independiente que sobrevive al corte de la sesión).
- [x] Consciencia de GPO (heurística por ruta de directiva). 🔜 RSoP e Intune precisos.
- [x] Olas por riesgo de rotura (`--wave 1|2|3`).
- [x] Ciclo real `harden → verificar → rollback` en CI sobre Ubuntu y Windows Server.
- [ ] *Health checks* personalizados tras aplicar.
- [ ] `studio` v1: perfiles propios y exportación a GPO, Ansible, DSC y scripts.
- [ ] `bastion rules new|test` con fixtures; laboratorio de VMs en CI nocturna.

## Fase 3 · Flota 🔜

- [ ] `bastion agent` (servicio de Windows / systemd), alta con token y mTLS.
- [ ] `bastion-server` (Go + PostgreSQL), API REST y gRPC.
- [ ] Consola web (React) con dashboard, activos, detalle, políticas, informes e historial.
- [ ] `guard` (desviaciones en tiempo real) y `observe` (auditar antes de aplicar).
- [ ] Excepciones con caducidad; RBAC; SSO/OIDC; MFA; aprobación a cuatro ojos.
- [ ] Paquetes nativos: MSI, `.deb` y `.rpm`.

## Fase 4 · Defensa 🔜

- [ ] `telemetry`: baseline de logging, Sysmon/auditd gestionados, eventos canario contra el SIEM.
- [ ] `hunt`: persistencia, integridad, credenciales expuestas, diferencias entre escaneos.
- [ ] `lockdown`: contención con TTL y evidencias.
- [ ] `vuln`: inventario, parches, OSV/NVD/MSRC, KEV y EPSS.
- [ ] Mapa ATT&CK de detección.

## Fase 5 · Enterprise 🔜

- [ ] `ad`: auditoría de Active Directory y AD CS.
- [ ] Anillos de despliegue con *health gates*.
- [ ] Integraciones SIEM/ITSM, webhooks.
- [ ] Informes por marco (PDF), marca blanca, multi-cliente (MSSP).
- [ ] Copiloto IA opcional y grafo de rutas de ataque.
