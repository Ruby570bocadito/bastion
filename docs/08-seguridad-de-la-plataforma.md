# 08 · Seguridad de la plataforma

Bastion se ejecuta como **SYSTEM/root** en equipos críticos. Para un atacante es un objetivo muy valioso: si lo compromete, controla toda la flota. Por eso la seguridad de la propia herramienta forma parte del diseño desde el primer día.

## Modelo de amenazas (resumen)

| Amenaza | Vector | Control |
|---|---|---|
| Bastion como herramienta de ejecución remota (C2) | Servidor comprometido que envía comandos | **No existe** la capacidad de ejecutar comandos arbitrarios ([ADR-0004](adr/0004-sin-ejecucion-arbitraria.md)) |
| Paquete de reglas malicioso | Regla que intenta ejecutar código | Reglas declarativas; los probes usan comandos fijos; `ps` solo admite una lista blanca |
| Secuestro de binarios | `PATH` manipulado para suplantar `secedit` o `powershell` | Rutas absolutas `%SystemRoot%\System32\...` en Windows |
| Actualización manipulada | Mirror comprometido o MITM | HTTPS + verificación SHA-256 obligatoria (🔜 firma cosign/minisign) |
| XSS en el informe | Valor hostil leído del sistema (p. ej. una línea de `sudoers`) | JSON escapado, `textContent`, CSP con nonce |
| Lectura de datos sensibles | Informes y configuración legibles por cualquiera | Directorios con permisos restringidos a root / Administradores+SYSTEM |
| Denegación de servicio del escaneo | Fichero enorme o probe colgado | Límite de 4 MiB por fichero, timeout de 60 s por comando, `recover` por regla |

## Controles implementados (✅)

### Sin ejecución arbitraria
- Las reglas son YAML declarativo. Los parámetros de un probe nunca se interpolan en comandos.
- Comandos usados por los probes: `secedit /export`, `auditpol /backup`, `powershell.exe -NoProfile -NonInteractive -Command <consulta fija>`, `sshd -T`, `systemctl show`, `dpkg-query`, `rpm -q`. Todos son de **solo lectura**.
- Las consultas PowerShell no usan `-EncodedCommand` ni `-ExecutionPolicy Bypass`, para no parecerse a malware ni generar ruido en el EDR. Quedan en el ScriptBlock Logging de forma legible.

### Cambios controlados (`harden`)
- Solo **acciones tipadas** (13 tipos). Ninguna ejecuta comandos libres: los cmdlets de Defender reciben GUIDs, enteros o nombres de una lista blanca, ya validados.
- Los parámetros se validan con listas blancas y expresiones regulares, también en `rules lint`: solo HKLM, claves `secedit` permitidas, rutas `/etc` sin `..`, nada de saltos de línea que inyecten directivas en `sshd_config` o `sudoers`.
- **Registro previo**: el estado anterior se escribe en el manifiesto antes de aplicar; un fallo a mitad sigue siendo reversible.
- `sshd -t` y `visudo -c` validan antes de dejar un cambio en SSH o sudoers; si falla, se restaura de inmediato.
- Dead-man switch en un proceso independiente para los cambios de acceso remoto.

### Solo lectura en `scan`
- `bastion scan` no modifica el sistema. Los únicos ficheros que escribe son los informes que se piden y ficheros temporales privados (`secpol.inf`, `audit.csv`), que se borran al terminar.

### Actualizaciones verificadas
- El instalador y `bastion update` descargan `checksums.txt` y verifican el SHA-256 del archivo **antes** de extraerlo. Si no coincide, abortan sin tocar la instalación existente.
- Reemplazo atómico en Linux (`rename`) y renombrado seguro en Windows (`.old`).
- Límites de tamaño en descargas y extracción.

### Informe HTML
- Los datos se serializan con `encoding/json`, que escapa `<`, `>` y `&`, así que no pueden cerrar la etiqueta `<script>`.
- El JavaScript inserta todo con `textContent` y nunca con `innerHTML`.
- **CSP**: `default-src 'none'; script-src 'nonce-<aleatorio>'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'`. Aunque se inyectara HTML, ningún script sin el nonce se ejecutaría y no se puede cargar nada externo.
- Los enlaces externos (MITRE) usan `rel="noopener noreferrer"`.

### Permisos
- Linux: `/etc/bastion` y `/var/lib/bastion` con `0750` (root). Informes con `0640`.
- Windows: `%ProgramData%\Bastion` sin herencia, acceso total solo para Administradores (`S-1-5-32-544`) y SYSTEM (`S-1-5-18`), por SID para que funcione en cualquier idioma. El directorio `reports` concede además **lectura** al usuario que ejecutó el escaneo: con UAC, su navegador corre sin elevar y no podría abrir el informe.
- Las reglas propias (`rules.d`) solo las puede escribir un administrador.

### Desarrollo seguro
- CI con `go vet` y tests en Linux y Windows (con detector de carreras en Linux), ShellCheck y PSScriptAnalyzer.
- Releases reproducibles con GoReleaser y SBOM (Syft).
- Sin CGO: binario estático con la mínima superficie.

## Controles planificados (🔜)

| Fase | Control |
|---|---|
| 1 | Firma de releases con cosign (keyless, OIDC de GitHub) y verificación en instalador y `update` |
| 1 | Authenticode para `bastion.exe` (evita SmartScreen y mejora la confianza del EDR) |
| 2 | Paquetes de reglas firmados; lista de claves de confianza para reglas propias |
| 2 | Instantáneas con hash y ACL; log local de cambios encadenado por hash |
| 3 | mTLS agente-servidor, alta con token de un solo uso y rotación de certificados |
| 3 | El agente no abre puertos; la UI local solo en `127.0.0.1` con token |
| 3 | RBAC, SSO/OIDC, MFA y aprobación a cuatro ojos para cambios en producción |
| 3 | Log de auditoría del servidor encadenado por hash |
| 4 | `lockdown` con MFA, motivo obligatorio y TTL |
| — | *Dogfooding*: Bastion endurece y vigila su propio servidor |

## Reporte de vulnerabilidades

Ver [SECURITY.md](../SECURITY.md).
