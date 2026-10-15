# 10 · Guía de uso

> Ejecuta Bastion como **administrador** (Windows) o con **sudo** (Linux). Sin privilegios funciona, pero algunos controles (directiva de seguridad y de auditoría, BitLocker, `/etc/shadow`, `sudoers`...) quedan **sin evaluar**, no cuentan en la puntuación y esta se marca como parcial. Los informes de `--save` se guardan entonces en tu carpeta de usuario: `%LOCALAPPDATA%\Bastion\reports` en Windows y `~/.local/share/bastion/reports` en Linux.

## Comandos

| Comando | Descripción |
|---|---|
| `bastion info [--json]` | Plataforma, rol, etiquetas, perfil por defecto, probes disponibles y rutas |
| `bastion scan` | Auditar el equipo (solo lectura) |
| `bastion profiles [--all]` | Perfiles disponibles y número de reglas |
| `bastion rules list [--all] [-p perfil]` | Reglas aplicables (o todas) |
| `bastion rules show <ID>` | Detalle, remediación, impacto y referencias de un control |
| `bastion rules lint [dir…]` | Validar el paquete oficial y reglas propias |
| `bastion rules doc` | Catálogo de controles en Markdown |
| `bastion harden [--apply] [--wave N]` | Corregir controles fallidos (simulación salvo `--apply`). Ver [05](05-remediacion-segura.md) |
| `bastion rollback [ID] [--yes]` | Deshacer un cambio de hardening (por defecto, el último) |
| `bastion history` | Cambios de hardening aplicados |
| `bastion exceptions [list\|add\|remove]` | Aceptar controles fallidos con motivo, responsable y caducidad (ver abajo) |
| `bastion update [--check] [--force]` | Actualizar Bastion y sus reglas (verificado con SHA-256) |
| `bastion init` | Crear directorios y configuración (lo hace el instalador) |
| `bastion version [--short]` | Versión |

Opciones globales: `--no-color`, `--rules-dir <dir>` (repetible).

## `bastion scan`

| Opción | Descripción |
|---|---|
| `-p, --profile <id>` | Perfil a evaluar. Por defecto el de `config.yaml` o el que corresponde al rol del equipo |
| `-f, --format console\|json` | Formato de la salida estándar |
| `-o, --output <fichero>` | Guardar el informe en `.html` o `.json` (repetible) |
| `--save` | Guardar HTML y JSON con fecha en el directorio de informes (conserva los últimos `keep`) |
| `--open` | Abrir el informe HTML al terminar (implica `--save` si no hay `-o *.html`) |
| `-a, --all` | Mostrar también los controles superados y los que no aplican |
| `--rule <ID,…>` | Evaluar solo esas reglas |
| `--category <nombre,…>` | Evaluar solo esas categorías |
| `--min-score <n>` | Salir con código 2 si la puntuación es inferior |
| `-q, --quiet` | Sin resumen en consola |

### Ejemplos

```bash
# Auditoría estándar con informe visual
sudo bastion scan --save --open

# Perfil de alta seguridad para el portátil de un administrador
bastion scan -p win-workstation-l2 -o C:\informes\pc-admin.html

# Solo SSH y firewall
sudo bastion scan --category SSH,Firewall

# Un control concreto, con todos los resultados
sudo bastion scan --rule LNX-SSH-001 -a

# JSON para integraciones (la consola no se mezcla con el JSON)
sudo bastion scan --format json > resultado.json

# Puerta de calidad en un pipeline de imágenes
sudo bastion scan --min-score 85 -q -o informe.html || echo "La imagen no cumple"
```

### Códigos de salida

| Código | Significado |
|---|---|
| 0 | Escaneo completado (y puntuación ≥ `--min-score`, si se indicó) |
| 1 | Error (perfil inexistente, reglas inválidas, sin permisos para guardar…) |
| 2 | Puntuación inferior a `--min-score` |
| 130 | Interrumpido (Ctrl+C) |

## Corregir: `bastion harden`

```bash
sudo bastion harden                  # 1. simulación: revisa el plan
sudo bastion harden --apply          # 2. aplica la ola 1 (riesgo nulo o bajo)
sudo bastion scan --save --open      # 3. comprueba la nueva postura
sudo bastion rollback                # si algo no te convence, se deshace todo
```

Cada control se aplica con instantánea previa, se verifica y, si no se cumple o falla, se revierte solo. Olas, acceso remoto, GPO e instantáneas se explican en [05-remediacion-segura.md](05-remediacion-segura.md).

## Aceptar un riesgo: `bastion exceptions`

Cuando un control falla y hay un buen motivo para no corregirlo (un control compensatorio, hardware antiguo, un proveedor que lo exige), regístralo como excepción en lugar de ignorarlo:

```bash
sudo bastion exceptions add WIN-SYS-003 --reason "Equipo sin UEFI; se sustituye en enero" --expires 2027-01-31
sudo bastion exceptions add LNX-FW-001 --reason "Filtrado en el cortafuegos perimetral FW-02" --expires 90d
sudo bastion exceptions add WIN-RDP-001 --reason "Cliente RDP heredado del proveedor" --expires 6m --host SRV-ERP01
bastion exceptions list           # vigencia de cada una (en amarillo si caduca en menos de 30 días)
sudo bastion exceptions remove LNX-FW-001
```

| Opción | Descripción |
|---|---|
| `-r, --reason` | Motivo (obligatorio, una línea de al menos 10 caracteres) |
| `-e, --expires` | Caducidad obligatoria: fecha `AAAA-MM-DD` o plazo `90d`, `12w`, `6m`, `1y`. Como mucho un año |
| `--owner` | Responsable (por defecto, el usuario actual) |
| `--host` | Limitar a estos equipos (repetible) |

`add` sobre una regla que ya tiene excepción la **renueva**. El control con excepción vigente sale como ◇ **excepción**: no cuenta en la puntuación y `harden` no lo modifica. Al caducar vuelve a fallar y Bastion lo avisa en cada escaneo.

Se guardan en `exceptions.yaml`, junto a `config.yaml` (`/etc/bastion` o `%ProgramData%\Bastion`):

```yaml
schema: bastion.exceptions/v1
exceptions:
  - rule: LNX-FW-001
    reason: Filtrado en el cortafuegos perimetral FW-02
    owner: seguridad
    created: "2026-10-15"
    expires: "2027-01-13"
```

Si editas el fichero a mano, Bastion ignora las excepciones inválidas (sin motivo, sin caducidad o con más de un año de vigencia) y lo avisa.

## Interpretar los resultados

| Estado | Significado | ¿Cuenta en la puntuación? |
|---|---|---|
| ✓ **Superado** | El valor real cumple lo esperado | Sí |
| ✗ **Fallido** | El valor real no cumple (o no está configurado y el valor por defecto del sistema no cumple) | Sí |
| ! **Error** | No se pudo leer por un problema inesperado (comando que falla, formato desconocido…) | No; la puntuación se marca como **parcial** |
| ◇ **Excepción** | Falla, pero hay una excepción vigente que lo acepta | No; se muestra aparte y con su caducidad |
| ⊘ **Sin evaluar** | El dato solo se puede leer como administrador o root y el escaneo se ejecutó sin privilegios. En consola se resumen en una línea; `--all` los lista | No; la puntuación se marca como **parcial** |
| – **No aplica** | El elemento no existe en este equipo (sin OpenSSH, sin systemd, Defender sustituido por otro antivirus…) | No |

Cuando el informe dice `actual 1 (por defecto)`, el valor no estaba configurado explícitamente y Bastion aplicó el valor por defecto documentado del sistema operativo.

## Formato JSON (`bastion.report/v1`)

```json
{
  "schema": "bastion.report/v1",
  "tool": { "name": "bastion", "version": "0.1.0", "commit": "abc1234" },
  "host": { "hostname": "web-01", "os": "linux", "name": "Ubuntu 24.04.1 LTS", "role": "server",
            "tags": ["linux-ubuntu", "linux-debian", "linux"], "is_admin": true },
  "profile": { "id": "linux-server-l1", "name": "Linux Servidor · Nivel 1" },
  "started_at": "2026-10-15T14:35:00Z", "finished_at": "…", "duration_ms": 39,
  "score": { "value": 65, "grade": "D", "partial": false, "total": 57, "passed": 22, "failed": 15,
             "errors": 0, "skipped": 0, "exceptions": 0, "na": 20, "by_severity": { "high": { "failed": 2 } }, "by_category": [ … ] },
  "results": [
    { "rule": { "id": "LNX-FW-001", "title": "…", "severity": "high", "category": "Firewall",
                "references": { … }, "remediation": { … } },
      "status": "fail", "actual": "…", "expected": "…", "source": "…",
      "children": [ { "status": "fail", "label": "ufw", "actual": "no configurado", "expected": "yes",
                      "source": "/etc/ufw/ufw.conf" } ] }
  ]
}
```

El formato es estable dentro de `v1`: solo se añadirán campos, nunca se eliminarán ni cambiarán de significado.

## Configuración (`config.yaml`)

```yaml
profile: auto                 # o un perfil concreto
reports:
  dir: /var/lib/bastion/reports
  keep: 30                    # escaneos que se conservan con --save
rules:
  extra_dirs:
    - /etc/bastion/rules.d    # reglas propias (*.yaml)
update:
  # repo: mi-org/bastion
  # releases_url: https://mirror.interno/bastion
```

## Reglas propias

1. Crea un `.yaml` en `rules.d` siguiendo [04-motor-de-reglas.md](04-motor-de-reglas.md). Usa un prefijo propio en el ID (p. ej. `ACME-WEB-001`) y asígnalo a un perfil existente.
2. Valídalo: `bastion rules lint /etc/bastion/rules.d`.
3. Ejecuta `bastion scan`: las reglas propias se evalúan junto a las oficiales.
