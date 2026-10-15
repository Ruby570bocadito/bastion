# 05 · Remediación segura (diseño de `bastion harden`, fase 2)

> Estado: 🔜 diseño aprobado, pendiente de implementar. Hoy cada regla ya trae `remediation` (resumen, GPO, comandos, riesgo de rotura, reinicio) y la guía manual se muestra en `bastion rules show` y en el informe HTML.

## Objetivo

Aplicar hardening **sin miedo**: cada cambio es simulable, reversible, verificado y auditado.

## Pipeline transaccional

```
  PLAN ──► SNAPSHOT ──► APLICAR ──► VERIFICAR ──┬──► COMMIT (registrado en el log de auditoría)
   │          │                                  │
   │          │                                  └──► FALLA ──► ROLLBACK automático
   │          └─ export del registro, copia de ficheros, secedit /export,
   │             punto de restauración opcional (Windows), snapshot LVM/btrfs (Linux)
   └─ diff "actual → esperado", avisos de impacto, ¿requiere reinicio?
```

1. **Plan.** Se evalúan las reglas y, para cada fallo con acción automatizable, se calcula el cambio exacto. Se muestra un diff y se guarda como `plan-<fecha>.json`.
2. **Instantánea.** Antes de tocar nada se guarda el valor previo de cada elemento: valor y tipo del registro, fichero completo, plantilla de `secedit`, estado de servicios. Va a `snapshots/<id>/` con manifiesto y hashes.
3. **Aplicar.** Remediadores nativos, idempotentes y en orden determinista.
4. **Verificar.** Se reevalúan las reglas afectadas y se ejecutan los *health checks*.
5. **Commit o rollback.** Si algo falla, se restaura la instantánea automáticamente.

## Remediadores

| Windows | Linux |
|---|---|
| Registro (API nativa) | `sysctl` → `/etc/sysctl.d/99-bastion.conf` |
| Directiva de seguridad (`secedit /configure` con plantilla INF) | SSH → `/etc/ssh/sshd_config.d/00-bastion.conf` (en sshd gana la primera aparición) |
| Directiva de auditoría (`auditpol /set`) | Módulos → `/etc/modprobe.d/bastion.conf` |
| Servicios (Service Control Manager) | systemd (`disable`, `mask`) |
| Características opcionales (DISM) | PAM vía `authselect` (RHEL) o `pam-auth-update` (Debian) |
| Firewall (API NetSecurity) | auditd → `/etc/audit/rules.d/bastion.rules` |
| Defender (`MSFT_MpPreference`) | Opciones de montaje (fstab + remount) |

**Principio:** en Linux se usan **ficheros drop-in** en lugar de editar los originales. El rollback es limpio y las actualizaciones de paquetes no generan conflictos.

## Formato de la acción en las reglas (borrador)

```yaml
remediation:
  summary: ...
  breaking_risk: low
  action:                      # 🔜 fase 2
    type: registry.set
    path: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient
    name: EnableMulticast
    value: 0
    value_type: DWORD
```

Tipos previstos: `registry.set`, `registry.delete`, `secpol.set`, `auditpol.set`, `service.config`, `feature.disable`, `sysctl.set`, `sshd.set`, `kmod.block`, `systemd.mask`, `file.mode`, `file.line`, `mount.options`. **No existirá un tipo "ejecutar comando"** ([ADR-0004](adr/0004-sin-ejecucion-arbitraria.md)).

## Salvaguardas

### Consciencia de GPO e Intune

Si un valor lo gestiona una GPO de dominio (claves `...\Policies\...` aplicadas por RSoP) o Intune (`PolicyManager`), Bastion **no lo cambia en local**, porque la directiva lo volvería a pisar en el siguiente `gpupdate`. Lo marca como *gestionado externamente* y genera el arreglo para la GPO (exportación con `studio`).

### Dead-man switch para el acceso remoto

Las reglas con `safety: remote-access` (SSH, RDP, firewall, NTLM) se aplican con temporizador:

```
$ sudo bastion harden --plan plan.json --apply
 ⚡ Cambio en el acceso remoto. Confirma desde OTRA sesión en 120 s:
    bastion confirm chg_01JA7…
 (si no se confirma, se revierte automáticamente)
```

En Linux, además, `sshd -t` valida la sintaxis antes de recargar.

### Comprobaciones previas y health checks

- **Previas**: espacio en disco, reinicio pendiente, batería, herramientas de gestión de configuración (Ansible/Puppet/Chef) que revertirían el cambio.
- **Integradas**: servicios críticos activos, red accesible, RDP/SSH escuchando, *secure channel* de dominio (`Test-ComputerSecureChannel`).
- **Personalizadas**: HTTP 200 en tu aplicación, puerto TCP abierto, script propio aprobado.

### Olas y riesgo de rotura

`breaking_risk` de cada regla, junto con los datos de `observe`, alimenta el planificador:

| Ola | Criterio | Ejemplos |
|---|---|---|
| 1 · Cambios rápidos | `breaking_risk: none/low`, alto impacto | WDigest off, Guest off, logging de PowerShell, ASR LSASS |
| 2 · Validar antes | `medium` | Firma SMB, LLMNR/NBT-NS off, `noexec` en `/tmp` |
| 3 · Disruptivos | `high` o con usos detectados por `observe` | Restringir NTLM, Kerberos solo AES, WDAC, TLS 1.0 off |

## CLI prevista

```
bastion harden --profile linux-server-l1 --wave 1 --dry-run     # plan + diff
bastion harden --plan plan-20261015.json --apply                 # aplicar
bastion confirm <cambio>                                         # dead-man switch
bastion rollback --change <id> | --snapshot <id>                 # deshacer
bastion history                                                  # cambios aplicados
```
