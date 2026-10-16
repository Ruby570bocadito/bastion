# 09 · Instalación

Un **único comando** instala Bastion, lo actualiza si ya estaba, lo prepara (directorios, configuración y permisos) y lanza un primer escaneo de solo lectura. Para actualizar en el futuro basta con volver a pegarlo, o ejecutar `bastion update`.

## Linux

Requisitos: amd64 o arm64, `curl` o `wget`, `sha256sum` o `shasum`, y root.

```bash
curl -fsSL https://raw.githubusercontent.com/Ruby570bocadito/bastion/main/scripts/install.sh | sudo bash
```

Con opciones (todo lo que va tras `--` son argumentos del instalador):

```bash
curl -fsSL https://raw.githubusercontent.com/Ruby570bocadito/bastion/main/scripts/install.sh | sudo bash -s -- --no-scan
curl -fsSL https://raw.githubusercontent.com/Ruby570bocadito/bastion/main/scripts/install.sh | sudo bash -s -- --version v0.2.0
```

| Opción | Variable | Descripción |
|---|---|---|
| `--version <tag>` | `BASTION_VERSION` | Versión concreta (por defecto, la última) |
| `--no-scan` | `BASTION_NO_SCAN=1` | No lanzar el primer escaneo |
| `--force` | | Reinstalar aunque ya esté actualizado |
| `--local <archivo.tar.gz>` | | Instalar sin conexión. Si hay un `checksums.txt` al lado, se verifica |
| `--repo <owner/repo>` | `BASTION_REPO` | Repositorio de GitHub |
| `--releases-url <url>` | `BASTION_RELEASES_URL` | Espejo interno de releases |
| `--prefix <dir>` | `BASTION_PREFIX` | Directorio del binario (por defecto `/usr/local/bin`) |
| `--uninstall [--purge]` | | Desinstalar; `--purge` borra también configuración e informes |

Qué hace, paso a paso:

1. Comprueba que es Linux, que se ejecuta como root y la arquitectura.
2. Consulta la última versión en `<releases>/latest/download/version.txt` y la compara con la instalada.
3. Descarga `checksums.txt` y `bastion_linux_<arch>.tar.gz` y **verifica el SHA-256**.
4. Instala `/usr/local/bin/bastion` con reemplazo atómico.
5. Ejecuta `bastion init`: crea `/etc/bastion` (con `config.yaml` y `rules.d/`) y `/var/lib/bastion` (con `reports/` y `snapshots/`) con permisos `0750`.
6. Si `sudo` usa un `secure_path` sin `/usr/local/bin` (RHEL), crea el enlace `/usr/bin/bastion`.
7. Lanza `bastion scan --save` y muestra el resumen y la ruta del informe HTML.

El script completo está dentro de una función `main` que se invoca en la última línea: si la descarga se corta a medias, no se ejecuta nada.

> **¿Prefieres revisar antes de ejecutar?**
> `curl -fsSLO https://raw.githubusercontent.com/Ruby570bocadito/bastion/main/scripts/install.sh && less install.sh && sudo bash install.sh`

## Windows 10/11 y Windows Server 2016-2025

Abre **PowerShell como administrador** y pega:

```powershell
irm https://raw.githubusercontent.com/Ruby570bocadito/bastion/main/scripts/install.ps1 | iex
```

Si no lo abres como administrador, el script pide elevación (UAC) y continúa en una ventana nueva.

Con parámetros:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Ruby570bocadito/bastion/main/scripts/install.ps1))) -NoScan
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Ruby570bocadito/bastion/main/scripts/install.ps1))) -Uninstall -Purge
```

| Parámetro | Variable | Descripción |
|---|---|---|
| `-Version <tag>` | `BASTION_VERSION` | Versión concreta |
| `-NoScan` | `BASTION_NO_SCAN=1` | No lanzar el primer escaneo |
| `-NoOpen` | | No abrir el informe HTML al terminar |
| `-Force` | | Reinstalar aunque esté actualizado |
| `-Local <archivo.zip>` | | Instalar sin conexión |
| `-Repo <owner/repo>` | `BASTION_REPO` | Repositorio de GitHub |
| `-ReleasesUrl <url>` | `BASTION_RELEASES_URL` | Espejo interno |
| `-Uninstall [-Purge]` | | Desinstalar |

Qué hace: activa TLS 1.2 (Windows PowerShell 5.1), detecta la arquitectura (AMD64/ARM64), descarga y verifica `bastion_windows_<arch>.zip`, instala en `C:\Program Files\Bastion\bastion.exe` (renombrando el anterior si está en uso), lo añade al `PATH` del sistema, ejecuta `bastion init` (crea `C:\ProgramData\Bastion` con ACL solo para Administradores y SYSTEM) y lanza `bastion scan --save --open`.

Compatible con Windows PowerShell 5.1 y PowerShell 7. Los mensajes evitan símbolos que la consola clásica no puede mostrar.

## Despliegue masivo

| Entorno | Cómo |
|---|---|
| GPO | Tarea programada de inicio que ejecute el one-liner con `-NoScan -NoOpen`, o copia del `.exe` + `bastion init` |
| Intune / SCCM | Script de PowerShell con el one-liner; detección por `C:\Program Files\Bastion\bastion.exe` |
| Ansible | `ansible.builtin.shell: curl -fsSL …/install.sh \| bash -s -- --no-scan` o `win_shell` con el one-liner de PowerShell |
| Imágenes doradas | Packer: instalar y ejecutar `bastion scan --min-score 90` como validación |
| 🔜 Paquetes nativos | MSI (WiX), `.deb` y `.rpm` (nfpm) en la fase 3 |

## Redes aisladas y espejos internos

Copia los ficheros de una release a un servidor web interno con esta estructura (la misma que GitHub):

```
https://mirror.interno/bastion/
├── latest/download/version.txt          ← contiene la etiqueta, p. ej. v0.2.0
└── download/v0.2.0/
    ├── checksums.txt
    ├── bastion_linux_amd64.tar.gz
    ├── bastion_linux_arm64.tar.gz
    ├── bastion_windows_amd64.zip
    └── bastion_windows_arm64.zip
```

Y úsalo en el instalador (`--releases-url` / `-ReleasesUrl`), en la variable `BASTION_RELEASES_URL` o en `config.yaml`:

```yaml
update:
  releases_url: https://mirror.interno/bastion
```

Sin ningún servidor: copia el archivo y su `checksums.txt` y usa `--local` / `-Local`.

## Actualizar

```bash
sudo bastion update                    # descarga, verifica y reemplaza
sudo bastion update --check            # solo comprobar
sudo bastion update --version v0.3.2   # una versión concreta (también para volver atrás); avisa si aún no está publicada
```

Las reglas oficiales van dentro del binario: al actualizar Bastion se actualizan también las reglas.

Justo después de publicar una versión, GitHub puede seguir anunciando la anterior como "última" durante unos minutos (caché). `--version` no depende de eso.

En Windows, `C:\Program Files\Bastion` solo lo puede modificar un administrador. Si ejecutas `bastion update` en una ventana normal, Bastion lo detecta antes de descargar nada y abre una ventana de administrador (aviso de UAC) que termina la actualización y espera a que pulses Intro. En Linux, sin root, te pide repetir con `sudo`.

## Rutas

| | Linux | Windows |
|---|---|---|
| Binario | `/usr/local/bin/bastion` | `C:\Program Files\Bastion\bastion.exe` |
| Configuración | `/etc/bastion/config.yaml` | `C:\ProgramData\Bastion\config.yaml` |
| Reglas propias | `/etc/bastion/rules.d/` | `C:\ProgramData\Bastion\rules.d\` |
| Informes | `/var/lib/bastion/reports/` | `C:\ProgramData\Bastion\reports\` |
| Instantáneas (fase 2) | `/var/lib/bastion/snapshots/` | `C:\ProgramData\Bastion\snapshots\` |

`BASTION_HOME` sustituye la configuración y los datos por un único directorio (útil en desarrollo).

## Desinstalar

```bash
curl -fsSL https://raw.githubusercontent.com/Ruby570bocadito/bastion/main/scripts/install.sh | sudo bash -s -- --uninstall [--purge]
```

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Ruby570bocadito/bastion/main/scripts/install.ps1))) -Uninstall [-Purge]
```
