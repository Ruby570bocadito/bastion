<#
=============================================================================
 Bastion · instalador para Windows 10/11 y Windows Server 2016-2025

 Instala o actualiza Bastion, lo prepara y lanza un primer escaneo.
 Abre PowerShell como administrador y pega:

   irm https://raw.githubusercontent.com/Ruby570bocadito/bastion/main/scripts/install.ps1 | iex

 Con opciones:

   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Ruby570bocadito/bastion/main/scripts/install.ps1))) -NoScan
   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Ruby570bocadito/bastion/main/scripts/install.ps1))) -Uninstall

 Parámetros:
   -Version <tag>       versión concreta (por defecto: la última)
   -NoScan              no lanzar el primer escaneo
   -NoOpen              no abrir el informe HTML al terminar
   -Force               reinstalar aunque ya esté en la última versión
   -Local <archivo>     instalar desde un .zip local (sin conexión)
   -Repo <owner/nombre> repositorio de GitHub
   -ReleasesUrl <url>   espejo interno de releases
   -Uninstall [-Purge]  desinstalar (con -Purge borra también config e informes)

 Variables equivalentes: BASTION_VERSION, BASTION_NO_SCAN=1, BASTION_REPO,
 BASTION_RELEASES_URL.

 Seguridad: el .zip descargado se verifica contra checksums.txt (SHA-256)
 antes de instalarse.
=============================================================================
#>
param(
    [string]$Version = $(if ($env:BASTION_VERSION) { $env:BASTION_VERSION } else { 'latest' }),
    [string]$Repo = $(if ($env:BASTION_REPO) { $env:BASTION_REPO } else { 'Ruby570bocadito/bastion' }),
    [string]$ReleasesUrl = $env:BASTION_RELEASES_URL,
    [string]$Local,
    [switch]$NoScan,
    [switch]$NoOpen,
    [switch]$Force,
    [switch]$Uninstall,
    [switch]$Purge
)

function Install-Bastion {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest es mucho más rápido sin barra

    # Windows PowerShell 5.1 no activa TLS 1.2 por defecto en sistemas antiguos.
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }

    $ScriptUrl  = "https://raw.githubusercontent.com/$Repo/main/scripts/install.ps1"
    if (-not $ReleasesUrl) { $ReleasesUrl = "https://github.com/$Repo/releases" }
    $ReleasesUrl = $ReleasesUrl.TrimEnd('/')
    $InstallDir = Join-Path $env:ProgramFiles 'Bastion'
    $Exe        = Join-Path $InstallDir 'bastion.exe'
    $DataDir    = Join-Path $env:ProgramData 'Bastion'

    Write-Banner

    # --- Elevación ------------------------------------------------------------
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Step 'Se necesitan permisos de administrador: se abrirá una ventana elevada (UAC)'
        $flags = @()
        if ($Version -ne 'latest') { $flags += "-Version '$Version'" }
        if ($Local)       { $flags += "-Local '$Local'" }
        if ($ReleasesUrl -ne "https://github.com/$Repo/releases") { $flags += "-ReleasesUrl '$ReleasesUrl'" }
        if ($NoScan)      { $flags += '-NoScan' }
        if ($NoOpen)      { $flags += '-NoOpen' }
        if ($Force)       { $flags += '-Force' }
        if ($Uninstall)   { $flags += '-Uninstall' }
        if ($Purge)       { $flags += '-Purge' }
        $flags += "-Repo '$Repo'"
        if ($PSCommandPath) {
            $cmd = "& '$PSCommandPath' $($flags -join ' ')"
        } else {
            $cmd = "& ([scriptblock]::Create((Invoke-RestMethod '$ScriptUrl'))) $($flags -join ' ')"
        }
        Start-Process -FilePath (Get-PowerShellExe) -Verb RunAs -ArgumentList @('-NoProfile', '-NoExit', '-Command', $cmd)
        return
    }

    if ($Uninstall) { Uninstall-Bastion -InstallDir $InstallDir -DataDir $DataDir; return }

    $arch = Get-BastionArch
    $asset = "bastion_windows_$arch.zip"
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("bastion-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null

    # bastion.exe escribe UTF-8; sin esto PowerShell lee su salida con la
    # página de códigos OEM y los acentos salen corruptos.
    $prevEncoding = [Console]::OutputEncoding
    try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

    try {
        # --- 1. Versión objetivo y versión instalada ------------------------
        $current = $null
        if (Test-Path $Exe) { $current = (& $Exe version --short 2>$null | Select-Object -First 1) }

        $zip = Join-Path $tmp $asset
        $doInstall = $true
        if ($Local) {
            Write-Step "Instalación sin conexión desde $Local"
            if (-not (Test-Path $Local)) { throw "No existe $Local" }
            Copy-Item $Local $zip
            $sums = Join-Path (Split-Path -Parent (Resolve-Path $Local)) 'checksums.txt'
            if (Test-Path $sums) { Test-Checksum -File $zip -Asset $asset -Sums (Get-Content $sums -Raw) }
            else { Write-Warn 'No hay checksums.txt junto al archivo: no se puede verificar la integridad' }
        } else {
            if ($Version -eq 'latest') {
                Write-Step "Buscando la última versión en $ReleasesUrl"
                $Version = ([string](Invoke-RestMethod -UseBasicParsing "$ReleasesUrl/latest/download/version.txt")).Trim()
                if (-not $Version) { throw 'version.txt vacío' }
            }
            if ($current -and ($current.TrimStart('v') -eq $Version.TrimStart('v')) -and -not $Force) {
                Write-Ok "Bastion $Version ya está instalado y actualizado"
                $doInstall = $false
            } else {
                if ($current) { Write-Step "Actualizando Bastion $current -> $Version ($arch)" }
                else { Write-Step "Instalando Bastion $Version ($arch)" }
                $base = "$ReleasesUrl/download/$Version"
                $sums = [string](Invoke-RestMethod -UseBasicParsing "$base/checksums.txt")
                Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $zip
                Test-Checksum -File $zip -Asset $asset -Sums $sums
            }
        }

        if ($doInstall) {
            $extract = Join-Path $tmp 'x'
            Expand-Archive -Path $zip -DestinationPath $extract -Force
            $new = Get-ChildItem -Path $extract -Recurse -Filter 'bastion.exe' | Select-Object -First 1
            if (-not $new) { throw 'El archivo no contiene bastion.exe' }
            New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
            # Un ejecutable en uso no se puede sobrescribir pero sí renombrar.
            if (Test-Path $Exe) {
                Remove-Item "$Exe.old" -Force -ErrorAction SilentlyContinue
                Move-Item $Exe "$Exe.old" -Force
            }
            Copy-Item $new.FullName $Exe -Force
            Unblock-File $Exe -ErrorAction SilentlyContinue
            Remove-Item "$Exe.old" -Force -ErrorAction SilentlyContinue
            Write-Ok "Instalado en $Exe ($(& $Exe version --short))"
            Add-ToMachinePath $InstallDir
        }

        # --- 2. Preparación -------------------------------------------------
        Write-Step 'Preparando Bastion'
        & $Exe init --no-color | ForEach-Object { "  $_" }
        if ($LASTEXITCODE -ne 0) { throw 'bastion init falló' }

        # --- 3. Primer escaneo (solo lectura) ---------------------------------
        if (-not $NoScan) {
            Write-Step 'Primer escaneo (solo lectura: no se modifica nada)'
            $scanArgs = @('scan', '--save')
            if (-not $NoOpen -and [Environment]::UserInteractive) { $scanArgs += '--open' }
            & $Exe @scanArgs
        }

        Write-Summary
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
        try { [Console]::OutputEncoding = $prevEncoding } catch { }
    }
}

function Get-PowerShellExe {
    $p = (Get-Process -Id $PID).Path
    if ($p) { return $p }
    return (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
}

function Get-BastionArch {
    $a = $env:PROCESSOR_ARCHITEW6432
    if (-not $a) { $a = $env:PROCESSOR_ARCHITECTURE }
    switch ($a) {
        'AMD64' { return 'amd64' }
        'ARM64' { return 'arm64' }
        default { throw "Arquitectura no soportada: $a (soportadas: AMD64, ARM64)" }
    }
}

function Test-Checksum([string]$File, [string]$Asset, [string]$Sums) {
    $want = $null
    foreach ($line in ($Sums -split "`r?`n")) {
        $parts = $line.Trim() -split '\s+'
        if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq $Asset) { $want = $parts[0].ToLower() }
    }
    if (-not $want) { throw "checksums.txt no contiene $Asset" }
    $got = (Get-FileHash -Algorithm SHA256 -Path $File).Hash.ToLower()
    if ($got -ne $want) { throw "La suma SHA-256 no coincide (esperada $want, obtenida $got). Instalación abortada." }
    Write-Ok 'Suma SHA-256 verificada'
}

function Add-ToMachinePath([string]$Dir) {
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $parts = $path -split ';' | Where-Object { $_ }
    if ($parts -notcontains $Dir) {
        [Environment]::SetEnvironmentVariable('Path', (($parts + $Dir) -join ';'), 'Machine')
        Write-Ok "$Dir añadido al PATH del sistema"
    }
    if (($env:Path -split ';') -notcontains $Dir) { $env:Path = "$env:Path;$Dir" }
}

function Uninstall-Bastion([string]$InstallDir, [string]$DataDir) {
    Write-Step 'Desinstalando Bastion'
    # El análisis programado y el origen del Visor de eventos.
    $task = Get-ScheduledTask -TaskPath '\Bastion\' -TaskName 'Escaneo diario' -ErrorAction SilentlyContinue
    if ($task) {
        $task | Unregister-ScheduledTask -Confirm:$false
        Write-Ok 'Quitado el análisis programado'
    }
    Remove-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Bastion' -Recurse -ErrorAction SilentlyContinue
    if (Test-Path $InstallDir) {
        Remove-Item -Recurse -Force $InstallDir
        Write-Ok "Eliminado $InstallDir"
    } else {
        Write-Warn "No se encontró $InstallDir"
    }
    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $new = ($path -split ';' | Where-Object { $_ -and $_ -ne $InstallDir }) -join ';'
    if ($new -ne $path) { [Environment]::SetEnvironmentVariable('Path', $new, 'Machine') }
    if ($Purge) {
        Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
        Write-Ok "Eliminado $DataDir"
    } else {
        Write-Host "  Se conservan la configuración y los informes en $DataDir. Usa -Purge para borrarlos." -ForegroundColor DarkGray
    }
}

function Write-Banner {
    Write-Host ''
    Write-Host '  BASTION' -ForegroundColor Cyan -NoNewline
    Write-Host '  · hardening para Windows, Windows Server y Linux' -ForegroundColor DarkGray
    Write-Host ''
}
function Write-Step([string]$m) { Write-Host '==> ' -ForegroundColor Cyan -NoNewline; Write-Host $m -ForegroundColor White }
function Write-Ok([string]$m)   { Write-Host '  [OK] ' -ForegroundColor Green -NoNewline; Write-Host $m }
function Write-Warn([string]$m) { Write-Host '  [!] ' -ForegroundColor Yellow -NoNewline; Write-Host $m }

function Write-Summary {
    Write-Host ''
    Write-Host '  Bastion está listo.' -ForegroundColor Green
    Write-Host ''
    Write-Host '  Comandos útiles (PowerShell como administrador)'
    Write-Host '    bastion scan                 auditar el equipo'
    Write-Host '    bastion scan --save --open   informe visual (HTML)'
    Write-Host '    bastion rules show <ID>      detalle y remediación de un control'
    Write-Host '    bastion update               actualizar Bastion y sus reglas'
    Write-Host ''
    Write-Host '  Vuelve a ejecutar este mismo comando en cualquier momento para actualizar.' -ForegroundColor DarkGray
    Write-Host ''
}

if ($env:BASTION_NO_SCAN -eq '1') { $NoScan = [switch]$true }

try {
    Install-Bastion
} catch {
    Write-Host ''
    Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ''
}
