<# 
.SYNOPSIS
  Instala/actualiza Tailscale en Windows y lo deja funcionando como servicio + unattended.
  Compatible con Windows Server Core / Server / Desktop.

.DESCRIPTION
  - Descarga el MSI más reciente desde pkgs.tailscale.com/stable/ según arquitectura (amd64/arm64/x86).
  - Instala/actualiza silencioso.
  - Asegura el servicio "Tailscale" en automático + DelayedAutoStart + recuperación ante fallos.
  - Crea una tarea programada al inicio (SYSTEM, Highest) que reintenta "tailscale up --unattended" 
    con los flags que pases al script, para sobrevivir a arranques sin sesión de usuario.
  - Idempotente: seguro de re-ejecutar.

.PARAMETER AuthKey
  (Opcional) Auth key de Tailscale (idealmente preaprobada). Si no se da, se configura todo pero
  el "up" requerirá aprobación o la harás luego.

.PARAMETER LoginServer
  (Opcional) URL alterna de control plane (Enterprise/self-hosted).

.PARAMETER AcceptRoutes
  (Switch) Aceptar rutas anunciadas.

.PARAMETER AdvertiseRoutes
  (Opcional) CSV de subredes a anunciar (p.ej. "192.168.10.0/24,192.168.20.0/24").

.PARAMETER AcceptDNS
  (Switch) Forzar aceptar DNS de Tailscale (por defecto, NO se fuerza y se pasa --accept-dns=false).

.PARAMETER Hostname
  (Opcional) Nombre de host a reportar en Tailscale (si omites, usa el del sistema).

.PARAMETER Operator
  (Opcional) Etiqueta operator para auditoría (si aplica a tu tailnet).

.EXAMPLE
  .\Install-Tailscale-Unattended.ps1 -AuthKey 'tskey-auth-xxxxx' -AcceptDNS:$false

.EXAMPLE
  .\Install-Tailscale-Unattended.ps1 -AuthKey 'tskey-auth-xxxxx' -LoginServer 'https://login.miempresa.tld' -AcceptRoutes

.EXAMPLE
  .\Install-Tailscale-Unattended.ps1 -AuthKey 'tskey-auth-xxxxx' -AdvertiseRoutes '192.168.10.0/24,192.168.20.0/24' -AcceptDNS:$false -Hostname 'vlabs-srv-01'
#>

[CmdletBinding()]
param(
  [string]$AuthKey,
  [string]$LoginServer,
  [switch]$AcceptRoutes,
  [string]$AdvertiseRoutes,
  [switch]$AcceptDNS,
  [string]$Hostname,
  [string]$Operator
)

# ------------------ Helpers ------------------

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw "Ejecuta este script en PowerShell 'Como Administrador'."
  }
}

function Enable-Tls12 {
  try {
    [System.Net.ServicePointManager]::SecurityProtocol = `
      [System.Net.SecurityProtocolType]::Tls12 -bor `
      [System.Net.SecurityProtocolType]::Tls11 -bor `
      [System.Net.SecurityProtocolType]::Tls
  } catch { }
}

function Get-ArchTag {
  switch ($env:PROCESSOR_ARCHITECTURE.ToLower()) {
    'amd64' { 'amd64' }
    'arm64' { 'arm64' }
    'x86'   { 'x86' }
    default { 'amd64' }
  }
}

function Get-LatestMsiUrl {
  param([string]$ArchTag)

  $indexUrl = 'https://pkgs.tailscale.com/stable/'
  Write-Host "Consultando índice de paquetes: $indexUrl"
  $resp = Invoke-WebRequest -Uri $indexUrl -UseBasicParsing
  if(-not $resp -or -not $resp.Content){ throw "No pude obtener el índice de paquetes." }

  $msiRegex = [regex]"tailscale-setup-(?<ver>\d+\.\d+\.\d+)-$([regex]::Escape($ArchTag))\.msi"
  $matches = $msiRegex.Matches($resp.Content) | Sort-Object { [version]$_.Groups['ver'].Value } -Descending
  if($matches.Count -eq 0){ throw "No encontré MSI para arquitectura $ArchTag en stable." }

  $latestFile = $matches[0].Value
  $latestUrl  = ($indexUrl.TrimEnd('/') + '/' + $latestFile)
  $shaUrl     = $latestUrl + '.sha256'

  [pscustomobject]@{
    FileName = $latestFile
    Url      = $latestUrl
    Sha256   = $shaUrl
    Version  = $matches[0].Groups['ver'].Value
  }
}

function Download-File {
  param([string]$Url, [string]$OutPath)
  Write-Host "Descargando $Url -> $OutPath"
  Invoke-WebRequest -Uri $Url -OutFile $OutPath -UseBasicParsing
  if(-not (Test-Path $OutPath)){ throw "Falló la descarga: $Url" }
}

function Verify-FileSha256 {
  param([string]$FilePath, [string]$ShaUrl)
  try {
    $tmpSha = Join-Path ([IO.Path]::GetDirectoryName($FilePath)) (([IO.Path]::GetFileName($FilePath)) + '.sha256')
    Invoke-WebRequest -Uri $ShaUrl -OutFile $tmpSha -UseBasicParsing -ErrorAction Stop
    $expected = (Get-Content $tmpSha | Select-Object -First 1).Split(' ')[0].Trim()
    $actualObj = Get-FileHash -Algorithm SHA256 -Path $FilePath
    if($actualObj.Hash.ToLower() -ne $expected.ToLower()){
      throw "SHA256 no coincide. Esperado=$expected Actual=$($actualObj.Hash)"
    }
    Remove-Item $tmpSha -Force -ErrorAction SilentlyContinue
  } catch {
    Write-Warning "No se pudo verificar SHA256: $($_.Exception.Message). Continúo."
  }
}

function Install-Or-Upgrade-MSI {
  param([string]$MsiPath)

  Write-Host "Instalando/Actualizando Tailscale MSI (modo silencioso)..."
  $args = "/i `"$MsiPath`" /qn /norestart"
  $p = Start-Process msiexec.exe -ArgumentList $args -Wait -PassThru
  if($p.ExitCode -ne 0){
    throw "msiexec devolvió código $($p.ExitCode)"
  }
}

function Get-TailscaleExe {
  # Candidatos conocidos (ruta nueva, x86, legacy)
  $candidates = @(
    'C:\Program Files\Tailscale\tailscale.exe',
    'C:\Program Files (x86)\Tailscale\tailscale.exe',
    'C:\Program Files\Tailscale IPN\tailscale.exe'
  )

  # Además, buscar por si cambia otra vez
  $candidates += (Get-ChildItem 'C:\Program Files','C:\Program Files (x86)' -Recurse `
                   -Filter tailscale.exe -ErrorAction SilentlyContinue `
                   | Select-Object -ExpandProperty FullName)

  $hit = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
  if(-not $hit){ throw "No se encontró tailscale.exe tras la instalación en rutas conocidas." }
  return $hit
}

function Ensure-Service {
  $svc = Get-Service -Name 'Tailscale' -ErrorAction SilentlyContinue
  if(-not $svc){ throw "Servicio 'Tailscale' no encontrado tras instalación." }

  Set-Service -Name 'Tailscale' -StartupType Automatic
  $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tailscale'
  New-ItemProperty -Path $svcKey -Name 'DelayedAutoStart' -PropertyType DWord -Value 1 -Force | Out-Null

  # Recuperación del servicio: reiniciar 3 veces con backoff
  & sc.exe failure Tailscale reset= 60 actions= restart/3000/restart/60000/restart/120000 | Out-Null
  & sc.exe failureflag Tailscale 1 | Out-Null

  if($svc.Status -ne 'Running'){
    Write-Host "Iniciando servicio Tailscale..."
    Start-Service -Name 'Tailscale'
  }
}

function Build-UpArgs {
  param(
    [string]$AuthKey, [string]$LoginServer, [switch]$AcceptRoutes, 
    [string]$AdvertiseRoutes, [switch]$AcceptDNS, [string]$Hostname, [string]$Operator
  )

  $args = @('--unattended')

  if($AuthKey){      $args += "--authkey=$AuthKey" }
  if($LoginServer){  $args += "--login-server=$LoginServer" }
  if($AcceptRoutes){ $args += "--accept-routes=true" }
  if($AdvertiseRoutes){ $args += "--advertise-routes=$AdvertiseRoutes" }
  if($AcceptDNS){    $args += "--accept-dns=true" } else { $args += "--accept-dns=false" }
  if($Hostname){     $args += "--hostname=$Hostname" }
  if($Operator){     $args += "--operator=$Operator" }

  # Asegurar quoting si hay espacios
  ($args | ForEach-Object { if($_ -match '\s'){ '"{0}"' -f $_ } else { $_ } }) -join ' '
}

function Ensure-StartupScheduledTask {
  param([string]$ArgsForUp, [string]$TailscaleExe)

  $taskName = 'Tailscale-EnsureUp-AtStartup'
  $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  if($existing){
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
  }

  $scriptPath = "$env:ProgramData\Tailscale\EnsureUp.ps1"
  New-Item -ItemType Directory -Path (Split-Path $scriptPath) -Force | Out-Null

  $psCmd = @"
try {
  if((Get-Service Tailscale -ErrorAction Stop).Status -ne 'Running'){
    Start-Service Tailscale
  }
  # Espera breve por red
  Start-Sleep -Seconds 5
  & '$TailscaleExe' up $ArgsForUp 2>&1 | Out-Null
} catch {
  try {
    New-Item -ItemType Directory -Path 'C:\ProgramData\Tailscale' -Force | Out-Null
  } catch {}
  Add-Content -Path 'C:\ProgramData\Tailscale\StartupTask.log' -Value ("`$(Get-Date -f s) ERROR: $($_.Exception.Message)")
}
"@

  Set-Content -Path $scriptPath -Value $psCmd -Encoding UTF8

  $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
  $trigger   = New-ScheduledTaskTrigger -AtStartup
  $trigger.Delay = 'PT60S'   # 60s para dar tiempo a la red/servicios
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
  $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable `
                -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 1)

  Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
}

# ------------------ MAIN ------------------

try {
  Assert-Admin
  Enable-Tls12

  $arch = Get-ArchTag
  $pkg  = Get-LatestMsiUrl -ArchTag $arch

  Write-Host "Última versión stable encontrada: $($pkg.Version) para $arch"

  $tmpDir = Join-Path $env:TEMP "tailscale-installer"
  New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
  $msiPath = Join-Path $tmpDir $pkg.FileName

  if(-not (Test-Path $msiPath)){
    Download-File -Url $pkg.Url -OutPath $msiPath
    Verify-FileSha256 -FilePath $msiPath -ShaUrl $pkg.Sha256
  } else {
    Write-Host "MSI ya presente en caché: $msiPath"
  }

  Install-Or-Upgrade-MSI -MsiPath $msiPath
  Ensure-Service

  $tailscaleExe = Get-TailscaleExe
  $upArgs = Build-UpArgs -AuthKey $AuthKey -LoginServer $LoginServer -AcceptRoutes:$AcceptRoutes `
                         -AdvertiseRoutes $AdvertiseRoutes -AcceptDNS:$AcceptDNS -Hostname $Hostname -Operator $Operator

  Ensure-StartupScheduledTask -ArgsForUp $upArgs -TailscaleExe $tailscaleExe

  # Ejecutar up ahora si hay AuthKey (si no, la tarea al arranque lo intentará)
  if($AuthKey){
    Write-Host "Ejecutando: $tailscaleExe up $upArgs"
    & $tailscaleExe up $upArgs
    if($LASTEXITCODE -ne 0){
      Write-Warning "tailscale up devolvió código $LASTEXITCODE; la tarea al arranque volverá a intentarlo."
    }
  } else {
    Write-Warning "No se proporcionó -AuthKey. Instalado y configurado; ejecuta luego 'tailscale up' o re-lanza con -AuthKey."
  }

  Write-Host "`n✔ Listo. Tailscale $($pkg.Version) instalado y configurado (servicio + unattended + tarea de inicio)."
  Write-Host "  Servicio.........: Tailscale (Automático + DelayedAutoStart + recuperación)"
  Write-Host "  Tarea al inicio..: Tailscale-EnsureUp-AtStartup (SYSTEM, delay 60s)"
  Write-Host "  Ejecutable.......: $tailscaleExe"
  Write-Host "  Logs.............: C:\ProgramData\Tailscale (incluye StartupTask.log)"
  Write-Host "  Comprobación.....: 'tailscale status'"

  exit 0
}
catch {
  Write-Error $_.Exception.Message
  exit 1
}
