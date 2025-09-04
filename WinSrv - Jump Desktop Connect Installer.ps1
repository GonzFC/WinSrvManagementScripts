<# 
Instala la última Jump Desktop Connect, habilita RDP, fija ComputerName al hostname
y solicita tu código de 6 dígitos (Connect Code).

Guárdalo como .ps1 y ejecútalo en PowerShell **elevado**.
#>

[CmdletBinding()]
param()

# --- (Opcional) Relajar ExecutionPolicy solo para ESTA sesión ---
#   OJO: si hay GPO forzada, esto no la sobrepasa para archivos .ps1.
try { Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop } catch {}

$ErrorActionPreference = 'Stop'

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $pr = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Re-lanzando como Administrador..."
    $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    $psi.Verb = "runas"
    [Diagnostics.Process]::Start($psi) | Out-Null
    exit
  }
}
Assert-Admin

# TLS 1.2 para descargas en hosts viejos
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

# Pedir el código de 6 dígitos (Connect Code)
$rawCode = Read-Host "Enter your 6-digit Jump user code (Connect Code)"
if ([string]::IsNullOrWhiteSpace($rawCode)) { throw "Connect Code is required." }
$ConnectCode = ($rawCode -replace '\s','')
if ($ConnectCode -notmatch '^\d{6}$' -and $ConnectCode.Length -lt 6) {
  Write-Warning "El código no parece de 6 dígitos; continúo (Jump también acepta códigos más largos de Teams)."
}

# Endpoints de la última versión
$msiUrl = "https://jumpdesktop.com/downloads/connect/winmsi"
$exeUrl = "https://jumpdesktop.com/downloads/connect/win"

# Carpeta temporal
$tempDir = Join-Path $env:TEMP ("JumpConnect_" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tempDir | Out-Null
$msiPath = Join-Path $tempDir "JumpDesktopConnect.msi"
$exePath = Join-Path $tempDir "JumpDesktopConnect.exe"

function Download-File {
  param([string]$Url,[string]$Dest)
  Write-Host "Descargando $Url ..."
  Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
}

$computerName = $env:COMPUTERNAME
$installed = $false

# Intentar MSI primero (acepta variables de instalador)
try {
  Download-File -Url $msiUrl -Dest $msiPath
  Write-Host "Instalando Jump Desktop Connect (MSI, silencioso)..."
  $msiArgs = "/i `"$msiPath`" /qn CONNECTCODE=$ConnectCode RDPENABLED=true"
  $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
  if ($p.ExitCode -eq 0) { $installed = $true }
  else { Write-Warning "MSI devolvió código $($p.ExitCode). Intento con EXE..." }
}
catch {
  Write-Warning "Fallo con MSI: $($_.Exception.Message). Intento con EXE..."
}

if (-not $installed) {
  Download-File -Url $exeUrl -Dest $exePath
  Write-Host "Instalando Jump Desktop Connect (EXE, silencioso)..."
  # El EXE también soporta /qn y variables de instalador
  $exeArgs = "/qn CONNECTCODE=$ConnectCode RDPENABLED=true"
  $p = Start-Process -FilePath $exePath -ArgumentList $exeArgs -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "Instalación EXE falló con código $($p.ExitCode)." }
}

# Localizar JumpConnect.exe por registro
$connectPath = $null
try {
  $connectPath = (Get-ItemProperty "HKLM:\SOFTWARE\Jump Desktop\Connect\Shared" -ErrorAction Stop).ConnectPath
} catch {
  Start-Sleep -Seconds 3
  try { $connectPath = (Get-ItemProperty "HKLM:\SOFTWARE\Jump Desktop\Connect\Shared" -ErrorAction Stop).ConnectPath } catch {}
}

if (-not $connectPath -or -not (Test-Path $connectPath)) {
  throw "No se encontró JumpConnect.exe después de instalar."
}

# Ajustes post-instalación
Write-Host "Fijando ComputerName en Jump a '$computerName'..."
& $connectPath --serverconfig ComputerName="$computerName" | Out-Null

Write-Host "Aplicando Connect Code para agregar el usuario de acceso remoto..."
& $connectPath --connectcode $ConnectCode | Out-Null

Write-Host ""
Write-Host "✅ Jump Desktop Connect instalado y configurado."
Write-Host "   • RDP habilitado (tunneling)"
Write-Host "   • Computer Name: $computerName"
Write-Host "   • Connect Code aplicado"

# Limpieza
try { Remove-Item -Path $tempDir -Recurse -Force } catch {}