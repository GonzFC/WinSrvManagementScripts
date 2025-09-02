<# 
Installs latest Jump Desktop Connect, enables RDP, sets ComputerName to host's name,
and prompts for your 6-digit Connect Code.

Paste the whole script into an elevated PowerShell session, or save and run it.
#>

# --- Ensure script runs unrestricted in this session ---
try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
} catch {
    Write-Warning "Could not set ExecutionPolicy to Bypass. Proceeding anyway..."
}

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Re-launching with Administrator privileges..."
    $psi = New-Object System.Diagnostics.ProcessStartInfo "PowerShell"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $psi.Verb = "runas"
    [Diagnostics.Process]::Start($psi) | Out-Null
    exit
  }
}
Assert-Admin

# Force TLS1.2 for downloads
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

# Ask for 6-digit user code (Connect Code)
$rawCode = Read-Host "Enter your 6-digit Jump user code (Connect Code)"
if ([string]::IsNullOrWhiteSpace($rawCode)) { throw "Connect Code is required." }
$ConnectCode = ($rawCode -replace '\s','')

if ($ConnectCode -notmatch '^\d{6}$' -and $ConnectCode.Length -lt 6) {
  Write-Warning "The code doesn’t look like 6 digits; proceeding anyway."
}

# Latest Jump Connect endpoints
$msiUrl = "https://jumpdesktop.com/downloads/connect/winmsi"
$exeUrl = "https://jumpdesktop.com/downloads/connect/win"

$tempDir = Join-Path $env:TEMP ("JumpConnect_" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tempDir | Out-Null
$msiPath = Join-Path $tempDir "JumpDesktopConnect.msi"
$exePath = Join-Path $tempDir "JumpDesktopConnect.exe"

function Download-File([string]$Url,[string]$Dest) {
  Write-Host "Downloading $Url ..."
  Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
}

$computerName = $env:COMPUTERNAME
$installed = $false

try {
  Download-File $msiUrl $msiPath
  Write-Host "Installing Jump Desktop Connect (MSI, silent)..."
  $msiArgs = "/i `"$msiPath`" /qn CONNECTCODE=$ConnectCode RDPENABLED=true"
  $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
  if ($p.ExitCode -eq 0) { $installed = $true }
  else { Write-Warning "MSI failed with exit code $($p.ExitCode). Trying EXE..." }
} catch { Write-Warning "MSI failed: $($_.Exception.Message). Trying EXE..." }

if (-not $installed) {
  Download-File $exeUrl $exePath
  Write-Host "Installing Jump Desktop Connect (EXE, silent)..."
  $exeArgs = "/qn CONNECTCODE=$ConnectCode RDPENABLED=true"
  $p = Start-Process -FilePath $exePath -ArgumentList $exeArgs -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "EXE failed with exit code $($p.ExitCode)." }
}

# Locate JumpConnect.exe
$connectPath = $null
try { $connectPath = (Get-ItemProperty "HKLM:\SOFTWARE\Jump Desktop\Connect\Shared").ConnectPath } catch {}
if (-not $connectPath -or -not (Test-Path $connectPath)) { throw "Couldn't find JumpConnect.exe." }

# Set ComputerName and reapply Connect Code
Write-Host "Setting Jump ComputerName to '$computerName'..."
& $connectPath --serverconfig ComputerName="$computerName" | Out-Null

Write-Host "Applying Connect Code..."
& $connectPath --connectcode $ConnectCode | Out-Null

Write-Host ""
Write-Host "✅ Jump Desktop Connect installed and configured."
Write-Host "   • RDP tunneling enabled"
Write-Host "   • Computer Name set to: $computerName"
Write-Host "   • Connect Code applied"

try { Remove-Item -Path $tempDir -Recurse -Force } catch {}