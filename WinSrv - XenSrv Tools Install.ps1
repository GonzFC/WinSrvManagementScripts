<# 
.SYNOPSIS
  Installs/updates XenServer / Citrix Hypervisor VM Tools (Windows x64).

.DESCRIPTION
  - Discovers latest Management Agent MSI from xenserver.com (scrapes multiple patterns).
  - Falls back to known stable 9.4.1 if discovery fails.
  - Skips install when the same or newer version is already present (unless -Force).
  - Silent install with pinned drivers (ALLOWDRIVERUPDATE=NO).
  - Optional: block Windows Update driver delivery (-DisableWUDrivers).
  - Optional: verify Authenticode signature of the downloaded MSI (-VerifySignature).
  - Retries downloads and falls back to BITS if needed.
  - Explicit exit codes:
      0 = success/no action needed
      2 = installed/updated, reboot pending (suppressed by -NoReboot)
      10 = skipped (same or newer)
      100+ = error

.NOTES
  Run as Administrator. A reboot is recommended unless -NoReboot is used.
#>

[CmdletBinding()]
param(
  [switch]$NoReboot,
  [switch]$DisableWUDrivers,
  [switch]$Force,               # Force reinstall even if same/newer version present
  [switch]$VerifySignature,     # Authenticode check of MSI
  [string]$UrlOverride          # Provide a direct MSI URL and skip scraping
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#--------------------------- Helpers ------------------------------------------
function Write-Log {
  param([string]$Msg, [ValidateSet('INFO','WARN','ERR')]$Level='INFO')
  $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  $prefix = @{INFO='[+]';WARN='[!]';ERR='[x]'}[$Level]
  Write-Host "$stamp $prefix $Msg"
}

function Try-GetLatestMsiUrl {
  # Try multiple patterns in case the website structure changes slightly
  $page = 'https://www.xenserver.com/downloads'
  Write-Log "Fetching latest XenServer Tools page: $page"
  $html = (Invoke-WebRequest -UseBasicParsing $page).Content
  $patterns = @(
    'https://downloads\.xenserver\.com/vm-tools-windows/[^"''/]+/managementagent-[^"''/]+-x64\.msi',
    'https://downloads\.xenserver\.com/.+?/managementagent-[^"''/]+-x64\.msi'
  )
  foreach ($rx in $patterns) {
    $m = [regex]::Match($html, $rx)
    if ($m.Success) { return $m.Value }
  }
  throw "No MSI link found via scraping."
}

function Get-FallbackUrl {
  # Known good as of your previous script
  return 'https://downloads.xenserver.com/vm-tools-windows/9.4.1/managementagent-9.4.1-x64.msi'
}

function Download-File {
  param([string]$Url, [string]$Path)
  $attempts = 0
  $max = 3
  while ($true) {
    try {
      $attempts++
      Write-Log "Downloading ($attempt $attempts/$max): $Url"
      try {
        Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing -TimeoutSec 120
      } catch {
        Write-Log "Invoke-WebRequest failed: $($_.Exception.Message). Trying BITS..." 'WARN'
        Start-BitsTransfer -Source $Url -Destination $Path -RetryInterval 5 -ErrorAction Stop
      }
      if (-not (Test-Path $Path) -or ((Get-Item $Path).Length -lt 1024)) {
        throw "Downloaded file looks too small or missing."
      }
      return
    } catch {
      if ($attempts -ge $max) {
        throw "Failed to download after $max attempts: $($_.Exception.Message)"
      }
      Start-Sleep -Seconds ([int][Math]::Min(15, $attempts * 5))
    }
  }
}

function Get-MsiVersionFromName {
  param([string]$UrlOrPath)
  $name = Split-Path $UrlOrPath -Leaf
  $m = [regex]::Match($name, 'managementagent-([\d\.]+)-x64\.msi', 'IgnoreCase')
  if ($m.Success) { return $m.Groups[1].Value } else { return $null }
}

function Get-InstalledAgentInfo {
  # Scan Uninstall registry for common names. Avoid Win32_Product.
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
  )
  $candidates = @()
  foreach ($p in $paths) {
    if (Test-Path $p) {
      Get-ChildItem $p | ForEach-Object {
        $dn = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName
        $dv = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayVersion
        $us = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).UninstallString
        if ($dn -and ($dn -match 'XenServer|Citrix.*(VM|Hypervisor).*Tools|Management Agent')) {
          $candidates += [pscustomobject]@{ DisplayName=$dn; DisplayVersion=$dv; UninstallString=$us }
        }
      }
    }
  }
  # Return the best match if any
  return $candidates | Sort-Object DisplayName | Select-Object -First 1
}

function Compare-Version {
  param([string]$A, [string]$B)
  if (-not $A) { return -1 }
  if (-not $B) { return 1 }
  try {
    $va = [version]$A
    $vb = [version]$B
    return $va.CompareTo($vb)  # -1 if A<B, 0 equal, 1 if A>B
  } catch {
    # Fallback: lexical
    return [string]::Compare($A,$B)
  }
}

function Verify-FileSignature {
  param([string]$Path)
  $sig = Get-AuthenticodeSignature -FilePath $Path
  if ($sig.Status -ne 'Valid') {
    throw "MSI Authenticode signature invalid: $($sig.Status) by $($sig.SignerCertificate.Subject)"
  }
  Write-Log "MSI signature valid: $($sig.SignerCertificate.Subject)"
}

function Install-ManagementAgent {
  param([string]$MsiPath)

  Write-Log "Installing XenServer VM Tools (Management Agent)..."
  $args = @(
    '/i', "`"$MsiPath`"",
    '/qn', '/norestart',
    'ALLOWDRIVERINSTALL=YES',
    'ALLOWDRIVERUPDATE=NO',
    'ALLOWAUTOUPDATE=YES',
    'IDENTIFYAUTOUPDATE=NO'
  )
  $p = Start-Process -FilePath msiexec.exe -ArgumentList $args -PassThru -Wait
  if ($p.ExitCode -ne 0) { throw "msiexec exited with code $($p.ExitCode)" }
}

function Set-DisableWUDrivers {
  Write-Log "Disabling driver delivery via Windows Update..."
  $wuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
  if (-not (Test-Path $wuKey)) { New-Item -Path $wuKey -Force | Out-Null }
  New-ItemProperty -Path $wuKey -Name 'ExcludeWUDriversInQualityUpdate' -PropertyType DWord -Value 1 -Force | Out-Null
  gpupdate /target:computer /force | Out-Null
}

#--------------------------- Main ---------------------------------------------
try {
  if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please run from an elevated PowerShell session."
  }

  $url = $null
  if ($UrlOverride) {
    $url = $UrlOverride
    Write-Log "Using override URL."
  } else {
    try {
      $url = Try-GetLatestMsiUrl
    } catch {
      Write-Log "Discovery failed: $($_.Exception.Message). Falling back to 9.4.1" 'WARN'
      $url = Get-FallbackUrl
    }
  }

  $tempDir = Join-Path $env:TEMP 'XenTools'
  New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
  $dst = Join-Path $tempDir 'XenServer-VM-Tools-x64.msi'

  Download-File -Url $url -Path $dst

  if ($VerifySignature) { Verify-FileSignature -Path $dst }

  $incomingVer = Get-MsiVersionFromName $url
  if ($incomingVer) { Write-Log "Incoming package version (from name): $incomingVer" }

  $installed = Get-InstalledAgentInfo
  if ($installed) {
    Write-Log "Detected installed: '$($installed.DisplayName)' v$($installed.DisplayVersion)"
  } else {
    Write-Log "No existing XenServer/Citrix VM Tools Management Agent detected."
  }

  $skip = $false
  if (-not $Force -and $installed -and $incomingVer) {
    $cmp = Compare-Version $installed.DisplayVersion $incomingVer
    if ($cmp -ge 0) {
      Write-Log "Installed version ($($installed.DisplayVersion)) is same or newer than incoming ($incomingVer). Skipping. Use -Force to reinstall." 'WARN'
      $skip = $true
    }
  }

  if (-not $skip) {
    Install-ManagementAgent -MsiPath $dst
    Write-Log "Installation completed."
  }

  if ($DisableWUDrivers) { Set-DisableWUDrivers }

  if (-not $NoReboot) {
    Write-Log "Rebooting to complete driver initialization..."
    Restart-Computer -Force
    exit 2
  } else {
    Write-Log "Install complete. Reboot required to finish driver init." 'WARN'
    if ($skip) { exit 10 } else { exit 0 }
  }
}
catch {
  Write-Log $_.Exception.Message 'ERR'
  exit 100
}