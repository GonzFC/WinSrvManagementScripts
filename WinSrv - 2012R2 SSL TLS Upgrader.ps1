<# 
  Upgrade-PowerShellTLS.ps1
  - PowerShell 4.0 compatible
  - Enables TLS 1.2 for .NET and SChannel
  - Installs .NET Framework 4.8 (if needed)
  - Upgrades Windows PowerShell to 5.1 (WMF 5.1) per OS
  - Optional: -UpdateRoots to refresh root CAs from Windows Update
#>

param(
  [switch]$UpdateRoots
)

# --- Self-elevate if not admin ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $IsAdmin) {
  $psi = '-NoProfile -ExecutionPolicy Bypass -File "{0}"{1}' -f $PSCommandPath, ($(if($UpdateRoots){' -UpdateRoots'} else {''}))
  Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $psi
  return
}

# --- Ensure TLS 1.2 for *this* process (so downloads succeed even on old defaults) ---
try {
  $sp = [Net.ServicePointManager]::SecurityProtocol
  $tls12EnumPresent = [enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls12'
  if ($tls12EnumPresent) {
    [Net.ServicePointManager]::SecurityProtocol = $sp -bor [Net.SecurityProtocolType]::Tls12
  } else {
    # 3072 is the enum value for Tls12 on older .NETs
    [Net.ServicePointManager]::SecurityProtocol = $sp -bor 3072
  }
} catch {}

$Work = Join-Path $env:TEMP "PS-TLS-Upgrade"
New-Item -ItemType Directory -Path $Work -Force | Out-Null

function Get-OSInfo {
  $os = Get-WmiObject -Class Win32_OperatingSystem
  $v  = [Version]$os.Version
  $is64 = [Environment]::Is64BitOperatingSystem
  [pscustomobject]@{
    Version = $v
    Caption = $os.Caption
    Arch64  = $is64
  }
}

function Get-Net48Release {
  $path = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
  (Get-ItemProperty -Path $path -Name Release -ErrorAction SilentlyContinue).Release
}

function Install-Net48 {
  $release = Get-Net48Release
  # 528040/528049+ indicate .NET 4.8 (varies by OS)
  if ($release -ge 528040) { Write-Host "✓ .NET Framework 4.8 already installed ($release)"; return }

  $net48Url = 'https://download.microsoft.com/download/f/3/a/f3a6af84-da23-40a5-8d1c-49cc10c8e76f/NDP48-x86-x64-AllOS-ENU.exe'
  $netPath  = Join-Path $Work 'NDP48-x86-x64-AllOS-ENU.exe'
  Write-Host "↓ Downloading .NET Framework 4.8 ..."
  (New-Object System.Net.WebClient).DownloadFile($net48Url, $netPath)
  Write-Host "→ Installing .NET Framework 4.8 (quiet) ..."
  $p = Start-Process -FilePath $netPath -ArgumentList '/quiet /norestart' -PassThru -Wait
  if ($p.ExitCode -ne 0) { Write-Warning "NET 4.8 installer exit code: $($p.ExitCode)" }
}

function Enable-DotNetStrongCrypto {
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
  )
  foreach ($p in $paths) {
    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
    New-ItemProperty -Path $p -Name 'SchUseStrongCrypto' -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $p -Name 'SystemDefaultTlsVersions' -Value 1 -PropertyType DWord -Force | Out-Null
  }
  Write-Host "✓ Enabled .NET strong crypto + OS default TLS via registry."
}

function Enable-SChannelTls12 {
  $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2'
  foreach ($role in 'Client','Server') {
    $key = Join-Path $base $role
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    New-ItemProperty -Path $key -Name 'Enabled' -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $key -Name 'DisabledByDefault' -Value 0 -PropertyType DWord -Force | Out-Null
  }
  Write-Host "✓ Ensured SChannel TLS 1.2 is enabled for Client/Server."
}

function Set-DefaultSecureProtocols {
  # For Win7/2008R2/2012/2012R2 & 8.1, add WinHTTP DefaultSecureProtocols = TLS1.1+1.2 (0x0A00)
  $os = Get-OSInfo
  if ($os.Version.Major -eq 6) {
    $paths = @(
      'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp',
      'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
    )
    foreach ($p in $paths) {
      if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
      New-ItemProperty -Path $p -Name 'DefaultSecureProtocols' -Value 0x00000A00 -PropertyType DWord -Force | Out-Null
    }
    Write-Host "✓ Set WinHTTP DefaultSecureProtocols = TLS 1.1+1.2."
  }
}

function Install-WMF51 {
  $os = Get-OSInfo
  $v  = $os.Version
  $is64 = $os.Arch64

  # Direct Microsoft links (download.microsoft.com) for WMF 5.1
  $links = @{
    '6.1_x86'  = 'https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7-KB3191566-x86.zip'
    '6.1_x64'  = 'https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7AndW2K8R2-KB3191566-x64.zip'
    '6.2_x64'  = 'https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/W2K12-KB3191565-x64.msu'
    '6.3_x86'  = 'https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win8.1-KB3191564-x86.msu'
    '6.3_x64'  = 'https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win8.1AndW2K12R2-KB3191564-x64.msu'
  }

  $key =
    if ($v.Major -eq 6 -and $v.Minor -eq 1) { if ($is64){'6.1_x64'} else {'6.1_x86'} } # Win7/2008 R2
    elseif ($v.Major -eq 6 -and $v.Minor -eq 2) { '6.2_x64' }                             # Win8/2012 (x64 only)
    elseif ($v.Major -eq 6 -and $v.Minor -eq 3) { if ($is64){'6.3_x64'} else {'6.3_x86'} }# 8.1/2012 R2
    else { $null }

  if (-not $key) { Write-Host "OS '$($os.Caption)' not in WMF 5.1 target list; skipping." ; return }

  # If already 5.1+, skip
  if ($PSVersionTable.PSVersion -ge [Version]'5.1') { Write-Host "✓ PowerShell $($PSVersionTable.PSVersion) already present."; return }

  $url = $links[$key]
  $dl  = Join-Path $Work (Split-Path $url -Leaf)
  Write-Host "↓ Downloading WMF 5.1 package for $($os.Caption) ..."
  (New-Object System.Net.WebClient).DownloadFile($url, $dl)

  if ($dl.ToLower().EndsWith('.zip')) {
    Write-Host "→ Extracting ZIP..."
    $extract = Join-Path $Work "wmf51"
    New-Item -ItemType Directory -Path $extract -Force | Out-Null
    # Try .NET ZipFile first, fall back to Shell COM if missing
    try {
      Add-Type -AssemblyName System.IO.Compression.FileSystem
      [IO.Compression.ZipFile]::ExtractToDirectory($dl, $extract)
    } catch {
      $shell = New-Object -ComObject Shell.Application
      $shell.NameSpace($extract).CopyHere($shell.NameSpace($dl).Items(), 16)
    }
    $msu = Get-ChildItem $extract -Filter *.msu -Recurse | Select-Object -First 1
  } else {
    $msu = Get-Item $dl
  }

  if (-not $msu) { throw "WMF 5.1 .msu not found; cannot continue." }

  Write-Host "→ Installing WMF 5.1 (quiet) ..."
  $proc = Start-Process -FilePath "wusa.exe" -ArgumentList ('"{0}" /quiet /norestart' -f $msu.FullName) -PassThru -Wait
  if ($proc.ExitCode -in 0,3010) {
    if ($proc.ExitCode -eq 3010) { Write-Host "⚠ WMF 5.1 requires a reboot to complete." }
    else { Write-Host "✓ WMF 5.1 installation completed (may still require reboot)." }
  } else {
    Write-Warning "WMF installer exit code: $($proc.ExitCode)"
  }
}

function Update-RootCAs {
  if (-not $UpdateRoots) { return }
  $sst = Join-Path $Work 'roots.sst'
  Write-Host "↓ Generating latest Microsoft Root list (certutil) ..."
  certutil.exe -generateSSTFromWU $sst | Out-Null
  Write-Host "→ Importing into LocalMachine\Root ..."
  $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')
  $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
  $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
  $col.Import($sst)
  $store.AddRange($col)
  $store.Close()
  Write-Host "✓ Root CAs refreshed."
}

function Test-TLS {
  Write-Host "→ Testing TLS 1.2 with Invoke-WebRequest..."
  try {
    $r = Invoke-WebRequest 'https://www.howsmyssl.com/a/check' -UseBasicParsing -TimeoutSec 20
    $j = $r.Content | ConvertFrom-Json
    Write-Host ("TLS reported by server: {0}" -f $j.tls_version)
  } catch {
    Write-Warning "Test failed: $_"
  }
}

# ---- Execute steps ----
Write-Host "=== Enabling modern TLS and upgrading PowerShell ==="
Install-Net48
Enable-DotNetStrongCrypto
Enable-SChannelTls12
Set-DefaultSecureProtocols
Install-WMF51
Update-RootCAs
Write-Host "=== Done. You may need to REBOOT if WMF/.NET requested it. ==="
Test-TLS