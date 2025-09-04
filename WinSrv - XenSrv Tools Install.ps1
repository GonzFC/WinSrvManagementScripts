<#
.SYNOPSIS
    Installs XenServer / Citrix Hypervisor VM Tools (Windows x64).

.DESCRIPTION
    - Fetches latest Management Agent MSI from xenserver.com.
    - Falls back to known stable (9.4.1) if scraping fails.
    - Installs silently with:
        • ALLOWDRIVERINSTALL=YES
        • ALLOWDRIVERUPDATE=NO  (drivers pinned, no auto-update)
        • ALLOWAUTOUPDATE=YES   (management agent can auto-update itself)
        • IDENTIFYAUTOUPDATE=NO
    - Reboots unless -NoReboot is provided.
    - Optional: block Windows Update from delivering drivers with -DisableWUDrivers.
    - Bootstrap at start re-launches the script with ExecutionPolicy=Bypass (and elevates) so it runs even if unsigned.

.NOTES
    Recommended for production servers where drivers should remain stable,
    but the Management Agent may receive auto-updates.
#>

try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
} catch {
    Write-Warning "Could not set ExecutionPolicy to Bypass. Proceeding anyway..."
}



param(
    [switch]$NoReboot,
    [switch]$DisableWUDrivers    # Optional: block Windows Update driver delivery
)

# --- Bootstrap: ensure Admin + ExecutionPolicy Bypass by relaunching self ---
function Test-Admin {
    try {
        $id  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pri = New-Object Security.Principal.WindowsPrincipal($id)
        return $pri.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

try {
    # Unblock MOTW if present (safe no-op when not blocked)
    Unblock-File -Path $PSCommandPath -ErrorAction SilentlyContinue
} catch { }

$needAdmin  = -not (Test-Admin)
try { $effectiveEP = Get-ExecutionPolicy } catch { $effectiveEP = 'Unknown' }
$needBypass = ($effectiveEP -ne 'Bypass' -and $effectiveEP -ne 'Unrestricted')

if ($needAdmin -or $needBypass) {
    # Forward only the switches that were actually passed
    $forward = @()
    if ($PSBoundParameters.ContainsKey('NoReboot') -and $NoReboot)           { $forward += '-NoReboot' }
    if ($PSBoundParameters.ContainsKey('DisableWUDrivers') -and $DisableWUDrivers) { $forward += '-DisableWUDrivers' }

    # Path to current PowerShell
    $psExe = (Get-Process -Id $PID).Path
    $args  = ('-NoProfile -ExecutionPolicy Bypass -File "{0}" {1}' -f $PSCommandPath, ($forward -join ' ')).Trim()

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName        = $psExe
    $psi.Arguments       = $args
    $psi.UseShellExecute = $true
    if ($needAdmin) { $psi.Verb = 'runas' }  # trigger UAC elevation if needed

    [Diagnostics.Process]::Start($psi) | Out-Null
    exit
}

# From here on, we are running in an elevated process with EP=Bypass
$ErrorActionPreference = 'Stop'

# Prefer TLS 1.2 for reliable HTTPS on older boxes
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor `
        [Net.SecurityProtocolType]::Tls12
} catch { }

# 1) Discover latest MSI
try {
    Write-Host "Fetching latest XenServer Tools download link..."
    $page = 'https://www.xenserver.com/downloads'
    $html = (Invoke-WebRequest -UseBasicParsing $page).Content
    $m = [regex]::Match(
        $html,
        'https://downloads\.xenserver\.com/vm-tools-windows/[^"''/]+/managementagent-[^"''/]+-x64\.msi'
    )
    if (-not $m.Success) { throw "No MSI link found" }
    $url = $m.Value
} catch {
    Write-Warning "Falling back to known stable 9.4.1"
    $url = 'https://downloads.xenserver.com/vm-tools-windows/9.4.1/managementagent-9.4.1-x64.msi'
}

# 2) Download
$dst = Join-Path $env:TEMP 'XenServer-VM-Tools-x64.msi'
Write-Host "Downloading: $url"
Invoke-WebRequest -Uri $url -OutFile $dst -UseBasicParsing

# 3) Install silently
Write-Host "Installing XenServer VM Tools..."
$msiArgs = @(
    '/i', $dst,
    '/qn',
    '/norestart',
    'ALLOWDRIVERINSTALL=YES',
    'ALLOWDRIVERUPDATE=NO',
    'ALLOWAUTOUPDATE=YES',
    'IDENTIFYAUTOUPDATE=NO'
)
$proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
switch ($proc.ExitCode) {
    0    { Write-Host "Install completed successfully." }
    3010 { Write-Host "Install completed; reboot required (3010)." }
    default { throw "msiexec exited with code $($proc.ExitCode)." }
}

# 4) Optional: block driver delivery from Windows Update
if ($DisableWUDrivers) {
    Write-Host "Disabling driver delivery via Windows Update..."
    $wuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    if (-not (Test-Path $wuKey)) { New-Item -Path $wuKey -Force | Out-Null }
    New-ItemProperty -Path $wuKey -Name 'ExcludeWUDriversInQualityUpdate' -PropertyType DWord -Value 1 -Force | Out-Null
    gpupdate /target:computer /force | Out-Null
}

# 5) Reboot (unless suppressed)
if (-not $NoReboot) {
    Write-Host "Rebooting to complete driver initialization..."
    Restart-Computer -Force
} else {
    Write-Host "Install complete. Reboot required to finish driver init."
}
