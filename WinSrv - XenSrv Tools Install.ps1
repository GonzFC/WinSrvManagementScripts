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
    - Runs even if the script is unsigned by temporarily setting ExecutionPolicy=Bypass for this process only.

.NOTES
    Recommended for production servers where drivers should remain stable,
    but the Management Agent may receive auto-updates.
#>

param(
    [switch]$NoReboot,
    [switch]$DisableWUDrivers    # Optional: block Windows Update driver delivery
)

$ErrorActionPreference = 'Stop'

# --- Allow unsigned script for this process only; restore at the end ---
$oldPolicy = $null
try {
    $oldPolicy = Get-ExecutionPolicy -Scope Process
    if ($oldPolicy -ne 'Bypass') {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    }

    # Optional but helpful on old boxes: ensure TLS 1.2 for HTTPS downloads
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
    Start-Process msiexec.exe -ArgumentList $msiArgs -Wait

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
}
finally {
    # Restore execution policy for this process if we changed it
    if ($oldPolicy -and $oldPolicy -ne 'Bypass') {
        try {
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy $oldPolicy -Force
        } catch {
            Write-Warning "Could not restore original ExecutionPolicy for this process: $($_.Exception.Message)"
        }
    }
}