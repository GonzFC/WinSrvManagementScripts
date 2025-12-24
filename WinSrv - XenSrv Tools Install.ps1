<#
.SYNOPSIS
    Installs XCP-ng or XenServer/Citrix Hypervisor VM Tools (Windows x64).

.DESCRIPTION
    Interactive installer for virtualization guest tools:

    XCP-ng Windows PV Tools (Recommended for XCP-ng):
    - Latest stable release with digitally signed drivers
    - Improved performance and features
    - Requires Windows 10 1607 / Windows Server 2016 minimum
    - Open-source and community-supported

    XenServer/Citrix Hypervisor VM Tools:
    - Official Citrix/XenServer management agent
    - Compatible with older Windows versions
    - Stable and widely deployed

    Installation options:
    - Silent installation with optimal settings
    - Pinned drivers (no auto-update for stability)
    - Optional reboot control
    - Optional Windows Update driver blocking

.NOTES
    Script is fully interactive - no parameters required.
    Automatically elevates to Administrator if needed.
#>

try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction Stop
} catch {
    Write-Warning "Could not set ExecutionPolicy to Bypass. Proceeding anyway..."
}

# --- Helper Functions ---
function Test-Admin {
    try {
        $id  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $pri = New-Object Security.Principal.WindowsPrincipal($id)
        return $pri.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-OSVersionInfo {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $version = [Version]$os.Version
        return [PSCustomObject]@{
            Caption = $os.Caption
            Version = $version
            Build = $os.BuildNumber
        }
    } catch {
        return $null
    }
}

function Test-XCPngCompatibility {
    $osInfo = Get-OSVersionInfo
    if (-not $osInfo) { return $false }

    # XCP-ng requires Windows 10 1607 (build 14393) or Windows Server 2016 minimum
    # Windows 10 1607 = Version 10.0.14393
    # Windows Server 2016 = Version 10.0.14393

    if ($osInfo.Version.Major -lt 10) {
        return $false
    }

    if ($osInfo.Version.Major -eq 10 -and $osInfo.Build -lt 14393) {
        return $false
    }

    return $true
}

# --- Bootstrap: ensure Admin + ExecutionPolicy Bypass by relaunching self ---
try {
    Unblock-File -Path $PSCommandPath -ErrorAction SilentlyContinue
} catch { }

$needAdmin  = -not (Test-Admin)
try { $effectiveEP = Get-ExecutionPolicy } catch { $effectiveEP = 'Unknown' }
$needBypass = ($effectiveEP -ne 'Bypass' -and $effectiveEP -ne 'Unrestricted')

if ($needAdmin -or $needBypass) {
    $psExe = (Get-Process -Id $PID).Path
    $args  = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName        = $psExe
    $psi.Arguments       = $args
    $psi.UseShellExecute = $true
    if ($needAdmin) { $psi.Verb = 'runas' }

    [Diagnostics.Process]::Start($psi) | Out-Null
    exit
}

# From here on, we are running elevated with EP=Bypass
$ErrorActionPreference = 'Stop'

# Enable TLS 1.2
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor `
        [Net.SecurityProtocolType]::Tls12
} catch { }

# --- Interactive Menu ---
Clear-Host
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Virtualization Guest Tools Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$osInfo = Get-OSVersionInfo
$xcpngCompatible = Test-XCPngCompatibility

Write-Host "System Information:" -ForegroundColor Yellow
Write-Host "  OS: $($osInfo.Caption)" -ForegroundColor White
Write-Host "  Version: $($osInfo.Version) (Build $($osInfo.Build))" -ForegroundColor White
Write-Host ""

Write-Host "Available Options:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  [1] XCP-ng Windows PV Tools (v9.1.100)" -ForegroundColor White
Write-Host "      - Latest stable release with signed drivers" -ForegroundColor Gray
Write-Host "      - Improved performance for XCP-ng hosts" -ForegroundColor Gray
Write-Host "      - Requires: Windows 10 1607+ / Server 2016+" -ForegroundColor Gray

if (-not $xcpngCompatible) {
    Write-Host "      - NOT COMPATIBLE WITH THIS OS VERSION" -ForegroundColor Red
}

Write-Host ""
Write-Host "  [2] XenServer/Citrix Hypervisor VM Tools" -ForegroundColor White
Write-Host "      - Official Citrix management agent (v9.4.1+)" -ForegroundColor Gray
Write-Host "      - Compatible with older Windows versions" -ForegroundColor Gray
Write-Host "      - Stable and widely deployed" -ForegroundColor Gray
Write-Host ""

if (-not $xcpngCompatible) {
    Write-Host "Recommendation: Option 2 (XenServer) - XCP-ng tools require newer OS" -ForegroundColor Yellow
} else {
    Write-Host "Recommendation: Option 1 (XCP-ng) if running on XCP-ng host" -ForegroundColor Yellow
}

Write-Host ""
Write-Host -NoNewline "Select option [1 or 2]: " -ForegroundColor Cyan
$choice = Read-Host

if ($choice -ne '1' -and $choice -ne '2') {
    Write-Host ""
    Write-Host "Invalid selection. Exiting." -ForegroundColor Red
    Write-Host ""
    exit 1
}

if ($choice -eq '1' -and -not $xcpngCompatible) {
    Write-Host ""
    Write-Host "ERROR: XCP-ng tools require Windows 10 1607 / Server 2016 or newer." -ForegroundColor Red
    Write-Host "Your system: $($osInfo.Caption) (Build $($osInfo.Build))" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please use option 2 (XenServer tools) instead." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# Ask for reboot preference
Write-Host ""
Write-Host -NoNewline "Automatically reboot after installation? [Y/n]: " -ForegroundColor Cyan
$rebootResponse = Read-Host
$autoReboot = ($rebootResponse -eq '' -or $rebootResponse -match '^[Yy]')

# Ask about Windows Update driver blocking
Write-Host ""
Write-Host -NoNewline "Block Windows Update from delivering drivers? [Y/n]: " -ForegroundColor Cyan
$wuResponse = Read-Host
$disableWUDrivers = ($wuResponse -eq '' -or $wuResponse -match '^[Yy]')

Write-Host ""
Write-Host "Installation starting..." -ForegroundColor Green
Write-Host ""

# --- Install based on choice ---
if ($choice -eq '1') {
    # XCP-ng Windows PV Tools
    Write-Host "Installing XCP-ng Windows PV Tools v9.1.100..." -ForegroundColor Cyan

    $url = 'https://github.com/xcp-ng/win-pv-drivers/releases/download/v9.1.100/XenTools-x64.msi'
    $destination = Join-Path $env:TEMP 'XCPng-PV-Tools-x64.msi'

    try {
        Write-Host "Downloading from GitHub..." -ForegroundColor White
        Invoke-WebRequest -Uri $url -OutFile $destination -UseBasicParsing

        Write-Host "Installing XCP-ng PV Tools (this may take a few minutes)..." -ForegroundColor White
        $msiArgs = @(
            '/i', $destination,
            '/qn',
            '/norestart',
            '/log', (Join-Path $env:TEMP 'xcpng-install.log')
        )

        $process = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru

        switch ($process.ExitCode) {
            0    { Write-Host "Installation completed successfully." -ForegroundColor Green }
            3010 { Write-Host "Installation completed; reboot required (exit code 3010)." -ForegroundColor Yellow }
            default {
                Write-Host "WARNING: msiexec exited with code $($process.ExitCode)" -ForegroundColor Yellow
                Write-Host "Check log: $env:TEMP\xcpng-install.log" -ForegroundColor Gray
            }
        }

        Write-Host ""
        Write-Host "XCP-ng Windows PV Tools installation complete!" -ForegroundColor Green
        Write-Host "  Version: 9.1.100" -ForegroundColor White
        Write-Host "  Drivers: Digitally signed, pinned" -ForegroundColor White
        Write-Host "  Install log: $env:TEMP\xcpng-install.log" -ForegroundColor White

    } catch {
        Write-Host "ERROR: Installation failed - $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        exit 1
    }

} else {
    # XenServer/Citrix Hypervisor VM Tools
    Write-Host "Installing XenServer/Citrix Hypervisor VM Tools..." -ForegroundColor Cyan

    # Discover latest MSI from xenserver.com
    try {
        Write-Host "Fetching latest XenServer Tools download link..." -ForegroundColor White
        $pageUrl = 'https://www.xenserver.com/downloads'
        $html = (Invoke-WebRequest -UseBasicParsing $pageUrl).Content
        $match = [regex]::Match($html,
            'https://downloads\.xenserver\.com/vm-tools-windows/[^"''/]+/managementagent-[^"''/]+-x64\.msi')

        if (-not $match.Success) { throw "No MSI link found" }
        $url = $match.Value
    } catch {
        Write-Host "Falling back to known stable version 9.4.1" -ForegroundColor Yellow
        $url = 'https://downloads.xenserver.com/vm-tools-windows/9.4.1/managementagent-9.4.1-x64.msi'
    }

    $destination = Join-Path $env:TEMP 'XenServer-VM-Tools-x64.msi'

    try {
        Write-Host "Downloading: $url" -ForegroundColor White
        Invoke-WebRequest -Uri $url -OutFile $destination -UseBasicParsing

        Write-Host "Installing XenServer VM Tools (this may take a few minutes)..." -ForegroundColor White
        $msiArgs = @(
            '/i', $destination,
            '/qn',
            '/norestart',
            'ALLOWDRIVERINSTALL=YES',
            'ALLOWDRIVERUPDATE=NO',
            'ALLOWAUTOUPDATE=YES',
            'IDENTIFYAUTOUPDATE=NO'
        )

        $process = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru

        switch ($process.ExitCode) {
            0    { Write-Host "Installation completed successfully." -ForegroundColor Green }
            3010 { Write-Host "Installation completed; reboot required (exit code 3010)." -ForegroundColor Yellow }
            default { throw "msiexec exited with code $($process.ExitCode)" }
        }

        Write-Host ""
        Write-Host "XenServer VM Tools installation complete!" -ForegroundColor Green
        Write-Host "  Drivers: Installed (pinned, no auto-update)" -ForegroundColor White
        Write-Host "  Management Agent: Auto-update enabled" -ForegroundColor White

    } catch {
        Write-Host "ERROR: Installation failed - $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        exit 1
    }
}

# Block Windows Update driver delivery if requested
if ($disableWUDrivers) {
    Write-Host ""
    Write-Host "Disabling driver delivery via Windows Update..." -ForegroundColor White
    try {
        $wuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        if (-not (Test-Path $wuKey)) { New-Item -Path $wuKey -Force | Out-Null }
        New-ItemProperty -Path $wuKey -Name 'ExcludeWUDriversInQualityUpdate' -PropertyType DWord -Value 1 -Force | Out-Null
        gpupdate /target:computer /force | Out-Null
        Write-Host "Windows Update driver delivery disabled." -ForegroundColor Green
    } catch {
        Write-Host "WARNING: Could not disable Windows Update drivers - $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Reboot
Write-Host ""
if ($autoReboot) {
    Write-Host "Rebooting in 10 seconds to complete driver initialization..." -ForegroundColor Yellow
    Write-Host "Press Ctrl+C to cancel" -ForegroundColor Gray
    Write-Host ""
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-Host "Installation complete!" -ForegroundColor Green
    Write-Host "Reboot is required to complete driver initialization." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}
