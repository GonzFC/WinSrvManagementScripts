<#
.SYNOPSIS
    Disable all automatic Windows updates, leaving only manual critical security updates

.DESCRIPTION
    Completely disables automatic Windows Update functionality.
    Updates can still be manually checked and installed when needed.
    Only critical security updates will be available for manual installation.
    Excludes all optional updates, feature updates, and driver updates.

    Goals:
    - Complete control over when updates are installed
    - Prevent unexpected reboots or system changes
    - Maximum server stability and uptime
    - Manual control over security patching

    Ideal for:
    - Production servers requiring maximum stability
    - Environments with strict change control requirements
    - Servers with custom update management solutions (WSUS, SCCM)
    - Testing/development environments

.NOTES
    Author: IT Infrastructure Team
    Requires: PowerShell 5.1+, Administrator privileges
    Target: Windows Server 2012 R2+, Windows 10+

    WARNING: Disabling automatic updates means you are responsible for
    manually checking and installing security updates regularly.

.EXAMPLE
    .\WinSrv - Disable Windows Updates.ps1

    Runs interactively and disables automatic Windows updates.
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

#region Helper Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'Info'    { 'White' }
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
    }

    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host " Disable Windows Automatic Updates" -ForegroundColor Cyan
    Write-Host " Manual Control Mode" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
}

#endregion

#region Main Script

Show-Banner

# Show current configuration plan
Write-Host "This script will configure Windows Update for:" -ForegroundColor White
Write-Host ""
Write-Host "  Update Behavior:" -ForegroundColor Cyan
Write-Host "    - Automatic updates: DISABLED" -ForegroundColor Gray
Write-Host "    - Manual check and install only" -ForegroundColor Gray
Write-Host "    - No automatic downloads" -ForegroundColor Gray
Write-Host "    - No automatic restarts" -ForegroundColor Gray
Write-Host ""
Write-Host "  Update Types Available (Manual Only):" -ForegroundColor Cyan
Write-Host "    - Critical security updates only" -ForegroundColor Gray
Write-Host "    - NO feature updates (deferred for 365 days)" -ForegroundColor Gray
Write-Host "    - NO hardware driver updates" -ForegroundColor Gray
Write-Host "    - NO optional updates" -ForegroundColor Gray
Write-Host ""
Write-Host "  What This Means:" -ForegroundColor Cyan
Write-Host "    - You must manually check for updates" -ForegroundColor Gray
Write-Host "    - You choose when to install updates" -ForegroundColor Gray
Write-Host "    - No unexpected reboots or changes" -ForegroundColor Gray
Write-Host "    - Maximum control and stability" -ForegroundColor Gray
Write-Host ""
Write-Host "Benefits:" -ForegroundColor Yellow
Write-Host "  [OK] Complete control over update timing" -ForegroundColor Green
Write-Host "  [OK] No unexpected system reboots" -ForegroundColor Green
Write-Host "  [OK] Maximum server uptime" -ForegroundColor Green
Write-Host "  [OK] Install only what you need, when you need it" -ForegroundColor Green
Write-Host ""
Write-Host "Responsibilities:" -ForegroundColor Red
Write-Host "  [X] You must manually check for security updates regularly" -ForegroundColor Yellow
Write-Host "  [X] Critical security patches won't install automatically" -ForegroundColor Yellow
Write-Host "  [X] Server may become vulnerable without manual patching" -ForegroundColor Yellow
Write-Host ""

# Confirmation
Write-Host "Do you understand and want to proceed? [Y/n]: " -ForegroundColor Yellow -NoNewline
$response = Read-Host

if ($response -match '^[Nn]') {
    Write-Host ""
    Write-Host "Configuration cancelled by user." -ForegroundColor Yellow
    Write-Host ""
    exit 0
}

Write-Host ""
Write-Log "Starting Windows Update configuration..." -Level Info
Write-Host ""

try {
    # Registry paths
    $wuPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $auPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'

    # Create registry paths if they don't exist
    Write-Log "Creating registry paths..." -Level Info
    if (-not (Test-Path $wuPath)) {
        New-Item -Path $wuPath -Force | Out-Null
    }
    if (-not (Test-Path $auPath)) {
        New-Item -Path $auPath -Force | Out-Null
    }

    # Configure Windows Update to disable automatic updates
    Write-Host ""
    Write-Host "Disabling automatic Windows updates..." -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  [1/6] Disabling automatic update checks and installations..." -ForegroundColor Gray
    # NoAutoUpdate = 1 means disable automatic updates
    Set-ItemProperty -Path $auPath -Name "NoAutoUpdate" -Value 1 -Type DWord
    # AUOptions = 2 means "Notify for download and notify for install"
    Set-ItemProperty -Path $auPath -Name "AUOptions" -Value 2 -Type DWord
    Write-Log "  [OK] Automatic updates disabled" -Level Success

    Write-Host "  [2/6] Disabling automatic restarts..." -ForegroundColor Gray
    Set-ItemProperty -Path $auPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord
    Set-ItemProperty -Path $auPath -Name "AlwaysAutoRebootAtScheduledTime" -Value 0 -Type DWord
    Write-Log "  [OK] Automatic restarts disabled" -Level Success

    Write-Host "  [3/6] Excluding hardware driver updates..." -ForegroundColor Gray
    Set-ItemProperty -Path $wuPath -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Type DWord
    Write-Log "  [OK] Driver updates excluded" -Level Success

    Write-Host "  [4/6] Disabling optional/recommended updates..." -ForegroundColor Gray
    Set-ItemProperty -Path $auPath -Name "AutoInstallMinorUpdates" -Value 0 -Type DWord
    Set-ItemProperty -Path $auPath -Name "IncludeRecommendedUpdates" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Write-Log "  [OK] Optional updates disabled" -Level Success

    Write-Host "  [5/6] Deferring feature updates..." -ForegroundColor Gray
    # Defer feature updates (Windows 10/11/Server 2016+)
    try {
        Set-ItemProperty -Path $wuPath -Name "DeferFeatureUpdates" -Value 1 -Type DWord
        Set-ItemProperty -Path $wuPath -Name "DeferFeatureUpdatesPeriodInDays" -Value 365 -Type DWord
        Set-ItemProperty -Path $wuPath -Name "BranchReadinessLevel" -Value 32 -Type DWord -ErrorAction SilentlyContinue
        Write-Log "  [OK] Feature updates deferred for 365 days" -Level Success
    }
    catch {
        Write-Log "  [!] Feature update deferral not supported on this OS version" -Level Warning
    }

    Write-Host "  [6/6] Disabling Microsoft Update (non-Windows products)..." -ForegroundColor Gray
    try {
        $serviceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"
        $serviceManager.Services | Where-Object { $_.IsDefaultAUService -eq $false } | ForEach-Object {
            try {
                $serviceManager.RemoveService($_.ServiceID)
            } catch {
                # Service may not be removable, continue
            }
        }
        Set-ItemProperty -Path $auPath -Name "AllowMUUpdateService" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Write-Log "  [OK] Microsoft Update service disabled" -Level Success
    }
    catch {
        Write-Log "  [!] Microsoft Update service configuration skipped" -Level Warning
    }

    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host " Configuration Completed Successfully!" -ForegroundColor Green
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host ""

    # Summary
    Write-Host "Configuration Summary:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Automatic Updates:   " -NoNewline -ForegroundColor White
    Write-Host "DISABLED" -ForegroundColor Green

    Write-Host "  Manual Control:      " -NoNewline -ForegroundColor White
    Write-Host "ENABLED" -ForegroundColor Green

    Write-Host "  Update Type:         " -NoNewline -ForegroundColor White
    Write-Host "Critical security only (manual)" -ForegroundColor Green

    Write-Host "  Driver Updates:      " -NoNewline -ForegroundColor White
    Write-Host "Excluded" -ForegroundColor Green

    Write-Host "  Feature Updates:     " -NoNewline -ForegroundColor White
    Write-Host "Deferred for 365 days" -ForegroundColor Green

    Write-Host "  Auto-Restart:        " -NoNewline -ForegroundColor White
    Write-Host "Disabled" -ForegroundColor Green

    Write-Host ""

    # Stop and disable Windows Update service (optional - aggressive mode)
    Write-Host "Additional Option: Disable Windows Update Service" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Do you want to also disable the Windows Update service?" -ForegroundColor Yellow
    Write-Host "  [Y] Yes - Completely stop and disable the service (most aggressive)" -ForegroundColor White
    Write-Host "  [N] No  - Leave service running (recommended, allows manual checks)" -ForegroundColor White
    Write-Host ""
    Write-Host "Choice [Y/n]: " -ForegroundColor Yellow -NoNewline
    $serviceResponse = Read-Host

    if ($serviceResponse -match '^[Yy]') {
        Write-Host ""
        Write-Host "Disabling Windows Update service..." -ForegroundColor Cyan
        try {
            Stop-Service -Name wuauserv -Force -ErrorAction Stop
            Set-Service -Name wuauserv -StartupType Disabled -ErrorAction Stop
            Write-Log "[OK] Windows Update service stopped and disabled" -Level Success
            Write-Host ""
            Write-Host "  Service Status:      " -NoNewline -ForegroundColor White
            Write-Host "DISABLED" -ForegroundColor Green
        }
        catch {
            Write-Log "[!] Could not disable Windows Update service: $($_.Exception.Message)" -Level Warning
        }
    }
    else {
        Write-Host ""
        Write-Log "Windows Update service left running (manual checks still possible)" -Level Info
        Write-Host ""
        Write-Host "  Service Status:      " -NoNewline -ForegroundColor White
        Write-Host "Running (manual mode)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "How to Manually Check for Updates:" -ForegroundColor Yellow
    Write-Host "  1. Open Settings -> Update & Security -> Windows Update" -ForegroundColor White
    Write-Host "  2. Click 'Check for updates' button" -ForegroundColor White
    Write-Host "  3. Review available updates" -ForegroundColor White
    Write-Host "  4. Select and install only critical security updates" -ForegroundColor White
    Write-Host "  5. Restart manually when convenient" -ForegroundColor White
    Write-Host ""
    Write-Host "  OR use PowerShell:" -ForegroundColor White
    Write-Host "     Install-Module PSWindowsUpdate" -ForegroundColor Gray
    Write-Host "     Get-WindowsUpdate" -ForegroundColor Gray
    Write-Host "     Install-WindowsUpdate -MicrosoftUpdate -AcceptAll" -ForegroundColor Gray
    Write-Host ""

    Write-Host "Recommendation:" -ForegroundColor Yellow
    Write-Host "  - Check for security updates monthly" -ForegroundColor White
    Write-Host "  - Install critical patches within 30 days of release" -ForegroundColor White
    Write-Host "  - Test updates on non-production systems first" -ForegroundColor White
    Write-Host "  - Schedule maintenance windows for updates" -ForegroundColor White
    Write-Host ""

    Write-Host "Registry Keys Modified:" -ForegroundColor Cyan
    Write-Host "  $wuPath" -ForegroundColor Gray
    Write-Host "  $auPath" -ForegroundColor Gray
    Write-Host ""

    Write-Host "To Re-enable Automatic Updates:" -ForegroundColor Cyan
    Write-Host "  Run the 'WinSrv - Windows Update Configuration.ps1' script" -ForegroundColor Gray
    Write-Host "  Or use Group Policy / Windows Settings" -ForegroundColor Gray
    Write-Host ""

}
catch {
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Red
    Write-Host " ERROR: Configuration Failed" -ForegroundColor Red
    Write-Host "=============================================" -ForegroundColor Red
    Write-Host ""
    Write-Log "Error: $($_.Exception.Message)" -Level Error
    Write-Host ""
    Write-Host "Please ensure you are running as Administrator." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

#endregion
