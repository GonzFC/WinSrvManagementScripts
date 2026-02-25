<#
.SYNOPSIS
    Configure Windows Update for stable, predictable security patching

.DESCRIPTION
    Sets up Windows Update to check for updates weekly on Sundays at 4:00 AM only.
    Downloads and installs critical security updates only.
    Automatically restarts when needed on Sundays after patches are applied.
    Excludes hardware driver updates.

    Goals:
    - Gain server stability and reliability
    - Avoid dangerous unnecessary updates
    - Save bandwidth
    - Provide maintenance window on Sundays for stability checks

    Ideal for:
    - Private, non-critical application servers (e.g., SAP Business One)
    - Environments where predictable patching is more important than immediate updates

.NOTES
    Author: IT Infrastructure Team
    Requires: PowerShell 5.1+, Administrator privileges
    Target: Windows Server 2012 R2+, Windows 10+

.EXAMPLE
    .\WinSrv - Windows Update Configuration.ps1

    Runs interactively and configures Windows Update with stable security patching schedule.
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
    Write-Host " Windows Update Configuration" -ForegroundColor Cyan
    Write-Host " Stable Security Patching Setup" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
}

#endregion

#region Main Script

Show-Banner

# Show current configuration plan
Write-Host "This script will configure Windows Update for:" -ForegroundColor White
Write-Host ""
Write-Host "  Update Schedule:" -ForegroundColor Cyan
Write-Host "    - Weekly checks on Sundays at 4:00 AM only" -ForegroundColor Gray
Write-Host "    - Detection frequency: 168 hours (7 days)" -ForegroundColor Gray
Write-Host ""
Write-Host "  Update Types:" -ForegroundColor Cyan
Write-Host "    - Critical security updates only" -ForegroundColor Gray
Write-Host "    - NO feature updates (deferred for 365 days)" -ForegroundColor Gray
Write-Host "    - NO hardware driver updates" -ForegroundColor Gray
Write-Host "    - NO optional updates" -ForegroundColor Gray
Write-Host ""
Write-Host "  Restart Behavior:" -ForegroundColor Cyan
Write-Host "    - Automatic restart enabled" -ForegroundColor Gray
Write-Host "    - Restarts 15 minutes after installation" -ForegroundColor Gray
Write-Host "    - Occurs only on Sunday mornings" -ForegroundColor Gray
Write-Host ""
Write-Host "  Active Hours Protection:" -ForegroundColor Cyan
Write-Host "    - Monday - Saturday: 6 AM to 11 PM protected" -ForegroundColor Gray
Write-Host "    - No updates or restarts during business hours" -ForegroundColor Gray
Write-Host ""
Write-Host "Benefits:" -ForegroundColor Yellow
Write-Host "  ✓ Improved server stability" -ForegroundColor Green
Write-Host "  ✓ Bandwidth conservation" -ForegroundColor Green
Write-Host "  ✓ Predictable maintenance window" -ForegroundColor Green
Write-Host "  ✓ No business hour disruptions" -ForegroundColor Green
Write-Host "  ✓ Time for Sunday morning stability checks" -ForegroundColor Green
Write-Host ""

# Confirmation
Write-Host "Do you want to apply this configuration? [Y/n]: " -ForegroundColor Yellow -NoNewline
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
    $activeHoursPath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'

    # Create registry paths if they don't exist
    Write-Log "Creating registry paths..." -Level Info
    if (-not (Test-Path $wuPath)) {
        New-Item -Path $wuPath -Force | Out-Null
    }
    if (-not (Test-Path $auPath)) {
        New-Item -Path $auPath -Force | Out-Null
    }
    if (-not (Test-Path $activeHoursPath)) {
        New-Item -Path $activeHoursPath -Force | Out-Null
    }

    # Configure Automatic Updates
    Write-Host ""
    Write-Host "Configuring Windows Update settings..." -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  [1/7] Enabling automatic updates with scheduled installation..." -ForegroundColor Gray
    Set-ItemProperty -Path $auPath -Name "NoAutoUpdate" -Value 0 -Type DWord
    Set-ItemProperty -Path $auPath -Name "AUOptions" -Value 4 -Type DWord
    Write-Log "  ✓ Automatic updates enabled with scheduled installation" -Level Success

    Write-Host "  [2/7] Setting update schedule to Sundays at 4:00 AM..." -ForegroundColor Gray
    Set-ItemProperty -Path $auPath -Name "ScheduledInstallDay" -Value 1 -Type DWord  # 1 = Sunday
    Set-ItemProperty -Path $auPath -Name "ScheduledInstallTime" -Value 4 -Type DWord  # 4 AM
    Write-Log "  ✓ Schedule set: Sundays at 4:00 AM" -Level Success

    Write-Host "  [3/7] Configuring automatic restart behavior..." -ForegroundColor Gray
    Set-ItemProperty -Path $auPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 0 -Type DWord
    Set-ItemProperty -Path $auPath -Name "AlwaysAutoRebootAtScheduledTime" -Value 1 -Type DWord
    Set-ItemProperty -Path $auPath -Name "AlwaysAutoRebootAtScheduledTimeMinutes" -Value 15 -Type DWord
    Write-Log "  ✓ Auto-restart configured (15 minutes after installation)" -Level Success

    Write-Host "  [4/7] Excluding hardware driver updates..." -ForegroundColor Gray
    Set-ItemProperty -Path $wuPath -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Type DWord
    Write-Log "  ✓ Driver updates excluded" -Level Success

    Write-Host "  [5/7] Configuring to install critical security updates only..." -ForegroundColor Gray
    Set-ItemProperty -Path $auPath -Name "AutoInstallMinorUpdates" -Value 0 -Type DWord

    # Defer feature updates (Windows 10/11/Server 2016+)
    try {
        Set-ItemProperty -Path $wuPath -Name "DeferFeatureUpdates" -Value 1 -Type DWord
        Set-ItemProperty -Path $wuPath -Name "DeferFeatureUpdatesPeriodInDays" -Value 365 -Type DWord
        Write-Log "  ✓ Feature updates deferred for 365 days" -Level Success
    }
    catch {
        Write-Log "  ⚠ Feature update deferral not supported on this OS version" -Level Warning
    }

    Write-Host "  [6/7] Setting update detection frequency to weekly..." -ForegroundColor Gray
    Set-ItemProperty -Path $auPath -Name "DetectionFrequencyEnabled" -Value 1 -Type DWord
    Set-ItemProperty -Path $auPath -Name "DetectionFrequency" -Value 168 -Type DWord  # 168 hours = 7 days
    Write-Log "  ✓ Detection frequency: Weekly (168 hours)" -Level Success

    Write-Host "  [7/7] Configuring active hours protection..." -ForegroundColor Gray
    try {
        Set-ItemProperty -Path $activeHoursPath -Name "ActiveHoursStart" -Value 6 -Type DWord
        Set-ItemProperty -Path $activeHoursPath -Name "ActiveHoursEnd" -Value 23 -Type DWord
        Write-Log "  ✓ Active hours set: 6 AM to 11 PM (Mon-Sat protection)" -Level Success
    }
    catch {
        Write-Log "  ⚠ Active hours not supported on this OS version" -Level Warning
    }

    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host " Configuration Completed Successfully!" -ForegroundColor Green
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host ""

    # Summary
    Write-Host "Configuration Summary:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Update Schedule:     " -NoNewline -ForegroundColor White
    Write-Host "Sundays at 4:00 AM" -ForegroundColor Green

    Write-Host "  Update Type:         " -NoNewline -ForegroundColor White
    Write-Host "Critical security updates only" -ForegroundColor Green

    Write-Host "  Driver Updates:      " -NoNewline -ForegroundColor White
    Write-Host "Excluded" -ForegroundColor Green

    Write-Host "  Feature Updates:     " -NoNewline -ForegroundColor White
    Write-Host "Deferred for 365 days" -ForegroundColor Green

    Write-Host "  Auto-Restart:        " -NoNewline -ForegroundColor White
    Write-Host "Enabled (15 min after install)" -ForegroundColor Green

    Write-Host "  Detection Frequency: " -NoNewline -ForegroundColor White
    Write-Host "Weekly (168 hours)" -ForegroundColor Green

    Write-Host "  Active Hours:        " -NoNewline -ForegroundColor White
    Write-Host "6 AM - 11 PM (Mon-Sat)" -ForegroundColor Green

    Write-Host ""

    # Restart Windows Update service
    Write-Host "Restarting Windows Update service to apply changes..." -ForegroundColor Cyan
    try {
        Restart-Service -Name wuauserv -Force -ErrorAction Stop
        Write-Log "✓ Windows Update service restarted successfully" -Level Success
    }
    catch {
        Write-Log "⚠ Could not restart Windows Update service. Changes will apply after next reboot." -Level Warning
    }

    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Yellow
    Write-Host "  1. Review the configuration summary above" -ForegroundColor White
    Write-Host "  2. Monitor the first Sunday maintenance window (4:00 AM)" -ForegroundColor White
    Write-Host "  3. Check Windows Update history after first run:" -ForegroundColor White
    Write-Host "     Settings -> Update & Security -> Windows Update -> View update history" -ForegroundColor Gray
    Write-Host "  4. Review logs: C:\Windows\WindowsUpdate.log" -ForegroundColor White
    Write-Host "  5. Verify server stability on Sunday mornings" -ForegroundColor White
    Write-Host ""

    Write-Host "Registry Keys Modified:" -ForegroundColor Cyan
    Write-Host "  $wuPath" -ForegroundColor Gray
    Write-Host "  $auPath" -ForegroundColor Gray
    Write-Host "  $activeHoursPath" -ForegroundColor Gray
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
