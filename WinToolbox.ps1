<#
.SYNOPSIS
    Windows Server and Client Management Toolbox

.DESCRIPTION
    Unified menu-driven PowerShell application for Windows Server and Client management tasks.

    Categories:
    - System Optimization: Disk cleanup, UI optimizations
    - Remote Access: Tailscale VPN, Jump Desktop Connect
    - Security & Privacy: Browser hardening, privacy settings
    - Maintenance: Desktop info widget, TLS/PowerShell upgrades, VM tools

.NOTES
    Author: IT Infrastructure Team
    Requires: PowerShell 5.1+, Administrator privileges
    Logs: C:\VLABS\Maintenance\
#>

[CmdletBinding()]
param(
    [switch]$AutoCleanup,
    [int]$DaysInactive = 30,
    [switch]$DeepComponentCleanup
)

#Requires -Version 5.1

# Script root and module path
$ScriptRoot = $PSScriptRoot
$ModulePath = Join-Path $ScriptRoot 'modules'

# Import all modules
$modules = @('Common', 'SystemOptimization', 'SecurityPrivacy', 'RemoteAccess', 'Maintenance')

foreach ($module in $modules) {
    $modulePath = Join-Path $ModulePath "$module.psm1"

    if (Test-Path $modulePath) {
        try {
            Import-Module $modulePath -Force -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to load module $module : $_"
            exit 1
        }
    }
    else {
        Write-Error "Module not found: $modulePath"
        exit 1
    }
}

#region Prerequisites Check

function Test-Prerequisites {
    $issues = @()

    # Check Administrator
    if (-not (Test-Administrator)) {
        $issues += "Not running as Administrator"
    }

    # Check PowerShell version
    if (-not (Test-PowerShellVersion -MinimumVersion 5)) {
        $issues += "PowerShell version must be 5.1 or higher (current: $($PSVersionTable.PSVersion))"
    }

    if ($issues.Count -gt 0) {
        Write-Host ""
        Write-Host "Prerequisites not met:" -ForegroundColor Red
        foreach ($issue in $issues) {
            Write-Host "  - $issue" -ForegroundColor Yellow
        }
        Write-Host ""

        if (-not (Test-Administrator)) {
            $response = Show-Confirmation -Message "Would you like to restart as Administrator?" -DefaultYes
            if ($response) {
                $scriptPath = $PSCommandPath
                $args = @()

                Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList `
                    "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" $($args -join ' ')"

                exit 0
            }
        }

        return $false
    }

    return $true
}

#endregion

#region Menu System

function Show-MainMenu {
    $options = [ordered]@{
        '1' = 'System Optimization'
        '2' = 'Remote Access'
        '3' = 'Security & Privacy'
        '4' = 'Maintenance'
        '5' = 'View System Information'
        '6' = 'View Logs'
    }

    $selection = Show-Menu -Title "Windows Management Toolbox" -Options $options
    return $selection
}

function Show-SystemOptimizationMenu {
    $options = [ordered]@{
        '1' = 'Reclaim Disk Space (WinSxS, Updates, TEMP, Profiles)'
        '2' = 'Disable Backgrounds and Animations'
    }

    $selection = Show-Menu -Title "System Optimization" -Options $options -AllowBack

    switch ($selection) {
        '1' {
            Write-Host ""
            Write-Host "Disk Space Reclamation Options:" -ForegroundColor Cyan
            Write-Host ""

            $daysInactive = Read-Host "Days of inactivity for profile deletion (default: 30)"
            if ([string]::IsNullOrWhiteSpace($daysInactive)) { $daysInactive = 30 }
            else { $daysInactive = [int]$daysInactive }

            Write-Host ""
            $deepClean = Show-Confirmation -Message "Perform deep component cleanup (/ResetBase)? This prevents uninstalling existing updates" -DefaultYes:$false

            Write-Host ""
            $skipProfiles = -not (Show-Confirmation -Message "Delete inactive user profiles?" -DefaultYes:$false)

            Write-Host ""
            $schedule = Show-Confirmation -Message "Create weekly scheduled task?" -DefaultYes:$false

            Write-Host ""
            Write-Host "Starting disk space reclamation..." -ForegroundColor Cyan

            Invoke-DiskSpaceReclamation -DaysInactive $daysInactive `
                -DeepComponentCleanup:$deepClean `
                -SkipProfileDeletion:$skipProfiles `
                -Schedule:$schedule

            Invoke-Pause
        }

        '2' {
            Write-Host ""
            if (Show-Confirmation -Message "Disable backgrounds and animations for all users?" -DefaultYes) {
                Disable-BackgroundsAndAnimations
                Invoke-Pause
            }
        }

        'B' { return 'BACK' }
        'Q' { return 'QUIT' }
    }

    return 'CONTINUE'
}

function Show-RemoteAccessMenu {
    $options = [ordered]@{
        '1' = 'Install Tailscale VPN'
        '2' = 'Install Jump Desktop Connect'
    }

    $selection = Show-Menu -Title "Remote Access" -Options $options -AllowBack

    switch ($selection) {
        '1' {
            Write-Host ""
            Write-Host "Tailscale Installation Options:" -ForegroundColor Cyan
            Write-Host ""

            $authKey = Read-Host "Auth Key (leave blank to configure later)"
            $loginServer = Read-Host "Login Server (leave blank for default)"

            Write-Host ""
            $acceptRoutes = Show-Confirmation -Message "Accept routes from other Tailscale nodes?" -DefaultYes:$false

            Write-Host ""
            $advertiseRoutes = Read-Host "Advertise routes (comma-separated, e.g., 192.168.1.0/24)"

            Write-Host ""
            $acceptDNS = Show-Confirmation -Message "Accept DNS from Tailscale?" -DefaultYes:$false

            Write-Host ""
            $hostname = Read-Host "Hostname (leave blank for system default)"

            Write-Host ""
            Write-Host "Installing Tailscale..." -ForegroundColor Cyan

            $params = @{}
            if ($authKey) { $params['AuthKey'] = $authKey }
            if ($loginServer) { $params['LoginServer'] = $loginServer }
            if ($acceptRoutes) { $params['AcceptRoutes'] = $true }
            if ($advertiseRoutes) { $params['AdvertiseRoutes'] = $advertiseRoutes }
            if ($acceptDNS) { $params['AcceptDNS'] = $true }
            if ($hostname) { $params['Hostname'] = $hostname }

            Install-Tailscale @params

            Invoke-Pause
        }

        '2' {
            Write-Host ""
            if (Show-Confirmation -Message "Install Jump Desktop Connect?" -DefaultYes) {
                Install-JumpDesktopConnect
                Invoke-Pause
            }
        }

        'B' { return 'BACK' }
        'Q' { return 'QUIT' }
    }

    return 'CONTINUE'
}

function Show-SecurityPrivacyMenu {
    $options = [ordered]@{
        '1' = 'Harden Microsoft Edge (Privacy & Clean Homepage)'
    }

    $selection = Show-Menu -Title "Security & Privacy" -Options $options -AllowBack

    switch ($selection) {
        '1' {
            Write-Host ""
            if (Show-Confirmation -Message "Configure Microsoft Edge for privacy and minimal browsing?" -DefaultYes) {
                Set-EdgePrivacySettings
                Invoke-Pause
            }
        }

        'B' { return 'BACK' }
        'Q' { return 'QUIT' }
    }

    return 'CONTINUE'
}

function Show-MaintenanceMenu {
    $options = [ordered]@{
        '1' = 'Install Desktop Info Widget'
        '2' = 'Upgrade TLS and PowerShell (Legacy Systems)'
        '3' = 'Install XenServer VM Tools'
    }

    $selection = Show-Menu -Title "Maintenance" -Options $options -AllowBack

    switch ($selection) {
        '1' {
            Write-Host ""
            if (Show-Confirmation -Message "Install/Update Desktop Info Widget?" -DefaultYes) {
                Install-DesktopInfoWidget
                Invoke-Pause
            }
        }

        '2' {
            Write-Host ""
            Write-Host "TLS and PowerShell Upgrade Options:" -ForegroundColor Cyan
            Write-Host ""

            $updateRoots = Show-Confirmation -Message "Update root certificates from Windows Update?" -DefaultYes:$false

            Write-Host ""
            Write-Host "Starting upgrade (this may take several minutes)..." -ForegroundColor Cyan

            Invoke-TLSAndPowerShellUpgrade -UpdateRoots:$updateRoots

            Invoke-Pause
        }

        '3' {
            Write-Host ""
            Write-Host "XenServer VM Tools Installation Options:" -ForegroundColor Cyan
            Write-Host ""

            $noReboot = -not (Show-Confirmation -Message "Automatically reboot after installation?" -DefaultYes)

            Write-Host ""
            $disableWUDrivers = Show-Confirmation -Message "Block Windows Update from delivering drivers?" -DefaultYes

            Write-Host ""
            Write-Host "Installing XenServer VM Tools..." -ForegroundColor Cyan

            Install-XenServerTools -NoReboot:$noReboot -DisableWUDrivers:$disableWUDrivers

            if (-not $noReboot) {
                # Script will reboot, won't reach here
                return 'QUIT'
            }

            Invoke-Pause
        }

        'B' { return 'BACK' }
        'Q' { return 'QUIT' }
    }

    return 'CONTINUE'
}

function Show-SystemInformation {
    Clear-Host
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host " System Information" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1

    Write-Host "Computer Name:   " -NoNewline -ForegroundColor Gray
    Write-Host $env:COMPUTERNAME -ForegroundColor White

    Write-Host "OS:              " -NoNewline -ForegroundColor Gray
    Write-Host "$($os.Caption) (Build $($os.BuildNumber))" -ForegroundColor White

    Write-Host "Architecture:    " -NoNewline -ForegroundColor Gray
    Write-Host $env:PROCESSOR_ARCHITECTURE -ForegroundColor White

    Write-Host "Is Server:       " -NoNewline -ForegroundColor Gray
    Write-Host (Test-WindowsServer) -ForegroundColor White

    Write-Host "PowerShell:      " -NoNewline -ForegroundColor Gray
    Write-Host $PSVersionTable.PSVersion -ForegroundColor White

    Write-Host "CPU:             " -NoNewline -ForegroundColor Gray
    Write-Host $cpu.Name -ForegroundColor White

    Write-Host "RAM:             " -NoNewline -ForegroundColor Gray
    Write-Host "$([math]::Round($cs.TotalPhysicalMemory / 1GB, 2)) GB" -ForegroundColor White

    Write-Host "Free Space (C:): " -NoNewline -ForegroundColor Gray
    Write-Host "$(Get-FreeSpaceGB -DriveLetter 'C') GB" -ForegroundColor White

    Write-Host ""
    Invoke-Pause
}

function Show-LogViewer {
    Clear-Host
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host " Log Viewer" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""

    $logDir = 'C:\VLABS\Maintenance'

    if (-not (Test-Path $logDir)) {
        Write-Host "Log directory not found: $logDir" -ForegroundColor Yellow
        Write-Host ""
        Invoke-Pause
        return
    }

    $logFiles = Get-ChildItem -Path $logDir -Filter "*.log" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending

    if ($logFiles.Count -eq 0) {
        Write-Host "No log files found in $logDir" -ForegroundColor Yellow
        Write-Host ""
        Invoke-Pause
        return
    }

    Write-Host "Available log files:" -ForegroundColor White
    Write-Host ""

    for ($i = 0; $i -lt $logFiles.Count; $i++) {
        $file = $logFiles[$i]
        $sizeKB = [math]::Round($file.Length / 1KB, 2)
        Write-Host "  [$($i + 1)] " -NoNewline -ForegroundColor Cyan
        Write-Host "$($file.Name) " -NoNewline -ForegroundColor White
        Write-Host "($sizeKB KB, $($file.LastWriteTime))" -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "  [O] Open log directory in Explorer" -ForegroundColor Gray
    Write-Host "  [B] Back" -ForegroundColor Gray
    Write-Host ""
    Write-Host -NoNewline "Select log file to view (or O/B): " -ForegroundColor Yellow

    $selection = Read-Host

    if ($selection -match '^\d+$') {
        $index = [int]$selection - 1
        if ($index -ge 0 -and $index -lt $logFiles.Count) {
            $selectedFile = $logFiles[$index]

            Write-Host ""
            Write-Host "Opening $($selectedFile.Name)..." -ForegroundColor Cyan

            # Open in default text editor
            Start-Process notepad.exe -ArgumentList $selectedFile.FullName
        }
    }
    elseif ($selection -eq 'O') {
        Start-Process explorer.exe -ArgumentList $logDir
    }
}

#endregion

#region Main Execution

# If called with -AutoCleanup (for scheduled task)
if ($AutoCleanup) {
    Initialize-Logging
    Write-LogMessage "Auto cleanup initiated via scheduled task" -Level Info -Component 'AutoCleanup'

    Invoke-DiskSpaceReclamation -DaysInactive $DaysInactive `
        -DeepComponentCleanup:$DeepComponentCleanup `
        -SkipProfileDeletion:$false

    exit 0
}

# Initialize
Initialize-Logging

# Check prerequisites
if (-not (Test-Prerequisites)) {
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit 1
}

# Main menu loop
$running = $true

while ($running) {
    $mainSelection = Show-MainMenu

    switch ($mainSelection) {
        '1' {
            $result = Show-SystemOptimizationMenu
            if ($result -eq 'QUIT') { $running = $false }
        }

        '2' {
            $result = Show-RemoteAccessMenu
            if ($result -eq 'QUIT') { $running = $false }
        }

        '3' {
            $result = Show-SecurityPrivacyMenu
            if ($result -eq 'QUIT') { $running = $false }
        }

        '4' {
            $result = Show-MaintenanceMenu
            if ($result -eq 'QUIT') { $running = $false }
        }

        '5' {
            Show-SystemInformation
        }

        '6' {
            Show-LogViewer
        }

        'Q' {
            $running = $false
        }

        default {
            Write-Host ""
            Write-Host "Invalid selection. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}

Clear-Host
Write-Host ""
Write-Host "Thank you for using Windows Management Toolbox!" -ForegroundColor Cyan
Write-Host "Logs are available in: C:\VLABS\Maintenance\" -ForegroundColor Gray
Write-Host ""

#endregion
