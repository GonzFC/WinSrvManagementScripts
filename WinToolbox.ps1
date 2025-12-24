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
    Version: See $ToolboxVersion variable
#>

[CmdletBinding()]
param(
    [switch]$AutoCleanup,
    [int]$DaysInactive = 30,
    [switch]$DeepComponentCleanup,
    [switch]$SkipUpdateCheck
)

#Requires -Version 5.1

# Version information
$script:ToolboxVersion = '1.0.4'
$script:ToolboxRepo = 'GonzFC/WinSrvManagementScripts'
$script:ToolboxBranch = 'main'

# Script root and module path
$ScriptRoot = $PSScriptRoot
$ModulePath = Join-Path $ScriptRoot 'modules'

# Verify modules directory exists
if (-not (Test-Path $ModulePath)) {
    Write-Host ""
    Write-Host "ERROR: Modules directory not found: $ModulePath" -ForegroundColor Red
    Write-Host "Please ensure the 'modules' folder exists in the same directory as WinToolbox.ps1" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit 1
}

# Display startup banner
Clear-Host
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Windows Management Toolbox" -ForegroundColor Cyan
Write-Host " v$script:ToolboxVersion" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Green
Write-Host "Installation Path:  $ScriptRoot" -ForegroundColor Green
Write-Host ""
Write-Host "Loading modules..." -ForegroundColor White

# Unblock all module files to prevent execution policy issues
Get-ChildItem -Path $ModulePath -Filter "*.psm1" -File | Unblock-File -ErrorAction SilentlyContinue

# Load all modules by reading content and executing with Invoke-Expression
# This ensures functions are loaded directly into the script's scope
$modules = @('Common', 'SystemOptimization', 'SecurityPrivacy', 'RemoteAccess', 'Maintenance')

foreach ($module in $modules) {
    $moduleFile = Join-Path $ModulePath "$module.psm1"

    if (Test-Path $moduleFile) {
        try {
            Write-Host "  Loading $module..." -NoNewline -ForegroundColor Gray

            # Read the module content and execute it with Invoke-Expression
            # This ensures the code runs in the current scope
            $moduleContent = Get-Content -Path $moduleFile -Raw -ErrorAction Stop
            Invoke-Expression $moduleContent -ErrorAction Stop

            # Verify the module loaded by checking for a known function
            $testFunction = switch ($module) {
                'Common' { 'Show-Menu' }
                'SystemOptimization' { 'Invoke-DiskSpaceReclamation' }
                'SecurityPrivacy' { 'Set-EdgePrivacySettings' }
                'RemoteAccess' { 'Install-Tailscale' }
                'Maintenance' { 'Install-XenServerTools' }
            }

            if (Get-Command $testFunction -ErrorAction SilentlyContinue) {
                Write-Host " OK" -ForegroundColor Green
            }
            else {
                Write-Host " FAILED (function $testFunction not found)" -ForegroundColor Red
                Write-Host ""
                Write-Host "ERROR: Module loaded but functions not available" -ForegroundColor Red
                Write-Host ""
                Write-Host "Diagnostic Information:" -ForegroundColor Yellow
                Write-Host "  Module: $module" -ForegroundColor White
                Write-Host "  File: $moduleFile" -ForegroundColor White
                Write-Host "  Test Function: $testFunction" -ForegroundColor White
                Write-Host ""
                Write-Host "Available functions in current scope:" -ForegroundColor Yellow
                Get-Command -CommandType Function | Where-Object { $_.Source -eq '' } | Select-Object -First 10 | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor White }
                Write-Host ""
                Write-Host "Press any key to exit..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
                exit 1
            }
        }
        catch {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Host ""
            Write-Host "ERROR: Failed to load module $module" -ForegroundColor Red
            Write-Host "Module path: $moduleFile" -ForegroundColor Yellow
            Write-Host "Error: $_" -ForegroundColor Red
            Write-Host "Error Line: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
            Write-Host ""
            Write-Host "Press any key to exit..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            exit 1
        }
    }
    else {
        Write-Host ""
        Write-Host "ERROR: Module not found: $moduleFile" -ForegroundColor Red
        Write-Host ""
        Write-Host "Press any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        exit 1
    }
}

Write-Host ""
Write-Host "All modules loaded successfully!" -ForegroundColor Green
Write-Host ""

#region Update Management

function Test-ToolboxUpdate {
    <#
    .SYNOPSIS
        Checks if a newer version of the toolbox is available
    #>
    [CmdletBinding()]
    param()

    try {
        # Enable TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

        # Get latest version from GitHub
        $versionUrl = "https://raw.githubusercontent.com/$script:ToolboxRepo/$script:ToolboxBranch/version.txt"
        $latestVersion = (Invoke-WebRequest -Uri $versionUrl -UseBasicParsing -TimeoutSec 5).Content.Trim()

        # Compare versions
        $current = [version]$script:ToolboxVersion
        $latest = [version]$latestVersion

        if ($latest -gt $current) {
            return @{
                UpdateAvailable = $true
                CurrentVersion = $script:ToolboxVersion
                LatestVersion = $latestVersion
            }
        }

        return @{
            UpdateAvailable = $false
            CurrentVersion = $script:ToolboxVersion
            LatestVersion = $latestVersion
        }
    }
    catch {
        # Silently fail - don't interrupt user if update check fails
        return @{
            UpdateAvailable = $false
            CurrentVersion = $script:ToolboxVersion
            LatestVersion = 'Unknown'
            Error = $_.Exception.Message
        }
    }
}

function Invoke-ToolboxUpdate {
    <#
    .SYNOPSIS
        Downloads and runs the latest installer
    #>
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host " Update Available" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""

    try {
        # Enable TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

        # Download and run installer
        $installerUrl = "https://raw.githubusercontent.com/$script:ToolboxRepo/$script:ToolboxBranch/install.ps1"

        Write-Host "Downloading latest installer..." -ForegroundColor Cyan
        $installerScript = Invoke-RestMethod -Uri $installerUrl -UseBasicParsing

        Write-Host "Launching updater..." -ForegroundColor Cyan
        Write-Host ""

        # Save to temp file and execute
        $tempInstaller = Join-Path $env:TEMP 'WinToolbox-Update.ps1'
        $installerScript | Out-File -FilePath $tempInstaller -Encoding UTF8 -Force

        # Launch installer and exit current instance
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tempInstaller`"" -Verb RunAs

        Write-Host "Update initiated. This window will now close." -ForegroundColor Green
        Start-Sleep -Seconds 2
        exit 0
    }
    catch {
        Write-Host ""
        Write-Host "ERROR: Failed to download update" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host ""
        Write-Host "You can manually update by running:" -ForegroundColor Cyan
        Write-Host "  iex (irm https://raw.githubusercontent.com/$script:ToolboxRepo/$script:ToolboxBranch/install.ps1)" -ForegroundColor White
        Write-Host ""
        Invoke-Pause
    }
}

#endregion

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
        '7' = 'Check for Updates'
    }

    $title = "Windows Management Toolbox v$script:ToolboxVersion"
    $selection = Show-Menu -Title $title -Options $options
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
        '3' = 'Install Virtualization Tools (XCP-ng / XenServer)'
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
            Write-Host "Virtualization Guest Tools Installation:" -ForegroundColor Cyan
            Write-Host ""

            $noReboot = -not (Show-Confirmation -Message "Automatically reboot after installation?" -DefaultYes)

            Write-Host ""
            $disableWUDrivers = Show-Confirmation -Message "Block Windows Update from delivering drivers?" -DefaultYes

            Write-Host ""
            Write-Host "Starting installation (you will choose XCP-ng or XenServer)..." -ForegroundColor Cyan

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

# Check for updates (unless skipped)
if (-not $SkipUpdateCheck) {
    $updateInfo = Test-ToolboxUpdate
    if ($updateInfo.UpdateAvailable) {
        Clear-Host
        Write-Host ""
        Write-Host "======================================" -ForegroundColor Cyan
        Write-Host " Update Available" -ForegroundColor Cyan
        Write-Host "======================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "A new version of Windows Management Toolbox is available!" -ForegroundColor White
        Write-Host ""
        Write-Host "  Current version: $($updateInfo.CurrentVersion)" -ForegroundColor Yellow
        Write-Host "  Latest version:  $($updateInfo.LatestVersion)" -ForegroundColor Green
        Write-Host ""

        if (Show-Confirmation -Message "Would you like to update now?" -DefaultYes) {
            Invoke-ToolboxUpdate
            # If we reach here, update failed - continue with current version
        }
        else {
            Write-Host ""
            Write-Host "You can update later from the main menu (option 7)" -ForegroundColor Gray
            Write-Host ""
            Invoke-Pause
        }
    }
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

        '7' {
            # Check for updates
            Write-Host ""
            Write-Host "Checking for updates..." -ForegroundColor Cyan
            $updateInfo = Test-ToolboxUpdate

            if ($updateInfo.UpdateAvailable) {
                Write-Host ""
                Write-Host "Update available!" -ForegroundColor Green
                Write-Host "  Current version: $($updateInfo.CurrentVersion)" -ForegroundColor Yellow
                Write-Host "  Latest version:  $($updateInfo.LatestVersion)" -ForegroundColor Green
                Write-Host ""

                if (Show-Confirmation -Message "Would you like to update now?" -DefaultYes) {
                    Invoke-ToolboxUpdate
                    # If we reach here, update failed
                }
            }
            else {
                Write-Host ""
                Write-Host "You're running the latest version ($($updateInfo.CurrentVersion))" -ForegroundColor Green
                Write-Host ""
                Invoke-Pause
            }
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
