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

    Every menu action can also run straight from the command line, without the
    menu:  .\WinToolbox.ps1 -Run <Action> [action parameters]
    List the actions:  .\WinToolbox.ps1 -Run List   (full reference: README.md)

.EXAMPLE
    .\WinToolbox.ps1 -Run DesktopInfo

.EXAMPLE
    .\WinToolbox.ps1 -Run SpeedTest -Peer 10.0.0.5 -Duration 30
#>

[CmdletBinding()]
param(
    [switch]$AutoCleanup,
    [int]$DaysInactive = 30,
    [switch]$DeepComponentCleanup,
    [switch]$SkipUpdateCheck,

    # Run one action without the menu (name or menu number), then exit.
    # Parameters after it are passed to that action.
    [string]$Run,
    [Parameter(ValueFromRemainingArguments = $true)]
    [object[]]$RunArgs
)

#Requires -Version 5.1

# Version information
$script:ToolboxVersion = '1.3.0'
$script:ToolboxRepo = 'GonzFC/WinSrvManagementScripts'
$script:ToolboxBranch = 'main'

# Distribution source: when installed from an xscp runner (internal distribution),
# distribution.json next to this script holds the base URL to check for updates.
# Falls back to the GitHub raw URLs (requires the repo to be reachable).
function Get-DistributionBase {
    try {
        $distFile = Join-Path $Global:ToolboxRoot 'distribution.json'
        if (Test-Path $distFile) {
            $dist = Get-Content -Path $distFile -Raw | ConvertFrom-Json
            if ($dist.BaseUrl) { return $dist.BaseUrl.TrimEnd('/') }
        }
    }
    catch { }
    return "https://raw.githubusercontent.com/$script:ToolboxRepo/$script:ToolboxBranch"
}

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

# Set global variable for modules to use (since $PSScriptRoot isn't available with Invoke-Expression)
$Global:ToolboxRoot = $ScriptRoot

# Display startup banner
if (-not $Run) { Clear-Host }
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
$modules = @('Common', 'SystemOptimization', 'SecurityPrivacy', 'RemoteAccess', 'Maintenance', 'Monitoring')

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
                'Maintenance' { 'Invoke-NetworkSpeedTest' }
                'Monitoring' { 'Install-WSBReporter' }
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

        # Get latest version from the distribution source (xscp or GitHub)
        $versionUrl = "$(Get-DistributionBase)/version.txt"
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

        # Download and run installer from the distribution source (xscp or GitHub)
        $installerUrl = "$(Get-DistributionBase)/install.ps1"

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
        Write-Host "  iex (irm $(Get-DistributionBase)/install.ps1)" -ForegroundColor White
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
    Clear-Host
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " Windows Management Toolbox v$script:ToolboxVersion" -ForegroundColor Cyan
    Write-Host " $env:COMPUTERNAME" -ForegroundColor DarkCyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  System Optimization" -ForegroundColor Cyan
    Write-Host "   [ 1]  Reclaim Disk Space (WinSxS, Updates, TEMP, Profiles)" -ForegroundColor White
    Write-Host "   [ 2]  Disable Backgrounds and Animations" -ForegroundColor White
    Write-Host ""

    Write-Host "  Remote Access" -ForegroundColor Cyan
    Write-Host "   [ 3]  Install Tailscale VPN" -ForegroundColor White
    Write-Host "   [ 4]  Install Jump Desktop Connect" -ForegroundColor White
    Write-Host ""

    Write-Host "  Security & Privacy" -ForegroundColor Cyan
    Write-Host "   [ 5]  Harden Microsoft Edge (Privacy & Clean Homepage)" -ForegroundColor White
    Write-Host ""

    Write-Host "  Maintenance" -ForegroundColor Cyan
    Write-Host "   [ 6]  Install Desktop Info Widget" -ForegroundColor White
    Write-Host "   [ 7]  Upgrade TLS and PowerShell (Legacy Systems)" -ForegroundColor White
    Write-Host "   [ 8]  Install Virtualization Tools (XCP-ng / XenServer)" -ForegroundColor White
    Write-Host ""

    Write-Host "  Performance & Updates" -ForegroundColor Cyan
    Write-Host "   [ 9]  Network Speed Test (iperf3)" -ForegroundColor White
    Write-Host "   [10]  Configure Windows Update (Stable Security Patching)" -ForegroundColor White
    Write-Host "   [11]  Disable Windows Updates (Manual Control Only)" -ForegroundColor White
    Write-Host ""

    Write-Host "  Monitoring and Management" -ForegroundColor Cyan
    Write-Host "   [15]  Enable WinRM Management (remote control from xscp)" -ForegroundColor White
    Write-Host "   [16]  Install Backup Reporter (WSB status -> xscp)" -ForegroundColor White
    Write-Host ""

    Write-Host "  System" -ForegroundColor Cyan
    Write-Host "   [12]  View System Information" -ForegroundColor White
    Write-Host "   [13]  View Logs" -ForegroundColor White
    Write-Host "   [14]  Check for Updates" -ForegroundColor White
    Write-Host ""

    Write-Host "   [ Q]  Quit" -ForegroundColor Gray
    Write-Host ""
    Write-Host -NoNewline "Select: " -ForegroundColor Yellow

    $selection = Read-Host
    return $selection.Trim().ToUpper()
}

function Show-SystemInformation {
    param([switch]$NoPause)
    if (-not $NoPause) { Clear-Host }
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
    if (-not $NoPause) { Invoke-Pause }
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

#region Command-line mode (-Run)

# One entry per menu action: CLI name, menu number, what it runs. Kept in step
# with the menu and the "Command-Line Usage" section of README.md.
$script:CliActions = [ordered]@{
    'DiskCleanup'           = @{ Menu = '1';  Help = 'Reclaim disk space  [-DaysInactive 30] [-DeepComponentCleanup] [-DeleteProfiles] [-Schedule]' }
    'DisableAnimations'     = @{ Menu = '2';  Help = 'Disable backgrounds and animations for all users' }
    'Tailscale'             = @{ Menu = '3';  Help = 'Install Tailscale  [-AuthKey k] [-LoginServer url] [-AcceptRoutes] [-AdvertiseRoutes cidrs] [-AcceptDNS] [-Hostname n] [-Operator u]' }
    'JumpDesktop'           = @{ Menu = '4';  Help = 'Install Jump Desktop Connect  -ConnectCode 123456' }
    'EdgeHardening'         = @{ Menu = '5';  Help = 'Harden Microsoft Edge (privacy + clean homepage)' }
    'DesktopInfo'           = @{ Menu = '6';  Help = 'Install/update the Desktop Info Widget for all users (+ daily auto-update)' }
    'TlsUpgrade'            = @{ Menu = '7';  Help = 'Upgrade TLS and PowerShell (legacy systems)  [-UpdateRoots]' }
    'VMTools'               = @{ Menu = '8';  Help = 'Install VM tools  -Platform XCPng|XenServer [-NoReboot] [-DisableWUDrivers]' }
    'SpeedTest'             = @{ Menu = '9';  Help = 'iperf3 speed test  -Peer 10.0.0.5 [-Duration 5|10|30]' }
    'WindowsUpdateConfig'   = @{ Menu = '10'; Help = 'Windows Update: Sundays 4 AM, security only, no drivers' }
    'DisableWindowsUpdates' = @{ Menu = '11'; Help = 'Disable automatic Windows updates  [-DisableService]' }
    'SystemInfo'            = @{ Menu = '12'; Help = 'Show system information' }
    'Logs'                  = @{ Menu = '13'; Help = 'List log files in C:\VLABS\Maintenance' }
    'Update'                = @{ Menu = '14'; Help = 'Update the toolbox now if a newer version exists  [-Force]' }
    'WinRM'                 = @{ Menu = '15'; Help = 'Enable hardened WinRM  [-AllowedSource ip,cidr] [-Https] [-DisableHttp]' }
    'BackupReporter'        = @{ Menu = '16'; Help = 'Install WSB Reporter  -XscpUrl url -Token t [-IntervalMinutes 15]' }
}

function Show-CliActions {
    Write-Host ""
    Write-Host "Usage: .\WinToolbox.ps1 -Run <Action> [parameters]   (Action = name or menu number)" -ForegroundColor Cyan
    Write-Host ""
    foreach ($name in $script:CliActions.Keys) {
        $a = $script:CliActions[$name]
        Write-Host ("  [{0,2}] {1,-22} {2}" -f $a.Menu, $name, $a.Help)
    }
    Write-Host ""
}

# "-Peer 10.0.0.5 -NoReboot -AllowedSource a,b" -> @{ Peer='10.0.0.5'; NoReboot=$true; ... }
function ConvertTo-CliParameters {
    param([object[]]$Arguments)
    $params = @{}
    $i = 0
    while ($i -lt $Arguments.Count) {
        $token = "$($Arguments[$i])"
        if ($token -notmatch '^-([A-Za-z][\w]*)(:(.*))?$') { throw "Unexpected argument '$token' (parameters look like -Name value)" }
        $name = $Matches[1]
        if ($Matches[2]) { $params[$name] = $Matches[3]; $i++; continue }
        $next = if ($i + 1 -lt $Arguments.Count) { "$($Arguments[$i + 1])" } else { $null }
        if ($null -ne $next -and $next -notmatch '^-[A-Za-z]') { $params[$name] = $next; $i += 2 }
        else { $params[$name] = $true; $i++ }
    }
    return $params
}

function Invoke-CliAction {
    param([string]$Action, [hashtable]$Params)

    if ($Action -in @('List', 'Help', '?')) { Show-CliActions; return }

    # Accept menu numbers and any letter case
    $name = $script:CliActions.Keys | Where-Object { $_ -eq $Action -or $script:CliActions[$_].Menu -eq $Action } | Select-Object -First 1
    if (-not $name) { Show-CliActions; throw "Unknown action '$Action'" }
    if ($name -notin @('SystemInfo', 'Logs') -and -not (Test-Administrator)) {
        throw "Administrator privileges are required (open PowerShell as Administrator)"
    }

    Write-LogMessage "Command-line run: $name $(($Params.Keys | ForEach-Object { "-$_" }) -join ' ')" -Level Info -Component 'CLI'

    switch ($name) {
        'DiskCleanup' {
            # Never stop to ask: profiles are only deleted with -DeleteProfiles
            $delete = [bool]$Params['DeleteProfiles']; $Params.Remove('DeleteProfiles')
            if ($delete) { $Params['Force'] = $true } else { $Params['SkipProfileDeletion'] = $true }
            Invoke-DiskSpaceReclamation @Params
        }
        'DisableAnimations'     { Disable-BackgroundsAndAnimations @Params }
        'Tailscale'             { Install-Tailscale @Params }
        'JumpDesktop' {
            if (-not $Params['ConnectCode']) { throw "-ConnectCode is required" }
            Install-JumpDesktopConnect @Params
        }
        'EdgeHardening'         { Set-EdgePrivacySettings @Params }
        'DesktopInfo'           { Install-DesktopInfoWidget @Params }
        'TlsUpgrade'            { Invoke-TLSAndPowerShellUpgrade @Params }
        'VMTools' {
            if (-not $Params['Platform']) { throw "-Platform XCPng or -Platform XenServer is required" }
            Install-XenServerTools @Params
        }
        'SpeedTest' {
            if (-not $Params['Peer']) { throw "-Peer <IP address> is required" }
            Invoke-NetworkSpeedTest @Params
        }
        'WindowsUpdateConfig'   { Set-WindowsUpdateConfiguration @Params }
        'DisableWindowsUpdates' { Disable-WindowsUpdates -Unattended @Params }
        'SystemInfo'            { Show-SystemInformation -NoPause }
        'Logs' {
            Get-ChildItem -Path 'C:\VLABS\Maintenance' -Filter '*.log' -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Format-Table @{ n = 'Modified'; e = { $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm') } }, Name, @{ n = 'KB'; e = { [math]::Round($_.Length / 1KB, 1) } } -AutoSize
        }
        'Update' {
            $updater = Join-Path $Global:ToolboxRoot 'WinSrv - Toolbox Auto Update.ps1'
            & $updater @Params
            if ($LASTEXITCODE) { throw "Update failed (see C:\VLABS\Maintenance\ToolboxAutoUpdate_*.log)" }
        }
        'WinRM' {
            if ($Params['AllowedSource']) { $Params['AllowedSource'] = @("$($Params['AllowedSource'])" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
            Enable-WinRMManagement @Params
        }
        'BackupReporter'        { Install-WSBReporter @Params }
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

# Command-line mode: run one action, no menu, no prompts, exit code 0/1
if ($Run) {
    try {
        $cliParams = ConvertTo-CliParameters -Arguments $RunArgs
        # These two are also toolbox parameters, so PowerShell binds them there
        if ($PSBoundParameters.ContainsKey('DaysInactive')) { $cliParams['DaysInactive'] = $DaysInactive }
        if ($DeepComponentCleanup) { $cliParams['DeepComponentCleanup'] = $true }
        Invoke-CliAction -Action $Run -Params $cliParams
        exit 0
    }
    catch {
        Write-Host ""
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        Write-LogMessage "Command-line run '$Run' failed: $_" -Level Error -Component 'CLI'
        exit 1
    }
}

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
            Write-Host "You can update later from the main menu (option 14)" -ForegroundColor Gray
            Write-Host ""
            Invoke-Pause
        }
    }
}

# Main menu loop
$running = $true

while ($running) {
    $sel = Show-MainMenu

    switch ($sel) {

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

        '3' {
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

        '4' {
            Write-Host ""
            if (Show-Confirmation -Message "Install Jump Desktop Connect?" -DefaultYes) {
                Install-JumpDesktopConnect
                Invoke-Pause
            }
        }

        '5' {
            Write-Host ""
            if (Show-Confirmation -Message "Configure Microsoft Edge for privacy and minimal browsing?" -DefaultYes) {
                Set-EdgePrivacySettings
                Invoke-Pause
            }
        }

        '6' {
            Write-Host ""
            Install-DesktopInfoWidget
            Invoke-Pause
        }

        '7' {
            Write-Host ""
            Write-Host "TLS and PowerShell Upgrade Options:" -ForegroundColor Cyan
            Write-Host ""
            $updateRoots = Show-Confirmation -Message "Update root certificates from Windows Update?" -DefaultYes:$false
            Write-Host ""
            Write-Host "Starting upgrade (this may take several minutes)..." -ForegroundColor Cyan
            Invoke-TLSAndPowerShellUpgrade -UpdateRoots:$updateRoots
            Invoke-Pause
        }

        '8' {
            Write-Host ""
            Write-Host "Virtualization Guest Tools Installation:" -ForegroundColor Cyan
            Write-Host ""
            $noReboot = -not (Show-Confirmation -Message "Automatically reboot after installation?" -DefaultYes)
            Write-Host ""
            $disableWUDrivers = Show-Confirmation -Message "Block Windows Update from delivering drivers?" -DefaultYes
            Write-Host ""
            Write-Host "Starting installation (you will choose XCP-ng or XenServer)..." -ForegroundColor Cyan
            Install-XenServerTools -NoReboot:$noReboot -DisableWUDrivers:$disableWUDrivers
            if (-not $noReboot) { $running = $false }
            else { Invoke-Pause }
        }

        '9' {
            try {
                Invoke-NetworkSpeedTest
                Invoke-Pause
            }
            catch {
                Write-Host ""
                Write-Host "Network speed test failed. Check logs for details." -ForegroundColor Red
                Invoke-Pause
            }
        }

        '10' {
            Write-Host ""
            if (Show-Confirmation -Message "Configure Windows Update with stable security patching settings?" -DefaultYes) {
                try {
                    Set-WindowsUpdateConfiguration
                    Invoke-Pause
                }
                catch {
                    Write-Host ""
                    Write-Host "Configuration failed. Check logs for details." -ForegroundColor Red
                    Invoke-Pause
                }
            }
        }

        '11' {
            Write-Host ""
            if (Show-Confirmation -Message "DISABLE automatic Windows updates? (Only manual updates will be possible)" -DefaultYes:$false) {
                try {
                    Disable-WindowsUpdates
                    Invoke-Pause
                }
                catch {
                    Write-Host ""
                    Write-Host "Configuration failed. Check logs for details." -ForegroundColor Red
                    Invoke-Pause
                }
            }
        }

        '12' { Show-SystemInformation }

        '13' { Show-LogViewer }

        '14' {
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
                }
            }
            else {
                Write-Host ""
                Write-Host "You're running the latest version ($($updateInfo.CurrentVersion))" -ForegroundColor Green
                Write-Host ""
                Invoke-Pause
            }
        }

        '15' {
            Write-Host ""
            Write-Host "Enable WinRM Management" -ForegroundColor Cyan
            Write-Host "Lets a management host (your xscp runner / announcer) run remote PowerShell." -ForegroundColor Gray
            Write-Host ""
            $allowed = Read-Host "Allowed source IPs/CIDRs (comma-separated, e.g. 192.168.1.240,192.168.1.252)"
            Write-Host ""
            $useHttps = Show-Confirmation -Message "Create an HTTPS listener (self-signed cert)?" -DefaultYes:$false
            Write-Host ""
            if (Show-Confirmation -Message "Enable WinRM now (hardened: Basic off, unencrypted off)?" -DefaultYes) {
                $params = @{}
                if (-not [string]::IsNullOrWhiteSpace($allowed)) {
                    $params['AllowedSource'] = ($allowed -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                }
                if ($useHttps) { $params['Https'] = $true }
                Enable-WinRMManagement @params
            }
            Invoke-Pause
        }

        '16' {
            Write-Host ""
            Write-Host "Install Backup Reporter (Windows Server Backup -> xscp)" -ForegroundColor Cyan
            Write-Host "Pushes this server's WSB status to the xscp dashboard on a schedule." -ForegroundColor Gray
            Write-Host ""
            $xscpUrl = Read-Host "xscp ingest URL (e.g. http://xscp.yoursite.example:8899/ingest/wsb)"
            $token = Read-Host "Ingest token (from xscp: /opt/hwmon/etc/ingest.token)"
            $intervalRaw = Read-Host "Report interval in minutes (default: 15)"
            $interval = 15
            if (-not [string]::IsNullOrWhiteSpace($intervalRaw)) { $interval = [int]$intervalRaw }
            Write-Host ""
            if (-not [string]::IsNullOrWhiteSpace($xscpUrl) -and -not [string]::IsNullOrWhiteSpace($token)) {
                Install-WSBReporter -XscpUrl $xscpUrl -Token $token -IntervalMinutes $interval
            }
            else {
                Write-Host "URL and token are both required." -ForegroundColor Yellow
            }
            Invoke-Pause
        }

        'Q' { $running = $false }

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
