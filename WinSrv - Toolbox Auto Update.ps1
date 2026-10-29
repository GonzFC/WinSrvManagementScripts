<#
.SYNOPSIS
    Keeps the Windows Management Toolbox (and the Desktop Info Widget) up to date

.DESCRIPTION
    Compares the installed toolbox version (C:\ProgramData\WinToolbox\version.txt)
    with the distribution source and, when a newer version exists, upgrades the
    toolbox in place and redeploys the Desktop Info Widget runtime. The running
    widget notices its script changed and relaunches itself.

    Distribution source: distribution.json in the install folder (xscp) when
    present, otherwise GitHub.

    Every run writes C:\ProgramData\WinToolbox\update-status.json, which the
    Desktop Info Widget displays (installed version, last update, last check).

    Modes:
      (no switch)  Run one update check now (this is what the scheduled task runs)
      -Install     Copy this script to C:\ProgramData\DesktopInfoWidget and register
                   the daily "WinToolbox Auto Update" task (SYSTEM), then run it once
      -Uninstall   Remove the scheduled task

.NOTES
    Author: IT Infrastructure Team
    Requires: PowerShell 5.1+, Administrator privileges (the task runs as SYSTEM)
    Logs: C:\VLABS\Maintenance\ToolboxAutoUpdate_yyyy-MM.log

.EXAMPLE
    .\WinSrv - Toolbox Auto Update.ps1 -Install

    Registers the daily auto-update task and runs the first check.

.EXAMPLE
    .\WinSrv - Toolbox Auto Update.ps1 -Force

    Reinstalls the latest toolbox even if the installed version is current.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$Repo          = 'GonzFC/WinSrvManagementScripts'
$Branch        = 'main'
$InstallPath   = Join-Path $env:ProgramData 'WinToolbox'
$WidgetRoot    = Join-Path $env:ProgramData 'DesktopInfoWidget'
$WidgetScript  = Join-Path $WidgetRoot 'DesktopInfoWidget.ps1'
$UpdaterCopy   = Join-Path $WidgetRoot 'ToolboxAutoUpdate.ps1'
$StatusFile    = Join-Path $InstallPath 'update-status.json'
$TaskName      = 'WinToolbox Auto Update'
$LogDir        = 'C:\VLABS\Maintenance'

#region Helper Functions

function Write-UpdateLog {
    param([string]$Message, [string]$Level = 'Info')
    $color = switch ($Level) { 'Success' { 'Green' } 'Warning' { 'Yellow' } 'Error' { 'Red' } default { 'White' } }
    Write-Host $Message -ForegroundColor $color
    try {
        if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
        Add-Content -Path (Join-Path $LogDir ("ToolboxAutoUpdate_{0}.log" -f (Get-Date -Format 'yyyy-MM'))) `
            -Value ("[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message) -ErrorAction SilentlyContinue
    } catch { }
}

function Test-IsAdmin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-InstalledVersion {
    $file = Join-Path $InstallPath 'version.txt'
    if (Test-Path $file) { return (Get-Content -Path $file -Raw).Trim() }
    return $null
}

# xscp installs record their source in distribution.json; otherwise use GitHub
function Get-Source {
    $distFile = Join-Path $InstallPath 'distribution.json'
    try {
        if (Test-Path $distFile) {
            $dist = Get-Content -Path $distFile -Raw | ConvertFrom-Json
            if ($dist.BaseUrl) {
                $base = $dist.BaseUrl.TrimEnd('/')
                return [PSCustomObject]@{ Name = 'xscp'; VersionUrl = "$base/version.txt"; ZipUrl = "$base/WinToolbox.zip" }
            }
        }
    } catch { }
    [PSCustomObject]@{
        Name       = 'GitHub'
        VersionUrl = "https://raw.githubusercontent.com/$Repo/$Branch/version.txt"
        ZipUrl     = "https://github.com/$Repo/archive/refs/heads/$Branch.zip"
    }
}

function Save-Status {
    param([string]$Installed, [string]$Latest, [string]$Result, [string]$Source, [switch]$Updated)
    $previous = $null
    try { if (Test-Path $StatusFile) { $previous = Get-Content -Path $StatusFile -Raw | ConvertFrom-Json } } catch { }
    $now = (Get-Date).ToString('s')
    $status = [ordered]@{
        InstalledVersion = $Installed
        LatestVersion    = $Latest
        LastCheck        = $now
        LastCheckResult  = $Result
        LastUpdate       = if ($Updated) { $now } elseif ($previous) { $previous.LastUpdate } else { $null }
        Source           = $Source
    }
    try {
        if (-not (Test-Path $InstallPath)) { New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null }
        $status | ConvertTo-Json | Set-Content -Path $StatusFile -Encoding ASCII -Force
    } catch {
        Write-UpdateLog "Could not write status file: $($_.Exception.Message)" -Level Warning
    }
}

# Extract the widget runtime ($widgetPs1 here-string) from the Desktop Info installer
function Get-WidgetRuntime {
    param([string]$InstallerPath)
    $content = Get-Content -Path $InstallerPath -Raw
    $start = $content.IndexOf('$widgetPs1 = @''')
    if ($start -lt 0) { throw "Widget runtime not found in $InstallerPath" }
    $end = $content.IndexOf('''@', $start) + 2
    Invoke-Expression $content.Substring($start, $end - $start)
    return $widgetPs1
}

#endregion

#region Install / Uninstall the scheduled task

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-UpdateLog "Scheduled task '$TaskName' removed" -Level Success
    return
}

if ($Install) {
    if (-not (Test-IsAdmin)) { throw "Administrator privileges are required to register the auto-update task" }

    if (-not (Test-Path $WidgetRoot)) { New-Item -ItemType Directory -Path $WidgetRoot -Force | Out-Null }
    if ($PSCommandPath -ne $UpdaterCopy) { Copy-Item -Path $PSCommandPath -Destination $UpdaterCopy -Force }

    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch { }

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$UpdaterCopy`""
    # Once every 24 hours; the random delay keeps a fleet of servers from all
    # hitting the source at the same minute, StartWhenAvailable catches up a
    # check missed while the server was off.
    $trigger   = New-ScheduledTaskTrigger -Daily -At '03:17' -RandomDelay (New-TimeSpan -Minutes 30)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings | Out-Null
    Write-UpdateLog "Scheduled task '$TaskName' registered (daily, 03:17 + up to 30 min, as SYSTEM)" -Level Success

    # First check now so the widget has a status to show right away
    Start-ScheduledTask -TaskName $TaskName
    Write-UpdateLog "First update check started in the background" -Level Info
    return
}

#endregion

#region Update check

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$source    = Get-Source
$installed = Get-InstalledVersion
$latest    = $null

try {
    $latest = (Invoke-WebRequest -Uri $source.VersionUrl -UseBasicParsing -TimeoutSec 30).Content.Trim()
    [void][version]$latest
}
catch {
    Write-UpdateLog "Update check failed ($($source.Name)): $($_.Exception.Message)" -Level Error
    Save-Status -Installed $installed -Latest $latest -Result "Check failed" -Source $source.Name
    exit 1
}

$needsUpdate = $Force -or (-not $installed) -or ([version]$latest -gt [version]$installed)
if (-not $needsUpdate) {
    Write-UpdateLog "Up to date (v$installed, source $($source.Name))" -Level Success
    Save-Status -Installed $installed -Latest $latest -Result "Up to date" -Source $source.Name
    exit 0
}

Write-UpdateLog "Updating toolbox: v$installed -> v$latest (source $($source.Name))" -Level Info

$runId       = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$zipPath     = Join-Path $env:TEMP "WinToolbox_AutoUpdate_$runId.zip"
$extractPath = Join-Path $env:TEMP "WinToolbox_AutoUpdate_$runId"

try {
    Invoke-WebRequest -Uri $source.ZipUrl -OutFile $zipPath -UseBasicParsing -TimeoutSec 300
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractPath)

    $extracted  = Get-ChildItem $extractPath -Directory | Select-Object -First 1
    $sourceRoot = if ($extracted -and -not (Test-Path (Join-Path $extractPath 'WinToolbox.ps1'))) { $extracted.FullName } else { $extractPath }
    if (-not (Test-Path (Join-Path $sourceRoot 'WinToolbox.ps1'))) { throw "Downloaded package does not contain WinToolbox.ps1" }

    # The site's distribution.json is not part of the package; keep it as it is
    $distFile = Join-Path $InstallPath 'distribution.json'
    $distBackup = if (Test-Path $distFile) { Get-Content -Path $distFile -Raw } else { $null }

    # Upgrade IN PLACE (copy-over); the toolbox may be running from this folder
    if (-not (Test-Path $InstallPath)) { New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null }
    Copy-Item -Path (Join-Path $sourceRoot '*') -Destination $InstallPath -Recurse -Force
    if ($distBackup) { Set-Content -Path $distFile -Value $distBackup -Encoding ASCII -Force }
    Get-ChildItem -Path $InstallPath -Recurse -File | Unblock-File -ErrorAction SilentlyContinue

    $installedNow = Get-InstalledVersion
    Write-UpdateLog "Toolbox updated to v$installedNow" -Level Success

    # Redeploy the widget runtime, only when its code actually changed (the
    # running widget relaunches itself when it sees its script file change)
    $newInstaller = Join-Path $InstallPath 'WinSrv - Desktop Info.ps1'
    if ((Test-Path $WidgetScript) -and (Test-Path $newInstaller)) {
        $runtime = Get-WidgetRuntime -InstallerPath $newInstaller
        $current = Get-Content -Path $WidgetScript -Raw
        if ($current.Trim() -ne $runtime.Trim()) {
            $runtime | Out-File -FilePath $WidgetScript -Encoding UTF8 -Force
            Write-UpdateLog "Desktop Info Widget runtime redeployed" -Level Success
        }
    }

    # Keep the task's own copy of this updater current
    $newUpdater = Join-Path $InstallPath 'WinSrv - Toolbox Auto Update.ps1'
    if ((Test-Path $newUpdater) -and (Test-Path $WidgetRoot)) {
        Copy-Item -Path $newUpdater -Destination $UpdaterCopy -Force
    }

    Save-Status -Installed $installedNow -Latest $latest -Result "Updated to v$installedNow" -Source $source.Name -Updated
}
catch {
    Write-UpdateLog "Update failed: $($_.Exception.Message)" -Level Error
    Save-Status -Installed $installed -Latest $latest -Result "Update failed" -Source $source.Name
    exit 1
}
finally {
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue
}

#endregion
