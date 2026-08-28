<#
.SYNOPSIS
    Windows Management Toolbox - Bootstrap Installer (internal xscp distribution)

.DESCRIPTION
    One-liner installer served from a VLABS xscp runner (LAN / tailnet only).

    Usage:
        iex (irm http://xscp.ait.mesker.us:8899/toolbox/install.ps1)

    Downloads WinToolbox.zip from the same xscp, installs to C:\ProgramData\WinToolbox,
    and records the distribution source so in-app updates (option 14) come from this
    xscp too. The GitHub repo is private; this replaces the public raw URLs.

.NOTES
    Automatically elevates to Administrator if needed.
#>

$ErrorActionPreference = 'Stop'

# Base URL of the xscp distribution this installer was fetched from.
$BaseUrl = 'http://xscp.ait.mesker.us:8899/toolbox'

function Write-ColorOutput {
    param([string]$Message, [string]$Color = 'White')
    Write-Host $Message -ForegroundColor $Color
}

Clear-Host
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Windows Management Toolbox" -ForegroundColor Cyan
Write-Host " Bootstrap Installer (xscp)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-ColorOutput "Administrator privileges required." -Color Yellow
    Write-ColorOutput "Relaunching as Administrator..." -Color Yellow
    Write-Host ""
    try {
        $scriptContent = Invoke-RestMethod -Uri "$BaseUrl/install.ps1" -UseBasicParsing
        $encodedScript = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($scriptContent))
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedScript"
        exit 0
    }
    catch {
        Write-ColorOutput "Failed to elevate. Please run PowerShell as Administrator manually." -Color Red
        Write-Host ""
        Write-Host "Then run:" -ForegroundColor Gray
        Write-Host "  iex (irm $BaseUrl/install.ps1)" -ForegroundColor White
        Write-Host ""
        pause
        exit 1
    }
}

if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-ColorOutput "ERROR: PowerShell 5.1 or higher is required." -Color Red
    Write-ColorOutput "Current version: $($PSVersionTable.PSVersion)" -Color Yellow
    Write-Host ""
    pause
    exit 1
}

Write-ColorOutput "Running as Administrator" -Color Green
Write-ColorOutput "PowerShell Version: $($PSVersionTable.PSVersion)" -Color Green
Write-ColorOutput "Distribution: $BaseUrl" -Color Green
Write-Host ""

$installPath = Join-Path $env:ProgramData 'WinToolbox'
Write-ColorOutput "Installation directory: $installPath" -Color Cyan
Write-Host ""

try {
    $zipUrl = "$BaseUrl/WinToolbox.zip"
    # Unique temp paths per run: two concurrent installer runs (e.g. the in-app
    # updater's window plus a manual one-liner) previously collided on shared
    # %TEMP% paths and one of them died with "Access is denied".
    $runId = [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $zipPath = Join-Path $env:TEMP "WinToolbox_$runId.zip"
    $extractPath = Join-Path $env:TEMP "WinToolbox_Extract_$runId"

    Write-ColorOutput "Downloading toolbox from xscp..." -Color White
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing

    Write-ColorOutput "Extracting files..." -Color White
    if (Test-Path $extractPath) { Remove-Item -Path $extractPath -Recurse -Force }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractPath)

    $extractedFolder = Get-ChildItem $extractPath -Directory | Select-Object -First 1
    $sourceRoot = if ($extractedFolder) { $extractedFolder.FullName } else { $extractPath }
    # Upgrade IN PLACE (copy-over). Never delete the install directory: when the
    # update is launched from inside the running toolbox, that directory is the
    # running shell's working directory and Remove-Item fails with "in use".
    if (-not (Test-Path $installPath)) { New-Item -ItemType Directory -Path $installPath -Force | Out-Null }
    Copy-Item -Path (Join-Path $sourceRoot '*') -Destination $installPath -Recurse -Force

    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue

    Write-ColorOutput "Unblocking downloaded files..." -Color White
    Get-ChildItem -Path $installPath -Recurse -File | Unblock-File -ErrorAction SilentlyContinue

    # Record the distribution source so in-app update checks use this xscp.
    @{ BaseUrl = $BaseUrl; InstalledFrom = 'xscp'; Installed = (Get-Date).ToString('s') } |
        ConvertTo-Json | Set-Content -Path (Join-Path $installPath 'distribution.json') -Encoding ASCII -Force

    Write-ColorOutput "Download complete!" -Color Green
}
catch {
    Write-ColorOutput "ERROR: Toolbox install failed (distribution: $BaseUrl)" -Color Red
    Write-ColorOutput $_.Exception.Message -Color Red
    Write-Host ""
    Write-Host "Is this machine on the site LAN (or the VPN) where the xscp lives?" -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

Write-Host ""
Write-ColorOutput "Installation complete!" -Color Green
Write-Host ""
Write-ColorOutput "Toolbox installed to: $installPath" -Color Cyan
Write-Host ""

try {
    $startMenuPath = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
    $shortcutPath = Join-Path $startMenuPath 'Windows Management Toolbox.lnk'
    $WScriptShell = New-Object -ComObject WScript.Shell
    $shortcut = $WScriptShell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = 'powershell.exe'
    $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$installPath\WinToolbox.ps1`""
    $shortcut.WorkingDirectory = $installPath
    $shortcut.Description = 'Windows Management Toolbox - System maintenance and configuration tool'
    $shortcut.Save()
    Write-ColorOutput "Start Menu shortcut created" -Color Green
    Write-Host ""
}
catch { }

Write-Host "Would you like to run the toolbox now? [Y/n]: " -NoNewline -ForegroundColor Yellow
$response = Read-Host

if ($response -eq '' -or $response -match '^[Yy]') {
    Write-Host ""
    Write-ColorOutput "Launching Windows Management Toolbox..." -Color Cyan
    Write-Host ""
    Start-Sleep -Seconds 1
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$installPath\WinToolbox.ps1`"" -WorkingDirectory $installPath
}
else {
    Write-Host ""
    Write-ColorOutput "To run the toolbox later, use:" -Color Cyan
    Write-Host ""
    Write-Host "  cd $installPath" -ForegroundColor White
    Write-Host "  .\WinToolbox.ps1" -ForegroundColor White
    Write-Host ""
    Write-Host "Or search for 'Windows Management Toolbox' in Start Menu" -ForegroundColor Gray
    Write-Host ""
}
