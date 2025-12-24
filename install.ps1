<#
.SYNOPSIS
    Windows Management Toolbox - Bootstrap Installer

.DESCRIPTION
    One-liner installer for Windows Management Toolbox.

    Usage:
        iex (irm https://raw.githubusercontent.com/GonzFC/WinSrvManagementScripts/main/install.ps1)

    Or:
        irm https://raw.githubusercontent.com/GonzFC/WinSrvManagementScripts/main/install.ps1 | iex

.NOTES
    Inspired by Chris Titus Tech's Windows Utility
    Automatically elevates to Administrator if needed
#>

$ErrorActionPreference = 'Stop'

# Colors
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = 'White'
    )
    Write-Host $Message -ForegroundColor $Color
}

# Banner
Clear-Host
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Windows Management Toolbox" -ForegroundColor Cyan
Write-Host " Bootstrap Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-ColorOutput "Administrator privileges required." -Color Yellow
    Write-ColorOutput "Relaunching as Administrator..." -Color Yellow
    Write-Host ""

    try {
        # Re-download and execute as admin
        $scriptContent = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/GonzFC/WinSrvManagementScripts/main/install.ps1' -UseBasicParsing
        $encodedScript = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($scriptContent))

        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedScript"
        exit 0
    }
    catch {
        Write-ColorOutput "Failed to elevate. Please run PowerShell as Administrator manually." -Color Red
        Write-Host ""
        Write-Host "Then run:" -ForegroundColor Gray
        Write-Host "  iex (irm https://raw.githubusercontent.com/GonzFC/WinSrvManagementScripts/main/install.ps1)" -ForegroundColor White
        Write-Host ""
        pause
        exit 1
    }
}

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-ColorOutput "ERROR: PowerShell 5.1 or higher is required." -Color Red
    Write-ColorOutput "Current version: $($PSVersionTable.PSVersion)" -Color Yellow
    Write-Host ""
    Write-ColorOutput "Please upgrade PowerShell and try again." -Color Yellow
    Write-Host ""
    pause
    exit 1
}

Write-ColorOutput "Running as Administrator" -Color Green
Write-ColorOutput "PowerShell Version: $($PSVersionTable.PSVersion)" -Color Green
Write-Host ""

# Enable TLS 1.2
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
catch {
    Write-ColorOutput "Warning: Could not enable TLS 1.2" -Color Yellow
}

# Determine installation directory
$installPath = Join-Path $env:ProgramData 'WinToolbox'

Write-ColorOutput "Installation directory: $installPath" -Color Cyan
Write-Host ""

# Check if Git is available
$gitAvailable = $null -ne (Get-Command git -ErrorAction SilentlyContinue)

if ($gitAvailable) {
    Write-ColorOutput "Git detected - using git clone for installation" -Color Green

    try {
        # Remove existing directory if it exists
        if (Test-Path $installPath) {
            Write-ColorOutput "Removing existing installation..." -Color Yellow
            Remove-Item -Path $installPath -Recurse -Force -ErrorAction Stop
        }

        # Clone repository
        Write-ColorOutput "Cloning repository..." -Color Cyan
        git clone --quiet https://github.com/GonzFC/WinSrvManagementScripts.git $installPath

        # Unblock all files (removes Zone.Identifier that blocks execution)
        Write-ColorOutput "Unblocking files..." -Color White
        Get-ChildItem -Path $installPath -Recurse -File | Unblock-File -ErrorAction SilentlyContinue

        Write-ColorOutput "Repository cloned successfully!" -Color Green
    }
    catch {
        Write-ColorOutput "Git clone failed: $($_.Exception.Message)" -Color Red
        Write-ColorOutput "Falling back to ZIP download..." -Color Yellow
        $gitAvailable = $false
    }
}

if (-not $gitAvailable) {
    Write-ColorOutput "Downloading toolbox (ZIP method)..." -Color Cyan

    try {
        $zipUrl = 'https://github.com/GonzFC/WinSrvManagementScripts/archive/refs/heads/main.zip'
        $zipPath = Join-Path $env:TEMP 'WinToolbox.zip'
        $extractPath = Join-Path $env:TEMP 'WinToolbox_Extract'

        # Download
        Write-ColorOutput "Downloading from GitHub..." -Color White
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing

        # Extract
        Write-ColorOutput "Extracting files..." -Color White
        if (Test-Path $extractPath) {
            Remove-Item -Path $extractPath -Recurse -Force
        }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractPath)

        # Move to final location
        $extractedFolder = Get-ChildItem $extractPath -Directory | Select-Object -First 1

        if (Test-Path $installPath) {
            Remove-Item -Path $installPath -Recurse -Force
        }

        Move-Item -Path $extractedFolder.FullName -Destination $installPath

        # Cleanup
        Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue

        # Unblock all files (removes Zone.Identifier that blocks execution)
        Write-ColorOutput "Unblocking downloaded files..." -Color White
        Get-ChildItem -Path $installPath -Recurse -File | Unblock-File -ErrorAction SilentlyContinue

        Write-ColorOutput "Download complete!" -Color Green
    }
    catch {
        Write-ColorOutput "ERROR: Failed to download toolbox" -Color Red
        Write-ColorOutput $_.Exception.Message -Color Red
        Write-Host ""
        pause
        exit 1
    }
}

Write-Host ""
Write-ColorOutput "Installation complete!" -Color Green
Write-Host ""
Write-ColorOutput "Toolbox installed to: $installPath" -Color Cyan
Write-Host ""

# Create shortcut in Start Menu (optional)
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
catch {
    # Not critical, just skip
}

# Offer to run now
Write-Host "Would you like to run the toolbox now? [Y/n]: " -NoNewline -ForegroundColor Yellow
$response = Read-Host

if ($response -eq '' -or $response -match '^[Yy]') {
    Write-Host ""
    Write-ColorOutput "Launching Windows Management Toolbox..." -Color Cyan
    Write-Host ""
    Start-Sleep -Seconds 1

    # Launch the toolbox in a new PowerShell session
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
