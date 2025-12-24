<#
.SYNOPSIS
    Common functions and utilities for Windows Toolbox

.DESCRIPTION
    Shared functions for admin checks, logging, OS detection, and common utilities
#>

# Global variables
$script:LogDirectory = 'C:\VLABS\Maintenance'
$script:LogFile = Join-Path $script:LogDirectory "WinToolbox_$(Get-Date -Format 'yyyy-MM').log"

#region Logging Functions

<#
.SYNOPSIS
    Initializes the logging system
#>
function Initialize-Logging {
    [CmdletBinding()]
    param()

    try {
        if (-not (Test-Path $script:LogDirectory)) {
            New-Item -ItemType Directory -Path $script:LogDirectory -Force | Out-Null
        }

        Write-LogMessage "=== Windows Toolbox Session Started ===" -Level Info
        Write-LogMessage "Computer: $env:COMPUTERNAME" -Level Info
        Write-LogMessage "User: $env:USERNAME" -Level Info
        Write-LogMessage "OS: $(Get-OSInfo)" -Level Info
    }
    catch {
        Write-Warning "Could not initialize logging: $_"
    }
}

<#
.SYNOPSIS
    Writes a message to the log file and console
#>
function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info',

        [Parameter(Mandatory = $false)]
        [string]$Component = 'General'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] [$Component] $Message"

    # Write to log file
    try {
        Add-Content -Path $script:LogFile -Value $logEntry -ErrorAction SilentlyContinue
    }
    catch {
        # Silently fail if logging doesn't work
    }

    # Write to console with color
    $color = switch ($Level) {
        'Info'    { 'White' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
        default   { 'White' }
    }

    Write-Host $Message -ForegroundColor $color
}

#endregion

#region Admin and Prerequisites

<#
.SYNOPSIS
    Checks if running as Administrator
#>
function Test-Administrator {
    [CmdletBinding()]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

<#
.SYNOPSIS
    Ensures script is running as Administrator
#>
function Assert-Administrator {
    [CmdletBinding()]
    param(
        [string]$ErrorMessage = "This operation requires Administrator privileges."
    )

    if (-not (Test-Administrator)) {
        Write-LogMessage $ErrorMessage -Level Error -Component 'Admin'
        throw $ErrorMessage
    }
}

<#
.SYNOPSIS
    Checks PowerShell version requirements
#>
function Test-PowerShellVersion {
    [CmdletBinding()]
    param(
        [int]$MinimumVersion = 5
    )

    return $PSVersionTable.PSVersion.Major -ge $MinimumVersion
}

<#
.SYNOPSIS
    Enables TLS 1.2 for current session
#>
function Enable-Tls12 {
    [CmdletBinding()]
    param()

    try {
        [Net.ServicePointManager]::SecurityProtocol = `
            [Net.ServicePointManager]::SecurityProtocol -bor `
            [Net.SecurityProtocolType]::Tls12
        Write-LogMessage "TLS 1.2 enabled for this session" -Level Info -Component 'TLS'
    }
    catch {
        Write-LogMessage "Could not enable TLS 1.2: $_" -Level Warning -Component 'TLS'
    }
}

#endregion

#region OS Detection

<#
.SYNOPSIS
    Gets OS information
#>
function Get-OSInfo {
    [CmdletBinding()]
    param()

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        return "$($os.Caption) (Build $($os.BuildNumber))"
    }
    catch {
        return "Unknown OS"
    }
}

<#
.SYNOPSIS
    Checks if OS is Windows Server
#>
function Test-WindowsServer {
    [CmdletBinding()]
    param()

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        return $os.ProductType -ne 1  # 1 = Workstation, 2 = Domain Controller, 3 = Server
    }
    catch {
        return $false
    }
}

<#
.SYNOPSIS
    Checks if OS is Windows Client (10/11)
#>
function Test-WindowsClient {
    [CmdletBinding()]
    param()

    return -not (Test-WindowsServer)
}

#endregion

#region UI Helpers

<#
.SYNOPSIS
    Shows a confirmation prompt
#>
function Show-Confirmation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$Title = "Confirm",

        [Parameter(Mandatory = $false)]
        [switch]$DefaultYes
    )

    $prompt = if ($DefaultYes) { " [Y/n]" } else { " [y/N]" }
    Write-Host "$Message$prompt" -ForegroundColor Yellow -NoNewline
    $response = Read-Host " "

    if ($DefaultYes) {
        return ($response -eq '' -or $response -match '^[Yy]')
    }
    else {
        return ($response -match '^[Yy]')
    }
}

<#
.SYNOPSIS
    Shows a menu and returns the selected option
#>
function Show-Menu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary]$Options,

        [Parameter(Mandatory = $false)]
        [switch]$AllowBack
    )

    Clear-Host
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""

    foreach ($key in $Options.Keys) {
        Write-Host "  [$key] $($Options[$key])" -ForegroundColor White
    }

    if ($AllowBack) {
        Write-Host ""
        Write-Host "  [B] Back to Main Menu" -ForegroundColor Gray
    }

    Write-Host "  [Q] Quit" -ForegroundColor Gray
    Write-Host ""
    Write-Host -NoNewline "Select an option: " -ForegroundColor Yellow

    $selection = Read-Host
    return $selection.ToUpper()
}

<#
.SYNOPSIS
    Pauses execution until user presses a key
#>
function Invoke-Pause {
    [CmdletBinding()]
    param(
        [string]$Message = "Press any key to continue..."
    )

    Write-Host ""
    Write-Host $Message -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

#endregion

#region Disk and File Helpers

<#
.SYNOPSIS
    Gets free space in GB for a drive
#>
function Get-FreeSpaceGB {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$DriveLetter = 'C'
    )

    try {
        $drive = Get-PSDrive -Name $DriveLetter -ErrorAction Stop
        return [math]::Round($drive.Free / 1GB, 2)
    }
    catch {
        return 0
    }
}

<#
.SYNOPSIS
    Gets directory size in GB
#>
function Get-DirectorySizeGB {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        return 0
    }

    try {
        $size = Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty Sum

        if ($null -eq $size) {
            return 0
        }

        return [math]::Round($size / 1GB, 2)
    }
    catch {
        return 0
    }
}

<#
.SYNOPSIS
    Formats bytes to human-readable string
#>
function Format-ByteSize {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [double]$Bytes
    )

    $sizes = 'B', 'KB', 'MB', 'GB', 'TB'
    $order = 0

    while ($Bytes -ge 1024 -and $order -lt $sizes.Length - 1) {
        $Bytes = $Bytes / 1024
        $order++
    }

    return "{0:N2} {1}" -f $Bytes, $sizes[$order]
}

#endregion

#region Service Helpers

<#
.SYNOPSIS
    Safely stops a service
#>
function Stop-ServiceSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 30
    )

    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop

        if ($service.Status -eq 'Running') {
            Write-LogMessage "Stopping service: $ServiceName" -Level Info -Component 'Service'
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds($TimeoutSeconds))
            return $true
        }

        return $true
    }
    catch {
        Write-LogMessage "Failed to stop service ${ServiceName}: ${_}" -Level Warning -Component 'Service'
        return $false
    }
}

<#
.SYNOPSIS
    Safely starts a service
#>
function Start-ServiceSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 30
    )

    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop

        if ($service.Status -ne 'Running') {
            Write-LogMessage "Starting service: $ServiceName" -Level Info -Component 'Service'
            Start-Service -Name $ServiceName -ErrorAction Stop
            $service.WaitForStatus('Running', [TimeSpan]::FromSeconds($TimeoutSeconds))
            return $true
        }

        return $true
    }
    catch {
        Write-LogMessage "Failed to start service ${ServiceName}: ${_}" -Level Warning -Component 'Service'
        return $false
    }
}

#endregion

# Export module members (only used when loaded with Import-Module, not needed for dot-sourcing)
# Export-ModuleMember -Function @(
#     'Initialize-Logging',
#     'Write-LogMessage',
#     'Test-Administrator',
#     'Assert-Administrator',
#     'Test-PowerShellVersion',
#     'Enable-Tls12',
#     'Get-OSInfo',
#     'Test-WindowsServer',
#     'Test-WindowsClient',
#     'Show-Confirmation',
#     'Show-Menu',
#     'Invoke-Pause',
#     'Get-FreeSpaceGB',
#     'Get-DirectorySizeGB',
#     'Format-ByteSize',
#     'Stop-ServiceSafe',
#     'Start-ServiceSafe'
# )
