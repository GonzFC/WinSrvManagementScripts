<#
.SYNOPSIS
    Remote Access functions for Windows Toolbox

.DESCRIPTION
    Functions for installing and configuring remote access solutions (Tailscale, Jump Desktop)
#>

# Import common functions
$commonModule = Join-Path $PSScriptRoot 'Common.psm1'
Import-Module $commonModule -Force

#region Tailscale Installation

<#
.SYNOPSIS
    Installs and configures Tailscale VPN
#>
function Install-Tailscale {
    [CmdletBinding()]
    param(
        [string]$AuthKey,
        [string]$LoginServer,
        [switch]$AcceptRoutes,
        [string]$AdvertiseRoutes,
        [switch]$AcceptDNS,
        [string]$Hostname,
        [string]$Operator
    )

    Write-LogMessage "Installing Tailscale..." -Level Info -Component 'Tailscale'

    Enable-Tls12

    # Detect architecture
    $arch = switch ($env:PROCESSOR_ARCHITECTURE.ToLower()) {
        'amd64' { 'amd64' }
        'arm64' { 'arm64' }
        'x86'   { 'x86' }
        default { 'amd64' }
    }

    # Get latest MSI
    try {
        Write-LogMessage "Fetching latest Tailscale package..." -Level Info -Component 'Tailscale'
        $indexUrl = 'https://pkgs.tailscale.com/stable/'
        $response = Invoke-WebRequest -Uri $indexUrl -UseBasicParsing
        $msiRegex = [regex]"tailscale-setup-(?<ver>\d+\.\d+\.\d+)-$([regex]::Escape($arch))\.msi"
        $matches = $msiRegex.Matches($response.Content) | Sort-Object { [version]$_.Groups['ver'].Value } -Descending

        if ($matches.Count -eq 0) {
            throw "No MSI found for architecture $arch"
        }

        $latestFile = $matches[0].Value
        $version = $matches[0].Groups['ver'].Value
        $msiUrl = "$($indexUrl.TrimEnd('/'))/$latestFile"

        Write-LogMessage "Latest version: $version" -Level Info -Component 'Tailscale'
    }
    catch {
        Write-LogMessage "Failed to fetch latest version, using fallback" -Level Warning -Component 'Tailscale'
        $msiUrl = 'https://downloads.tailscale.com/stable/tailscale-setup-latest-amd64.msi'
        $version = 'latest'
    }

    # Download
    $tempDir = Join-Path $env:TEMP "tailscale-installer"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    $msiPath = Join-Path $tempDir "tailscale-setup.msi"

    Write-LogMessage "Downloading from $msiUrl..." -Level Info -Component 'Tailscale'
    Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing

    # Install
    Write-LogMessage "Installing Tailscale $version..." -Level Info -Component 'Tailscale'
    $msiArgs = "/i `"$msiPath`" /qn /norestart"
    $process = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru

    if ($process.ExitCode -ne 0) {
        throw "MSI installer returned exit code $($process.ExitCode)"
    }

    # Configure service
    Write-LogMessage "Configuring Tailscale service..." -Level Info -Component 'Tailscale'
    Set-Service -Name 'Tailscale' -StartupType Automatic
    $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tailscale'
    New-ItemProperty -Path $svcKey -Name 'DelayedAutoStart' -PropertyType DWord -Value 1 -Force | Out-Null

    # Service recovery
    & sc.exe failure Tailscale reset=60 actions=restart/3000/restart/60000/restart/120000 | Out-Null
    & sc.exe failureflag Tailscale 1 | Out-Null

    # Start service
    if ((Get-Service Tailscale).Status -ne 'Running') {
        Start-Service Tailscale
    }

    # Find tailscale.exe
    $tailscaleExe = Get-TailscaleExecutable

    # Build up arguments
    $upArgs = Build-TailscaleUpArgs -AuthKey $AuthKey -LoginServer $LoginServer `
        -AcceptRoutes:$AcceptRoutes -AdvertiseRoutes $AdvertiseRoutes `
        -AcceptDNS:$AcceptDNS -Hostname $Hostname -Operator $Operator

    # Create startup task
    Create-TailscaleStartupTask -TailscaleExe $tailscaleExe -UpArgs $upArgs

    # Run up now if AuthKey provided
    if ($AuthKey) {
        Write-LogMessage "Connecting to Tailscale network..." -Level Info -Component 'Tailscale'
        & $tailscaleExe up $upArgs
        if ($LASTEXITCODE -ne 0) {
            Write-LogMessage "Tailscale up returned code $LASTEXITCODE" -Level Warning -Component 'Tailscale'
        }
    }
    else {
        Write-LogMessage "No auth key provided. Run 'tailscale up' manually or provide -AuthKey" -Level Warning -Component 'Tailscale'
    }

    Write-LogMessage "Tailscale $version installed successfully" -Level Success -Component 'Tailscale'
    Write-Host ""
    Write-Host "Tailscale installation complete!" -ForegroundColor Green
    Write-Host "  Version: $version" -ForegroundColor White
    Write-Host "  Service: Configured (Automatic + Recovery)" -ForegroundColor White
    Write-Host "  Startup Task: Created" -ForegroundColor White
    Write-Host "  Check status: tailscale status" -ForegroundColor White
    Write-Host ""

    # Cleanup
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

function Get-TailscaleExecutable {
    $candidates = @(
        'C:\Program Files\Tailscale\tailscale.exe',
        'C:\Program Files (x86)\Tailscale\tailscale.exe',
        'C:\Program Files\Tailscale IPN\tailscale.exe'
    )

    $candidates += Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' -Recurse `
        -Filter tailscale.exe -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName

    $found = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

    if (-not $found) {
        throw "Could not find tailscale.exe after installation"
    }

    return $found
}

function Build-TailscaleUpArgs {
    param(
        [string]$AuthKey,
        [string]$LoginServer,
        [switch]$AcceptRoutes,
        [string]$AdvertiseRoutes,
        [switch]$AcceptDNS,
        [string]$Hostname,
        [string]$Operator
    )

    $args = @('--unattended')

    if ($AuthKey) { $args += "--authkey=$AuthKey" }
    if ($LoginServer) { $args += "--login-server=$LoginServer" }
    if ($AcceptRoutes) { $args += "--accept-routes=true" }
    if ($AdvertiseRoutes) { $args += "--advertise-routes=$AdvertiseRoutes" }
    if ($AcceptDNS) { $args += "--accept-dns=true" } else { $args += "--accept-dns=false" }
    if ($Hostname) { $args += "--hostname=$Hostname" }
    if ($Operator) { $args += "--operator=$Operator" }

    return ($args | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -join ' '
}

function Create-TailscaleStartupTask {
    param(
        [string]$TailscaleExe,
        [string]$UpArgs
    )

    $taskName = 'Tailscale-EnsureUp-AtStartup'

    # Remove existing task
    $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }

    # Create script
    $scriptPath = "$env:ProgramData\Tailscale\EnsureUp.ps1"
    New-Item -ItemType Directory -Path (Split-Path $scriptPath) -Force | Out-Null

    $psScript = @"
try {
    if ((Get-Service Tailscale -ErrorAction Stop).Status -ne 'Running') {
        Start-Service Tailscale
    }
    Start-Sleep -Seconds 5
    & '$TailscaleExe' up $UpArgs 2>&1 | Out-Null
}
catch {
    try {
        New-Item -ItemType Directory -Path 'C:\ProgramData\Tailscale' -Force | Out-Null
    } catch {}
    Add-Content -Path 'C:\ProgramData\Tailscale\StartupTask.log' -Value "`$(Get-Date -f s) ERROR: `$(`$_.Exception.Message)"
}
"@

    Set-Content -Path $scriptPath -Value $psScript -Encoding UTF8

    # Register task
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument `
        "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

    $trigger = New-ScheduledTaskTrigger -AtStartup
    $trigger.Delay = 'PT60S'

    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable `
        -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 1)

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings | Out-Null
}

#endregion

#region Jump Desktop Connect Installation

<#
.SYNOPSIS
    Installs and configures Jump Desktop Connect
#>
function Install-JumpDesktopConnect {
    [CmdletBinding()]
    param()

    Write-LogMessage "Installing Jump Desktop Connect..." -Level Info -Component 'JumpDesktop'

    Enable-Tls12

    # Get connect code
    Write-Host ""
    $rawCode = Read-Host "Enter your 6-digit Jump Desktop Connect Code"
    if ([string]::IsNullOrWhiteSpace($rawCode)) {
        throw "Connect Code is required"
    }

    $connectCode = ($rawCode -replace '\s', '')
    if ($connectCode -notmatch '^\d{6}$' -and $connectCode.Length -lt 6) {
        Write-LogMessage "Code doesn't appear to be 6 digits; continuing (Jump also accepts longer codes)" -Level Warning -Component 'JumpDesktop'
    }

    # Download URLs
    $msiUrl = "https://jumpdesktop.com/downloads/connect/winmsi"
    $exeUrl = "https://jumpdesktop.com/downloads/connect/win"

    $tempDir = Join-Path $env:TEMP ("JumpConnect_" + [Guid]::NewGuid())
    New-Item -ItemType Directory -Path $tempDir | Out-Null

    $msiPath = Join-Path $tempDir "JumpDesktopConnect.msi"
    $exePath = Join-Path $tempDir "JumpDesktopConnect.exe"

    $computerName = $env:COMPUTERNAME
    $installed = $false

    # Try MSI first
    try {
        Write-LogMessage "Downloading MSI installer..." -Level Info -Component 'JumpDesktop'
        Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing

        Write-LogMessage "Installing Jump Desktop Connect (MSI)..." -Level Info -Component 'JumpDesktop'
        $msiArgs = "/i `"$msiPath`" /qn CONNECTCODE=$connectCode RDPENABLED=true"
        $process = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru

        if ($process.ExitCode -eq 0) {
            $installed = $true
        }
        else {
            Write-LogMessage "MSI returned code $($process.ExitCode), trying EXE..." -Level Warning -Component 'JumpDesktop'
        }
    }
    catch {
        Write-LogMessage "MSI installation failed: $_, trying EXE..." -Level Warning -Component 'JumpDesktop'
    }

    # Try EXE if MSI failed
    if (-not $installed) {
        Write-LogMessage "Downloading EXE installer..." -Level Info -Component 'JumpDesktop'
        Invoke-WebRequest -Uri $exeUrl -OutFile $exePath -UseBasicParsing

        Write-LogMessage "Installing Jump Desktop Connect (EXE)..." -Level Info -Component 'JumpDesktop'
        $exeArgs = "/qn CONNECTCODE=$connectCode RDPENABLED=true"
        $process = Start-Process -FilePath $exePath -ArgumentList $exeArgs -Wait -PassThru

        if ($process.ExitCode -ne 0) {
            throw "EXE installation failed with code $($process.ExitCode)"
        }
    }

    # Find JumpConnect.exe
    $connectPath = $null
    try {
        $connectPath = (Get-ItemProperty 'HKLM:\SOFTWARE\Jump Desktop\Connect\Shared' -ErrorAction Stop).ConnectPath
    }
    catch {
        Start-Sleep -Seconds 3
        try {
            $connectPath = (Get-ItemProperty 'HKLM:\SOFTWARE\Jump Desktop\Connect\Shared' -ErrorAction Stop).ConnectPath
        }
        catch { }
    }

    if (-not $connectPath -or -not (Test-Path $connectPath)) {
        throw "Could not find JumpConnect.exe after installation"
    }

    # Post-installation configuration
    Write-LogMessage "Configuring Jump Desktop Connect..." -Level Info -Component 'JumpDesktop'

    & $connectPath --serverconfig ComputerName="$computerName" | Out-Null
    & $connectPath --connectcode $connectCode | Out-Null

    Write-LogMessage "Jump Desktop Connect installed successfully" -Level Success -Component 'JumpDesktop'

    Write-Host ""
    Write-Host "Jump Desktop Connect installation complete!" -ForegroundColor Green
    Write-Host "  RDP: Enabled (tunneling)" -ForegroundColor White
    Write-Host "  Computer Name: $computerName" -ForegroundColor White
    Write-Host "  Connect Code: Applied" -ForegroundColor White
    Write-Host ""

    # Cleanup
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Install-Tailscale',
    'Install-JumpDesktopConnect'
)
