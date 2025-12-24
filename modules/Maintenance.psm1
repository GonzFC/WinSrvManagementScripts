<#
.SYNOPSIS
    Maintenance functions for Windows Toolbox

.DESCRIPTION
    Functions for system maintenance tasks (Desktop Info widget, TLS upgrade, XenServer Tools)
#>

# Note: Common functions are loaded by WinToolbox.ps1 before this module
# No need to import Common.psm1 here when using Invoke-Expression

#region Desktop Info Widget

<#
.SYNOPSIS
    Installs/updates Desktop Info widget
#>
function Install-DesktopInfoWidget {
    [CmdletBinding()]
    param()

    Write-LogMessage "Installing Desktop Info Widget..." -Level Info -Component 'DesktopInfo'

    $installRoot = Join-Path $env:ProgramData 'DesktopInfoWidget'

    try {
        if (-not (Test-Path $installRoot)) {
            New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
        }
    }
    catch {
        $installRoot = Join-Path $env:LOCALAPPDATA 'DesktopInfoWidget'
        if (-not (Test-Path $installRoot)) {
            New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
        }
    }

    $widgetScript = Join-Path $installRoot 'DesktopInfoWidget.ps1'
    $taskName = 'Desktop Info Widget'

    # Read the widget script content from the original file
    $originalScript = Join-Path $Global:ToolboxRoot 'WinSrv - Desktop Info.ps1'

    if (Test-Path $originalScript) {
        $widgetContent = Get-Content $originalScript -Raw

        # Extract just the runtime script portion (everything after the installer part)
        $runtimeStart = $widgetContent.IndexOf('$widgetPs1 = @''')
        if ($runtimeStart -gt 0) {
            $runtimeEnd = $widgetContent.IndexOf('''@', $runtimeStart) + 2
            $widgetPs1Decl = $widgetContent.Substring($runtimeStart, $runtimeEnd - $runtimeStart)

            # Execute the declaration to get the actual widget script
            Invoke-Expression $widgetPs1Decl

            # Write runtime script
            $widgetPs1 | Out-File -FilePath $widgetScript -Encoding UTF8 -Force
        }
        else {
            throw "Could not extract widget runtime script"
        }
    }
    else {
        throw "Original Desktop Info script not found at $originalScript"
    }

    # Configure autostart
    $autostartMethod = Set-WidgetAutostart -TaskName $taskName -ScriptPath $widgetScript

    # Restart existing instances
    try {
        $needle = [Regex]::Escape($widgetScript)
        $processes = Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -and $_.CommandLine -match $needle }

        if ($processes) {
            $processes | ForEach-Object {
                try {
                    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                }
                catch { }
            }
            Start-Sleep -Milliseconds 300
        }
    }
    catch { }

    # Launch widget
    Start-Process -FilePath "powershell.exe" -ArgumentList `
        "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$widgetScript`"" -WindowStyle Hidden

    Write-LogMessage "Desktop Info Widget installed successfully" -Level Success -Component 'DesktopInfo'

    Write-Host ""
    Write-Host "Desktop Info Widget installed!" -ForegroundColor Green
    Write-Host "  Location: $installRoot" -ForegroundColor White
    Write-Host "  Autostart: $autostartMethod" -ForegroundColor White
    Write-Host "  Shows: Network info, Windows Server Backup status" -ForegroundColor White
    Write-Host "  Control: System tray icon (right-click)" -ForegroundColor White
    Write-Host ""
}

function Set-WidgetAutostart {
    param(
        [string]$TaskName,
        [string]$ScriptPath
    )

    $created = $false

    try {
        # Remove existing task
        try {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        catch { }

        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument `
            "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`""

        $trigger = New-ScheduledTaskTrigger -AtLogOn

        try {
            $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
                -LogonType Interactive -RunLevel LeastPrivilege
        }
        catch {
            $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
                -LogonType InteractiveOrPassword -RunLevel LeastPrivilege
        }

        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal | Out-Null
        $created = $true
    }
    catch {
        $created = $false
    }

    # Fallback to registry Run key
    if (-not $created) {
        $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        New-Item -Path $runKey -Force | Out-Null
        New-ItemProperty -Path $runKey -Name 'DesktopInfoWidget' -PropertyType String -Force `
            -Value "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`"" | Out-Null
        return "Registry Run Key"
    }
    else {
        return "Scheduled Task"
    }
}

#endregion

#region TLS and PowerShell Upgrade

<#
.SYNOPSIS
    Upgrades TLS, .NET Framework, and PowerShell for legacy systems
#>
function Invoke-TLSAndPowerShellUpgrade {
    [CmdletBinding()]
    param(
        [switch]$UpdateRoots
    )

    Write-LogMessage "Starting TLS and PowerShell upgrade..." -Level Info -Component 'TLSUpgrade'

    # Enable TLS 1.2 for current session
    Enable-Tls12

    $workDir = Join-Path $env:TEMP "PS-TLS-Upgrade"
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null

    # Get OS info
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $osVersion = [Version]$os.Version
    $is64Bit = [Environment]::Is64BitOperatingSystem

    Write-LogMessage "OS: $($os.Caption) ($osVersion)" -Level Info -Component 'TLSUpgrade'

    # Install .NET Framework 4.8
    Install-DotNet48

    # Enable strong crypto
    Enable-DotNetStrongCrypto

    # Enable SChannel TLS 1.2
    Enable-SChannelTLS12

    # Set default secure protocols
    Set-DefaultSecureProtocols -OSVersion $osVersion

    # Install WMF 5.1
    Install-WindowsManagementFramework51 -OSVersion $osVersion -Is64Bit $is64Bit

    # Update root CAs if requested
    if ($UpdateRoots) {
        Update-RootCertificates -WorkDir $workDir
    }

    # Test TLS
    Test-TLSConnection

    Write-LogMessage "TLS and PowerShell upgrade complete. Reboot may be required." -Level Success -Component 'TLSUpgrade'

    Write-Host ""
    Write-Host "TLS and PowerShell upgrade complete!" -ForegroundColor Green
    Write-Host "  .NET Framework 4.8: Installed/Updated" -ForegroundColor White
    Write-Host "  TLS 1.2: Enabled" -ForegroundColor White
    Write-Host "  PowerShell 5.1: Installed/Updated (if applicable)" -ForegroundColor White
    Write-Host ""
    Write-Host "A reboot may be required to complete the installation." -ForegroundColor Yellow
    Write-Host ""

    # Cleanup
    Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

function Install-DotNet48 {
    $release = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' `
        -Name Release -ErrorAction SilentlyContinue).Release

    if ($release -ge 528040) {
        Write-LogMessage ".NET Framework 4.8 already installed ($release)" -Level Info -Component 'TLSUpgrade'
        return
    }

    $net48Url = 'https://download.microsoft.com/download/f/3/a/f3a6af84-da23-40a5-8d1c-49cc10c8e76f/NDP48-x86-x64-AllOS-ENU.exe'
    $netPath = Join-Path $env:TEMP 'NDP48-x86-x64-AllOS-ENU.exe'

    Write-LogMessage "Downloading .NET Framework 4.8..." -Level Info -Component 'TLSUpgrade'
    (New-Object System.Net.WebClient).DownloadFile($net48Url, $netPath)

    Write-LogMessage "Installing .NET Framework 4.8 (this may take several minutes)..." -Level Info -Component 'TLSUpgrade'
    $process = Start-Process -FilePath $netPath -ArgumentList '/quiet /norestart' -PassThru -Wait

    if ($process.ExitCode -ne 0) {
        Write-LogMessage ".NET 4.8 installer exit code: $($process.ExitCode)" -Level Warning -Component 'TLSUpgrade'
    }
}

function Enable-DotNetStrongCrypto {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
    )

    foreach ($path in $paths) {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        New-ItemProperty -Path $path -Name 'SchUseStrongCrypto' -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $path -Name 'SystemDefaultTlsVersions' -Value 1 -PropertyType DWord -Force | Out-Null
    }

    Write-LogMessage "Enabled .NET strong crypto" -Level Success -Component 'TLSUpgrade'
}

function Enable-SChannelTLS12 {
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2'

    foreach ($role in 'Client', 'Server') {
        $key = Join-Path $base $role
        if (-not (Test-Path $key)) {
            New-Item -Path $key -Force | Out-Null
        }
        New-ItemProperty -Path $key -Name 'Enabled' -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $key -Name 'DisabledByDefault' -Value 0 -PropertyType DWord -Force | Out-Null
    }

    Write-LogMessage "Enabled SChannel TLS 1.2" -Level Success -Component 'TLSUpgrade'
}

function Set-DefaultSecureProtocols {
    param([Version]$OSVersion)

    if ($OSVersion.Major -eq 6) {
        $paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
        )

        foreach ($path in $paths) {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
            New-ItemProperty -Path $path -Name 'DefaultSecureProtocols' -Value 0x00000A00 -PropertyType DWord -Force | Out-Null
        }

        Write-LogMessage "Set WinHTTP default secure protocols" -Level Success -Component 'TLSUpgrade'
    }
}

function Install-WindowsManagementFramework51 {
    param([Version]$OSVersion, [bool]$Is64Bit)

    if ($PSVersionTable.PSVersion -ge [Version]'5.1') {
        Write-LogMessage "PowerShell $($PSVersionTable.PSVersion) already present" -Level Info -Component 'TLSUpgrade'
        return
    }

    $links = @{
        '6.1_x86' = 'https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7-KB3191566-x86.zip'
        '6.1_x64' = 'https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7AndW2K8R2-KB3191566-x64.zip'
        '6.2_x64' = 'https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/W2K12-KB3191565-x64.msu'
        '6.3_x86' = 'https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win8.1-KB3191564-x86.msu'
        '6.3_x64' = 'https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win8.1AndW2K12R2-KB3191564-x64.msu'
    }

    $key = $null
    if ($OSVersion.Major -eq 6 -and $OSVersion.Minor -eq 1) {
        $key = if ($Is64Bit) { '6.1_x64' } else { '6.1_x86' }
    }
    elseif ($OSVersion.Major -eq 6 -and $OSVersion.Minor -eq 2) {
        $key = '6.2_x64'
    }
    elseif ($OSVersion.Major -eq 6 -and $OSVersion.Minor -eq 3) {
        $key = if ($Is64Bit) { '6.3_x64' } else { '6.3_x86' }
    }

    if (-not $key) {
        Write-LogMessage "OS not in WMF 5.1 target list, skipping" -Level Info -Component 'TLSUpgrade'
        return
    }

    $url = $links[$key]
    $downloadPath = Join-Path $env:TEMP (Split-Path $url -Leaf)

    Write-LogMessage "Downloading WMF 5.1..." -Level Info -Component 'TLSUpgrade'
    (New-Object System.Net.WebClient).DownloadFile($url, $downloadPath)

    if ($downloadPath.ToLower().EndsWith('.zip')) {
        $extractPath = Join-Path $env:TEMP "wmf51"
        New-Item -ItemType Directory -Path $extractPath -Force | Out-Null

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($downloadPath, $extractPath)

        $msu = Get-ChildItem $extractPath -Filter *.msu -Recurse | Select-Object -First 1
    }
    else {
        $msu = Get-Item $downloadPath
    }

    Write-LogMessage "Installing WMF 5.1 (this may take several minutes)..." -Level Info -Component 'TLSUpgrade'
    $process = Start-Process -FilePath "wusa.exe" -ArgumentList "`"$($msu.FullName)`" /quiet /norestart" -PassThru -Wait

    if ($process.ExitCode -in 0, 3010) {
        Write-LogMessage "WMF 5.1 installation completed (reboot may be required)" -Level Success -Component 'TLSUpgrade'
    }
    else {
        Write-LogMessage "WMF installer exit code: $($process.ExitCode)" -Level Warning -Component 'TLSUpgrade'
    }
}

function Update-RootCertificates {
    param([string]$WorkDir)

    $sstPath = Join-Path $WorkDir 'roots.sst'

    Write-LogMessage "Generating latest root certificate list..." -Level Info -Component 'TLSUpgrade'
    certutil.exe -generateSSTFromWU $sstPath | Out-Null

    Write-LogMessage "Importing root certificates..." -Level Info -Component 'TLSUpgrade'
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $collection.Import($sstPath)
    $store.AddRange($collection)
    $store.Close()

    Write-LogMessage "Root certificates refreshed" -Level Success -Component 'TLSUpgrade'
}

function Test-TLSConnection {
    Write-LogMessage "Testing TLS 1.2 connection..." -Level Info -Component 'TLSUpgrade'

    try {
        $response = Invoke-WebRequest 'https://www.howsmyssl.com/a/check' -UseBasicParsing -TimeoutSec 20
        $json = $response.Content | ConvertFrom-Json
        Write-LogMessage "TLS version reported by server: $($json.tls_version)" -Level Success -Component 'TLSUpgrade'
    }
    catch {
        Write-LogMessage "TLS test failed: $_" -Level Warning -Component 'TLSUpgrade'
    }
}

#endregion

#region XenServer / XCP-ng Tools Installation

<#
.SYNOPSIS
    Installs XCP-ng or XenServer/Citrix Hypervisor VM Tools
#>
function Install-XenServerTools {
    [CmdletBinding()]
    param(
        [switch]$NoReboot,
        [switch]$DisableWUDrivers
    )

    Write-LogMessage "Starting virtualization tools installer..." -Level Info -Component 'VMTools'

    Enable-Tls12

    # Get OS information and check XCP-ng compatibility
    $osInfo = Get-OSVersionInfo
    $xcpngCompatible = Test-XCPngCompatibility -OSInfo $osInfo

    # Interactive menu
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " Virtualization Guest Tools" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "System Information:" -ForegroundColor Yellow
    Write-Host "  OS: $($osInfo.Caption)" -ForegroundColor White
    Write-Host "  Version: $($osInfo.Version) (Build $($osInfo.Build))" -ForegroundColor White
    Write-Host ""

    Write-Host "Available Options:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [1] XCP-ng Windows PV Tools (v9.1.100)" -ForegroundColor White
    Write-Host "      - Latest stable release with signed drivers" -ForegroundColor Gray
    Write-Host "      - Improved performance for XCP-ng hosts" -ForegroundColor Gray
    Write-Host "      - Requires: Windows 10 1607+ / Server 2016+" -ForegroundColor Gray

    if (-not $xcpngCompatible) {
        Write-Host "      - NOT COMPATIBLE WITH THIS OS VERSION" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "  [2] XenServer/Citrix Hypervisor VM Tools" -ForegroundColor White
    Write-Host "      - Official Citrix management agent (v9.4.1+)" -ForegroundColor Gray
    Write-Host "      - Compatible with older Windows versions" -ForegroundColor Gray
    Write-Host "      - Stable and widely deployed" -ForegroundColor Gray
    Write-Host ""

    if (-not $xcpngCompatible) {
        Write-Host "Recommendation: Option 2 (XenServer) - XCP-ng tools require newer OS" -ForegroundColor Yellow
    } else {
        Write-Host "Recommendation: Option 1 (XCP-ng) if running on XCP-ng host" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host -NoNewline "Select option [1 or 2]: " -ForegroundColor Cyan
    $choice = Read-Host

    if ($choice -ne '1' -and $choice -ne '2') {
        Write-LogMessage "Invalid selection: $choice" -Level Error -Component 'VMTools'
        throw "Invalid selection. Please select 1 or 2."
    }

    if ($choice -eq '1' -and -not $xcpngCompatible) {
        Write-LogMessage "XCP-ng tools not compatible with OS version: $($osInfo.Caption)" -Level Error -Component 'VMTools'
        Write-Host ""
        Write-Host "ERROR: XCP-ng tools require Windows 10 1607 / Server 2016 or newer." -ForegroundColor Red
        Write-Host "Your system: $($osInfo.Caption) (Build $($osInfo.Build))" -ForegroundColor Yellow
        Write-Host ""
        throw "XCP-ng tools not compatible with this OS version"
    }

    Write-Host ""

    # Install based on choice
    if ($choice -eq '1') {
        Install-XCPngTools -NoReboot:$NoReboot -DisableWUDrivers:$DisableWUDrivers
    } else {
        Install-XenServerToolsLegacy -NoReboot:$NoReboot -DisableWUDrivers:$DisableWUDrivers
    }
}

function Get-OSVersionInfo {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $version = [Version]$os.Version
        return [PSCustomObject]@{
            Caption = $os.Caption
            Version = $version
            Build = $os.BuildNumber
        }
    } catch {
        return $null
    }
}

function Test-XCPngCompatibility {
    param($OSInfo)

    if (-not $OSInfo) { return $false }

    # XCP-ng requires Windows 10 1607 (build 14393) or Windows Server 2016 minimum
    if ($OSInfo.Version.Major -lt 10) {
        return $false
    }

    if ($OSInfo.Version.Major -eq 10 -and $OSInfo.Build -lt 14393) {
        return $false
    }

    return $true
}

function Install-XCPngTools {
    [CmdletBinding()]
    param(
        [switch]$NoReboot,
        [switch]$DisableWUDrivers
    )

    Write-LogMessage "Installing XCP-ng Windows PV Tools v9.1.100..." -Level Info -Component 'XCPng'

    $url = 'https://github.com/xcp-ng/win-pv-drivers/releases/download/v9.1.100/XenTools-x64.msi'
    $destination = Join-Path $env:TEMP 'XCPng-PV-Tools-x64.msi'

    try {
        Write-Host "Downloading XCP-ng PV Tools from GitHub..." -ForegroundColor White
        Write-LogMessage "Downloading from $url" -Level Info -Component 'XCPng'
        Invoke-WebRequest -Uri $url -OutFile $destination -UseBasicParsing

        Write-Host "Installing XCP-ng PV Tools (this may take a few minutes)..." -ForegroundColor White
        Write-LogMessage "Installing XCP-ng PV Tools..." -Level Info -Component 'XCPng'

        $logFile = Join-Path $env:TEMP 'xcpng-install.log'
        $msiArgs = @(
            '/i', $destination,
            '/qn',
            '/norestart',
            '/log', $logFile
        )

        $process = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru

        switch ($process.ExitCode) {
            0 {
                Write-LogMessage "Installation completed successfully" -Level Success -Component 'XCPng'
                Write-Host "Installation completed successfully." -ForegroundColor Green
            }
            3010 {
                Write-LogMessage "Installation completed, reboot required" -Level Info -Component 'XCPng'
                Write-Host "Installation completed; reboot required (exit code 3010)." -ForegroundColor Yellow
            }
            default {
                Write-LogMessage "msiexec exited with code $($process.ExitCode)" -Level Warning -Component 'XCPng'
                Write-Host "WARNING: msiexec exited with code $($process.ExitCode)" -ForegroundColor Yellow
                Write-Host "Check log: $logFile" -ForegroundColor Gray
            }
        }

        Write-Host ""
        Write-Host "XCP-ng Windows PV Tools installation complete!" -ForegroundColor Green
        Write-Host "  Version: 9.1.100" -ForegroundColor White
        Write-Host "  Drivers: Digitally signed, pinned" -ForegroundColor White
        Write-Host "  Install log: $logFile" -ForegroundColor White

    } catch {
        Write-LogMessage "XCP-ng installation failed: ${_}" -Level Error -Component 'XCPng'
        throw "XCP-ng installation failed: $_"
    }

    # Apply post-install settings
    Apply-VMToolsPostInstall -DisableWUDrivers:$DisableWUDrivers -NoReboot:$NoReboot
}

function Install-XenServerToolsLegacy {
    [CmdletBinding()]
    param(
        [switch]$NoReboot,
        [switch]$DisableWUDrivers
    )

    Write-LogMessage "Installing XenServer/Citrix Hypervisor VM Tools..." -Level Info -Component 'XenServer'

    # Discover latest MSI
    try {
        Write-Host "Fetching latest XenServer Tools download link..." -ForegroundColor White
        Write-LogMessage "Fetching latest XenServer Tools download link..." -Level Info -Component 'XenServer'
        $pageUrl = 'https://www.xenserver.com/downloads'
        $html = (Invoke-WebRequest -UseBasicParsing $pageUrl).Content
        $match = [regex]::Match($html,
            'https://downloads\.xenserver\.com/vm-tools-windows/[^"''/]+/managementagent-[^"''/]+-x64\.msi')

        if (-not $match.Success) {
            throw "No MSI link found"
        }

        $url = $match.Value
    }
    catch {
        Write-LogMessage "Falling back to known stable version 9.4.1" -Level Warning -Component 'XenServer'
        Write-Host "Falling back to known stable version 9.4.1" -ForegroundColor Yellow
        $url = 'https://downloads.xenserver.com/vm-tools-windows/9.4.1/managementagent-9.4.1-x64.msi'
    }

    $destination = Join-Path $env:TEMP 'XenServer-VM-Tools-x64.msi'

    try {
        Write-Host "Downloading: $url" -ForegroundColor White
        Write-LogMessage "Downloading from $url" -Level Info -Component 'XenServer'
        Invoke-WebRequest -Uri $url -OutFile $destination -UseBasicParsing

        Write-Host "Installing XenServer VM Tools (this may take a few minutes)..." -ForegroundColor White
        Write-LogMessage "Installing XenServer VM Tools..." -Level Info -Component 'XenServer'

        $msiArgs = @(
            '/i', $destination,
            '/qn',
            '/norestart',
            'ALLOWDRIVERINSTALL=YES',
            'ALLOWDRIVERUPDATE=NO',
            'ALLOWAUTOUPDATE=YES',
            'IDENTIFYAUTOUPDATE=NO'
        )

        $process = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru

        switch ($process.ExitCode) {
            0 {
                Write-LogMessage "Installation completed successfully" -Level Success -Component 'XenServer'
                Write-Host "Installation completed successfully." -ForegroundColor Green
            }
            3010 {
                Write-LogMessage "Installation completed, reboot required" -Level Info -Component 'XenServer'
                Write-Host "Installation completed; reboot required (exit code 3010)." -ForegroundColor Yellow
            }
            default {
                Write-LogMessage "msiexec exited with code $($process.ExitCode)" -Level Error -Component 'XenServer'
                throw "msiexec exited with code $($process.ExitCode)"
            }
        }

        Write-Host ""
        Write-Host "XenServer VM Tools installation complete!" -ForegroundColor Green
        Write-Host "  Drivers: Installed (pinned, no auto-update)" -ForegroundColor White
        Write-Host "  Management Agent: Auto-update enabled" -ForegroundColor White

    } catch {
        Write-LogMessage "XenServer installation failed: ${_}" -Level Error -Component 'XenServer'
        throw "XenServer installation failed: $_"
    }

    # Apply post-install settings
    Apply-VMToolsPostInstall -DisableWUDrivers:$DisableWUDrivers -NoReboot:$NoReboot
}

function Apply-VMToolsPostInstall {
    [CmdletBinding()]
    param(
        [switch]$DisableWUDrivers,
        [switch]$NoReboot
    )

    # Disable driver delivery from Windows Update if requested
    if ($DisableWUDrivers) {
        Write-Host ""
        Write-Host "Disabling driver delivery via Windows Update..." -ForegroundColor White
        Write-LogMessage "Disabling driver delivery via Windows Update..." -Level Info -Component 'VMTools'

        try {
            $wuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
            if (-not (Test-Path $wuKey)) {
                New-Item -Path $wuKey -Force | Out-Null
            }
            New-ItemProperty -Path $wuKey -Name 'ExcludeWUDriversInQualityUpdate' -PropertyType DWord -Value 1 -Force | Out-Null
            gpupdate /target:computer /force | Out-Null
            Write-Host "Windows Update driver delivery disabled." -ForegroundColor Green
            Write-LogMessage "Windows Update driver delivery disabled" -Level Success -Component 'VMTools'
        } catch {
            Write-Host "WARNING: Could not disable Windows Update drivers - $($_.Exception.Message)" -ForegroundColor Yellow
            Write-LogMessage "Could not disable Windows Update drivers: ${_}" -Level Warning -Component 'VMTools'
        }
    }

    # Reboot handling
    Write-Host ""
    if (-not $NoReboot) {
        Write-Host "Rebooting in 10 seconds to complete driver initialization..." -ForegroundColor Yellow
        Write-Host "Press Ctrl+C to cancel" -ForegroundColor Gray
        Write-LogMessage "Initiating reboot in 10 seconds..." -Level Info -Component 'VMTools'
        Start-Sleep -Seconds 10
        Restart-Computer -Force
    }
    else {
        Write-Host "Reboot required to complete driver initialization." -ForegroundColor Yellow
        Write-Host ""
        Write-LogMessage "Reboot required to complete installation" -Level Info -Component 'VMTools'
    }
}

#endregion

# Export functions (only used when loaded with Import-Module, not needed for dot-sourcing)
# Export-ModuleMember -Function @(
#     'Install-DesktopInfoWidget',
#     'Invoke-TLSAndPowerShellUpgrade',
#     'Install-XenServerTools'
# )
