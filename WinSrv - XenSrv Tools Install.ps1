#requires -Version 4.0
<#
.SYNOPSIS
    Installs XenServer / Citrix Hypervisor VM Tools (Windows x64).

.DESCRIPTION
    - Fetches latest Management Agent MSI from xenserver.com.
    - Falls back to known stable (9.4.1) if scraping fails.
    - Installs silently with:
        • ALLOWDRIVERINSTALL=YES
        • ALLOWDRIVERUPDATE=NO  (drivers pinned, no auto-update)
        • ALLOWAUTOUPDATE=YES   (management agent can auto-update itself)
        • IDENTIFYAUTOUPDATE=NO
    - Reboots unless -NoReboot is provided.
    - Optional: block Windows Update from delivering drivers with -DisableWUDrivers.

.NOTES
    Compatible with Windows Server 2012 R2 / PowerShell 4.0.
#>

function Install-XenTools {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [switch]$NoReboot,
        [switch]$DisableWUDrivers
    )

    $ErrorActionPreference = 'Stop'

    # Must be elevated
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "Administrator privileges are required to install XenServer/Citrix VM Tools."
    }

    # Prefer TLS 1.2 for downloads (older boxes may default to TLS 1.0)
    try {
        [Net.ServicePointManager]::SecurityProtocol = `
            [Net.ServicePointManager]::SecurityProtocol -bor `
            [Net.SecurityProtocolType]::Tls12
    } catch { }

    # 1) Discover latest MSI URL (with fallback)
    $url = $null
    try {
        Write-Verbose "Fetching latest XenServer Tools download link..."
        $page = 'https://www.xenserver.com/downloads'
        $html = (Invoke-WebRequest -UseBasicParsing $page).Content
        $m = [regex]::Match(
            $html,
            'https://downloads\.xenserver\.com/vm-tools-windows/[^"''/]+/managementagent-[^"''/]+-x64\.msi'
        )
        if (-not $m.Success) { throw "No MSI link found on downloads page." }
        $url = $m.Value
    } catch {
        Write-Warning "Falling back to known stable 9.4.1 package."
        $url = 'https://downloads.xenserver.com/vm-tools-windows/9.4.1/managementagent-9.4.1-x64.msi'
    }

    # 2) Execute install (download+install+policy), protected by ShouldProcess
    if ($PSCmdlet.ShouldProcess("XenServer VM Tools", "Install from $url")) {
        # Download to %TEMP%
        $dst = Join-Path $env:TEMP 'XenServer-VM-Tools-x64.msi'
        Write-Verbose "Downloading: $url -> $dst"
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $dst

        try {
            # Install silently
            Write-Verbose "Installing XenServer/Citrix VM Tools..."
            $msiArgs = @(
                '/i', $dst,
                '/qn',
                '/norestart',
                'ALLOWDRIVERINSTALL=YES',
                'ALLOWDRIVERUPDATE=NO',
                'ALLOWAUTOUPDATE=YES',
                'IDENTIFYAUTOUPDATE=NO'
            )

            $proc = Start-Process -FilePath msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
            switch ($proc.ExitCode) {
                0    { Write-Verbose "MSI install completed successfully (0)." }
                3010 { Write-Verbose "MSI completed; reboot required (3010)." }
                default { throw "msiexec exited with code $($proc.ExitCode)." }
            }

            # Optional: block driver delivery from Windows Update
            if ($DisableWUDrivers) {
                Write-Verbose "Disabling driver delivery via Windows Update..."
                $wuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
                if (-not (Test-Path $wuKey)) { New-Item -Path $wuKey -Force | Out-Null }
                New-ItemProperty -Path $wuKey -Name 'ExcludeWUDriversInQualityUpdate' -PropertyType DWord -Value 1 -Force | Out-Null
                & gpupdate /target:computer /force | Out-Null
            }

            # Reboot (unless suppressed)
            if (-not $NoReboot) {
                Write-Verbose "Rebooting to complete driver initialization..."
                Restart-Computer -Force
            } else {
                Write-Host "Install complete. Reboot required to finish driver initialization."
            }
        }
        finally {
            # Best-effort cleanup
            try { Remove-Item -LiteralPath $dst -Force -ErrorAction SilentlyContinue } catch { }
        }
    }
}

Export-ModuleMember -Function Install-XenTools