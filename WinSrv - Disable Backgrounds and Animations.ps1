<# 
.SYNOPSIS
  Force a plain (solid-color) Windows sign-in background and disable sign-in animations.

.DESCRIPTION
  - Disables the image on the sign-in screen (uses solid background color instead)
  - Disables the acrylic/blur effect on the sign-in screen (newer builds)
  - Disables the first sign-in animation ("Hi", "We're setting things up", etc.)
  - Idempotent: safe to run multiple times

.NOTES
  Requires elevation (run as Administrator).
#>

# --- Safety: ensure we're running as admin ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# --- Helper to set a DWORD policy value idempotently ---
function Set-PolicyDword {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [int]$Value
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
        if ($null -eq $current -or $current -ne $Value) {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
            Write-Host "Set $Path\$Name to $Value"
        } else {
            Write-Host "Already set: $Path\$Name = $Value"
        }
    } catch {
        Write-Error "Failed to set $Path\$Name. $_"
    }
}

Write-Host "Applying plain sign-in background and disabling animations..." -ForegroundColor Cyan

# 1) Disable sign-in (logon) background image → shows solid color
#    Policy: "Show lock screen background picture on the sign-in screen" (Disabled)
Set-PolicyDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableLogonBackgroundImage' -Value 1

# 2) Disable acrylic/blur on sign-in (Windows 10/11 / Server equivalents on newer builds)
Set-PolicyDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableAcrylicBackgroundOnLogon' -Value 1

# 3) Disable first sign-in animation
#    Policy: "Show first sign-in animation" (Disabled)
Set-PolicyDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableFirstLogonAnimation' -Value 0

# Optional: prompt to update policy cache
try {
    Write-Host "Refreshing policy (gpupdate /target:computer)..." -ForegroundColor DarkCyan
    gpupdate /target:computer /force | Out-Null
} catch {
    Write-Warning "Couldn't run gpupdate. A reboot will also apply the changes."
}

Write-Host "Done. Sign-out or reboot to see the solid-color sign-in screen with animations disabled." -ForegroundColor Green