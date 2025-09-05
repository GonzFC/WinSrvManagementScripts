<#
.SYNOPSIS
  Enforce a plain sign-in background and a solid-black desktop background for all users.

.DESCRIPTION
  - Disables logon/sign-in background image and acrylic blur (machine-wide)
  - Disables first sign-in animation (machine-wide)
  - Forces desktop background to solid black for:
      * Default profile (new users)
      * All loaded user profiles
      * All user profiles on disk (loads/unloads hives)
  - Idempotent and safe to re-run

.NOTES
  Run as Administrator. Sign out (or restart Explorer) for active users to see changes.
#>

# -------------------- Admin check --------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# -------------------- Ensure HKU: PSDrive exists --------------------
if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}

# -------------------- Helpers --------------------
function Set-PolicyDword {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Value
    )
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
        if ($null -eq $current -or $current -ne $Value) {
            New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
            Write-Host "Set $Path\$Name = $Value"
        } else {
            Write-Host "Already set: $Path\$Name = $Value"
        }
    } catch {
        Write-Warning "Failed to set $Path\$Name. $_"
    }
}

function Set-UserString {
    param(
        [Parameter(Mandatory)][string]$HiveRoot,     # e.g. HKU:\S-1-5-21-... or HKU:\.DEFAULT
        [Parameter(Mandatory)][string]$PathRel,      # e.g. 'Control Panel\Desktop'
        [Parameter(Mandatory)][string]$Name,
        [AllowEmptyString()]                         # allow '' (required for Wallpaper = '')
        [Parameter(Mandatory)][string]$Value
    )
    $path = Join-Path $HiveRoot $PathRel
    try {
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        $current = (Get-ItemProperty -Path $path -Name $Name -ErrorAction SilentlyContinue).$Name
        if ($null -eq $current -or $current -ne $Value) {
            New-ItemProperty -Path $path -Name $Name -PropertyType String -Value $Value -Force | Out-Null
            Write-Host "Set $path\$Name -> '$Value'"
        } else {
            Write-Host "Already set: $path\$Name"
        }
    } catch {
        Write-Warning "Failed to set $path\$Name. $_"
    }
}

function Set-UserDword {
    param(
        [Parameter(Mandatory)][string]$HiveRoot,
        [Parameter(Mandatory)][string]$PathRel,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Value
    )
    $path = Join-Path $HiveRoot $PathRel
    try {
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        $current = (Get-ItemProperty -Path $path -Name $Name -ErrorAction SilentlyContinue).$Name
        if ($null -eq $current -or $current -ne $Value) {
            New-ItemProperty -Path $path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
            Write-Host "Set $path\$Name = $Value"
        } else {
            Write-Host "Already set: $path\$Name = $Value"
        }
    } catch {
        Write-Warning "Failed to set $path\$Name. $_"
    }
}

function Apply-SolidBlackWallpaperToHive {
    param([Parameter(Mandatory)][string]$HiveRoot)

    # Force solid black color
    Set-UserString -HiveRoot $HiveRoot -PathRel 'Control Panel\Colors'  -Name 'Background' -Value '0 0 0'

    # Ensure no wallpaper image is used (empty string is intentional)
    try {
        Set-UserString -HiveRoot $HiveRoot -PathRel 'Control Panel\Desktop' -Name 'Wallpaper' -Value ''
    } catch {
        # Fallback (space) if a specific build blocks empty strings
        Set-UserString -HiveRoot $HiveRoot -PathRel 'Control Panel\Desktop' -Name 'Wallpaper' -Value ' '
    }

    # No stretch/tile
    Set-UserString -HiveRoot $HiveRoot -PathRel 'Control Panel\Desktop' -Name 'WallPaperStyle' -Value '0'
    Set-UserString -HiveRoot $HiveRoot -PathRel 'Control Panel\Desktop' -Name 'TileWallpaper'  -Value '0'

    # Optional: hide Background settings page so users can't change it
    Set-UserDword  -HiveRoot $HiveRoot -PathRel 'Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'NoDispBackgroundPage' -Value 1

    # Nudge active session (if this hive is the current user)
    try { rundll32.exe user32.dll,UpdatePerUserSystemParameters 1, True | Out-Null } catch { }
}

# Load a user hive from NTUSER.DAT, return mount (HKU:\Temp_<SID>) or existing HKU:\SID. Caller should unload if Temp_.
function Mount-UserHive {
    param(
        [Parameter(Mandatory)][string]$Sid,
        [Parameter(Mandatory)][string]$NtUserPath
    )
    $existing = Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq $Sid }
    if ($existing) { return "HKU:\$Sid" }

    if (-not (Test-Path $NtUserPath)) { return $null }
    $mountName = "HKU\Temp_$Sid"
    $null = reg.exe load $mountName $NtUserPath 2>$null
    if ($LASTEXITCODE -eq 0) { return "HKU:\Temp_$Sid" }
    return $null
}

function Unmount-UserHiveIfTemp {
    param([Parameter(Mandatory)][string]$HiveRoot)
    if ($HiveRoot -like 'HKU:\Temp_*') {
        $token = $HiveRoot.Replace('HKU:\', 'HKU\')
        reg.exe unload $token 2>$null | Out-Null
    }
}

Write-Host "Applying plain sign-in background + solid black desktop for all users..." -ForegroundColor Cyan

# -------------------- MACHINE-WIDE (Sign-in screen + animations) --------------------
Set-PolicyDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableLogonBackgroundImage' -Value 1
Set-PolicyDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableAcrylicBackgroundOnLogon' -Value 1
Set-PolicyDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableFirstLogonAnimation' -Value 0

# -------------------- USER-WIDE (Desktop = solid black) --------------------
# Default profile (affects NEW users)
Apply-SolidBlackWallpaperToHive -HiveRoot 'HKU:\.DEFAULT'

# Currently-loaded profiles
$loadedUserHives = (Get-ChildItem Registry::HKEY_USERS | Where-Object {
    $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$'
}) | ForEach-Object { "HKU:\$($_.PSChildName)" }

foreach ($h in $loadedUserHives) {
    Apply-SolidBlackWallpaperToHive -HiveRoot $h
}

# Profiles on disk (load if not mounted)
$profileListKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
Get-ChildItem $profileListKey | ForEach-Object {
    $sid = $_.PSChildName
    if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { return }

    $profilePath = (Get-ItemProperty -Path $_.PsPath -Name 'ProfileImagePath' -ErrorAction SilentlyContinue).ProfileImagePath
    if (-not $profilePath) { return }

    # Skip builtin/system-like
    if ($profilePath -match '\\(Default|Public|All Users|LocalService|NetworkService)$') { return }

    $ntUser = Join-Path $profilePath 'NTUSER.DAT'
    $hiveRoot = Mount-UserHive -Sid $sid -NtUserPath $ntUser
    if ($hiveRoot) {
        try { Apply-SolidBlackWallpaperToHive -HiveRoot $hiveRoot }
        finally { Unmount-UserHiveIfTemp -HiveRoot $hiveRoot }
    }
}

# -------------------- Refresh & finish --------------------
try {
    Write-Host "Refreshing policy (gpupdate /target:computer)..." -ForegroundColor DarkCyan
    gpupdate /target:computer /force | Out-Null
} catch {
    Write-Warning "Couldn't run gpupdate. A reboot will also apply the changes."
}

Write-Host "Done. Sign out (or restart Explorer) to see black desktops; sign-in screen is plain." -ForegroundColor Green