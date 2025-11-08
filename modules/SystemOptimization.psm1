<#
.SYNOPSIS
    System Optimization functions for Windows Toolbox

.DESCRIPTION
    Functions for disk space reclamation and UI/visual optimizations
#>

# Import common functions
$commonModule = Join-Path $PSScriptRoot 'Common.psm1'
Import-Module $commonModule -Force

#region Disk Space Reclamation

<#
.SYNOPSIS
    Reclaims disk space from WinSxS, Windows Update, Delivery Optimization, TEMP, and inactive profiles
#>
function Invoke-DiskSpaceReclamation {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [int]$DaysInactive = 30,
        [switch]$DeepComponentCleanup,
        [switch]$SkipProfileDeletion,
        [switch]$Schedule
    )

    Write-LogMessage "Starting disk space reclamation" -Level Info -Component 'DiskCleanup'

    # State management
    $stateDir = Join-Path $env:ProgramData 'StorageReclaim'
    $resetBaseMarker = Join-Path $stateDir 'last_resetbase.txt'
    New-Item -ItemType Directory -Force -Path $stateDir -ErrorAction SilentlyContinue | Out-Null

    $freeStart = Get-FreeSpaceGB

    # Report last ResetBase
    $lastResetBase = if (Test-Path $resetBaseMarker) {
        Get-Content $resetBaseMarker -ErrorAction SilentlyContinue | Select-Object -First 1
    } else {
        'Never'
    }
    Write-LogMessage "Last /ResetBase: $lastResetBase" -Level Info -Component 'DiskCleanup'

    # Estimate potential gains
    Write-LogMessage "Estimating potential disk space gains..." -Level Info -Component 'DiskCleanup'

    $dismInfo = Get-DismAnalysis
    $estWinSxS = [math]::Max($dismInfo.ReclaimableGB, 0)
    $estWU = Get-DirectorySizeGB (Join-Path $env:WINDIR 'SoftwareDistribution\Download')
    $estDO = Get-DeliveryOptimizationCacheSize
    $estTemp = Get-TempFoldersSize
    $estProfiles = Get-InactiveProfilesSize -DaysInactive $DaysInactive

    $estTotal = [math]::Round(($estWinSxS + $estWU + $estDO + $estTemp + $estProfiles), 2)

    Write-LogMessage "Estimated gains - WinSxS: $estWinSxS GB, WU: $estWU GB, DO: $estDO GB, TEMP: $estTemp GB, Profiles: $estProfiles GB" -Level Info -Component 'DiskCleanup'
    Write-LogMessage "Total estimated: $estTotal GB" -Level Info -Component 'DiskCleanup'

    # Skip if gain is too small
    $minGainGB = 5.0
    if ($estTotal -lt $minGainGB) {
        Write-LogMessage "Estimated gain ($estTotal GB) is less than threshold ($minGainGB GB). Skipping cleanup." -Level Warning -Component 'DiskCleanup'
        return
    }

    # Track gains per section
    $gains = [ordered]@{
        WinSxS   = 0.0
        WUCache  = 0.0
        DOCache  = 0.0
        TEMP     = 0.0
        Profiles = 0.0
    }

    # 1. WinSxS Cleanup
    $gains['WinSxS'] = Clear-ComponentStore -DeepClean:$DeepComponentCleanup -ResetBaseMarker $resetBaseMarker

    # 2. Windows Update Cache
    $gains['WUCache'] = Clear-WindowsUpdateCache

    # 3. Delivery Optimization Cache
    $gains['DOCache'] = Clear-DeliveryOptimizationCache

    # 4. TEMP Folders
    $gains['TEMP'] = Clear-TempFolders

    # 5. Inactive Profiles
    if (-not $SkipProfileDeletion) {
        $gains['Profiles'] = Remove-InactiveProfiles -DaysInactive $DaysInactive
    }

    # 6. Schedule task if requested
    if ($Schedule) {
        Register-DiskCleanupTask -DaysInactive $DaysInactive -DeepComponentCleanup:$DeepComponentCleanup
    }

    # Summary
    $freeEnd = Get-FreeSpaceGB
    $totalGain = [math]::Round(($freeEnd - $freeStart), 2)

    Write-LogMessage "Cleanup complete!" -Level Success -Component 'DiskCleanup'
    Write-LogMessage "WinSxS: $($gains['WinSxS']) GB | WU: $($gains['WUCache']) GB | DO: $($gains['DOCache']) GB | TEMP: $($gains['TEMP']) GB | Profiles: $($gains['Profiles']) GB" -Level Info -Component 'DiskCleanup'
    Write-LogMessage "Free space: $freeStart GB -> $freeEnd GB (gained $totalGain GB)" -Level Success -Component 'DiskCleanup'
}

function Get-DismAnalysis {
    $output = & Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore 2>&1
    $reclaimable = 0.0
    $recommended = $false

    foreach ($line in $output) {
        if ($line -match 'Recom.*Limpieza|Cleanup Recommended') {
            if ($line -match 'S[ií]|Yes') { $recommended = $true }
        }
        if ($line -match '(Backups?|Copia.*seguridad).*:\s*([\d\.,]+)\s*(KB|MB|GB)') {
            $val = [double]::Parse($Matches[2].Replace(',', '.'))
            $reclaimable += ConvertTo-GB -Value $val -Unit $Matches[3]
        }
        if ($line -match '(Cache|Cach[eé]).*:\s*([\d\.,]+)\s*(KB|MB|GB)') {
            $val = [double]::Parse($Matches[2].Replace(',', '.'))
            $reclaimable += ConvertTo-GB -Value $val -Unit $Matches[3]
        }
    }

    return [PSCustomObject]@{
        ReclaimableGB = [math]::Round($reclaimable, 2)
        Recommended   = $recommended
    }
}

function ConvertTo-GB {
    param([double]$Value, [string]$Unit)

    switch -Regex ($Unit.ToUpper()) {
        'GB' { [math]::Round($Value, 2) }
        'MB' { [math]::Round($Value / 1024, 2) }
        'KB' { [math]::Round($Value / 1048576, 2) }
        default { [math]::Round($Value / 1073741824, 2) }
    }
}

function Get-DeliveryOptimizationCacheSize {
    $doBase = 'C:\ProgramData\Microsoft\Windows\DeliveryOptimization'
    $cachePath = Join-Path $doBase 'Cache'
    return Get-DirectorySizeGB -Path $cachePath
}

function Get-TempFoldersSize {
    $total = 0.0

    # System TEMP
    $total += Get-DirectorySizeGB -Path (Join-Path $env:WINDIR 'Temp')

    # User TEMP folders (non-loaded profiles)
    $profiles = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object {
        -not $_.Special -and -not $_.Loaded -and $_.LocalPath -and ($_.LocalPath -like 'C:\Users\*')
    }

    foreach ($profile in $profiles) {
        $tempPath = Join-Path $profile.LocalPath 'AppData\Local\Temp'
        $total += Get-DirectorySizeGB -Path $tempPath
    }

    return [math]::Round($total, 2)
}

function Get-InactiveProfilesSize {
    param([int]$DaysInactive)

    $threshold = (Get-Date).AddDays(-[Math]::Abs($DaysInactive))
    $total = 0.0

    $profiles = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object {
        -not $_.Special -and -not $_.Loaded -and $_.LocalPath -and ($_.LocalPath -like 'C:\Users\*')
    }

    foreach ($profile in $profiles) {
        $lastUse = Get-ProfileLastUse -Profile $profile
        if ($lastUse -and $lastUse -lt $threshold) {
            $total += Get-DirectorySizeGB -Path $profile.LocalPath
        }
    }

    return [math]::Round($total, 2)
}

function Get-ProfileLastUse {
    param($Profile)

    # Try LastUseTime first
    if ($Profile.LastUseTime) {
        try {
            $dt = [System.Management.ManagementDateTimeConverter]::ToDateTime($Profile.LastUseTime)
            if ($dt -gt [datetime]'1970-01-01' -and $dt -lt (Get-Date).AddYears(5)) {
                return $dt
            }
        }
        catch { }
    }

    # Fallback to folder LastWriteTime
    if ($Profile.LocalPath -and (Test-Path $Profile.LocalPath)) {
        try {
            return (Get-Item $Profile.LocalPath -ErrorAction SilentlyContinue).LastWriteTime
        }
        catch { }
    }

    return $null
}

function Clear-ComponentStore {
    param(
        [switch]$DeepClean,
        [string]$ResetBaseMarker
    )

    $before = Get-FreeSpaceGB

    Write-LogMessage "Running DISM StartComponentCleanup..." -Level Info -Component 'DiskCleanup'
    & Dism.exe /Online /Cleanup-Image /StartComponentCleanup /Quiet | Out-Null

    if ($DeepClean) {
        $analysis = Get-DismAnalysis
        if ($analysis.ReclaimableGB -ge 1) {
            Write-LogMessage "Running DISM StartComponentCleanup /ResetBase..." -Level Info -Component 'DiskCleanup'
            & Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase /Quiet | Out-Null
            (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') | Set-Content -Path $ResetBaseMarker -Encoding UTF8
        }
        else {
            Write-LogMessage "Skipping /ResetBase (less than 1 GB reclaimable)" -Level Info -Component 'DiskCleanup'
        }
    }

    $after = Get-FreeSpaceGB
    return [math]::Max([math]::Round(($after - $before), 2), 0)
}

function Clear-WindowsUpdateCache {
    $before = Get-FreeSpaceGB
    $wuPath = Join-Path $env:WINDIR 'SoftwareDistribution\Download'

    Write-LogMessage "Clearing Windows Update cache..." -Level Info -Component 'DiskCleanup'

    $wuWasRunning = (Get-Service wuauserv).Status -eq 'Running'
    $bitsWasRunning = (Get-Service bits).Status -eq 'Running'

    Stop-ServiceSafe -ServiceName 'wuauserv' | Out-Null
    Stop-ServiceSafe -ServiceName 'bits' | Out-Null

    if (Test-Path $wuPath) {
        Get-ChildItem -Path $wuPath -Force -Recurse -ErrorAction SilentlyContinue |
            Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }

    if ($wuWasRunning) { Start-ServiceSafe -ServiceName 'wuauserv' | Out-Null }
    if ($bitsWasRunning) { Start-ServiceSafe -ServiceName 'bits' | Out-Null }

    $after = Get-FreeSpaceGB
    return [math]::Max([math]::Round(($after - $before), 2), 0)
}

function Clear-DeliveryOptimizationCache {
    $before = Get-FreeSpaceGB

    Write-LogMessage "Clearing Delivery Optimization cache..." -Level Info -Component 'DiskCleanup'

    if (Get-Command Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue) {
        Delete-DeliveryOptimizationCache -Force -IncludePinnedFiles -ErrorAction SilentlyContinue | Out-Null
    }
    else {
        $doPath = 'C:\ProgramData\Microsoft\Windows\DeliveryOptimization\Cache'
        if (Test-Path $doPath) {
            Get-ChildItem -Path $doPath -Force -Recurse -ErrorAction SilentlyContinue |
                Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        }
    }

    $after = Get-FreeSpaceGB
    return [math]::Max([math]::Round(($after - $before), 2), 0)
}

function Clear-TempFolders {
    $before = Get-FreeSpaceGB

    Write-LogMessage "Clearing TEMP folders..." -Level Info -Component 'DiskCleanup'

    # System TEMP
    $sysTemp = Join-Path $env:WINDIR 'Temp'
    if (Test-Path $sysTemp) {
        Get-ChildItem -Path $sysTemp -Force -Recurse -ErrorAction SilentlyContinue |
            Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }

    # User TEMP folders
    $profiles = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object {
        -not $_.Special -and -not $_.Loaded -and $_.LocalPath -and ($_.LocalPath -like 'C:\Users\*')
    }

    foreach ($profile in $profiles) {
        $tempPath = Join-Path $profile.LocalPath 'AppData\Local\Temp'
        if (Test-Path $tempPath) {
            Get-ChildItem -Path $tempPath -Force -Recurse -ErrorAction SilentlyContinue |
                Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        }
    }

    $after = Get-FreeSpaceGB
    return [math]::Max([math]::Round(($after - $before), 2), 0)
}

function Remove-InactiveProfiles {
    param([int]$DaysInactive)

    $before = Get-FreeSpaceGB
    $threshold = (Get-Date).AddDays(-[Math]::Abs($DaysInactive))

    Write-LogMessage "Removing inactive profiles (>$DaysInactive days)..." -Level Info -Component 'DiskCleanup'

    $profiles = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object {
        -not $_.Special -and -not $_.Loaded -and $_.LocalPath -and ($_.LocalPath -like 'C:\Users\*')
    }

    foreach ($profile in $profiles) {
        $lastUse = Get-ProfileLastUse -Profile $profile
        if ($lastUse -and $lastUse -lt $threshold) {
            # CONFIRMATION PROMPT FOR EACH PROFILE
            $userName = Split-Path $profile.LocalPath -Leaf
            $question = "Delete inactive profile '$userName' (Last used: $lastUse)?"

            if (Show-Confirmation -Message $question -DefaultYes:$false) {
                Write-LogMessage "Deleting profile: $($profile.LocalPath)" -Level Info -Component 'DiskCleanup'

                try {
                    Remove-CimInstance -InputObject $profile -ErrorAction Stop
                    if (Test-Path $profile.LocalPath) {
                        Remove-Item -Path $profile.LocalPath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    Write-LogMessage "Profile deleted successfully" -Level Success -Component 'DiskCleanup'
                }
                catch {
                    Write-LogMessage "Failed to delete profile: $_" -Level Error -Component 'DiskCleanup'
                }
            }
            else {
                Write-LogMessage "Skipped profile: $userName" -Level Info -Component 'DiskCleanup'
            }
        }
    }

    $after = Get-FreeSpaceGB
    return [math]::Max([math]::Round(($after - $before), 2), 0)
}

function Register-DiskCleanupTask {
    param(
        [int]$DaysInactive,
        [switch]$DeepComponentCleanup
    )

    Write-LogMessage "Creating scheduled task for weekly disk cleanup..." -Level Info -Component 'DiskCleanup'

    $taskName = 'StorageCleanup-Weekly'
    $taskPath = '\Maintenance'
    $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'WinToolbox.ps1'

    try {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument `
            "-NoProfile -ExecutionPolicy Bypass -Command `"& '$scriptPath' -AutoCleanup -DaysInactive $DaysInactive -DeepComponentCleanup:`$$($DeepComponentCleanup.IsPresent)`""

        $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 6:00am
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest

        $existing = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
        if ($existing) {
            Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Trigger $trigger -Principal $principal | Out-Null
            Write-LogMessage "Scheduled task updated" -Level Success -Component 'DiskCleanup'
        }
        else {
            Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Trigger $trigger -Principal $principal `
                -Description "Weekly disk space reclamation (WinSxS, Updates, TEMP, inactive profiles)" | Out-Null
            Write-LogMessage "Scheduled task created" -Level Success -Component 'DiskCleanup'
        }
    }
    catch {
        Write-LogMessage "Failed to create scheduled task: $_" -Level Error -Component 'DiskCleanup'
    }
}

#endregion

#region UI Optimizations

<#
.SYNOPSIS
    Disables backgrounds and animations for all users
#>
function Disable-BackgroundsAndAnimations {
    [CmdletBinding()]
    param()

    Write-LogMessage "Disabling backgrounds and animations..." -Level Info -Component 'UIOptimization'

    # Ensure HKU: drive
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }

    # Machine-wide policies
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableLogonBackgroundImage' -Value 1 -Type DWord
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableAcrylicBackgroundOnLogon' -Value 1 -Type DWord
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableFirstLogonAnimation' -Value 0 -Type DWord

    # Default profile
    Set-SolidBlackWallpaper -HiveRoot 'HKU:\.DEFAULT'

    # Currently loaded profiles
    $loadedHives = Get-ChildItem Registry::HKEY_USERS | Where-Object {
        $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$'
    } | ForEach-Object { "HKU:\$($_.PSChildName)" }

    foreach ($hive in $loadedHives) {
        Set-SolidBlackWallpaper -HiveRoot $hive
    }

    # Profiles on disk
    $profileListKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    Get-ChildItem $profileListKey -ErrorAction SilentlyContinue | ForEach-Object {
        $sid = $_.PSChildName
        if ($sid -match '^S-1-5-21-\d+-\d+-\d+-\d+$') {
            $profilePath = (Get-ItemProperty -Path $_.PSPath -Name 'ProfileImagePath' -ErrorAction SilentlyContinue).ProfileImagePath
            if ($profilePath -and $profilePath -like 'C:\Users\*' -and $profilePath -notmatch '\\(Default|Public|All Users)$') {
                $ntUser = Join-Path $profilePath 'NTUSER.DAT'
                if (Test-Path $ntUser) {
                    $mountPoint = Mount-UserHive -Sid $sid -NtUserPath $ntUser
                    if ($mountPoint) {
                        try {
                            Set-SolidBlackWallpaper -HiveRoot $mountPoint
                        }
                        finally {
                            Dismount-UserHive -HiveRoot $mountPoint
                        }
                    }
                }
            }
        }
    }

    # Refresh policy
    try {
        gpupdate /target:computer /force | Out-Null
    }
    catch {
        Write-LogMessage "Could not run gpupdate" -Level Warning -Component 'UIOptimization'
    }

    Write-LogMessage "Backgrounds and animations disabled. Sign out or restart Explorer to see changes." -Level Success -Component 'UIOptimization'
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type
    )

    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }

        New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
    }
    catch {
        Write-LogMessage "Failed to set registry value $Path\$Name" -Level Warning -Component 'UIOptimization'
    }
}

function Set-SolidBlackWallpaper {
    param([string]$HiveRoot)

    # Solid black color
    Set-RegistryValue -Path "$HiveRoot\Control Panel\Colors" -Name 'Background' -Value '0 0 0' -Type String

    # No wallpaper
    Set-RegistryValue -Path "$HiveRoot\Control Panel\Desktop" -Name 'Wallpaper' -Value '' -Type String
    Set-RegistryValue -Path "$HiveRoot\Control Panel\Desktop" -Name 'WallpaperStyle' -Value '0' -Type String
    Set-RegistryValue -Path "$HiveRoot\Control Panel\Desktop" -Name 'TileWallpaper' -Value '0' -Type String

    # Hide background settings page
    Set-RegistryValue -Path "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'NoDispBackgroundPage' -Value 1 -Type DWord

    # Nudge active session
    try {
        rundll32.exe user32.dll, UpdatePerUserSystemParameters 1, True | Out-Null
    }
    catch { }
}

function Mount-UserHive {
    param([string]$Sid, [string]$NtUserPath)

    # Check if already loaded
    $existing = Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object {
        $_.PSChildName -eq $Sid
    }
    if ($existing) {
        return "HKU:\$Sid"
    }

    if (-not (Test-Path $NtUserPath)) {
        return $null
    }

    $mountName = "HKU\Temp_$Sid"
    $result = reg.exe load $mountName $NtUserPath 2>&1
    if ($LASTEXITCODE -eq 0) {
        return "HKU:\Temp_$Sid"
    }

    return $null
}

function Dismount-UserHive {
    param([string]$HiveRoot)

    if ($HiveRoot -like 'HKU:\Temp_*') {
        $mountName = $HiveRoot.Replace('HKU:\', 'HKU\')
        reg.exe unload $mountName 2>&1 | Out-Null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Invoke-DiskSpaceReclamation',
    'Disable-BackgroundsAndAnimations'
)
