<#
.SYNOPSIS
    Monitoring functions for Windows Toolbox

.DESCRIPTION
    WSB Reporter: reads this server's Windows Server Backup (WSB) status from the
    event log and PUSHes a compact JSON report to a central "xscp" runner's ingest
    endpoint (POST /ingest/wsb, Bearer token). Push, not pull: no inbound WinRM and
    no Windows credentials stored off-box. A scheduled task reports on an interval;
    the runner folds every server's status into one unified Backups view and alerts
    on failures or on a server that goes silent.

    Endpoint contract (xscp hwmon-serve): POST <Url> with header
    'Authorization: Bearer <token>' and a JSON body:
      { host, reporter_version, os, sent_at,
        wsb: { configured, last_result, last_success, last_failure,
               window_days, success_count, failure_count, detail } }

    ASCII only (no Unicode) per the repo convention. Common functions
    (Write-LogMessage, Enable-Tls12) are loaded by WinToolbox.ps1 first.
#>

# Note: Common functions are loaded by WinToolbox.ps1 before this module.

$script:WSBReporterVersion = '1.0.0'
$script:WSBReporterRoot    = Join-Path $env:ProgramData 'WSBReporter'
$script:WSBReporterScript  = Join-Path $script:WSBReporterRoot 'WSBReporter.ps1'
$script:WSBReporterConfig  = Join-Path $script:WSBReporterRoot 'config.json'
$script:WSBTaskName        = 'VLABS WSB Reporter'

#region WSB status (shared reader)

<#
.SYNOPSIS
    Reads Windows Server Backup status from the event log (credential-free).
.DESCRIPTION
    Success = event ID 4, failures = 5 / 517, over an N-day window, from the
    'Microsoft-Windows-Backup' (and legacy 'Backup') providers. Enriches with
    Get-WBSummary when the Windows Server Backup feature/module is present.
#>
function Get-WSBStatus {
    [CmdletBinding()]
    param([int]$Days = 8)

    $start = (Get-Date).AddDays(-[math]::Abs($Days))
    $ids = @(4, 5, 517)
    $events = @()
    foreach ($provider in @('Microsoft-Windows-Backup', 'Backup')) {
        try {
            $events += Get-WinEvent -FilterHashtable @{ ProviderName = $provider; StartTime = $start; Id = $ids } -ErrorAction Stop
        }
        catch { }
    }

    $configured = $true
    if (-not $events -or $events.Count -eq 0) {
        try { $null = Get-WinEvent -ListLog 'Microsoft-Windows-Backup/Operational' -ErrorAction Stop }
        catch { $configured = $false }
    }

    $events = @($events | Sort-Object TimeCreated -Descending)
    $succ = @($events | Where-Object { $_.Id -eq 4 })
    $fail = @($events | Where-Object { $_.Id -ne 4 })

    $lastSuccess = if ($succ.Count -gt 0) { $succ[0].TimeCreated } else { $null }
    $lastFailure = if ($fail.Count -gt 0) { $fail[0].TimeCreated } else { $null }
    $last = if ($events.Count -gt 0) { $events[0] } else { $null }
    $lastResult = if (-not $last) { 'none' } elseif ($last.Id -eq 4) { 'success' } else { 'failure' }

    # Enrich with the Windows Server Backup cmdlet when available (authoritative time).
    try {
        if (Get-Command Get-WBSummary -ErrorAction SilentlyContinue) {
            $summary = Get-WBSummary -ErrorAction Stop
            $configured = $true
            if ($summary.LastSuccessfulBackupTime -and $summary.LastSuccessfulBackupTime -gt [datetime]'2000-01-01') {
                $lastSuccess = $summary.LastSuccessfulBackupTime
            }
        }
    }
    catch { }

    $detail = 'No WSB events in window'
    if ($last) {
        $flat = ($last.Message -replace '\s+', ' ').Trim()
        if ($flat.Length -gt 200) { $flat = $flat.Substring(0, 200) }
        $detail = $flat
    }
    elseif (-not $configured) {
        $detail = 'Windows Server Backup not configured'
    }

    [PSCustomObject]@{
        Configured   = $configured
        LastResult   = $lastResult
        LastSuccess  = $lastSuccess
        LastFailure  = $lastFailure
        SuccessCount = $succ.Count
        FailureCount = $fail.Count
        WindowDays   = $Days
        Detail       = $detail
    }
}

#endregion

#region Reporter runtime (written to disk, run by the scheduled task)

# Self-contained runtime: loads config, decrypts the token (DPAPI LocalMachine),
# computes WSB status, and POSTs it. Runs as SYSTEM on a schedule. The status
# reader below is kept in step with Get-WSBStatus above.
$script:WSBReporterRuntime = @'
param([switch]$ShowStatus)

$ErrorActionPreference = 'Stop'
$ConfigPath = Join-Path $env:ProgramData 'WSBReporter\config.json'
$LogDir = 'C:\VLABS\Maintenance'
$ReporterVersion = '1.0.0'

function Write-ReporterLog($msg) {
    try {
        if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
        Add-Content -Path (Join-Path $LogDir ("WSBReporter_{0}.log" -f (Get-Date -Format 'yyyy-MM'))) `
            -Value ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg) -ErrorAction SilentlyContinue
    } catch { }
}

function Get-WSBStatusRuntime([int]$Days = 8) {
    $start = (Get-Date).AddDays(-[math]::Abs($Days))
    $ids = @(4, 5, 517)
    $events = @()
    foreach ($provider in @('Microsoft-Windows-Backup', 'Backup')) {
        try { $events += Get-WinEvent -FilterHashtable @{ ProviderName = $provider; StartTime = $start; Id = $ids } -ErrorAction Stop } catch { }
    }
    $configured = $true
    if (-not $events -or $events.Count -eq 0) {
        try { $null = Get-WinEvent -ListLog 'Microsoft-Windows-Backup/Operational' -ErrorAction Stop } catch { $configured = $false }
    }
    $events = @($events | Sort-Object TimeCreated -Descending)
    $succ = @($events | Where-Object { $_.Id -eq 4 })
    $fail = @($events | Where-Object { $_.Id -ne 4 })
    $lastSuccess = if ($succ.Count -gt 0) { $succ[0].TimeCreated } else { $null }
    $lastFailure = if ($fail.Count -gt 0) { $fail[0].TimeCreated } else { $null }
    $last = if ($events.Count -gt 0) { $events[0] } else { $null }
    $lastResult = if (-not $last) { 'none' } elseif ($last.Id -eq 4) { 'success' } else { 'failure' }
    try {
        if (Get-Command Get-WBSummary -ErrorAction SilentlyContinue) {
            $s = Get-WBSummary -ErrorAction Stop
            $configured = $true
            if ($s.LastSuccessfulBackupTime -and $s.LastSuccessfulBackupTime -gt [datetime]'2000-01-01') { $lastSuccess = $s.LastSuccessfulBackupTime }
        }
    } catch { }
    $detail = 'No WSB events in window'
    if ($last) { $flat = ($last.Message -replace '\s+', ' ').Trim(); if ($flat.Length -gt 200) { $flat = $flat.Substring(0, 200) }; $detail = $flat }
    elseif (-not $configured) { $detail = 'Windows Server Backup not configured' }
    return [PSCustomObject]@{ Configured = $configured; LastResult = $lastResult; LastSuccess = $lastSuccess; LastFailure = $lastFailure; SuccessCount = $succ.Count; FailureCount = $fail.Count; WindowDays = $Days; Detail = $detail }
}

function ConvertTo-IsoZ($dt) { if ($dt) { ([datetime]$dt).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null } }

try {
    if (-not (Test-Path $ConfigPath)) { throw "Config not found: $ConfigPath" }
    $cfg = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    $st = Get-WSBStatusRuntime -Days 8
    $os = try { (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { 'Windows' }
    $report = [ordered]@{
        host = $env:COMPUTERNAME
        reporter_version = $ReporterVersion
        os = $os
        sent_at = ConvertTo-IsoZ (Get-Date)
        wsb = [ordered]@{
            configured    = [bool]$st.Configured
            last_result   = $st.LastResult
            last_success  = ConvertTo-IsoZ $st.LastSuccess
            last_failure  = ConvertTo-IsoZ $st.LastFailure
            window_days   = $st.WindowDays
            success_count = $st.SuccessCount
            failure_count = $st.FailureCount
            detail        = $st.Detail
        }
    }
    $json = $report | ConvertTo-Json -Depth 5 -Compress

    if ($ShowStatus) { Write-Output $json; return }

    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
    $prot = [Convert]::FromBase64String($cfg.TokenProtected)
    $tokenBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($prot, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    $token = [System.Text.Encoding]::UTF8.GetString($tokenBytes)

    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $resp = Invoke-RestMethod -Uri $cfg.Url -Method Post -Body $json -ContentType 'application/json' `
        -Headers @{ Authorization = "Bearer $token" } -TimeoutSec 15
    Write-ReporterLog ("Reported WSB status ({0}) to {1} -> ok" -f $st.LastResult, $cfg.Url)
}
catch {
    Write-ReporterLog ("ERROR: " + $_.Exception.Message)
    exit 1
}
'@

#endregion

#region Install / test

<#
.SYNOPSIS
    Installs the WSB Reporter: config + runtime script + scheduled task (SYSTEM).
.PARAMETER XscpUrl
    Full ingest URL, e.g. http://xscp.ait.<entity>.<tld>:8899/ingest/wsb
.PARAMETER Token
    The per-site ingest bearer token (stored DPAPI-protected, machine scope).
.PARAMETER IntervalMinutes
    How often to report (default 15).
#>
function Install-WSBReporter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$XscpUrl,
        [Parameter(Mandatory = $true)][string]$Token,
        [int]$IntervalMinutes = 15
    )

    Write-LogMessage "Installing WSB Reporter..." -Level Info -Component 'WSBReporter'

    if ($XscpUrl -notmatch '^https?://') { throw "XscpUrl must start with http:// or https:// (got '$XscpUrl')" }
    if ([string]::IsNullOrWhiteSpace($Token)) { throw "Token is required" }

    if (-not (Test-Path $script:WSBReporterRoot)) {
        New-Item -ItemType Directory -Path $script:WSBReporterRoot -Force | Out-Null
    }

    # Protect the token with DPAPI (LocalMachine so the SYSTEM task can decrypt it).
    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
    $tokenBytes = [System.Text.Encoding]::UTF8.GetBytes($Token)
    $protected = [System.Security.Cryptography.ProtectedData]::Protect($tokenBytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    $tokenB64 = [Convert]::ToBase64String($protected)

    $cfg = [ordered]@{
        Url            = $XscpUrl
        TokenProtected = $tokenB64
        Installed      = (Get-Date).ToString('s')
        Version        = $script:WSBReporterVersion
    }
    $cfg | ConvertTo-Json | Set-Content -Path $script:WSBReporterConfig -Encoding ASCII -Force

    # Lock the config down to admins/SYSTEM (it holds the protected token).
    try {
        icacls $script:WSBReporterConfig /inheritance:r /grant:r "SYSTEM:(R)" "Administrators:(F)" | Out-Null
    }
    catch { Write-LogMessage "Could not tighten ACL on config: $_" -Level Warning -Component 'WSBReporter' }

    # Write the runtime.
    Set-Content -Path $script:WSBReporterScript -Value $script:WSBReporterRuntime -Encoding ASCII -Force

    # Register the scheduled task (SYSTEM, at startup + repeating).
    try { Unregister-ScheduledTask -TaskName $script:WSBTaskName -Confirm:$false -ErrorAction SilentlyContinue } catch { }

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$($script:WSBReporterScript)`""
    # TWO triggers. A boot trigger's repetition only arms AFTER the next reboot
    # (a task installed on a running server would otherwise never fire - learned
    # the hard way), so a time trigger starting now covers the running system and
    # the boot trigger covers restarts.
    # NOTE: [TimeSpan]::MaxValue serializes to P99999999DT... which Task Scheduler
    # rejects ("value ... out of range"); use a bounded 10-year duration instead.
    $rep = (New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
        -RepetitionDuration (New-TimeSpan -Days 3650)).Repetition
    $bootTrigger = New-ScheduledTaskTrigger -AtStartup
    $bootTrigger.Delay = 'PT2M'
    $bootTrigger.Repetition = $rep
    $timeTrigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(2)) `
        -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
        -RepetitionDuration (New-TimeSpan -Days 3650)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

    Register-ScheduledTask -TaskName $script:WSBTaskName -Action $action `
        -Trigger @($bootTrigger, $timeTrigger) -Principal $principal -Settings $settings | Out-Null

    Write-LogMessage "WSB Reporter task registered (every $IntervalMinutes min)" -Level Success -Component 'WSBReporter'

    # Fire one report now to verify end to end.
    Write-Host ""
    Write-Host "Sending a test report to $XscpUrl ..." -ForegroundColor Cyan
    $ok = Test-WSBReporter
    Write-Host ""
    Write-Host "WSB Reporter installation complete!" -ForegroundColor Green
    Write-Host "  Endpoint:  $XscpUrl" -ForegroundColor White
    Write-Host "  Interval:  every $IntervalMinutes minutes (+ at startup)" -ForegroundColor White
    Write-Host "  Task:      $($script:WSBTaskName)" -ForegroundColor White
    Write-Host "  First report: $(if ($ok) { 'delivered' } else { 'FAILED - check C:\VLABS\Maintenance and the token/URL' })" `
        -ForegroundColor $(if ($ok) { 'Green' } else { 'Yellow' })
    Write-Host ""
}

<#
.SYNOPSIS
    Runs the installed reporter once and returns $true on success.
#>
function Test-WSBReporter {
    [CmdletBinding()]
    param()
    if (-not (Test-Path $script:WSBReporterScript)) {
        Write-LogMessage "Reporter not installed yet (run Install-WSBReporter)" -Level Warning -Component 'WSBReporter'
        return $false
    }
    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:WSBReporterScript
        if ($LASTEXITCODE -eq 0) {
            Write-LogMessage "Test report delivered" -Level Success -Component 'WSBReporter'
            return $true
        }
        Write-LogMessage "Test report failed (exit $LASTEXITCODE)" -Level Warning -Component 'WSBReporter'
        return $false
    }
    catch {
        Write-LogMessage "Test report error: $_" -Level Error -Component 'WSBReporter'
        return $false
    }
}

<#
.SYNOPSIS
    Prints the current WSB status JSON without sending it.
#>
function Show-WSBStatus {
    [CmdletBinding()]
    param([int]$Days = 8)
    Get-WSBStatus -Days $Days | ConvertTo-Json -Depth 5
}

#endregion

# Export-ModuleMember intentionally omitted (loaded via Invoke-Expression, per repo convention).
