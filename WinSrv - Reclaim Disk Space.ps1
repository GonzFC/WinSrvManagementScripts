<# 
.SYNOPSIS
  Recupera espacio en Windows: WinSxS, cachés de Update/DO, TEMP de usuarios no cargados y elimina perfiles inactivos.
.DESCRIPTION
  Idempotente. Registra a log unificado en C:\VLABS\disk_space_recovery.log.
  Crea/actualiza tarea semanal (domingos 06:00). Mide GB recuperados por sección.
  Si la ganancia estimada total < 5 GB, se omite la ejecución y se registra la decisión.
.PARAMETER DaysInactive
  Días de inactividad para eliminar perfiles (Default: 30).
.PARAMETER DeepComponentCleanup
  Incluye /ResetBase en DISM (máxima recuperación; no podrás desinstalar actualizaciones ya instaladas).
.PARAMETER SkipProfileDeletion
  Omite la eliminación de perfiles.
.PARAMETER Schedule
  Crea/actualiza tarea programada semanal (domingos 06:00).
.PARAMETER WhatIf
  Modo simulación.
.NOTES
  Requiere PowerShell 5+, ejecutar como Administrador.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
Param(
  [int]$DaysInactive = 30,
  [switch]$DeepComponentCleanup,
  [switch]$SkipProfileDeletion,
  [switch]$Schedule
)

# --- Utilidades y setup -------------------------------------------------------
$ErrorActionPreference = 'Stop'

# Rutas de log y marcadores
$VlabsDir = 'C:\VLABS'
$GlobalLog = Join-Path $VlabsDir 'disk_space_recovery.log'
$StateDir  = Join-Path $env:ProgramData 'StorageReclaim'
$ResetBaseMarker = Join-Path $StateDir 'last_resetbase.txt'
New-Item -ItemType Directory -Force -Path $VlabsDir, $StateDir | Out-Null

$script:StartTime = Get-Date
$SessionLogHeader = "=== Storage Reclaim @ {0:yyyy-MM-dd HH:mm:ss} ({1}) ===" -f $script:StartTime, $env:COMPUTERNAME

Function Write-Log { Param([string]$Message)
  $line = "[{0:yyyy-MM-dd HH:mm:ss}] {1}" -f (Get-Date), $Message
  $null = $line | Tee-Object -FilePath $GlobalLog -Append
}

Function Test-Admin {
  $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    throw "Este script debe ejecutarse como Administrador."
  }
}

Function Get-FreeGB([string]$Drive='C') {
  $d = Get-PSDrive -Name $Drive
  [math]::Round(($d.Free/1GB),2)
}

Function Get-DirSizeGB([string]$Path) {
  if (-not (Test-Path $Path)) { return 0 }
  try {
    $sum = (Get-ChildItem -Path $Path -Force -Recurse -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
    if (-not $sum) { return 0 }
    [math]::Round(($sum/1GB),2)
  } catch { 0 }
}

Function Convert-ToGB([double]$Value, [string]$Unit) {
  switch -Regex ($Unit.ToUpper()) {
    'GB' { [math]::Round($Value,2) }
    'MB' { [math]::Round($Value/1024,2) }
    'KB' { [math]::Round($Value/1MB,2) }
    default { [math]::Round($Value/1GB,2) }
  }
}

Function Human([double]$gb) { '{0:N2} GB' -f $gb }

# Convertidor CIM/WMI -> DateTime (seguro)
Function Convert-WmiDateToDT([string]$WmiDate) {
  if ([string]::IsNullOrWhiteSpace($WmiDate)) { return $null }
  # DMTF esperado: yyyymmddHHMMSS.mmmmmm+UUU  (25 chars)
  if ($WmiDate -notmatch '^\d{14}\.\d{6}(\+|\-)\d{3}$') { return $null }
  try {
    $dt = [System.Management.ManagementDateTimeConverter]::ToDateTime($WmiDate)
    if ($dt -lt [datetime]'1970-01-01' -or $dt -gt (Get-Date).AddYears(5)) { return $null }
    return $dt
  } catch { return $null }
}

# Fecha “mejor disponible” para un perfil
Function Get-ProfileLastUsed($prof) {
  $dt = Convert-WmiDateToDT $prof.LastUseTime
  if ($dt) { return $dt }
  try {
    if ($prof.LocalPath -and (Test-Path $prof.LocalPath)) {
      return (Get-Item $prof.LocalPath -ErrorAction SilentlyContinue).LastWriteTime
    }
  } catch {}
  return $null
}

# Parseo de DISM /AnalyzeComponentStore
Function Parse-DismAnalyze {
  $out = & Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore 2>&1
  $rec = $false; $reclaim = 0.0; $last = $null

  foreach ($line in $out) {
    if ($line -match 'Recom.*Limpieza|Cleanup Recommended') {
      if ($line -match 'Sí|Yes') { $rec = $true } else { $rec = $false }
    }
    if ($line -match '(Backups.*|Copia de seguridad.*):\s*([\d\.,]+)\s*(KB|MB|GB)') {
      $val = [double]::Parse($Matches[2].Replace(',','.'))
      $reclaim += Convert-ToGB $val $Matches[3]
    }
    if ($line -match '(Cache.*|Cach[eé].*temporales?)\s*:\s*([\d\.,]+)\s*(KB|MB|GB)') {
      $val = [double]::Parse($Matches[2].Replace(',','.'))
      $reclaim += Convert-ToGB $val $Matches[3]
    }
    if ($line -match '(Date of Last Cleanup|Fecha.*[úu]ltima.*limpieza)\s*:\s*(.+)$') {
      $try = $Matches[2].Trim()
      [datetime]::TryParse($try, [ref]$last) | Out-Null
    }
  }

  [pscustomobject]@{
    ReclaimableGB = [math]::Round($reclaim,2)
    Recommended   = $rec
    Raw           = $out
    LastCleanup   = $last
  }
}

# --- Inicio -------------------------------------------------------------------
Test-Admin
Write-Log $SessionLogHeader
Write-Log "Parámetros: DaysInactive=$DaysInactive, DeepComponentCleanup=$DeepComponentCleanup, SkipProfileDeletion=$SkipProfileDeletion, Schedule=$Schedule"
$freeStart = Get-FreeGB

# Reporte último ResetBase (vía marcador)
$lastResetBase = $null
if (Test-Path $ResetBaseMarker) {
  try { $lastResetBase = Get-Content $ResetBaseMarker -ErrorAction Stop | Select-Object -First 1 } catch { $lastResetBase = $null }
}
Write-Log ("Último /ResetBase registrado: {0}" -f ($(if($lastResetBase){$lastResetBase}else{'desconocido'})))

# --- Estimación de ganancia potencial ----------------------------------------
Write-Log "Estimando ganancia potencial antes de ejecutar…"

# 1) WinSxS (via DISM Analyze)
$dismInfo  = Parse-DismAnalyze
$estWinSxS = [math]::Max($dismInfo.ReclaimableGB, 0)

# 2) Windows Update cache
$WUPath = Join-Path $env:WINDIR 'SoftwareDistribution\Download'
$estWU  = Get-DirSizeGB $WUPath

# 3) Delivery Optimization cache
$DOBase = 'C:\ProgramData\Microsoft\Windows\DeliveryOptimization'
$estDO  = (Get-DirSizeGB (Join-Path $DOBase 'Cache')) + (Get-DirSizeGB (Join-Path $DOBase 'Cache\*'))

# 4) TEMP de usuarios no cargados
$profilesForTemp = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object {
  -not $_.Special -and -not $_.Loaded -and $_.LocalPath -and ($_.LocalPath -like 'C:\Users\*')
}
$estTemp = 0.0
foreach ($p in $profilesForTemp) {
  $estTemp += Get-DirSizeGB (Join-Path $p.LocalPath 'AppData\Local\Temp')
}
$estTemp += Get-DirSizeGB (Join-Path $env:WINDIR 'Temp')

# 5) Perfiles inactivos (≥ DaysInactive) con conversión robusta
$threshold = (Get-Date).AddDays(-[Math]::Abs($DaysInactive))
$profilesForDeletion = @()
$estProfiles = 0.0
if (-not $SkipProfileDeletion) {
  $allProfiles = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object {
    -not $_.Special -and -not $_.Loaded -and
    $_.LocalPath -and ($_.LocalPath -like 'C:\Users\*')
  }

  $profilesForDeletion = foreach ($prof in $allProfiles) {
    $lu = Get-ProfileLastUsed $prof
    if ($lu -and $lu -lt $threshold) { $prof }
  }

  foreach ($prof in $profilesForDeletion) {
    $estProfiles += Get-DirSizeGB $prof.LocalPath
  }
}

$estTotal = [math]::Round(($estWinSxS + $estWU + $estDO + $estTemp + $estProfiles),2)

# DISM recomienda…
$recText = if ($dismInfo.Recommended) { 'Sí' } else { 'No' }
Write-Log ("Estimación: WinSxS={0}, WU={1}, DO={2}, TEMP={3}, Perfiles={4}  -> Total≈ {5}" -f (Human $estWinSxS),(Human $estWU),(Human $estDO),(Human $estTemp),(Human $estProfiles),(Human $estTotal))
Write-Log ("DISM recomienda limpieza WinSxS: {0}" -f $recText)

# Umbral de 5 GB (omite ejecución si no conviene)
$MinGainGB = 5.0
if ($estTotal -lt $MinGainGB) {
  Write-Log ("Ganancia estimada ({0}) < {1:N2} GB. Se omite la ejecución esta vez." -f (Human $estTotal), $MinGainGB)
  Write-Log "Fin (sin cambios)."
  Write-Output ("[INFO] Ganancia estimada insuficiente ({0}); limpieza omitida. Último /ResetBase: {1}. Log: {2}" -f (Human $estTotal), ($(if($lastResetBase){$lastResetBase}else{'desconocido'})), $GlobalLog)
  return
}

# --- Acumuladores por sección -------------------------------------------------
$gain = [ordered]@{
  'WinSxS'   = 0.0
  'WUCache'  = 0.0
  'DOcache'  = 0.0
  'TEMP'     = 0.0
  'Perfiles' = 0.0
}

# --- 1) WinSxS ----------------------------------------------------------------
try {
  $before = Get-FreeGB
  Write-Log "Analizando Component Store (DISM /AnalyzeComponentStore)"
  $null = $dismInfo.Raw | Tee-Object -FilePath $GlobalLog -Append

  Write-Log "Ejecutando StartComponentCleanup"
  if ($PSCmdlet.ShouldProcess("Component Store", "StartComponentCleanup")) {
    $null = (& Dism.exe /Online /Cleanup-Image /StartComponentCleanup *>&1 | Tee-Object -FilePath $GlobalLog -Append)
  }

  if ($DeepComponentCleanup.IsPresent) {
    Write-Log "Evaluando /ResetBase…"
    if ($estWinSxS -ge 1) {
      Write-Log "Ejecutando StartComponentCleanup /ResetBase (impide desinstalar updates existentes)"
      if ($PSCmdlet.ShouldProcess("Component Store", "StartComponentCleanup /ResetBase")) {
        $null = (& Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase *>&1 | Tee-Object -FilePath $GlobalLog -Append)
        (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') | Set-Content -Path $ResetBaseMarker -Encoding UTF8
        Write-Log ("Marcado último /ResetBase: {0}" -f (Get-Content $ResetBaseMarker))
      }
    } else {
      Write-Log "Se omite /ResetBase: estimación WinSxS < 1 GB."
    }
  }

  $after = Get-FreeGB
  $gain['WinSxS'] = [math]::Max([math]::Round(($after - $before),2), 0)
  Write-Log ("WinSxS liberado ≈ {0}" -f (Human $gain['WinSxS']))
}
catch {
  Write-Log "ERROR DISM: $($_.Exception.Message)"
}

# --- 2) Windows Update cache --------------------------------------------------
try {
  $before = Get-FreeGB
  Write-Log "Parando servicios de Windows Update (wuauserv) y BITS"
  $wuWasRunning   = (Get-Service wuauserv).Status -eq 'Running'
  $bitsWasRunning = (Get-Service bits).Status -eq 'Running'
  if ($wuWasRunning)   { Stop-Service wuauserv -Force -ErrorAction SilentlyContinue }
  if ($bitsWasRunning) { Stop-Service bits -Force -ErrorAction SilentlyContinue }

  if (Test-Path $WUPath) {
    Write-Log "Borrando contenido de $WUPath"
    if ($PSCmdlet.ShouldProcess($WUPath, "Remove contents")) {
      Get-ChildItem -Path $WUPath -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
  }

  if ($wuWasRunning)   { Start-Service wuauserv -ErrorAction SilentlyContinue }
  if ($bitsWasRunning) { Start-Service bits -ErrorAction SilentlyContinue }

  $after = Get-FreeGB
  $gain['WUCache'] = [math]::Max([math]::Round(($after - $before),2), 0)
  Write-Log ("Windows Update cache liberado ≈ {0}" -f (Human $gain['WUCache']))
}
catch {
  Write-Log "ERROR SoftwareDistribution: $($_.Exception.Message)"
}

# --- 3) Delivery Optimization cache ------------------------------------------
try {
  $before = Get-FreeGB
  if (Get-Command Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue) {
    Write-Log "Limpiando caché de Delivery Optimization (Delete-DeliveryOptimizationCache)"
    if ($PSCmdlet.ShouldProcess("Delivery Optimization Cache", "Delete-DeliveryOptimizationCache -Force -IncludePinnedFiles")) {
      $null = (Delete-DeliveryOptimizationCache -Force -IncludePinnedFiles | Tee-Object -FilePath $GlobalLog -Append)
    }
  } else {
    $doPath1 = Join-Path $DOBase 'Cache'
    if (Test-Path $doPath1) {
      Write-Log "Cmdlet DO no disponible; limpiando carpeta $doPath1"
      if ($PSCmdlet.ShouldProcess($doPath1, "Remove contents")) {
        Get-ChildItem -Path $doPath1 -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
      }
    }
  }
  $after = Get-FreeGB
  $gain['DOcache'] = [math]::Max([math]::Round(($after - $before),2), 0)
  Write-Log ("Delivery Optimization liberado ≈ {0}" -f (Human $gain['DOcache']))
}
catch {
  Write-Log "ERROR Delivery Optimization: $($_.Exception.Message)"
}

# --- 4) TEMP por usuario NO cargado ------------------------------------------
Function Clear-UserTemp {
  Param([string]$ProfilePath, [string]$Sid)
  $tempPath = Join-Path $ProfilePath 'AppData\Local\Temp'
  if (Test-Path $tempPath) {
    Write-Log "Limpieza TEMP: $tempPath (SID=$Sid)"
    if ($PSCmdlet.ShouldProcess($tempPath, "Remove contents")) {
      Get-ChildItem -Path $tempPath -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
  }
}

try {
  $before = Get-FreeGB
  Write-Log "Enumerando perfiles para limpieza de TEMP"
  $profiles = Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object {
    -not $_.Special -and -not $_.Loaded -and $_.LocalPath -and ($_.LocalPath -like 'C:\Users\*')
  }

  foreach ($p in $profiles) {
    Clear-UserTemp -ProfilePath $p.LocalPath -Sid $p.SID
  }

  # TEMP del sistema
  $sysTemp = Join-Path $env:WINDIR 'Temp'
  if (Test-Path $sysTemp) {
    Write-Log "Limpieza TEMP sistema: $sysTemp"
    if ($PSCmdlet.ShouldProcess($sysTemp, "Remove contents")) {
      Get-ChildItem -Path $sysTemp -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    }
  }

  $after = Get-FreeGB
  $gain['TEMP'] = [math]::Max([math]::Round(($after - $before),2), 0)
  Write-Log ("TEMP liberado ≈ {0}" -f (Human $gain['TEMP']))
}
catch {
  Write-Log "ERROR limpieza TEMP: $($_.Exception.Message)"
}

# --- 5) Eliminar perfiles inactivos (≥ DaysInactive) --------------------------
if (-not $SkipProfileDeletion) {
  try {
    $before = Get-FreeGB
    Write-Log ("Umbral de inactividad perfiles: {0:yyyy-MM-dd HH:mm}" -f $threshold)

    $candidates = $profilesForDeletion  # ya calculados arriba
    foreach ($prof in $candidates) {
      $lp = $prof.LocalPath
      $lastUse = Get-ProfileLastUsed $prof
      Write-Log ("Eliminando perfil inactivo: {0} (LastUseTime={1})" -f $lp, $lastUse)

      if ($PSCmdlet.ShouldProcess($lp, "Remove-CimInstance Win32_UserProfile")) {
        $sizeGB = Get-DirSizeGB $lp
        Remove-CimInstance -InputObject $prof -ErrorAction SilentlyContinue
        if (Test-Path $lp) {
          try { Remove-Item $lp -Force -Recurse -ErrorAction SilentlyContinue } catch {}
        }
        Write-Log ("   → Perfil liberado (estimado): {0}" -f (Human $sizeGB))
      }
    }

    $after = Get-FreeGB
    $gain['Perfiles'] = [math]::Max([math]::Round(($after - $before),2), 0)
    Write-Log ("Perfiles liberado ≈ {0}" -f (Human $gain['Perfiles']))
  }
  catch {
    Write-Log "ERROR eliminando perfiles: $($_.Exception.Message)"
  }
} else {
  Write-Log "SkipProfileDeletion activo: No se eliminarán perfiles."
}

# --- 6) Programar tarea semanal (Dom 06:00) -----------------------------------
if ($Schedule) {
  try {
    $taskName   = 'StorageCleanup-Weekly'
    $taskFolder = '\Maintenance'
    $scriptPath = $MyInvocation.MyCommand.Path

    if (-not (Test-Path $scriptPath)) {
      throw "No se pudo determinar la ruta del script para agendarlo. Guarda el .ps1 y vuelve a ejecutar con -Schedule."
    }

    $svc = New-Object -ComObject 'Schedule.Service'; $svc.Connect()
    try { $null = $svc.GetFolder($taskFolder) } catch { $svc.GetFolder('\').CreateFolder('Maintenance') | Out-Null }

    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -DaysInactive $DaysInactive -DeepComponentCleanup:$($DeepComponentCleanup.IsPresent) -Verbose"
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 6:00am
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

    $exists = Get-ScheduledTask -TaskName $taskName -TaskPath $taskFolder  -ErrorAction SilentlyContinue
    if ($exists) {
      Write-Log "Actualizando tarea programada $taskFolder\$taskName"
      Set-ScheduledTask -TaskName $taskName -TaskPath $taskFolder -Action $action -Trigger $trigger -Principal $principal | Out-Null
    } else {
      Write-Log "Creando tarea programada $taskFolder\$taskName"
      Register-ScheduledTask -TaskName $taskName -TaskPath $taskFolder -Action $action -Trigger $trigger -Principal $principal -Description "Liberación de espacio semanal (WinSxS, Updates, DO, TEMP, perfiles inactivos)" | Out-Null
    }
  }
  catch {
    Write-Log "ERROR creando/actualizando tarea programada: $($_.Exception.Message)"
  }
}

# --- Fin & Resumen ------------------------------------------------------------
$freeEnd = Get-FreeGB
$totalGain = [math]::Round(($freeEnd - $freeStart),2)
Write-Log ("Resumen por sección: WinSxS={0}, WU={1}, DO={2}, TEMP={3}, Perfiles={4}" -f (Human $gain['WinSxS']),(Human $gain['WUCache']),(Human $gain['DOcache']),(Human $gain['TEMP']),(Human $gain['Perfiles']))
Write-Log ("Espacio libre antes: {0} | después: {1} | total liberado: {2}" -f (Human $freeStart),(Human $freeEnd),(Human $totalGain))
Write-Log "==== Fin ===="
Write-Output ("[OK] Total liberado: {0} (antes {1} → después {2}). Log: {3}" -f (Human $totalGain),(Human $freeStart),(Human $freeEnd), $GlobalLog)