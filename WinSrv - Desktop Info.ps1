<# 
  Desktop Info Widget - Installer (Wallpaper + Click-through + WSB last-8-days)
  Idempotent; safe to re-run. Shows only WSB Event IDs: Success (4) and Failures (5, 517).
#>

$ErrorActionPreference = 'Stop'

# --- Install paths (ProgramData → LocalAppData fallback)
$InstallRoot = Join-Path $env:ProgramData 'DesktopInfoWidget'
try {
  if (-not (Test-Path $InstallRoot)) { New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null }
} catch {
  $InstallRoot = Join-Path $env:LOCALAPPDATA 'DesktopInfoWidget'
  if (-not (Test-Path $InstallRoot)) { New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null }
}
$WidgetScript = Join-Path $InstallRoot 'DesktopInfoWidget.ps1'
$TaskName     = 'Desktop Info Widget'

# --- Runtime script (rewritten on every run)
$widgetPs1 = @'
# Desktop Info Widget (runtime, wallpaper + click-through + WSB last-8-days)
$ErrorActionPreference = "SilentlyContinue"
$Version = "2025-09-01b"

# Configure: how many days of WSB history to show (today + previous N-1 days)
$WSB_WindowDays = 8

# TLS 1.2 for public IP fetch
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

# Single instance guard
$global:mutex = New-Object System.Threading.Mutex($false, "Global\\DesktopInfoWidgetMutex")
if (-not $global:mutex.WaitOne(0, $false)) { exit }

# .NET assemblies
Add-Type -AssemblyName PresentationCore,PresentationFramework,WindowsBase,System.Windows.Forms,System.Drawing

# --- Win32 interop (WorkerW host + click-through styles)
$win32Src = @"
using System;
using System.Runtime.InteropServices;

public static class Win32 {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

    [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern IntPtr FindWindowEx(IntPtr parentHandle, IntPtr childAfter, string lclassName, string windowTitle);

    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll", SetLastError=true)]
    public static extern IntPtr SetParent(IntPtr hWndChild, IntPtr hWndNewParent);

    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

    [DllImport("user32.dll", SetLastError=true)]
    public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam, uint fuFlags, uint uTimeout, out IntPtr lpdwResult);

    public const int GWL_EXSTYLE        = -20;
    public const int WS_EX_TRANSPARENT  = 0x00000020;
    public const int WS_EX_LAYERED      = 0x00080000;
    public const int WS_EX_TOOLWINDOW   = 0x00000080;

    [DllImport("user32.dll", EntryPoint="GetWindowLong", SetLastError=true)]
    public static extern int GetWindowLong32(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll", EntryPoint="GetWindowLongPtr", SetLastError=true)]
    public static extern IntPtr GetWindowLongPtr64(IntPtr hWnd, int nIndex);

    public static IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex) {
        if (IntPtr.Size == 8) return GetWindowLongPtr64(hWnd, nIndex);
        return new IntPtr(GetWindowLong32(hWnd, nIndex));
    }

    [DllImport("user32.dll", EntryPoint="SetWindowLong", SetLastError=true)]
    public static extern int SetWindowLong32(IntPtr hWnd, int nIndex, int dwNewLong);

    [DllImport("user32.dll", EntryPoint="SetWindowLongPtr", SetLastError=true)]
    public static extern IntPtr SetWindowLongPtr64(IntPtr hWnd, int nIndex, IntPtr dwNewLong);

    public static IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong) {
        if (IntPtr.Size == 8) return SetWindowLongPtr64(hWnd, nIndex, dwNewLong);
        return new IntPtr(SetWindowLong32(hWnd, nIndex, dwNewLong.ToInt32()));
    }
}
"@
Add-Type -TypeDefinition $win32Src -Language CSharp

function Get-WorkerWHandle {
    $progman = [Win32]::FindWindow("Progman", $null)
    if ($progman -ne [IntPtr]::Zero) {
        $out = [IntPtr]::Zero
        [void][Win32]::SendMessageTimeout($progman, 0x052C, [IntPtr]::Zero, [IntPtr]::Zero, 0, 1000, [ref]$out)
    }

    $script:found = [IntPtr]::Zero
    $callback = [Win32+EnumWindowsProc]{
        param([IntPtr]$h, [IntPtr]$l)
        $shell = [Win32]::FindWindowEx($h, [IntPtr]::Zero, "SHELLDLL_DefView", $null)
        if ($shell -ne [IntPtr]::Zero) {
            $w = [Win32]::FindWindowEx([IntPtr]::Zero, $h, "WorkerW", $null)
            if ($w -ne [IntPtr]::Zero) { $script:found = $w; return $false }
        }
        return $true
    }
    [void][Win32]::EnumWindows($callback, [IntPtr]::Zero)
    if ($script:found -ne [IntPtr]::Zero) { return $script:found }
    if ($progman -ne [IntPtr]::Zero) { return $progman }
    return [IntPtr]::Zero
}

# --- Style (neutral palette, system fonts)
$bgColor     = "#202225"
$fgColor     = "#DADADA"
$mutedColor  = "#A8B0B9"
$accentColor = "#B7C5D3"
$headerFont  = "Segoe UI"
$monoFont    = "Consolas"

# --- Data providers
function Get-PublicIP {
    $urls = @('https://api.ipify.org','https://ifconfig.me/ip','https://ipv4.icanhazip.com')
    foreach ($u in $urls) {
        try {
            $res = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 4
            $ip  = ($res.Content).Trim()
            if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') { return $ip }
        } catch {}
    }
    'Unavailable'
}
function Get-LocalIPv4 {
    try {
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
          Where-Object { $_.IPAddress -ne '127.0.0.1' -and -not ($_.IPAddress -like '169.254.*') -and $_.PrefixLength } |
          Sort-Object InterfaceAlias,IPAddress |
          Select-Object -ExpandProperty IPAddress
    } catch {
        (ipconfig | Select-String 'IPv4 Address.*?:\s*(\d+\.\d+\.\d+\.\d+)').Matches.Value |
          ForEach-Object { ($_ -split ':')[-1].Trim() }
    }
}
function Get-ComputerDomainSafe {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        if ($cs.PartOfDomain -and $cs.Domain) { return $cs.Domain }
        elseif ($cs.Workgroup) { return $cs.Workgroup }
    } catch {}
    $env:USERDOMAIN
}

# --- WSB: only ID 4 (success) and failures (5, 517) within last $WSB_WindowDays; ignore ID 14
function Get-WSBEventsText {
    param([int]$Days = $WSB_WindowDays)

    $start      = (Get-Date).Date.AddDays(-[Math]::Abs($Days))
    $idsSuccess = @(4)
    $idsFail    = @(5,517)  # 5 (Operational log), 517 (Application log)
    $idsWanted  = $idsSuccess + $idsFail

    $events = @()
    $checkedAnyLog = $false

    foreach ($ln in @('Microsoft-Windows-Backup/Operational','Application')) {
        try {
            # Verify log exists/enabled (Operational); Application is always present
            if ($ln -ne 'Application') {
                $logInfo = Get-WinEvent -ListLog $ln -ErrorAction Stop
                if (-not $logInfo.IsEnabled) { continue }
            }
            $fh = @{ LogName = $ln; StartTime = $start; Id = $idsWanted }
            if ($ln -eq 'Application') { $fh.ProviderName = 'Microsoft-Windows-Backup' }
            $ev = Get-WinEvent -FilterHashtable $fh -ErrorAction SilentlyContinue

            # Older builds may log under source "Backup" in Application
            if ((-not $ev) -and $ln -eq 'Application') {
                $fh.ProviderName = 'Backup'
                $ev = Get-WinEvent -FilterHashtable $fh -ErrorAction SilentlyContinue
            }

            if ($ev) { $events += $ev }
            $checkedAnyLog = $true
        } catch {}
    }

    if (-not $checkedAnyLog) { return @("No WS Backup configured") }
    if (-not $events -or $events.Count -eq 0) { return @("No WSB events in last $Days days") }

    $events = $events | Sort-Object TimeCreated -Descending

    $lines = @()
    foreach ($e in $events) {
        $tag = if ($e.Id -eq 4) { 'Success' } else { 'Failure' }
        $msg = ($e.Message -replace '\s+', ' ').Trim()
        $firstSentence = ($msg -split '(\. |\r?\n)')[0]
        $lines += ("{0:yyyy-MM-dd HH:mm} [{1}] (ID {2}) {3}" -f $e.TimeCreated, $tag, $e.Id, $firstSentence)
        if ($lines.Count -ge 20) { break }  # keep the panel compact
    }
    return $lines
}

function Get-Info {
    [PSCustomObject]@{
        Hostname  = $env:COMPUTERNAME
        Domain    = Get-ComputerDomainSafe
        LocalIPs  = (Get-LocalIPv4) -join "`n"
        PublicIP  = Get-PublicIP
        WSB       = (Get-WSBEventsText) -join "`n"
        Timestamp = Get-Date
    }
}

# --- WPF UI (wallpaper + click-through)
$window                    = New-Object System.Windows.Window
$window.Title              = "Desktop Info (Wallpaper)"
$window.WindowStyle        = 'None'
$window.ResizeMode         = 'NoResize'
$window.AllowsTransparency = $true
$window.Background         = New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString($bgColor))
$window.Opacity            = 0.95
$window.Width              = 480
$window.Height             = 700
$window.ShowInTaskbar      = $false
$window.Topmost            = $false
$window.IsHitTestVisible   = $false

$rootGrid = New-Object Windows.Controls.Grid
$rootGrid.Margin = '10'
$rootGrid.IsHitTestVisible = $false
$window.Content = $rootGrid

$stack = New-Object Windows.Controls.StackPanel
$stack.Orientation = 'Vertical'
$stack.Margin = '8'
$stack.IsHitTestVisible = $false
[void]$rootGrid.Children.Add($stack)

function NewHeader($text) {
    $tb = New-Object Windows.Controls.TextBlock
    $tb.Text = $text
    $tb.FontFamily = $headerFont
    $tb.FontSize = 16
    $tb.FontWeight = 'SemiBold'
    $tb.Foreground = New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString($accentColor))
    $tb.Margin = '0,0,0,6'
    $tb.IsHitTestVisible = $false
    $tb
}
function NewLabelValue($labelText, $valueText) {
    $sp = New-Object Windows.Controls.StackPanel
    $sp.Orientation = 'Vertical'
    $sp.IsHitTestVisible = $false
    $lbl = New-Object Windows.Controls.TextBlock
    $lbl.Text = $labelText
    $lbl.FontFamily = $headerFont
    $lbl.FontSize = 12
    $lbl.Foreground = New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString($mutedColor))
    $lbl.Margin = '0,8,0,2'
    $lbl.IsHitTestVisible = $false
    $val = New-Object Windows.Controls.TextBlock
    $val.Text = $valueText
    $val.FontFamily = $headerFont
    $val.FontSize = 14
    $val.Foreground = New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString($fgColor))
    $val.TextWrapping = 'Wrap'
    $val.IsHitTestVisible = $false
    [void]$sp.Children.Add($lbl)
    [void]$sp.Children.Add($val)
    @{ Panel=$sp; ValueBlock=$val }
}

$stack.Children.Add((NewHeader "System & Network")) | Out-Null
$h  = NewLabelValue "Hostname" ""
$d  = NewLabelValue "Domain / Workgroup" ""
$li = NewLabelValue "Local IPv4" ""
$pi = NewLabelValue "Public IPv4" ""
$stack.Children.Add($h.Panel)  | Out-Null
$stack.Children.Add($d.Panel)  | Out-Null
$stack.Children.Add($li.Panel) | Out-Null
$stack.Children.Add($pi.Panel) | Out-Null

# --- WSB section (last $WSB_WindowDays days)
$wsbLabel = New-Object Windows.Controls.TextBlock
$wsbLabel.Text = "Windows Server Backup (last $WSB_WindowDays days)"
$wsbLabel.FontFamily = $headerFont
$wsbLabel.FontSize = 12
$wsbLabel.Foreground = New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString($mutedColor))
$wsbLabel.Margin = '0,10,0,6'
$wsbLabel.IsHitTestVisible = $false
$stack.Children.Add($wsbLabel) | Out-Null

$wsbBox = New-Object Windows.Controls.TextBlock
$wsbBox.FontFamily = $monoFont
$wsbBox.FontSize  = 12
$wsbBox.Foreground = New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString($fgColor))
$wsbBox.TextWrapping = 'Wrap'
$wsbBox.IsHitTestVisible = $false
$wsbBox.Text = ""
$stack.Children.Add($wsbBox) | Out-Null

# Timestamp
$ts = New-Object Windows.Controls.TextBlock
$ts.FontFamily = $headerFont
$ts.FontSize = 11
$ts.Foreground = New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString($mutedColor))
$ts.Margin = '0,6,0,0'
$ts.IsHitTestVisible = $false
$stack.Children.Add($ts) | Out-Null

# Position at top-right
$wa = [System.Windows.SystemParameters]::WorkArea
$window.Left = $wa.Right - $window.Width - 12
$window.Top  = $wa.Top + 12

# Refresh routine
function Update-UI {
    $info = Get-Info
    $h.ValueBlock.Text  = $info.Hostname
    $d.ValueBlock.Text  = $info.Domain
    $li.ValueBlock.Text = $info.LocalIPs
    $pi.ValueBlock.Text = $info.PublicIP
    $wsbBox.Text        = $info.WSB
    $ts.Text            = "Updated: " + ($info.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"))
}

# Host behind icons + click-through
$window.SourceInitialized.Add({
    $helper = New-Object System.Windows.Interop.WindowInteropHelper($window)
    $hwnd   = $helper.Handle
    $worker = Get-WorkerWHandle
    if ($worker -ne [IntPtr]::Zero) {
        [void][Win32]::SetParent($hwnd, $worker)
        $HWND_BOTTOM    = [IntPtr]1
        $SWP_NOSIZE     = 0x0001
        $SWP_NOMOVE     = 0x0002
        $SWP_NOACTIVATE = 0x0010
        [void][Win32]::SetWindowPos($hwnd, $HWND_BOTTOM, 0,0,0,0, ($SWP_NOSIZE -bor $SWP_NOMOVE -bor $SWP_NOACTIVATE))
        $ex   = [Win32]::GetWindowLongPtr($hwnd, [Win32]::GWL_EXSTYLE).ToInt64()
        $ex  = $ex -bor [Win32]::WS_EX_TRANSPARENT -bor [Win32]::WS_EX_LAYERED -bor [Win32]::WS_EX_TOOLWINDOW
        [void][Win32]::SetWindowLongPtr($hwnd, [Win32]::GWL_EXSTYLE, [IntPtr]$ex)
    }
})

# Tray icon (control)
$notifyIcon = New-Object System.Windows.Forms.NotifyIcon
$notifyIcon.Icon = [System.Drawing.SystemIcons]::Information
$notifyIcon.Visible = $true
$notifyIcon.Text = "Desktop Info (Wallpaper)"
$menu = New-Object System.Windows.Forms.ContextMenuStrip
$miRefresh = New-Object System.Windows.Forms.ToolStripMenuItem
$miRefresh.Text = "Refresh now"
$miRefresh.add_Click({ Update-UI })
[void]$menu.Items.Add($miRefresh)
$miExit = New-Object System.Windows.Forms.ToolStripMenuItem
$miExit.Text = "Exit"
$miExit.add_Click({ try { $global:mutex.ReleaseMutex() | Out-Null } catch {}; $window.Close() })
[void]$menu.Items.Add($miExit)
$notifyIcon.ContextMenuStrip = $menu
$window.Closing.Add({ $notifyIcon.Visible = $false; $notifyIcon.Dispose() })

# Initial + timer
Update-UI
$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(60)
$timer.Add_Tick({ Update-UI })
$timer.Start() | Out-Null

[void]$window.ShowDialog()
try { $global:mutex.ReleaseMutex() | Out-Null } catch {}
'@

# Write runtime
$widgetPs1 | Out-File -FilePath $WidgetScript -Encoding UTF8 -Force

# --- Autostart (Scheduled Task → HKCU Run fallback)
function Ensure-Autostart {
  param([string]$TaskName,[string]$ScriptPath)
  $created = $false
  try {
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    try {
      $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel LeastPrivilege
    } catch {
      $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType InteractiveOrPassword -RunLevel LeastPrivilege
    }
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal | Out-Null
    $created = $true
  } catch { $created = $false }
  if (-not $created) {
    $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    New-Item -Path $runKey -Force | Out-Null
    New-ItemProperty -Path $runKey -Name 'DesktopInfoWidget' -PropertyType String -Force `
      -Value "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`"" | Out-Null
    return "RunKey"
  } else { return "ScheduledTask" }
}
$autostartMethod = Ensure-Autostart -TaskName $TaskName -ScriptPath $WidgetScript

# --- Restart running instance (if any), then launch fresh
try {
  $needle = [Regex]::Escape($WidgetScript)
  $proc = Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
          Where-Object { $_.CommandLine -and $_.CommandLine -match $needle }
  if ($proc) {
    $proc | ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch {} }
    Start-Sleep -Milliseconds 300
  }
} catch {}
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$WidgetScript`"" -WindowStyle Hidden

Write-Host "✅ Desktop Info Widget installed/updated in: $InstallRoot"
Write-Host "   Autostart: $autostartMethod (Task '$TaskName' or HKCU\\...\\Run)"
Write-Host "   WSB panel: IDs 4 (success) and 5/517 (failure), last $([int]($WSB_WindowDays)) days"