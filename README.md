# Windows Management Toolbox

A unified, menu-driven PowerShell application for Windows Server and Client management tasks.

## Quick Start

```powershell
iex (irm https://raw.githubusercontent.com/GonzFC/WinSrvManagementScripts/main/install.ps1)
```

One command to install and run the complete Windows management suite!

## Features

### System Optimization
- **Disk Space Reclamation**: Comprehensive cleanup of WinSxS, Windows Update cache, Delivery Optimization, TEMP folders, and inactive user profiles
- **UI Optimization**: Disable backgrounds and animations across all users

### Remote Access
- **Tailscale VPN**: Automated installation and configuration with unattended mode
- **Jump Desktop Connect**: Remote desktop solution installer with RDP tunneling

### Security & Privacy
- **Edge Browser Hardening**: Privacy-focused configuration with about:blank homepage, DuckDuckGo search, disabled MSN feed, and minimal tracking

### Maintenance
- **Desktop Info Widget**: System and network information overlay on desktop
- **TLS/PowerShell Upgrade**: Modernize legacy Windows systems (2008R2/2012/2012R2) with TLS 1.2, .NET 4.8, and PowerShell 5.1
- **Virtualization Guest Tools**: Automated installation of XCP-ng Windows PV Tools or XenServer/Citrix Hypervisor VM Tools
  - XCP-ng PV Tools v9.1.100 (recommended for XCP-ng hosts, requires Windows 10 1607+/Server 2016+)
  - XenServer/Citrix VM Tools (compatible with older Windows versions)

### Performance
- **Network Speed Test**: Peer-to-peer bidirectional bandwidth testing using iperf3
  - Automatic iperf3 installation (no Visual C++ runtime required)
  - Upload and download measured separately with 4 parallel TCP streams
  - Test durations: Quick (5s), Standard (10s), Extended (30s)

### Windows Update Management
- **Configure Windows Update** (option 10): Stable, predictable security patching
  - Sunday 4 AM maintenance window
  - Critical security updates only, no driver or feature updates
  - 365-day feature update deferral
- **Disable Windows Updates** (option 11): Full manual control
  - Disables all automatic update downloads and installations
  - Optional: completely disable the wuauserv service
  - Updates remain available for manual installation

## Requirements

- **PowerShell**: Version 5.1 or higher
- **Privileges**: Administrator rights required
- **Operating System**: Windows Server 2012 R2+ or Windows 10/11

## Installation

### One-Liner Installation (Recommended)

Open PowerShell as Administrator and run:

```powershell
iex (irm https://raw.githubusercontent.com/GonzFC/WinSrvManagementScripts/main/install.ps1)
```

Or the alternative syntax:

```powershell
irm https://raw.githubusercontent.com/GonzFC/WinSrvManagementScripts/main/install.ps1 | iex
```

This will:
- Automatically elevate to Administrator if needed
- Download the latest version from GitHub
- Install to `C:\ProgramData\WinToolbox`
- Create a Start Menu shortcut
- Offer to launch the toolbox immediately

### Manual Installation

1. Clone or download this repository
2. Ensure the following structure exists:
   ```
   WinSrvManagementScripts/
   ├── WinToolbox.ps1          # Main launcher
   ├── modules/
   │   ├── Common.psm1
   │   ├── SystemOptimization.psm1
   │   ├── SecurityPrivacy.psm1
   │   ├── RemoteAccess.psm1
   │   └── Maintenance.psm1
   └── README.md
   ```
3. Run `WinToolbox.ps1` as Administrator

## Usage

### Interactive Mode

After installation, you can run the toolbox in several ways:

**From Start Menu:**
- Search for "Windows Management Toolbox" and click the shortcut

**From PowerShell:**
```powershell
cd C:\ProgramData\WinToolbox
.\WinToolbox.ps1
```

**Or if you cloned manually:**
```powershell
cd C:\Path\To\WinSrvManagementScripts
.\WinToolbox.ps1
```

Navigate through the menu using number keys:

```
Windows Management Toolbox v1.0.9
==================================

System Optimization:
  [1] Reclaim Disk Space
  [2] Disable Backgrounds and Animations

Remote Access:
  [3] Install Tailscale VPN
  [4] Install Jump Desktop Connect

Security & Privacy:
  [5] Harden Microsoft Edge

Maintenance:
  [6] Install Desktop Info Widget
  [7] Upgrade TLS and PowerShell
  [8] Install Virtualization Tools (XCP-ng / XenServer)

Performance & Updates:
  [9]  Network Speed Test (iperf3)
  [10] Configure Windows Update (Stable Security Patching)
  [11] Disable Windows Updates (Manual Control Only)

System:
  [12] View System Information
  [13] View Logs
  [14] Check for Updates

  [Q] Quit
```

### Updating the Toolbox

To update to the latest version, simply run the one-liner installer again:

```powershell
iex (irm https://raw.githubusercontent.com/GonzFC/WinSrvManagementScripts/main/install.ps1)
```

This will download and replace the existing installation with the latest version.

### Automated Disk Cleanup (Scheduled Task)

The disk cleanup function can create a weekly scheduled task:

```powershell
.\WinToolbox.ps1
# Select: 1 (System Optimization) -> 1 (Reclaim Disk Space)
# Answer "Yes" when prompted to create scheduled task
```

Or run cleanup directly:

```powershell
.\WinToolbox.ps1 -AutoCleanup -DaysInactive 30 -DeepComponentCleanup
```

## Logging

All operations are logged to: `C:\VLABS\Maintenance\`

View logs from within the toolbox:
- Main Menu -> 6 (View Logs)

## Architecture

### Modular Design

The toolbox uses a modular architecture for easy maintenance:

- **Common.psm1**: Shared utilities (logging, admin checks, OS detection, UI helpers)
- **SystemOptimization.psm1**: Disk cleanup and UI optimization functions
- **SecurityPrivacy.psm1**: Browser hardening and privacy configurations
- **RemoteAccess.psm1**: Remote access solution installers
- **Maintenance.psm1**: System maintenance and upgrade tools

### Why Modular?

- Easy to maintain and update individual components
- Clear separation of concerns
- Better version control with granular change tracking
- Reusable modules for other scripts
- Simplified testing

## Safety Features

- **Administrator Check**: Automatically prompts for elevation
- **PowerShell Version Check**: Ensures compatibility
- **Profile Deletion Confirmation**: Individual prompts for each inactive profile
- **Dry-run Estimation**: Disk cleanup estimates gains before execution
- **Minimum Gain Threshold**: Skips cleanup if estimated gain < 5 GB
- **Comprehensive Logging**: All operations logged with timestamps

## Original Scripts

The original standalone scripts are preserved in the repository for reference:

- `WinSrv - Desktop Info.ps1`
- `WinSrv - 2012R2 SSL TLS Upgrader.ps1`
- `WinSrv - Jump Desktop Connect Installer.ps1`
- `WinSrv - Disable Backgrounds and Animations.ps1`
- `WinSrv - Microsoft Edge Clean.ps1`
- `WinSrv - Tailscale Installer.ps1`
- `WinSrv - Reclaim Disk Space.ps1`
- `WinSrv - XenSrv Tools Install.ps1`

## Recent Improvements

### XCP-ng Guest Tools Support (December 2024)

The virtualization tools installer now supports both XCP-ng and XenServer:

- **XCP-ng Windows PV Tools v9.1.100** (Primary Option)
  - Latest stable release with digitally signed drivers
  - Improved performance and features for XCP-ng hosts
  - Requires Windows 10 1607 / Windows Server 2016 or newer
  - Open-source and community-supported
  - Includes security fixes for XSA-468 vulnerabilities

- **XenServer/Citrix Hypervisor VM Tools** (Legacy Option)
  - Official Citrix management agent
  - Compatible with older Windows versions
  - Stable and widely deployed

The installer automatically detects OS compatibility and recommends the appropriate option.

### Edge Browser Fix (Windows 10/11)

The Edge hardening script now properly disables the MSN home page and news feed on Windows 10/11 clients by:

- Setting `NewTabPageSetFeedType = 0` (disables MSN feed)
- Setting `NewTabPageContentEnabled = 0` (disables new tab content)
- Setting `NewTabPageQuickLinksEnabled = 0` (disables quick links)
- Setting `ShowHomeButton = 0` (hides home button)
- Setting `EdgeAssetDeliveryServiceEnabled = 0` (disables news/ads delivery)

## Troubleshooting

### Module Loading Issues

If you encounter "function not recognized" errors, this is typically due to PowerShell module loading challenges on Windows Server 2012 R2 / 2016 with PowerShell 5.1.

**Symptoms:**
- Functions like `Show-Menu`, `Initialize-Logging`, or `Test-Administrator` not recognized
- Modules appear to load successfully but functions aren't available
- Script cycles with "Invalid selection" errors

**Root Causes Identified:**

1. **Import-Module with -Scope Global doesn't work reliably** when scripts are launched via `Start-Process`
   - PowerShell 5.1 creates module session state isolation
   - Functions exist in module scope but aren't accessible from script scope
   - This is a known PowerShell 5.1 limitation

2. **Dot-sourcing (.psm1 files) can fail** due to Windows file associations
   - .psm1 files may open in Notepad instead of executing
   - Execution policy or file association issues prevent proper loading

3. **Export-ModuleMember conflicts with dot-sourcing**
   - When dot-sourcing, Export-ModuleMember removes functions instead of exporting them
   - This command only works correctly with Import-Module

4. **Cross-module dependencies cause empty path errors**
   - `$PSScriptRoot` is undefined when using Invoke-Expression
   - Modules trying to import other modules fail with empty string path errors

**Solution Implemented (v1.0.5):**

The toolbox uses **Invoke-Expression** to load module content:
```powershell
$moduleContent = Get-Content -Path $moduleFile -Raw
Invoke-Expression $moduleContent
```

**Why this works:**
- Explicitly reads file content and executes in current scope
- Bypasses file association and execution policy issues
- No module session state isolation
- Functions remain available throughout script execution

**Key implementation details:**
- `$Global:ToolboxRoot` provides script directory to modules (replaces `$PSScriptRoot`)
- All modules loaded in dependency order (Common first)
- No cross-module Import-Module statements needed
- Export-ModuleMember commented out (not needed with Invoke-Expression)

### Syntax Errors in Windows Update Scripts

**Symptoms** (after editing on macOS):
- "Missing string terminator"
- "Missing closing brace"
- "Output stream already redirected"
- All errors cascade from a single line far above the actual problem

**Root Cause:**
Scripts saved as **UTF-8 without BOM** on macOS are read by PowerShell 5.1 on Windows
as **Windows-1252**. The UTF-8 byte sequence for `checkmark U+2713` (`0xE2 0x9C 0x93`)
decodes in Windows-1252 as three characters, the last being a **curly left double-quote
(0x93)**. That stray quote terminates any string it lands inside, producing all the above
cascading errors. The error message points to a line far below the Unicode character,
making it appear unrelated.

**Rule:** Files without a UTF-8 BOM must contain **only ASCII characters** (codepoints
0-127). Use `[OK]`, `[X]`, `[!]` instead of `checkmark`, `ballot X`, `warning sign`.

**Check for Unicode in your files:**
```powershell
# On macOS/Linux
python3 -c "
import glob
for f in glob.glob('**/*.ps1', recursive=True) + glob.glob('**/*.psm1', recursive=True):
    chars = {repr(c) for line in open(f, encoding='utf-8') for c in line if ord(c) > 127}
    if chars: print(f, chars)
"
```

**Files with `\ufeff` (BOM) are safe** - PowerShell 5.1 will correctly read them as UTF-8
and Unicode symbols will display properly.

### Installation Issues

**Problem: Installer fails to download**
- **Solution**: Ensure TLS 1.2 is enabled: `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12`
- **Alternative**: Use Git clone method instead of ZIP download

**Problem: Files blocked by execution policy**
- **Solution**: The installer automatically runs `Unblock-File` on all downloaded files
- **Manual fix**: `Get-ChildItem C:\ProgramData\WinToolbox -Recurse | Unblock-File`

### Version History

See [CHANGELOG.md](CHANGELOG.md) for detailed version history and changes.

## Contributing

When adding new functionality:

1. Add functions to the appropriate module in `modules/`
2. Update `WinToolbox.ps1` to add menu entries
3. Use the `Write-LogMessage` function for all logging
4. Follow the existing code style and error handling patterns
5. **Important**: Do not use `$PSScriptRoot` - use `$Global:ToolboxRoot` instead
6. **Important**: Do not add `Import-Module` statements between modules
7. **Important**: Do not use `Export-ModuleMember` in .psm1 files
8. **Important**: Use only ASCII characters (0-127) in `.ps1` and `.psm1` files that
   do NOT have a UTF-8 BOM. Unicode symbols (`checkmark`, `arrow`, `bullet`) will
   corrupt string parsing on Windows PowerShell 5.1. Use `[OK]`, `[X]`, `[!]`, `->` instead.

### Development Notes

**Module Loading Architecture:**
- Modules loaded with `Invoke-Expression` (Get-Content + Invoke-Expression)
- All modules loaded in WinToolbox.ps1 in dependency order
- Common.psm1 must be first (provides shared functions)
- `$Global:ToolboxRoot` available to all modules for path references

**Testing Locally:**
```powershell
# Run directly without installer
cd C:\Path\To\WinSrvManagementScripts
.\WinToolbox.ps1

# Test specific module functionality
.\WinToolbox.ps1 -AutoCleanup -DaysInactive 30
```

## License

Internal use - IT Infrastructure Team

## Support

For issues or questions, check the logs in `C:\VLABS\Maintenance\` or contact the IT Infrastructure Team.
