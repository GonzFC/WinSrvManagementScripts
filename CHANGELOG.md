# Changelog

All notable changes to Windows Management Toolbox will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.5] - 2024-12-24

### Fixed
- **CRITICAL**: Module loading now works reliably on Windows Server 2012 R2 / 2016
- Removed cross-module Import-Module statements that caused empty path errors
- Fixed `$PSScriptRoot` undefined issue when using Invoke-Expression
- All modules now use `$Global:ToolboxRoot` for script directory references

### Changed
- Module loading architecture completely refactored to use Invoke-Expression
- Added `$Global:ToolboxRoot` global variable for module path references
- Removed all Export-ModuleMember statements (not needed with Invoke-Expression)

### Technical Details
- Modules loaded with `Get-Content -Raw` + `Invoke-Expression`
- Eliminates PowerShell 5.1 module session state isolation issues
- Functions remain available in script scope throughout execution
- No more cross-module dependencies

## [1.0.4] - 2024-12-24

### Changed
- Switched from dot-sourcing to Invoke-Expression for module loading
- Improved error diagnostics showing available functions and error line numbers

### Fixed
- Resolved issue where dot-sourcing caused .psm1 files to open in Notepad
- Added explicit file content reading to bypass Windows file association issues

## [1.0.3] - 2024-12-24

### Changed
- Commented out all Export-ModuleMember statements in modules
- Switched to dot-sourcing for module loading

### Fixed
- Export-ModuleMember was removing functions when dot-sourcing (opposite of intended behavior)

## [1.0.2] - 2024-12-24

### Changed
- Replaced Import-Module with dot-sourcing for all module files
- Added diagnostic output showing module load status

### Fixed
- Import-Module with -Scope Global not making functions available in script scope
- PowerShell 5.1 module session state isolation preventing function access

## [1.0.1] - 2024-12-24

### Added
- Diagnostic output during module loading
- Version display in startup banner
- Detailed error reporting for module import failures

### Fixed
- Added -Scope Global parameter to Import-Module calls
- Added Unblock-File for all downloaded .psm1 files

## [1.0.0] - 2024-12-24

### Added
- **One-liner installer** inspired by Chris Titus Tech's Windows Utility
  - `iex (irm https://raw.githubusercontent.com/GonzFC/WinSrvManagementScripts/main/install.ps1)`
- **Automatic version checking and updates**
  - Checks GitHub on startup for newer versions
  - Manual update check via main menu option 7
  - Auto-downloads and runs installer for updates
- **Versioning system** with version.txt tracking
- **Start Menu shortcut** with Windows icon
  - Installed to: All Users > Programs > Windows Management Toolbox

### Changed
- Main menu now shows version number in title
- Added -SkipUpdateCheck parameter to bypass update check
- Installer creates Start Menu shortcut automatically

### Technical Details
- Version stored in $script:ToolboxVersion variable
- Remote version checked via version.txt on GitHub
- Semantic versioning (Major.Minor.Patch)

## [0.9.0] - 2024-12-17

### Added
- **XCP-ng Windows PV Tools support** as primary virtualization option
  - XCP-ng PV Tools v9.1.100 (digitally signed, latest stable)
  - Requires Windows 10 1607+ / Server 2016+
  - Automatic OS compatibility detection
  - XenServer/Citrix tools available as secondary option for older OS
- Interactive menu for virtualization tools selection
- Comprehensive compatibility warnings and recommendations

### Changed
- Virtualization tools installer now offers XCP-ng as Option 1 (recommended)
- XenServer/Citrix tools moved to Option 2 (legacy support)
- Updated documentation with XCP-ng benefits and security fixes (XSA-468)

## [0.8.0] - 2024-12-17

### Fixed
- **Edge browser privacy settings** now properly disable MSN homepage on Windows 10/11
  - Added NewTabPageSetFeedType=0 (disables MSN feed)
  - Added NewTabPageContentEnabled=0 (disables new tab content)
  - Added NewTabPageQuickLinksEnabled=0 (disables quick links)
  - Added EdgeAssetDeliveryServiceEnabled=0 (disables news/ads delivery)
- Variable interpolation syntax error in Common.psm1 (PowerShell parser issue with `$_:`)
- Module path variable collision in WinToolbox.ps1 (loop variable overwrote directory variable)

### Changed
- All text converted to English (removed Spanish emoji and text)
- Improved Edge hardening with additional registry policies

### Technical Details
- Fixed `$ServiceName: $_` to `${ServiceName}: ${_}` to prevent parser errors
- Renamed loop variable from `$modulePath` to `$moduleFile` to avoid collision

## [0.7.0] - 2024-12-17

### Added
- **Modular architecture** with 5 separate modules:
  - Common.psm1: Shared utilities (logging, admin checks, OS detection, UI helpers)
  - SystemOptimization.psm1: Disk cleanup and UI optimization
  - SecurityPrivacy.psm1: Browser hardening
  - RemoteAccess.psm1: Tailscale and Jump Desktop installers
  - Maintenance.psm1: Desktop Info, TLS upgrade, VM tools
- **Centralized logging** to C:\VLABS\Maintenance\
- **Individual profile deletion confirmation** prompts
- **Prerequisites checking** (admin rights, PowerShell version)
- **Menu-driven interface** with categorized options
  - System Optimization
  - Remote Access
  - Security & Privacy
  - Maintenance
  - View System Information
  - View Logs

### Changed
- Unified 8 standalone scripts into single WinToolbox.ps1 launcher
- All scripts now use consistent logging framework
- Improved error handling throughout

### Technical Details
- Import-Module used for loading .psm1 modules
- Export-ModuleMember exports all functions from modules
- Ordered hashtables for menu display
- Show-Menu function with AllowBack support

## [0.6.0] - Initial Standalone Scripts

### Available Scripts
- WinSrv - Desktop Info.ps1
- WinSrv - 2012R2 SSL TLS Upgrader.ps1
- WinSrv - Jump Desktop Connect Installer.ps1
- WinSrv - Disable Backgrounds and Animations.ps1
- WinSrv - Microsoft Edge Clean.ps1
- WinSrv - Tailscale Installer.ps1
- WinSrv - Reclaim Disk Space.ps1
- WinSrv - XenSrv Tools Install.ps1

---

## Version History Summary

| Version | Date | Key Changes |
|---------|------|-------------|
| 1.0.5 | 2024-12-24 | ✅ **STABLE** - Fixed module loading with Invoke-Expression |
| 1.0.4 | 2024-12-24 | Switched to Invoke-Expression for module loading |
| 1.0.3 | 2024-12-24 | Removed Export-ModuleMember from modules |
| 1.0.2 | 2024-12-24 | Attempted dot-sourcing approach |
| 1.0.1 | 2024-12-24 | Added diagnostics and -Scope Global |
| 1.0.0 | 2024-12-24 | One-liner installer and auto-updates |
| 0.9.0 | 2024-12-17 | XCP-ng PV Tools support added |
| 0.8.0 | 2024-12-17 | Edge privacy fixes and bug fixes |
| 0.7.0 | 2024-12-17 | Initial modular architecture |
| 0.6.0 | Earlier | Original standalone scripts |

---

## Upgrade Notes

### From 0.x to 1.0.5

If you were using the standalone scripts:
1. Run the one-liner installer: `iex (irm https://raw.githubusercontent.com/GonzFC/WinSrvManagementScripts/main/install.ps1)`
2. All your scripts are now unified in the menu-driven toolbox
3. Start Menu shortcut created automatically
4. Auto-updates enabled by default

### Module Loading Architecture Change (1.0.0 → 1.0.5)

The module loading mechanism went through several iterations to solve PowerShell 5.1 compatibility issues:

| Version | Method | Status | Issue |
|---------|--------|--------|-------|
| 0.7.0 - 1.0.0 | Import-Module | ❌ Failed | Session state isolation |
| 1.0.1 | Import-Module -Scope Global | ❌ Failed | Still isolated in PS 5.1 |
| 1.0.2 | Dot-sourcing | ❌ Failed | File opened in Notepad |
| 1.0.3 | Dot-sourcing without Export | ❌ Failed | Same file association issue |
| 1.0.4 | Invoke-Expression | ⚠️ Partial | Cross-module import errors |
| 1.0.5 | Invoke-Expression + No cross-imports | ✅ **Success** | Fully working |

---

## Known Issues

None currently reported for v1.0.5.

## Future Enhancements

Potential features for future versions:
- Configuration file support for default settings
- Additional browser hardening (Chrome, Firefox)
- Enhanced telemetry removal options
- Custom scheduled task configurations
- Export/import settings profiles
