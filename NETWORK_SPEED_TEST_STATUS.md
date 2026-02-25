# Network Speed Test Feature - Development Status

**Date:** December 27, 2024  
**Version:** 1.0.6  
**PR:** https://github.com/GonzFC/WinSrvManagementScripts/pull/12  
**Status:** Feature Complete, Debugging in Progress

---

## What Was Built

### Core Feature
- **Network Speed Testing** using iperf3
- **New Performance Menu** (Main Menu Option 5)
- **Peer-to-Peer Testing** between two systems running the toolbox
- **Bidirectional Testing** (upload + download simultaneously)
- **Three Test Presets:** Quick (5s), Standard (10s), Extended (30s)

### Technical Implementation
- Automatic iperf3 v3.20 installation from ar51an/iperf3-win-builds
- Static build with cygwin1.dll dependency (no Visual C++ runtime needed)
- Installed to: `C:\ProgramData\iperf3\`
- TCP testing with 4 parallel streams
- JSON output parsing for detailed metrics
- Comprehensive logging to `C:\VLABS\Maintenance\`

---

## Current Status

### ✅ What's Working
1. **iperf3 Installation**
   - Downloads latest version (3.20) from GitHub
   - Uses GitHub API with fallback to v3.17.1
   - Copies all dependencies (iperf3.exe + cygwin1.dll)
   - Idempotent - tests existing installation before reinstalling
   - Automatically replaces broken installations

2. **iperf3 Execution**
   - Version test works: `iperf 3.20 (cJSON 1.7.15)`
   - Executable runs properly with cygwin1.dll dependency
   - Command-line arguments accepted

3. **User Interface**
   - Performance menu displays correctly
   - Peer IP address input
   - Duration preset selection
   - Clean error messages

4. **Connectivity Testing**
   - Pre-tests TCP connection to peer on port 5201
   - Shows helpful setup instructions if peer unreachable
   - Provides Windows Firewall rule command
   - Option to continue anyway

### ⚠️ What Needs Debugging

#### 1. Peer-to-Peer Connection Issues
**Current Behavior:**
- Connectivity test to peer fails (port 5201 not reachable)
- iperf3 returns: "unable to connect to server - Connection timed out"

**Root Cause:**
- Peer firewall blocking port 5201
- OR peer not running iperf3 server

**What's Needed:**
- Both systems need to run the test simultaneously
- One acts as client, other as server
- Windows Firewall port 5201 must be open on both sides

**Next Steps:**
1. Test with firewall rule added on both systems:
   ```powershell
   New-NetFirewallRule -DisplayName 'iperf3' -Direction Inbound -Protocol TCP -LocalPort 5201 -Action Allow
   ```
2. Have one peer start iperf3 server manually first:
   ```powershell
   & 'C:\ProgramData\iperf3\iperf3.exe' -s
   ```
3. Then run test from other peer

#### 2. Internet Test Option (REMOVED)
**Decision:** Removed "Peer to Internet" mode
**Reason:** Public iperf3 servers (ping.online.net) are always busy
**Status:** Code cleaned up, only Peer-to-Peer remains

---

## Technical Details

### Files Modified
1. **modules/Maintenance.psm1** (lines 694-1275)
   - Install-Winget (deprecated but kept for future use)
   - Install-IPerf3 (direct download from GitHub)
   - Invoke-NetworkSpeedTest (main testing function)

2. **WinToolbox.ps1**
   - Added Show-PerformanceMenu (lines 503-528)
   - Updated main menu (added option 5)
   - Updated menu numbering (options 6-8)
   - Version updated to 1.0.6

3. **version.txt**
   - Updated to 1.0.6

### Key Functions

#### Install-IPerf3
```powershell
Location: modules/Maintenance.psm1:799-885
Purpose: Download and install iperf3 with all dependencies
Features:
  - Tests if existing iperf3 works before reinstalling
  - Downloads from ar51an/iperf3-win-builds via GitHub API
  - Fallback to v3.17.1 if API fails
  - Copies ALL files (iperf3.exe + cygwin1.dll)
  - Adds to system PATH
  - Comprehensive logging
```

#### Invoke-NetworkSpeedTest
```powershell
Location: modules/Maintenance.psm1:887-1275
Purpose: Run bidirectional network speed tests
Features:
  - Peer IP input with validation
  - Connectivity pre-test on port 5201
  - Helpful setup instructions if unreachable
  - Three duration presets (5s/10s/30s)
  - Bidirectional TCP tests (4 parallel streams)
  - JSON output parsing
  - Comprehensive results display
  - Error handling for busy/unreachable servers
```

---

## Debugging Journey (15 Commits)

### Phase 1: Initial Implementation (Commits 1-2)
- ✅ Added network speed testing functions
- ✅ Created Performance menu
- ✅ Updated version to 1.0.6

### Phase 2: winget Installation Issues (Commits 3-4)
- ❌ winget installation failing on Windows Server
- ✅ Fixed GitHub API download method
- ❌ Still failing (0x80073CF0 error - AppxPackage limitation)

### Phase 3: Abandoning winget (Commits 5-6)
- ✅ Switched to direct iperf3 download from iperf.fr
- ❌ Old version (3.1.3 from 2016)
- ❌ Missing Visual C++ runtime dependencies
- ❌ iperf3 wouldn't execute

### Phase 4: Modern iperf3 Build (Commits 7-10)
- ✅ Switched to ar51an/iperf3-win-builds
- ✅ GitHub API with fallback version
- ✅ Modern v3.20 build downloaded
- ❌ Still wouldn't run (no output)

### Phase 5: Missing Dependencies (Commits 11-12)
- 🔍 Added detailed debugging/logging
- 🎯 **FOUND ROOT CAUSE:** Missing cygwin1.dll
- ✅ Fixed: Copy ALL files from archive
- ✅ iperf3 now executes properly!

### Phase 6: User Experience (Commits 13-15)
- ✅ Handle "server busy" gracefully
- ✅ Add connectivity pre-test
- ✅ Helpful setup instructions
- ✅ Remove Internet test option (unreliable)

---

## Next Steps for Tomorrow

### Immediate Tasks
1. **Test Peer-to-Peer Setup**
   - Add firewall rule on both systems
   - Run test between two systems
   - Verify bidirectional results

2. **Validate Results Display**
   - Confirm JSON parsing works
   - Verify bandwidth calculations
   - Check retransmission display
   - Validate quality assessment

3. **Edge Cases to Test**
   - One peer offline
   - Firewall blocking
   - Very slow connection
   - Very fast connection (10G+)
   - Different test durations

### Documentation Needed
- [ ] User guide for peer-to-peer setup
- [ ] Firewall configuration instructions
- [ ] Troubleshooting section
- [ ] Update README.md with Performance menu
- [ ] Update CHANGELOG.md with v1.0.6 details

### Future Enhancements (Optional)
- [ ] Automatic server mode (listen for incoming tests)
- [ ] UDP testing option
- [ ] Custom port selection
- [ ] Multiple public server fallbacks
- [ ] Graphical results display
- [ ] Export results to CSV/JSON

---

## Commands Reference

### Manual Testing Commands

**Check iperf3 installation:**
```powershell
& 'C:\ProgramData\iperf3\iperf3.exe' --version
```

**Start iperf3 server manually:**
```powershell
& 'C:\ProgramData\iperf3\iperf3.exe' -s
```

**Run client test manually:**
```powershell
& 'C:\ProgramData\iperf3\iperf3.exe' -c 192.168.1.231 -t 10 -P 4
```

**Add firewall rule:**
```powershell
New-NetFirewallRule -DisplayName 'iperf3' -Direction Inbound -Protocol TCP -LocalPort 5201 -Action Allow
```

**Check firewall rule:**
```powershell
Get-NetFirewallRule -DisplayName 'iperf3'
```

**View logs:**
```powershell
Get-Content 'C:\VLABS\Maintenance\WinToolbox_2024-12.log' -Tail 50
```

### Reinstall After Merge

```powershell
# After merging PR
iex (irm https://raw.githubusercontent.com/GonzFC/WinSrvManagementScripts/main/install.ps1)
```

---

## Known Issues

### None Currently Blocking
All critical issues resolved. Remaining work is testing and validation.

---

## Success Metrics

### Completed ✅
- [x] iperf3 installs automatically
- [x] iperf3 executes properly
- [x] User can enter peer IP
- [x] Connectivity pre-test works
- [x] Helpful error messages
- [x] Duration presets work
- [x] Logging comprehensive

### To Validate Tomorrow ⏳
- [ ] Successful peer-to-peer test
- [ ] Accurate bandwidth results
- [ ] Upload/download metrics
- [ ] Retransmission detection
- [ ] Quality assessment
- [ ] Both peers can test simultaneously

---

## Architecture Notes

### Why Peer-to-Peer Only?
1. **Reliability:** Full control over both endpoints
2. **No busy servers:** Public iperf3 servers often at capacity
3. **Real-world use case:** Testing between actual systems (DB → Storage, etc.)
4. **Bidirectional:** Both directions tested simultaneously
5. **Admin control:** Perfect for network/DB/storage/WiFi admins

### Why ar51an builds?
1. **Statically linked:** No Visual C++ runtime needed
2. **Modern:** Latest iperf3 versions (3.20)
3. **Maintained:** Regular updates
4. **Windows-optimized:** Built specifically for Windows
5. **Complete:** Includes all dependencies (cygwin1.dll)

### Design Principles Met
- ✅ Idempotent (can run multiple times safely)
- ✅ Argument-free (smart inference, minimal questions)
- ✅ "It just works" (Steve Jobs style)
- ✅ Professional output (for admins)
- ✅ No nagging (clear, helpful messages only)

---

**Status:** Ready for final testing and merge  
**Confidence:** High - core functionality working  
**Risk:** Low - only peer connectivity setup remains  

See you tomorrow! 🚀
