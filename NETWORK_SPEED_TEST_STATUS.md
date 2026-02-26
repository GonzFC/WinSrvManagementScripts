# Network Speed Test Feature - Status

**Last Updated:** 2026-02-25
**Version:** 1.0.9
**Status:** Feature Complete - Merged to Main

---

## Summary

Network speed testing (option 9) is implemented and working. Uses iperf3 with
automatic installation. Peer-to-peer only (no public server mode).

---

## What Was Built

### Core Feature
- Network Speed Testing using iperf3
- Peer-to-Peer Testing between two systems running the toolbox
- Bidirectional Testing (upload + download)
- Three Test Presets: Quick (5s), Standard (10s), Extended (30s)

### Technical Implementation
- Automatic iperf3 v3.20 installation from ar51an/iperf3-win-builds
- Static build with cygwin1.dll dependency (no Visual C++ runtime needed)
- Installed to: `C:\ProgramData\iperf3\`
- TCP testing with 4 parallel streams
- JSON output parsing for detailed metrics
- Comprehensive logging to `C:\VLABS\Maintenance\`

---

## Current Status: All Working

### [OK] Completed and Verified
1. iperf3 installation (automatic, idempotent)
2. iperf3 execution with cygwin1.dll dependency resolved
3. Peer IP input and validation
4. TCP connectivity pre-test on port 5201
5. Helpful firewall setup instructions
6. Duration preset selection
7. Bidirectional JSON test and parsing
8. Results display (upload/download Mbps, data transferred, retransmissions)
9. Quality assessment
10. Comprehensive logging
11. Merged to main branch

### Decisions Made
- **Removed Internet test mode**: Public iperf3 servers are always busy
- **Peer-to-Peer only**: More reliable, full control over both endpoints
- **ar51an builds**: Statically linked, no runtime dependencies, maintained

---

## How to Use

### Prerequisites
Both systems need iperf3 port open:
```powershell
New-NetFirewallRule -DisplayName 'iperf3' -Direction Inbound -Protocol TCP -LocalPort 5201 -Action Allow
```

### Running the Test
1. Run WinToolbox on both systems
2. On the **server** peer: select option 9, enter IP of the other peer when prompted
   (or start iperf3 manually: `& 'C:\ProgramData\iperf3\iperf3.exe' -s`)
3. On the **client** peer: select option 9, enter the server's IP

### Manual Commands Reference
```powershell
# Check iperf3 version
& 'C:\ProgramData\iperf3\iperf3.exe' --version

# Start server manually
& 'C:\ProgramData\iperf3\iperf3.exe' -s

# Run client test manually
& 'C:\ProgramData\iperf3\iperf3.exe' -c 192.168.1.231 -t 10 -P 4

# Check firewall rule
Get-NetFirewallRule -DisplayName 'iperf3'

# View logs
Get-Content 'C:\VLABS\Maintenance\WinToolbox_2026-02.log' -Tail 50
```

---

## Debugging Journey Summary (15 Commits)

| Phase | Approach | Outcome |
|---|---|---|
| 1 | winget for iperf3 | Failed - 0x80073CF0 on Windows Server (AppxPackage limitation) |
| 2 | Direct download from iperf.fr v3.1.3 | Failed - 2016 build, missing Visual C++ runtime |
| 3 | Modern ar51an/iperf3-win-builds | Partial - downloaded but wouldn't execute |
| 4 | Added debugging, found root cause | Root cause: missing cygwin1.dll |
| 5 | Copy ALL archive files (not just .exe) | [OK] iperf3 executes properly |
| 6 | UX improvements | [OK] "server busy" handling, connectivity pre-test |
| 7 | Remove Internet mode, peer-only | [OK] Simplified, reliable |

**Key Lesson:** Always copy all files from an archive - many Windows executables
depend on bundled DLLs that are easy to miss.

---

## Future Enhancements (Optional)

- [ ] Automatic server mode (listen for incoming tests, no coordination needed)
- [ ] UDP testing option
- [ ] Custom port selection
- [ ] Export results to CSV/JSON
- [ ] Historical results comparison
