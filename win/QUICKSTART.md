# File Security Monitor - Quick Start Guide

## 5-Minute Setup

### 1. Build the Application

```bash
cd FileSecurityMonitor
dotnet build -c Release
```

### 2. Run with Administrator Privileges

**Option A: PowerShell**
```powershell
Start-Process powershell -ArgumentList `
  "cd 'C:\path\to\FileSecurityMonitor'; `
   dotnet run -c Release" -Verb RunAs
```

**Option B: Command Prompt**
```bash
# Run command prompt as administrator, then:
cd C:\path\to\FileSecurityMonitor
dotnet run -c Release
```

### 3. Test with Policy File

The application will auto-create `security_policies.json` on first run.

```bash
# The monitor will start and display:
# [*] Starting File Security Monitor
# [*] Policy file: security_policies.json
# [*] Log file: security_monitor.log
# [+] Loaded 15 policy rules from 8 policies
# [+] Monitoring active. Press Ctrl+C to stop.
```

## Testing the Monitor

### Test 1: Monitor a Safe Executable

```powershell
# This should log successfully
& "C:\Windows\System32\notepad.exe"
```

Expected output:
```
[+] Process created: C:\Windows\System32\notepad.exe (PID: 5432)
    Extension: .exe
    File Type: PE Executable
    Security Level: 5
    [+] Policy enforcement complete - execution allowed
```

### Test 2: Block Unsigned Executable (if policy enabled)

Modify `security_policies.json` to require signatures:
```json
{
  "executable": {
    "extensions": [".exe"],
    "level": 5,
    "rules": ["require_signature"]
  }
}
```

Then create a test unsigned EXE (for testing only):
```powershell
# This will be blocked if signature requirement enabled
cmd /c "echo test > test.exe"
& ".\test.exe"
```

Expected output:
```
[!] POLICY VIOLATION: Unsigned executable blocked
```

### Test 3: Monitor Script Execution

```powershell
# This script will trigger warning rule
& "C:\Users\YourName\test.ps1"
```

The monitor logs it with policy level 3 (moderate).

## Configuration Scenarios

### Scenario 1: High-Security Workstation

Require signatures on all executables:

```json
{
  "executable": {
    "extensions": [".exe", ".scr", ".msi"],
    "level": 5,
    "rules": ["require_signature", "require_reputation_check"]
  },
  "script": {
    "extensions": [".bat", ".vbs", ".ps1"],
    "level": 4,
    "rules": ["require_signature"]
  }
}
```

### Scenario 2: Developer Machine

Allow more flexibility but log everything:

```json
{
  "executable": {
    "extensions": [".exe"],
    "level": 2,
    "rules": ["log_only"]
  },
  "script": {
    "extensions": [".ps1", ".bat"],
    "level": 1,
    "rules": ["log_only"]
  }
}
```

### Scenario 3: Kiosk/Public Computer

Maximum restrictions on everything:

```json
{
  "executable": {
    "extensions": [".exe", ".msi", ".scr"],
    "level": 5,
    "rules": ["require_signature", "block_execution"]
  },
  "script": {
    "extensions": [".bat", ".vbs", ".ps1"],
    "level": 5,
    "rules": ["block_execution"]
  }
}
```

## Analyzing Logs

### View Recent Events

```powershell
# PowerShell: Last 10 execution events
Get-Content security_monitor.log | 
    Select-String '\[EXEC' | 
    Select-Object -Last 10
```

### Filter by File Type

```powershell
# Find all PowerShell script executions
Get-Content security_monitor.log | 
    Select-String 'detected_file_type":"PowerShell' |
    ConvertFrom-Json
```

### Find Policy Violations

```powershell
# All security violations
Get-Content security_monitor.log | 
    Select-String '\[VIOLATION'
```

## Custom Policy Examples

### Example 1: Quarantine Zone

Block all execution from Downloads:

```json
{
  "quarantine": {
    "name": "Downloads Quarantine",
    "extensions": [".exe", ".bat", ".ps1"],
    "level": 5,
    "rules": ["block_if_in_downloads"],
    "paths": ["Downloads", "Temp"]
  }
}
```

### Example 2: Trusted Publisher Only

Only allow signed code from Microsoft:

```json
{
  "trusted_only": {
    "name": "Microsoft Signed Only",
    "extensions": [".exe", ".dll"],
    "level": 5,
    "rules": ["require_signature", "verify_publisher"],
    "trusted_publishers": ["Microsoft Corporation"]
  }
}
```

### Example 3: Time-Based Restrictions

Block execution outside business hours:

```json
{
  "time_restricted": {
    "name": "Business Hours Only",
    "extensions": [".exe"],
    "level": 3,
    "rules": ["block_outside_hours"],
    "business_hours": "09:00-17:00",
    "timezone": "America/New_York"
  }
}
```

## Troubleshooting

### Monitor not detecting processes

**Check 1: Administrator privileges**
```powershell
# Verify running as admin
[Security.Principal.WindowsIdentity]::GetCurrent().Groups | 
    Where-Object {$_ -match "S-1-5-32-544"}
```

**Check 2: Enable Security Auditing**
```powershell
# Enable process creation auditing
auditpol /set /subcategory:"Process Creation" /success:enable
```

**Check 3: Check Event Viewer**
```powershell
# View Security event log
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" | 
    Select-Object -First 10
```

### Policy file not loading

```powershell
# Validate JSON syntax
$json = Get-Content security_policies.json | ConvertFrom-Json
$json | ConvertTo-Json | Out-Null
Write-Host "JSON is valid"
```

### High CPU usage

1. Increase system process exclusions
2. Reduce signature verification frequency
3. Disable reputation checks for high-volume environments

## Performance Tuning

### Reduce Log Volume

```json
{
  "logging": {
    "level": "errors_only",
    "exclude_patterns": [
      "C:\\Windows\\*",
      "C:\\Program Files\\*"
    ]
  }
}
```

### Cache Reputation Checks

```csharp
// In FileSecurityMonitor.cs
private static Dictionary<string, bool> _reputationCache = new();

private bool CheckReputation(string filePath)
{
    if (_reputationCache.TryGetValue(filePath, out bool cached))
        return cached;
    
    // Check reputation...
    _reputationCache[filePath] = result;
    return result;
}
```

## Next Steps

1. **Customize policies** for your environment
2. **Enable ETW monitoring** for better performance
3. **Integrate with SIEM** for centralized logging
4. **Set up alerts** for high-level violations
5. **Regular policy review** based on detected threats

## Advanced Topics

- See `README.md` for API integration examples
- See source code for extending with custom rules
- See log format documentation for SIEM integration

## Support

For issues:
1. Check `security_monitor.log` for detailed errors
2. Verify administrator privileges
3. Enable Security Audit Policy (if using native logging)
4. Test with sample policies first
