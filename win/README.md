# File Security Monitor - ETW-Based Security Policy Engine

A Windows-based security monitoring application that enforces custom security policies for file types and executable compatibility using Event Tracing for Windows (ETW).

## Features

- **ETW-based Process Monitoring**: Real-time kernel-level process creation tracking
- **Custom Security Policies**: Define arbitrary security levels for file extensions
- **File Type Validation**: Detect actual file types using magic bytes (not just extension)
- **Code Signature Verification**: Validate Authenticode signatures on executables
- **Policy Enforcement**: Block, warn, or log based on configurable rules
- **Detailed Audit Logging**: JSON-formatted logs for analysis
- **WMI Fallback**: Automatic fallback to WMI monitoring if ETW unavailable

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│         File Security Monitor (Userspace)               │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  ┌──────────────────┐      ┌──────────────────┐        │
│  │  ETW Tracing     │      │  Policy Engine   │        │
│  │  (Real-time)     │      │  (Rules Engine)  │        │
│  └────────┬─────────┘      └────────┬─────────┘        │
│           │                         │                   │
│  ┌────────▼──────────────────────┬──▼──────────┐       │
│  │   Process Events              │  Load Pols  │       │
│  │   (from Kernel)               │  (JSON)     │       │
│  └────────┬─────────────────────┴─────────────┘       │
│           │                                              │
│  ┌────────▼─────────────────────────────────┐         │
│  │    File Inspector                        │         │
│  │  - Magic bytes detection                 │         │
│  │  - Signature verification                │         │
│  │  - Reputation checking                   │         │
│  └────────┬────────────────────────────────┘         │
│           │                                            │
│  ┌────────▼─────────────────────────────────┐        │
│  │   Enforcement Engine                     │        │
│  │  - Block execution                       │        │
│  │  - Warn user                             │        │
│  │  - Log events                            │        │
│  └────────┬────────────────────────────────┘        │
│           │                                           │
│  ┌────────▼─────────────────────────────────┐       │
│  │   Security Logger                        │       │
│  │  - File logging                          │       │
│  │  - Event serialization                   │       │
│  └──────────────────────────────────────────┘       │
│                                                       │
└───────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Windows 10/11 or Server 2019+
- .NET 6.0 Runtime or SDK
- Administrator privileges
- Optional: Sysmon (for enhanced ETW support)

### Build from Source

```bash
git clone <repository>
cd FileSecurityMonitor
dotnet build -c Release
```

### Run

```bash
# Must run as administrator
.\bin\Release\net6.0-windows\FileSecurityMonitor.exe
```

Or with elevated privileges:

```powershell
Start-Process powershell -ArgumentList "cd 'C:\path\to\FileSecurityMonitor'; dotnet run" -Verb RunAs
```

## Configuration

### Policy File Format

Create `security_policies.json`:

```json
{
  "policies": {
    "executable": {
      "name": "Executable Files",
      "extensions": [".exe", ".com", ".scr", ".msi"],
      "level": 5,
      "rules": ["require_signature", "require_reputation_check", "log_only"]
    },
    "script": {
      "name": "Script Files",
      "extensions": [".bat", ".vbs", ".ps1", ".cmd"],
      "level": 3,
      "rules": ["warn_user", "log_only"]
    },
    "library": {
      "name": "Dynamic Libraries",
      "extensions": [".dll", ".sys", ".drv"],
      "level": 4,
      "rules": ["require_signature", "log_only"]
    },
    "document": {
      "name": "Document Files",
      "extensions": [".txt", ".pdf", ".doc", ".docx"],
      "level": 1,
      "rules": ["log_only"]
    }
  }
}
```

### Security Levels

- **Level 1**: Minimal restrictions (logging only)
- **Level 2**: Low restrictions (document files)
- **Level 3**: Moderate restrictions (scripts, archives)
- **Level 4**: High restrictions (libraries, drivers)
- **Level 5**: Maximum restrictions (executables, system files)

### Policy Rules

| Rule | Description |
|------|-------------|
| `require_signature` | Block unsigned executables |
| `require_reputation_check` | Check file reputation (VirusTotal API) |
| `warn_user` | Display warning before execution |
| `log_only` | Log execution event, allow execution |
| `restrict_parent` | Only allow execution from trusted parent processes |

## Usage Examples

### Example 1: Block Unsigned EXE Files

```json
{
  "executable": {
    "name": "Unsigned Executables",
    "extensions": [".exe"],
    "level": 5,
    "rules": ["require_signature"]
  }
}
```

When an unsigned `.exe` is executed:
```
[+] Process created: C:\Users\Admin\Downloads\app.exe (PID: 2345)
    Extension: .exe
    File Type: PE Executable
    Security Level: 5
    [!] POLICY VIOLATION: Unsigned executable blocked
    [!] Terminated process due to policy violation
```

### Example 2: Warn on Script Execution

```json
{
  "script": {
    "name": "PowerShell Scripts",
    "extensions": [".ps1"],
    "level": 3,
    "rules": ["warn_user", "log_only"]
  }
}
```

Execution is logged but allowed after warning.

### Example 3: Custom Multi-Level Policy

```json
{
  "policies": {
    "high_risk": {
      "name": "High-Risk Extensions",
      "extensions": [".exe", ".scr", ".vbs", ".bat"],
      "level": 4,
      "rules": ["require_signature", "log_only"]
    },
    "medium_risk": {
      "name": "Medium-Risk Extensions",
      "extensions": [".dll", ".jar", ".app"],
      "level": 2,
      "rules": ["log_only"]
    }
  }
}
```

## Logging

### Log File Format

`security_monitor.log`:

```
[2024-01-15 14:32:45.123] [INFO  ] Monitor started
[2024-01-15 14:32:48.456] [EXEC  ] {"timestamp":"2024-01-15T14:32:48.456","process_path":"C:\\Windows\\System32\\notepad.exe","process_id":5432,"parent_process_id":1024,"file_extension":".exe","detected_file_type":"PE Executable","has_valid_signature":true,"security_policy_level":5,"policy_name":"Executable Files"}
[2024-01-15 14:33:22.789] [VIOLATION] {"timestamp":"2024-01-15T14:33:22.789","process_path":"C:\\Users\\Admin\\Downloads\\malware.exe","violation_type":"unsigned_executable","policy_level":5,"action":"block"}
```

### Parsing Logs

Use JSON parsing tools to analyze events:

```powershell
# PowerShell: Count executions by file type
Get-Content security_monitor.log | 
    Select-String '\[EXEC' | 
    ConvertFrom-Json -AsHashtable | 
    Group-Object detected_file_type | 
    Sort-Object Count -Descending
```

## Advanced Configuration

### Reputation Checking (Optional)

Integrate with VirusTotal API for file reputation:

Modify `FileSecurityMonitor.cs` in `CheckReputation()` method:

```csharp
private bool CheckReputation(string filePath)
{
    try
    {
        var hash = ComputeFileHash(filePath);
        var client = new HttpClient();
        var request = new HttpRequestMessage(HttpMethod.Get, 
            $"https://www.virustotal.com/api/v3/files/{hash}");
        request.Headers.Add("x-apikey", "YOUR_VT_API_KEY");
        
        var response = client.SendAsync(request).Result;
        var json = response.Content.ReadAsStringAsync().Result;
        
        // Parse response and check reputation
        // Return true if good, false if bad
        return true;
    }
    catch { return true; } // Default to allow on error
}
```

### ETW vs WMI

- **ETW**: Requires Sysmon or Security audit logging enabled
  - Advantages: Lower latency, kernel-level detail
  - Disadvantages: Requires additional setup
  
- **WMI**: Works out of the box
  - Advantages: No additional prerequisites
  - Disadvantages: Higher latency, fewer details

The application automatically falls back to WMI if ETW is unavailable.

## Performance Considerations

### System Impact

- Minimal CPU impact (event-driven, not polling)
- Memory: ~50-100 MB baseline
- Disk I/O: Low, only on file operations

### Optimization Tips

1. **Exclude system processes** to reduce event volume
2. **Adjust log level** - only log violations for high-volume environments
3. **Batch policy reloads** - avoid reloading policies frequently

## Troubleshooting

### "Requires administrator privileges"

```powershell
# Run with elevated privileges
Start-Process -FilePath "FileSecurityMonitor.exe" -Verb RunAs
```

### ETW monitoring not working

1. Enable Security Audit Policy:
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

2. Or install Sysmon:
```powershell
# Download Sysmon from Microsoft
# Install: Sysmon64.exe -i -accepteula
```

### File signature verification slow

This is normal for first run. Disable `require_signature` if performance is critical:

```json
{
  "rules": ["warn_user", "log_only"]
}
```

## Security Considerations

### Limitations

- **Userspace code can be bypassed** by kernel-mode malware
- **Race conditions** between detection and blocking
- **Performance cost** of signature verification
- **False positives** from reputation checking

### Mitigation

- Combine with kernel-mode driver for critical security
- Use alongside traditional antivirus
- Regularly review and update policies
- Monitor logs for policy bypasses

## Development

### Project Structure

```
FileSecurityMonitor/
├── FileSecurityMonitor.cs       # Main monitor class
├── PolicyEngine.cs              # Policy management & file analysis
├── LoggingAndETW.cs            # Logging & ETW integration
├── FileSecurityMonitor.csproj   # Project configuration
└── security_policies.json       # Policy configuration
```

### Adding New Rules

1. Add rule name to policy JSON
2. Implement handler in `EnforcePolicy()` method:

```csharp
case "custom_rule":
    if (CustomRuleLogic(fileInfo))
    {
        // Enforce
    }
    break;
```

3. Document in this README

### Extending File Types

Add magic bytes to `FileInspector.MagicNumbers`:

```csharp
{ ".xyz", (new byte[] { 0x12, 0x34 }, "Custom Format") }
```

## API Integration Examples

### VirusTotal API

```csharp
// Add package: Install-Package VirusNet
using VirusNet;

var vt = new VirusNetClient("YOUR_API_KEY");
var fileReport = vt.GetFileReport(filePath);
bool isSafe = fileReport.Positives == 0;
```

### Windows Defender API

```csharp
// Use Windows.Security.Malware.Scan
var scanner = new WindowsMalwareScan();
var result = scanner.ScanFile(filePath);
```

## License

MIT License

## Contributing

Contributions welcome. Please submit PRs for:
- Additional file type signatures
- Performance improvements
- Integration with security APIs
- Policy templates

## References

- [Windows Event Tracing](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)
- [Sysmon Documentation](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Code Signing](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-)
- [Security Event Log](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)

## Support

For issues:
1. Check logs in `security_monitor.log`
2. Enable verbose logging
3. Verify administrator privileges
4. Check ETW prerequisites
