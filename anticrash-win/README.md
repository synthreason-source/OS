# AntiCrash — .NET Process Watchdog

A lightweight, production-ready process watchdog for Windows built with .NET 8.

## Build

Requirements: .NET 8 SDK

```bash
cd AntiCrash
dotnet build -c Release
```

Publish as a single self-contained .exe:

```bash
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

---

## Usage

### 1. Launch and watch a process

```
AntiCrash.exe myapp.exe --port 8080
```

### 2. Attach to an already-running process

```
AntiCrash.exe --pid 1234
```

### 3. Use a config file (recommended)

```
AntiCrash.exe --config watchdog.json
```

---

## Config File (watchdog.json)

```json
{
  "Mode": "Launch",
  "ExecutablePath": "myapp.exe",
  "Arguments": "--port 8080",
  "WorkingDirectory": "",

  "MaxRestarts": 10,
  "RestartDelayMs": 3000,
  "MaxRestartsInWindow": 5,
  "MaxRestartWindowSeconds": 60,

  "MemoryLimitMb": 512,
  "CpuThresholdPercent": 95,
  "CpuSampleSeconds": 10,

  "HeartbeatTimeoutSeconds": 30,
  "HealthCheckUrl": "http://localhost:8080/health",
  "HealthCheckIntervalSeconds": 10,

  "OnCrashScript": "notify_crash.bat",
  "LogToFile": true,
  "LogFilePath": "anticrash.log",

  "GracefulExitCodes": [0]
}
```

### Config fields

| Field | Default | Description |
|-------|---------|-------------|
| `MaxRestarts` | 10 | Max total restarts. 0 = unlimited |
| `RestartDelayMs` | 2000 | ms to wait before each restart |
| `MaxRestartsInWindow` | 5 | Max restarts in `MaxRestartWindowSeconds` |
| `MaxRestartWindowSeconds` | 60 | Time window for rate limiting |
| `MemoryLimitMb` | 0 | Kill if working set exceeds this. 0 = disabled |
| `CpuThresholdPercent` | 0 | Kill if CPU % exceeds this over sample. 0 = disabled |
| `CpuSampleSeconds` | 10 | CPU sampling interval |
| `HeartbeatTimeoutSeconds` | 0 | Kill if unhealthy for this long. 0 = disabled |
| `HealthCheckUrl` | "" | HTTP endpoint to poll for health |
| `HealthCheckIntervalSeconds` | 10 | How often to poll the health endpoint |
| `OnCrashScript` | "" | Script to execute on each crash event |
| `GracefulExitCodes` | [0] | Exit codes that stop the watchdog (no restart) |

---

## Stop the watchdog

Press `Ctrl+C`. The watchdog will exit cleanly without killing the child process.

---

## Example: Run as a Windows Service

Wrap with [NSSM](https://nssm.cc/) or [WinSW](https://github.com/winsw/winsw):

```
nssm install MyAppWatchdog "C:\tools\AntiCrash.exe" "--config C:\myapp\watchdog.json"
nssm start MyAppWatchdog
```
