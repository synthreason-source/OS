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

## Stop the watchdog

Press `Ctrl+C`. The watchdog will exit cleanly without killing the child process.

---

## Example: Run as a Windows Service

Wrap with [NSSM](https://nssm.cc/) or [WinSW](https://github.com/winsw/winsw):

```
nssm install MyAppWatchdog "C:\tools\AntiCrash.exe" "--config C:\myapp\watchdog.json"
nssm start MyAppWatchdog
```
