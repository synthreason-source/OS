# 1. Dynamically gather active wmiprvse PIDs to block WMI actions
$WmiPids = (Get-WmiObject -Class Win32_Process -Filter "Name = 'wmiprvse.exe'").ProcessId
$ParentMatch = @()
foreach ($WmiId in $WmiPids) { $ParentMatch += "ParentProcessId = $WmiId" }
if ($ParentMatch.Count -eq 0) { $ParentMatch += "ParentProcessId = 0" }
$WmiQueryPiece = $ParentMatch -join " OR "

# 2. Build the precise Win32_ProcessStartTrace query
$Query = @"
SELECT * FROM Win32_ProcessStartTrace 
WHERE ProcessName = 'cmd.exe' 
OR ProcessName = 'powershell.exe' 
OR ProcessName = 'wscript.exe' 
OR ProcessName = 'cscript.exe' 
OR $WmiQueryPiece
"@

$Identifier = "NativeKernelBlocker"

# Clean out any conflicting event registrations in the legacy engine
Get-EventSubscriber -SourceIdentifier $Identifier -ErrorAction SilentlyContinue | Unregister-Event

Write-Host "[+] Hooking Kernel Event Pipeline via Native COM..." -ForegroundColor Cyan

# 3. Use Register-WmiEvent instead of CimIndication to avoid the 'Call Cancelled' block
Register-WmiEvent -Query $Query -SourceIdentifier $Identifier -Action {
    # Extract the target process data directly from the native WMI event properties
    $TargetPID  = $Event.SourceEventArgs.NewEvent.ProcessId
    $TargetName = $Event.SourceEventArgs.NewEvent.ProcessName
    
    # Instant enforcement drop
    Stop-Process -Id $TargetPID -Force -ErrorAction SilentlyContinue
    
    Write-Host "[BLOCKED] Kernel instantly dropped unauthorized execution: $TargetName (PID: $TargetPID)" -ForegroundColor Red
}

Write-Host "[SUCCESS] Active Blocker is officially armed and listening!" -ForegroundColor Green
Write-Host "[IMPORTANT] Keep this PowerShell script running to enforce the policy." -ForegroundColor Yellow
Write-Host "Press Ctrl+C to terminate the monitor." -ForegroundColor White

# 4. Stay Alive loop keeping the execution scope locked
try {
    while ($true) {
        Start-Sleep -Seconds 1
    }
}
catch {
    Write-Host "`n[-] Cleaning up native kernel event hooks..." -ForegroundColor Yellow
    Get-EventSubscriber -SourceIdentifier $Identifier -ErrorAction SilentlyContinue | Unregister-Event
}
