# 1. Get the PID of THIS exact PowerShell window so we don't kill ourselves
$CurrentPID = $PID

# 2. Grab all active WMI Provider Host (wmiprvse) PIDs dynamically
$WmiPids = @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'wmiprvse.exe'" | Select-Object -ExpandProperty ProcessId)
$ParentMatch = @()
foreach ($WmiId in $WmiPids) { 
    if ($WmiId -and $WmiId -ne $CurrentPID) { $ParentMatch += "ParentProcessId = $WmiId" } 
}
$WmiQueryPiece = if ($ParentMatch.Count -gt 0) { $ParentMatch -join " OR " } else { "ParentProcessId = 0" }

# 3. Build the query but EXCLUDE our current running process ID
$Query = @"
SELECT * FROM Win32_ProcessStartTrace 
WHERE (
    ProcessName = 'cmd.exe' 
    OR ProcessName = 'powershell.exe' 
    OR ProcessName = 'wscript.exe' 
    OR ProcessName = 'cscript.exe' 
    OR $WmiQueryPiece
) AND ProcessId <> $CurrentPID
"@

$Identifier = "InstantKernelBlocker"

# Clean up any stuck background events
Unregister-Event -SourceIdentifier $Identifier -ErrorAction SilentlyContinue

Write-Host "[+] Hooking Kernel Process Engine (Excluding Current PID: $CurrentPID)..." -ForegroundColor Cyan

# 4. Register the event safely
try {
    Register-CimIndicationEvent -Namespace "root\cimv2" -Query $Query -SourceIdentifier $Identifier -Action {
        $TargetPID  = $Event.SourceEventArgs.NewEvent.ProcessId
        $TargetName = $Event.SourceEventArgs.NewEvent.ProcessName
        
        # Kill the target unauthorized spawn
        Stop-Process -Id $TargetPID -Force -ErrorAction SilentlyContinue
        
        Write-Host "[KILLED INSTANTLY] Blocked unauthorized spawn: $TargetName (PID: $TargetPID)" -ForegroundColor Red
    } -ErrorAction Stop
    
    Write-Host "[SUCCESS] Active WMI Kernel Blocker Armed!" -ForegroundColor Green
    Write-Host "[IMPORTANT] Keep this window open. Press Ctrl+C to deactivate." -ForegroundColor Yellow
}
catch {
    Write-Host "[ERROR] Registration failed: $_" -ForegroundColor Red
}

# 5. Stable, non-crashing keep-alive loop
while ($true) {
    [System.Threading.Thread]::Sleep(1000)
}
