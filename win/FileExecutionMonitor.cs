using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Linq;
namespace FileSecurityMonitor
{
    /// <summary>
    /// File extension monitoring - detects opening of files in applications
    /// Monitors document, script, and other file executions
    /// </summary>
    public class FileExecutionMonitor
    {
        private SecurityLogger _logger;
        private PolicyEngine _policyEngine;
        private FileInspector _fileInspector;
        private bool _isMonitoring = false;

        public FileExecutionMonitor(SecurityLogger logger, PolicyEngine policyEngine, FileInspector fileInspector)
        {
            _logger = logger;
            _policyEngine = policyEngine;
            _fileInspector = fileInspector;
        }

        /// <summary>
        /// Start monitoring file access and execution events
        /// </summary>
        public void Start(CancellationToken cancellationToken)
        {
            _isMonitoring = true;

            // Start multiple monitoring threads
            Task monitorTasksTask = Task.Run(async () =>
            {
                await Task.WhenAll(
                    MonitorFileAssociations(cancellationToken),
                    MonitorDocumentAccess(cancellationToken),
                    MonitorScriptExecution(cancellationToken),
                    MonitorLsassEvents(cancellationToken)
                );
            }, cancellationToken);

            try
            {
                monitorTasksTask.Wait(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                _isMonitoring = false;
            }
        }

        /// <summary>
        /// Monitor file association/open operations via Windows API
        /// </summary>
        private Task MonitorFileAssociations(CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                try
                {
                    Console.WriteLine("[*] File association monitoring initialized");
                    _logger.Log("File association monitoring started");

                    // Monitor shell execute operations via WMI
                    EventLogQuery query = new EventLogQuery(
                        "Microsoft-Windows-Sysmon/Operational",
                        PathType.LogName,
                        "*[System[EventID=3]]" // Sysmon Network Connection
                    );

                    using (EventLogWatcher watcher = new EventLogWatcher(query))
                    {
                        watcher.EventRecordWritten += (sender, e) =>
                        {
                            // Secondary monitoring point
                        };

                        watcher.Enabled = true;

                        while (!cancellationToken.IsCancellationRequested)
                        {
                            Thread.Sleep(500);
                        }

                        watcher.Enabled = false;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError($"File association monitoring error: {ex.Message}");
                }
            }, cancellationToken);
        }

        /// <summary>
        /// Monitor document file access and opening
        /// </summary>
        private Task MonitorDocumentAccess(CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                try
                {
                    Console.WriteLine("[*] Document access monitoring initialized");
                    _logger.Log("Document access monitoring started");

                    // Monitor file I/O operations via ETW
                    EventLogQuery query = new EventLogQuery(
                        "Microsoft-Windows-Sysmon/Operational",
                        PathType.LogName,
                        "*[System[EventID=11]]" // Sysmon FileCreate event
                    );

                    using (EventLogWatcher watcher = new EventLogWatcher(query))
                    {
                        watcher.EventRecordWritten += (sender, e) =>
                        {
                            if (e.EventRecord != null)
                            {
                                try
                                {
                                    ProcessFileCreateEvent(e.EventRecord);
                                }
                                catch (Exception ex)
                                {
                                    // Silently ignore
                                }
                            }
                        };

                        watcher.Enabled = true;

                        while (!cancellationToken.IsCancellationRequested)
                        {
                            Thread.Sleep(500);
                        }

                        watcher.Enabled = false;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Document monitoring error: {ex.Message}");
                }
            }, cancellationToken);
        }

        /// <summary>
        /// Monitor script file execution via PowerShell/batch execution events
        /// </summary>
        private Task MonitorScriptExecution(CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                try
                {
                    Console.WriteLine("[*] Script execution monitoring initialized");
                    _logger.Log("Script execution monitoring started");

                    // Monitor PowerShell script executions
                    try
                    {
                        EventLogQuery psQuery = new EventLogQuery(
                            "Microsoft-Windows-PowerShell/Operational",
                            PathType.LogName,
                            "*[System[EventID=4103 or EventID=4104]]" // Script block execution
                        );

                        using (EventLogWatcher psWatcher = new EventLogWatcher(psQuery))
                        {
                            psWatcher.EventRecordWritten += (sender, e) =>
                            {
                                if (e.EventRecord != null)
                                {
                                    try
                                    {
                                        ProcessPowerShellEvent(e.EventRecord);
                                    }
                                    catch { }
                                }
                            };

                            psWatcher.Enabled = true;

                            while (!cancellationToken.IsCancellationRequested)
                            {
                                Thread.Sleep(500);
                            }

                            psWatcher.Enabled = false;
                        }
                    }
                    catch
                    {
                        // PowerShell logging might not be enabled
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Script monitoring error: {ex.Message}");
                }
            }, cancellationToken);
        }

        /// <summary>
        /// Monitor LSASS events (includes DLL loads and script execution)
        /// </summary>
        private Task MonitorLsassEvents(CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                try
                {
                    Console.WriteLine("[*] Module/DLL load monitoring initialized");
                    _logger.Log("Module load monitoring started");

                    // Monitor DLL/Module loads via Sysmon
                    EventLogQuery query = new EventLogQuery(
                        "Microsoft-Windows-Sysmon/Operational",
                        PathType.LogName,
                        "*[System[EventID=7]]" // Sysmon ImageLoad event
                    );

                    using (EventLogWatcher watcher = new EventLogWatcher(query))
                    {
                        watcher.EventRecordWritten += (sender, e) =>
                        {
                            if (e.EventRecord != null)
                            {
                                try
                                {
                                    ProcessImageLoadEvent(e.EventRecord);
                                }
                                catch { }
                            }
                        };

                        watcher.Enabled = true;

                        while (!cancellationToken.IsCancellationRequested)
                        {
                            Thread.Sleep(500);
                        }

                        watcher.Enabled = false;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Module monitoring error: {ex.Message}");
                }
            }, cancellationToken);
        }

        private void ProcessFileCreateEvent(EventRecord record)
        {
            // Parse Sysmon FileCreate event (Event ID 11)
            string targetFilename = ExtractProperty(record, "TargetFilename");
            
            if (string.IsNullOrEmpty(targetFilename))
                return;

            var fileInfo = _fileInspector.AnalyzeFile(targetFilename);
            if (fileInfo == null)
                return;

            // Only log non-executable file access for now
            if (fileInfo.Extension.ToLower() != ".exe")
            {
                _logger.Log($"File created/accessed: {targetFilename}");
            }
        }

        private void ProcessPowerShellEvent(EventRecord record)
        {
            string scriptContent = ExtractProperty(record, "ScriptBlockText");
            if (string.IsNullOrEmpty(scriptContent))
                return;

            _logger.Log($"PowerShell script executed (length: {scriptContent.Length} chars)");
        }

        private void ProcessImageLoadEvent(EventRecord record)
        {
            string imagePath = ExtractProperty(record, "ImageLoaded");
            if (string.IsNullOrEmpty(imagePath))
                return;

            var fileInfo = _fileInspector.AnalyzeFile(imagePath);
            if (fileInfo == null)
                return;

            // Log DLL/module loads
            if (fileInfo.Extension.ToLower() == ".dll" || fileInfo.Extension.ToLower() == ".sys")
            {
                _logger.Log($"Module loaded: {imagePath}");
            }
        }

        private string ExtractProperty(EventRecord record, string propertyName)
        {
            try
            {
                var xml = record.ToXml();
                int startIdx = xml.IndexOf($"<{propertyName}>", StringComparison.OrdinalIgnoreCase);
                if (startIdx >= 0)
                {
                    startIdx += propertyName.Length + 2;
                    int endIdx = xml.IndexOf($"</{propertyName}>", startIdx, StringComparison.OrdinalIgnoreCase);
                    if (endIdx > startIdx)
                    {
                        return xml.Substring(startIdx, endIdx - startIdx);
                    }
                }
                return "";
            }
            catch
            {
                return "";
            }
        }
    }

    /// <summary>
    /// File system watcher - monitors changes to specific directories
    /// </summary>
    public class FileSystemWatcherMonitor
    {
        private SecurityLogger _logger;
        private PolicyEngine _policyEngine;
        private FileInspector _fileInspector;
        private List<FileSystemWatcher> _watchers = new();

        public FileSystemWatcherMonitor(SecurityLogger logger, PolicyEngine policyEngine, FileInspector fileInspector)
        {
            _logger = logger;
            _policyEngine = policyEngine;
            _fileInspector = fileInspector;
        }

        /// <summary>
        /// Start monitoring specific directories for file changes
        /// </summary>
        public void Start()
        {
            Console.WriteLine("[*] File system monitoring initialized");
            _logger.Log("File system monitoring started");

            // Monitor critical directories
            string[] directoriesToMonitor = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
            };

            foreach (string dir in directoriesToMonitor)
            {
                try
                {
                    if (!Directory.Exists(dir))
                        continue;

                    FileSystemWatcher watcher = new FileSystemWatcher(dir)
                    {
                        Filter = "*.*",
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                        IncludeSubdirectories = false
                    };

                    watcher.Created += (s, e) => OnFileCreated(e.FullPath);
                    watcher.Changed += (s, e) => OnFileChanged(e.FullPath);

                    watcher.EnableRaisingEvents = true;
                    _watchers.Add(watcher);

                    Console.WriteLine($"[*] Monitoring: {dir}");
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Failed to monitor {dir}: {ex.Message}");
                }
            }
        }

        private void OnFileCreated(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return;

                // Skip monitor's own files
                if (IsMonitorFile(filePath))
                    return;

                var fileInfo = _fileInspector.AnalyzeFile(filePath);
                if (fileInfo == null)
                    return;

                var policy = _policyEngine.GetPolicy(fileInfo.Extension);
                
                _logger.Log($"[FILE-CREATE] {Path.GetFileName(filePath)} ({fileInfo.Extension}) - Level {policy.Level}");
            }
            catch { }
        }

        private void OnFileChanged(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return;

                // Skip monitor's own files
                if (IsMonitorFile(filePath))
                    return;

                var fileInfo = _fileInspector.AnalyzeFile(filePath);
                if (fileInfo == null)
                    return;

                // Only log potentially suspicious changes
                if (fileInfo.Extension.ToLower() == ".exe" || 
                    fileInfo.Extension.ToLower() == ".dll" ||
                    fileInfo.Extension.ToLower() == ".bat" ||
                    fileInfo.Extension.ToLower() == ".ps1")
                {
                    _logger.Log($"[FILE-CHANGE] {Path.GetFileName(filePath)} ({fileInfo.Extension})");
                }
            }
            catch { }
        }

        /// <summary>
        /// Check if file belongs to the monitor application
        /// </summary>
        private bool IsMonitorFile(string filePath)
        {
            string lowerPath = filePath.ToLower();
            string fileName = Path.GetFileName(lowerPath);

            // Exclude monitor's own files
            string[] monitorFiles = new[]
            {
                "filesecuritymonitor.exe",
                "filesecuritymonitor.dll",
                "security_monitor.log",
                "security_policies.json",
                "filesecuritymonitor.pdb",
                "filesecuritymonitor.csproj",
                "newtonsoft.json.dll",
                "system.management.dll",
                "system.diagnostics.eventlog.dll"
            };

            return monitorFiles.Any(f => fileName == f) ||
                   lowerPath.Contains("\\bin\\") ||
                   lowerPath.Contains("\\obj\\") ||
                   lowerPath.Contains("\\.vs\\");
        }

        public void Stop()
        {
            foreach (var watcher in _watchers)
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            _watchers.Clear();
        }
    }
}
