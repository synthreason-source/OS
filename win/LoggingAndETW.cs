using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace FileSecurityMonitor
{
    /// <summary>
    /// Security event logging
    /// </summary>
    public class SecurityLogger
    {
        public string LogFilePath { get; private set; }
        private readonly object _lockObj = new object();

        public SecurityLogger(string logFilePath)
        {
            LogFilePath = logFilePath;
        }

        public void Log(string message)
        {
            WriteLog("INFO", message);
        }

        public void LogWarning(string message)
        {
            WriteLog("WARN", message);
        }

        public void LogError(string message)
        {
            WriteLog("ERROR", message);
        }

        public void LogProcessExecution(ProcessExecutionEvent evt)
        {
            WriteLog("EXEC", JsonConvert.SerializeObject(evt));
        }

        public void LogViolation(PolicyViolation violation)
        {
            WriteLog("VIOLATION", JsonConvert.SerializeObject(violation));
        }

        private void WriteLog(string level, string message)
        {
            lock (_lockObj)
            {
                try
                {
                    string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                    string logEntry = $"[{timestamp}] [{level:6}] {message}";

                    // Write to console
                    Console.ForegroundColor = level switch
                    {
                        "ERROR" => ConsoleColor.Red,
                        "WARN" => ConsoleColor.Yellow,
                        "VIOLATION" => ConsoleColor.Magenta,
                        _ => ConsoleColor.White
                    };
                    if (level == "EXEC" || level == "VIOLATION")
                        Console.WriteLine(logEntry);
                    Console.ResetColor();

                    // Write to file
                    File.AppendAllText(LogFilePath, logEntry + Environment.NewLine);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Failed to write log: {ex.Message}");
                }
            }
        }
    }

    /// <summary>
    /// Process execution event data
    /// </summary>
    public class ProcessExecutionEvent
    {
        [JsonProperty("timestamp")]
        public DateTime Timestamp { get; set; }

        [JsonProperty("process_path")]
        public string ProcessPath { get; set; }

        [JsonProperty("process_id")]
        public int ProcessId { get; set; }

        [JsonProperty("parent_process_id")]
        public int ParentProcessId { get; set; }

        [JsonProperty("file_extension")]
        public string FileExtension { get; set; }

        [JsonProperty("detected_file_type")]
        public string DetectedFileType { get; set; }

        [JsonProperty("has_valid_signature")]
        public bool HasValidSignature { get; set; }

        [JsonProperty("security_policy_level")]
        public int SecurityPolicyLevel { get; set; }

        [JsonProperty("policy_name")]
        public string PolicyName { get; set; }
    }

    /// <summary>
    /// Policy violation event
    /// </summary>
    public class PolicyViolation
    {
        [JsonProperty("timestamp")]
        public DateTime Timestamp { get; set; }

        [JsonProperty("process_path")]
        public string ProcessPath { get; set; }

        [JsonProperty("violation_type")]
        public string ViolationType { get; set; }

        [JsonProperty("policy_level")]
        public int PolicyLevel { get; set; }

        [JsonProperty("action")]
        public string Action { get; set; }
    }

    /// <summary>
    /// Process monitor - tracks running processes
    /// </summary>
    public class ProcessMonitor
    {
        private Dictionary<int, ProcessInfo> _processes = new();

        public class ProcessInfo
        {
            public int ProcessId { get; set; }
            public string Name { get; set; }
            public string Path { get; set; }
            public DateTime CreatedAt { get; set; }
        }

        public void TrackProcess(int processId, string processName, string processPath)
        {
            lock (_processes)
            {
                _processes[processId] = new ProcessInfo
                {
                    ProcessId = processId,
                    Name = processName,
                    Path = processPath,
                    CreatedAt = DateTime.Now
                };
            }
        }

        public ProcessInfo GetProcessInfo(int processId)
        {
            lock (_processes)
            {
                return _processes.ContainsKey(processId) ? _processes[processId] : null;
            }
        }
    }

    /// <summary>
    /// ETW Trace Session - monitors process creation via Event Tracing for Windows
    /// </summary>
    public class ETWTraceSession
    {
        public string SessionName { get; private set; }
        public delegate void ProcessCreatedHandler(int processId, string processName, string commandLine, int parentProcessId);
        public event ProcessCreatedHandler OnProcessCreated;

        private EventLogWatcher _watcher;

        public ETWTraceSession(string sessionName)
        {
            SessionName = sessionName;
        }

        /// <summary>
        /// Start ETW monitoring for process creation
        /// </summary>
        public void Start(CancellationToken cancellationToken)
        {
            try
            {
                // Monitor the System event log for process creation events
                // Event ID 1 in the Operational log of Microsoft-Windows-Sysmon/Operational
                // Or Event ID 4688 in Security log for process creation (if auditing enabled)

                EventLogQuery query = new EventLogQuery(
                    "Microsoft-Windows-Sysmon/Operational",
                    PathType.LogName,
                    "*[System[EventID=1]]" // Sysmon process creation event
                );

                _watcher = new EventLogWatcher(query);

                _watcher.EventRecordWritten += (sender, e) =>
                {
                    if (e.EventRecord != null)
                    {
                        try
                        {
                            ParseSysmonProcessCreation(e.EventRecord);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[!] Error parsing Sysmon event: {ex.Message}");
                        }
                    }
                };

                _watcher.Enabled = true;

                // Keep running until cancellation
                while (!cancellationToken.IsCancellationRequested)
                {
                    Thread.Sleep(100);
                }

                _watcher.Enabled = false;
                _watcher.Dispose();
            }
            catch (Exception ex)
            {
                // Sysmon might not be installed, try alternative
                Console.WriteLine($"[!] Sysmon ETW session failed: {ex.Message}");
                Console.WriteLine("[*] Falling back to alternative ETW method...");
                StartAlternativeETWMonitoring(cancellationToken);
            }
        }

        /// <summary>
        /// Alternative ETW approach using System event log
        /// </summary>
        private void StartAlternativeETWMonitoring(CancellationToken cancellationToken)
        {
            try
            {
                // Try to use the Security event log if auditing is enabled
                // This requires "Audit process creation" to be enabled in Group Policy
                EventLogQuery query = new EventLogQuery(
                    "Security",
                    PathType.LogName,
                    "*[System[EventID=4688]]" // Process creation event
                );

                _watcher = new EventLogWatcher(query);

                _watcher.EventRecordWritten += (sender, e) =>
                {
                    if (e.EventRecord != null)
                    {
                        try
                        {
                            ParseSecurityProcessCreation(e.EventRecord);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[!] Error parsing Security event: {ex.Message}");
                        }
                    }
                };

                _watcher.Enabled = true;

                while (!cancellationToken.IsCancellationRequested)
                {
                    Thread.Sleep(100);
                }

                _watcher.Enabled = false;
                _watcher.Dispose();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Alternative ETW failed: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Parse Sysmon process creation event (Event ID 1)
        /// </summary>
        private void ParseSysmonProcessCreation(EventRecord record)
        {
            // Sysmon Event ID 1 structure
            string imagePath = ExtractEventProperty(record, "Image");
            string commandLine = ExtractEventProperty(record, "CommandLine");
            string parentImage = ExtractEventProperty(record, "ParentImage");
            int processId = int.TryParse(ExtractEventProperty(record, "ProcessId"), out int pid) ? pid : 0;
            int parentPid = int.TryParse(ExtractEventProperty(record, "ParentProcessId"), out int ppid) ? ppid : 0;

            OnProcessCreated?.Invoke(processId, imagePath, commandLine, parentPid);
        }

        /// <summary>
        /// Parse Security event log process creation (Event ID 4688)
        /// </summary>
        private void ParseSecurityProcessCreation(EventRecord record)
        {
            string newProcessName = ExtractEventProperty(record, "NewProcessName");
            string commandLine = ExtractEventProperty(record, "CommandLine");
            int newProcessId = int.TryParse(ExtractEventProperty(record, "NewProcessId"), out int pid) ? pid : 0;
            
            // Parent process ID might be in different field depending on Windows version
            int parentProcessId = int.TryParse(ExtractEventProperty(record, "ParentProcessId"), out int ppid) ? ppid : 0;

            OnProcessCreated?.Invoke(newProcessId, newProcessName, commandLine, parentProcessId);
        }

        /// <summary>
        /// Extract property from event record XML
        /// </summary>
        private string ExtractEventProperty(EventRecord record, string propertyName)
        {
            try
            {
                if (record.Properties.Count == 0)
                    return "";

                foreach (var prop in record.Properties)
                {
                    if (prop.Value?.ToString().Contains(propertyName) == true)
                        return prop.Value.ToString();
                }

                // Try XPath
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
}
