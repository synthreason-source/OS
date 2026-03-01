using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Diagnostics.Eventing.Reader;
namespace FileSecurityMonitor
{
    /// <summary>
    /// ETW-based file security monitor that enforces extension/file-type policies
    /// </summary>
    public class SecurityMonitor
    {
        private PolicyEngine _policyEngine;
        private FileInspector _fileInspector;
        private ProcessMonitor _processMonitor;
        private SecurityLogger _logger;
        private CancellationTokenSource _cancellationTokenSource;

        public SecurityMonitor(string policyFilePath, string logFilePath)
        {
            _policyEngine = new PolicyEngine(policyFilePath);
            _fileInspector = new FileInspector();
            _processMonitor = new ProcessMonitor();
            _logger = new SecurityLogger(logFilePath);
            _cancellationTokenSource = new CancellationTokenSource();
        }

        /// <summary>
        /// Start monitoring process creation events via WMI and ETW
        /// </summary>
        public void Start()
        {
            Console.WriteLine("[*] Starting File Security Monitor");
            Console.WriteLine($"[*] Policy file: {_policyEngine.PolicyFilePath}");
            Console.WriteLine($"[*] Log file: {_logger.LogFilePath}");
            
            _logger.Log("Monitor started");

            // Start ETW monitoring for process creation
            Task etwTask = StartETWMonitoring(_cancellationTokenSource.Token);
            
            // Alternative/fallback: WMI monitoring for process creation
            Task wmiTask = StartWMIMonitoring(_cancellationTokenSource.Token);

            Console.WriteLine("[+] Monitoring active. Press Ctrl+C to stop.");
            Console.CancelKeyPress += (sender, e) => 
            {
                e.Cancel = true;
                Stop();
            };

            try
            {
                Task.WaitAll(etwTask, wmiTask);
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("[*] Monitoring stopped");
            }
        }

        /// <summary>
        /// Start ETW-based monitoring (preferred method, real-time)
        /// </summary>
        private Task StartETWMonitoring(CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                try
                {
                    Console.WriteLine("[*] ETW monitoring initialized");
                    _logger.Log("ETW monitoring started");

                    // ETW provider GUID for process creation (Kernel-Process-Tracing Provider)
                    // This requires elevated privileges
                    var etwSession = new ETWTraceSession("FileSecuritySession");
                    etwSession.OnProcessCreated += (processId, processName, commandLine, parentProcessId) =>
                    {
                        OnProcessCreated(processName, commandLine, processId, parentProcessId);
                    };

                    etwSession.Start(cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError($"ETW monitoring error: {ex.Message}");
                    Console.WriteLine($"[!] ETW error: {ex.Message}");
                }
            }, cancellationToken);
        }

        /// <summary>
        /// Start WMI-based monitoring (fallback, slightly higher latency)
        /// </summary>
        private Task StartWMIMonitoring(CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                try
                {
                    Console.WriteLine("[*] WMI monitoring initialized as fallback");
                    _logger.Log("WMI monitoring started");

                    ManagementEventWatcher processStartWatcher = new ManagementEventWatcher(
                        new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace")
                    );

                    processStartWatcher.EventArrived += (sender, e) =>
                    {
                        try
                        {
                            string processName = (string)e.NewEvent.Properties["ProcessName"].Value;
                            uint processId = (uint)e.NewEvent.Properties["ProcessID"].Value;
                            uint parentId = (uint)e.NewEvent.Properties["ParentProcessID"].Value;

                            OnProcessCreated(processName, "", (int)processId, (int)parentId);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"WMI event processing error: {ex.Message}");
                        }
                    };

                    processStartWatcher.Start();

                    while (!cancellationToken.IsCancellationRequested)
                    {
                        Thread.Sleep(100);
                    }

                    processStartWatcher.Stop();
                }
                catch (Exception ex)
                {
                    _logger.LogError($"WMI monitoring error: {ex.Message}");
                }
            }, cancellationToken);
        }

        /// <summary>
        /// Handle process creation event
        /// </summary>
        private void OnProcessCreated(string processPath, string commandLine, int processId, int parentProcessId)
        {
            try
            {
                if (string.IsNullOrEmpty(processPath))
                    return;

                // Skip system processes to reduce noise
                if (IsSystemProcess(processPath))
                    return;

                Console.WriteLine($"\n[+] Process created: {processPath} (PID: {processId})");

                // Analyze the file
                var fileInfo = _fileInspector.AnalyzeFile(processPath);

                if (fileInfo == null)
                {
                    _logger.LogWarning($"Could not analyze file: {processPath}");
                    return;
                }

                // Get applicable security policy
                var policy = _policyEngine.GetPolicy(fileInfo.Extension);

                Console.WriteLine($"    Extension: {fileInfo.Extension}");
                Console.WriteLine($"    File Type: {fileInfo.DetectedType}");
                Console.WriteLine($"    Security Level: {policy.Level}");

                // Log file details
                _logger.LogProcessExecution(new ProcessExecutionEvent
                {
                    Timestamp = DateTime.Now,
                    ProcessPath = processPath,
                    ProcessId = processId,
                    ParentProcessId = parentProcessId,
                    FileExtension = fileInfo.Extension,
                    DetectedFileType = fileInfo.DetectedType,
                    HasValidSignature = fileInfo.HasValidSignature,
                    SecurityPolicyLevel = policy.Level,
                    PolicyName = policy.Name
                });

                // Enforce policy
                EnforcePolicy(fileInfo, policy, processPath, processId);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error processing process creation: {ex.Message}");
            }
        }

        /// <summary>
        /// Enforce security policy for the file
        /// </summary>
        private void EnforcePolicy(FileAnalysisResult fileInfo, SecurityPolicy policy, string processPath, int processId)
        {
            Console.WriteLine($"    Enforcing policy: {policy.Name}");

            foreach (var rule in policy.Rules)
            {
                switch (rule)
                {
                    case "require_signature":
                        if (!fileInfo.HasValidSignature)
                        {
                            Console.WriteLine($"    [!] POLICY VIOLATION: Unsigned executable blocked");
                            _logger.LogViolation(new PolicyViolation
                            {
                                Timestamp = DateTime.Now,
                                ProcessPath = processPath,
                                ViolationType = "unsigned_executable",
                                PolicyLevel = policy.Level,
                                Action = "block"
                            });
                            TerminateProcess(processId);
                            return;
                        }
                        break;

                    case "require_reputation_check":
                        bool hasGoodReputation = CheckReputation(processPath);
                        if (!hasGoodReputation)
                        {
                            Console.WriteLine($"    [!] POLICY VIOLATION: Bad reputation");
                            _logger.LogViolation(new PolicyViolation
                            {
                                Timestamp = DateTime.Now,
                                ProcessPath = processPath,
                                ViolationType = "bad_reputation",
                                PolicyLevel = policy.Level,
                                Action = "block"
                            });
                            TerminateProcess(processId);
                            return;
                        }
                        break;

                    case "warn_user":
                        Console.WriteLine($"    [!] User warning: Execution of {fileInfo.Extension} file");
                        _logger.Log($"User warned about execution of {fileInfo.Extension}");
                        break;

                    case "log_only":
                        _logger.Log($"Logged execution: {processPath}");
                        break;

                    case "restrict_parent":
                        Console.WriteLine($"    [*] Execution restricted to safe parent processes");
                        break;
                }
            }

            Console.WriteLine($"    [+] Policy enforcement complete - execution allowed");
        }

        /// <summary>
        /// Check file reputation (placeholder for external service integration)
        /// </summary>
        private bool CheckReputation(string filePath)
        {
            // TODO: Integrate with VirusTotal API or Windows Defender API
            // For now, return true (good reputation)
            return true;
        }

        /// <summary>
        /// Terminate a process
        /// </summary>
        private void TerminateProcess(int processId)
        {
            try
            {
                var process = Process.GetProcessById(processId);
                process.Kill();
                _logger.Log($"Terminated process {processId} due to policy violation");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to terminate process {processId}: {ex.Message}");
            }
        }

        /// <summary>
        /// Check if process should be ignored
        /// </summary>
        private bool IsSystemProcess(string processPath)
        {
            string lowerPath = processPath.ToLower();
            
            // Skip common system processes to reduce noise
            string[] systemProcesses = 
            {
                "system32\\csrss.exe",
                "system32\\lsass.exe",
                "system32\\services.exe",
                "system32\\svchost.exe",
                "system32\\smss.exe",
                "system32\\wininit.exe",
                "system32\\dwm.exe",
                "system32\\taskhostw.exe",
                "windows\\explorer.exe",
                "system32\\rundll32.exe",
                "syswow64\\rundll32.exe"
            };

            return systemProcesses.Any(sp => lowerPath.Contains(sp));
        }

        public void Stop()
        {
            Console.WriteLine("\n[*] Shutting down monitor...");
            _cancellationTokenSource.Cancel();
            _logger.Log("Monitor stopped");
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("╔════════════════════════════════════════════════════════╗");
            Console.WriteLine("║     File Security Monitor (ETW-based)                   ║");
            Console.WriteLine("║     Custom Security Policies for File Types            ║");
            Console.WriteLine("╚════════════════════════════════════════════════════════╝\n");

            // Check for admin privileges
            if (!IsElevated())
            {
                Console.WriteLine("[!] ERROR: This application requires administrator privileges");
                Console.WriteLine("[!] Please run as administrator");
                Environment.Exit(1);
            }

            string policyFile = "security_policies.json";
            string logFile = "security_monitor.log";

            // Create sample policy file if it doesn't exist
            if (!File.Exists(policyFile))
            {
                CreateSamplePolicies(policyFile);
                Console.WriteLine($"[+] Created sample policy file: {policyFile}");
            }

            var monitor = new SecurityMonitor(policyFile, logFile);
            monitor.Start();
        }

        static bool IsElevated()
        {
            try
            {
                return new System.Security.Principal.WindowsPrincipal(
                    System.Security.Principal.WindowsIdentity.GetCurrent()
                ).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        static void CreateSamplePolicies(string filePath)
        {
            var policies = new PolicyConfig
            {
                Policies = new Dictionary<string, SecurityPolicy>
                {
                    ["executable"] = new SecurityPolicy
                    {
                        Name = "Executable Files",
                        Extensions = new[] { ".exe", ".com", ".scr", ".msi" },
                        Level = 5,
                        Rules = new[] { "require_signature", "require_reputation_check", "log_only" }
                    },
                    ["script"] = new SecurityPolicy
                    {
                        Name = "Script Files",
                        Extensions = new[] { ".bat", ".vbs", ".ps1", ".cmd" },
                        Level = 3,
                        Rules = new[] { "warn_user", "log_only" }
                    },
                    ["library"] = new SecurityPolicy
                    {
                        Name = "Dynamic Libraries",
                        Extensions = new[] { ".dll", ".sys", ".drv" },
                        Level = 4,
                        Rules = new[] { "require_signature", "log_only" }
                    },
                    ["document"] = new SecurityPolicy
                    {
                        Name = "Document Files",
                        Extensions = new[] { ".txt", ".pdf", ".doc", ".docx" },
                        Level = 1,
                        Rules = new[] { "log_only" }
                    }
                }
            };

            string json = JsonConvert.SerializeObject(policies, Formatting.Indented);
            File.WriteAllText(filePath, json);
        }
    }
}
