using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AntiCrash
{
    public enum WatchdogMode
    {
        Launch,
        AttachPid
    }

    public class WatchdogConfig
    {
        public WatchdogMode Mode { get; set; } = WatchdogMode.Launch;

        // Launch mode
        public string ExecutablePath { get; set; } = "";
        public string Arguments { get; set; } = "";
        public string WorkingDirectory { get; set; } = "";

        // Attach mode
        public int TargetPid { get; set; } = 0;

        // Restart policy
        public int MaxRestarts { get; set; } = 10;           // 0 = unlimited
        public int RestartDelayMs { get; set; } = 2000;      // ms between restarts
        public int MaxRestartsInWindow { get; set; } = 5;    // max restarts in time window
        public int MaxRestartWindowSeconds { get; set; } = 60;

        // Resource limits (0 = disabled)
        public long MemoryLimitMb { get; set; } = 0;         // MB working set limit
        public double CpuThresholdPercent { get; set; } = 0; // % CPU over sample period
        public int CpuSampleSeconds { get; set; } = 10;

        // Health check
        public int HeartbeatTimeoutSeconds { get; set; } = 0;  // 0 = disabled
        public string HealthCheckUrl { get; set; } = "";        // HTTP URL to poll
        public int HealthCheckIntervalSeconds { get; set; } = 10;

        // Notifications
        public string OnCrashScript { get; set; } = "";         // Script to run on crash
        public bool LogToFile { get; set; } = true;
        public string LogFilePath { get; set; } = "anticrash.log";

        // Exit codes that should NOT trigger restart (e.g. clean shutdown)
        public int[] GracefulExitCodes { get; set; } = { 0 };

        public static WatchdogConfig LoadFromFile(string path)
        {
            if (!File.Exists(path))
                throw new FileNotFoundException($"Config file not found: {path}");

            var json = File.ReadAllText(path);
            var opts = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                Converters = { new JsonStringEnumConverter() }
            };
            return JsonSerializer.Deserialize<WatchdogConfig>(json, opts)
                ?? throw new InvalidOperationException("Failed to parse config file.");
        }

        public static void SaveExample(string path)
        {
            var example = new WatchdogConfig
            {
                Mode = WatchdogMode.Launch,
                ExecutablePath = "myapp.exe",
                Arguments = "--port 8080",
                WorkingDirectory = "",
                MaxRestarts = 10,
                RestartDelayMs = 3000,
                MaxRestartsInWindow = 5,
                MaxRestartWindowSeconds = 60,
                MemoryLimitMb = 512,
                CpuThresholdPercent = 95,
                CpuSampleSeconds = 10,
                HeartbeatTimeoutSeconds = 30,
                HealthCheckUrl = "http://localhost:8080/health",
                HealthCheckIntervalSeconds = 10,
                OnCrashScript = "",
                LogToFile = true,
                LogFilePath = "anticrash.log",
                GracefulExitCodes = new[] { 0 }
            };

            var opts = new JsonSerializerOptions
            {
                WriteIndented = true,
                Converters = { new JsonStringEnumConverter() }
            };
            File.WriteAllText(path, JsonSerializer.Serialize(example, opts));
        }
    }
}
