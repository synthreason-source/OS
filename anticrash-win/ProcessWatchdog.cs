using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace AntiCrash
{
    public class ProcessWatchdog : IDisposable
    {
        private readonly WatchdogConfig _cfg;
        private readonly WatchdogLogger _log;
        private readonly HttpClient _http;
        private int _restartCount = 0;
        private readonly Queue<DateTime> _restartWindow = new();
        private Process? _proc;

        public ProcessWatchdog(WatchdogConfig config)
        {
            _cfg = config;
            _log = new WatchdogLogger(config.LogToFile ? config.LogFilePath : null);
            _http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        }

        public async Task Run(CancellationToken ct)
        {
            if (_cfg.Mode == WatchdogMode.AttachPid)
            {
                await RunAttachMode(ct);
                return;
            }

            _log.Info($"Watchdog started for: {_cfg.ExecutablePath} {_cfg.Arguments}");
            _log.Info($"Policy: max {(_cfg.MaxRestarts == 0 ? "unlimited" : _cfg.MaxRestarts)} restarts, {_cfg.RestartDelayMs}ms delay");

            while (!ct.IsCancellationRequested)
            {
                // Rate-limit check
                if (IsRestartThrottled())
                {
                    _log.Error($"Restart rate limit hit: {_cfg.MaxRestartsInWindow} restarts in {_cfg.MaxRestartWindowSeconds}s window. Stopping.");
                    break;
                }

                if (_cfg.MaxRestarts > 0 && _restartCount >= _cfg.MaxRestarts)
                {
                    _log.Error($"Max restart limit reached ({_cfg.MaxRestarts}). Stopping watchdog.");
                    break;
                }

                bool isFirstLaunch = _restartCount == 0;
                if (!isFirstLaunch)
                {
                    _log.Info($"Waiting {_cfg.RestartDelayMs}ms before restart #{_restartCount + 1}...");
                    try { await Task.Delay(_cfg.RestartDelayMs, ct); } catch (OperationCanceledException) { break; }
                }

                int exitCode = await LaunchAndMonitor(ct);

                if (ct.IsCancellationRequested) break;

                if (_cfg.GracefulExitCodes.Contains(exitCode))
                {
                    _log.Info($"Process exited gracefully (code {exitCode}). Watchdog stopping.");
                    break;
                }

                _log.Warn($"Process exited with code {exitCode}. Scheduling restart.");
                _restartWindow.Enqueue(DateTime.UtcNow);
                _restartCount++;

                FireCrashScript(exitCode);
            }
        }

        private async Task<int> LaunchAndMonitor(CancellationToken ct)
        {
            _log.Info($"Launching: {_cfg.ExecutablePath} {_cfg.Arguments}");

            var psi = new ProcessStartInfo
            {
                FileName = _cfg.ExecutablePath,
                Arguments = _cfg.Arguments,
                WorkingDirectory = string.IsNullOrWhiteSpace(_cfg.WorkingDirectory)
                    ? Path.GetDirectoryName(Path.GetFullPath(_cfg.ExecutablePath)) ?? Environment.CurrentDirectory
                    : _cfg.WorkingDirectory,
                UseShellExecute = false,
                RedirectStandardOutput = false,
                RedirectStandardError = false
            };

            _proc = new Process { StartInfo = psi, EnableRaisingEvents = true };

            var tcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
            _proc.Exited += (s, e) => tcs.TrySetResult(_proc.ExitCode);

            try
            {
                _proc.Start();
                _log.Info($"Process started. PID: {_proc.Id}");
            }
            catch (Exception ex)
            {
                _log.Error($"Failed to start process: {ex.Message}");
                return -1;
            }

            // Start monitoring tasks
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var monitorTasks = new List<Task>();

            if (_cfg.MemoryLimitMb > 0)
                monitorTasks.Add(MonitorMemory(_proc, linkedCts.Token));

            if (_cfg.CpuThresholdPercent > 0)
                monitorTasks.Add(MonitorCpu(_proc, linkedCts.Token));

            if (_cfg.HeartbeatTimeoutSeconds > 0 && !string.IsNullOrWhiteSpace(_cfg.HealthCheckUrl))
                monitorTasks.Add(MonitorHealthCheck(_proc, linkedCts.Token));

            // Wait for process to exit
            using var ctReg = ct.Register(() => tcs.TrySetCanceled());

            int exitCode;
            try
            {
                exitCode = await tcs.Task;
            }
            catch (OperationCanceledException)
            {
                _log.Info("Cancellation requested. Terminating process...");
                KillProcessSafely(_proc);
                exitCode = -1;
            }
            finally
            {
                linkedCts.Cancel();
                if (monitorTasks.Count > 0)
                    await Task.WhenAll(monitorTasks.Select(t => t.ContinueWith(_ => { })));
            }

            _log.Info($"Process exited. Code: {exitCode}");
            return exitCode;
        }

        private async Task MonitorMemory(Process proc, CancellationToken ct)
        {
            long limitBytes = _cfg.MemoryLimitMb * 1024 * 1024;
            _log.Info($"Memory monitor active: limit {_cfg.MemoryLimitMb} MB");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(5000, ct);
                    proc.Refresh();
                    if (proc.HasExited) break;

                    long mem = proc.WorkingSet64;
                    double memMb = mem / 1024.0 / 1024.0;

                    if (mem > limitBytes)
                    {
                        _log.Warn($"Memory limit exceeded: {memMb:F1} MB > {_cfg.MemoryLimitMb} MB. Killing process.");
                        KillProcessSafely(proc);
                        break;
                    }
                    else
                    {
                        _log.Debug($"Memory: {memMb:F1} MB / {_cfg.MemoryLimitMb} MB");
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (InvalidOperationException) { break; } // process exited
                catch (Exception ex) { _log.Warn($"Memory monitor error: {ex.Message}"); }
            }
        }

        private async Task MonitorCpu(Process proc, CancellationToken ct)
        {
            _log.Info($"CPU monitor active: threshold {_cfg.CpuThresholdPercent}% over {_cfg.CpuSampleSeconds}s");
            int processorCount = Environment.ProcessorCount;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    proc.Refresh();
                    if (proc.HasExited) break;
                    var t1 = proc.TotalProcessorTime;
                    var w1 = DateTime.UtcNow;

                    await Task.Delay(_cfg.CpuSampleSeconds * 1000, ct);

                    proc.Refresh();
                    if (proc.HasExited) break;
                    var t2 = proc.TotalProcessorTime;
                    var w2 = DateTime.UtcNow;

                    double cpuUsed = (t2 - t1).TotalMilliseconds;
                    double wallMs = (w2 - w1).TotalMilliseconds * processorCount;
                    double pct = wallMs > 0 ? (cpuUsed / wallMs) * 100.0 : 0;

                    if (pct > _cfg.CpuThresholdPercent)
                    {
                        _log.Warn($"CPU threshold exceeded: {pct:F1}% > {_cfg.CpuThresholdPercent}%. Killing process.");
                        KillProcessSafely(proc);
                        break;
                    }
                    else
                    {
                        _log.Debug($"CPU: {pct:F1}% / {_cfg.CpuThresholdPercent}%");
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (InvalidOperationException) { break; }
                catch (Exception ex) { _log.Warn($"CPU monitor error: {ex.Message}"); }
            }
        }

        private async Task MonitorHealthCheck(Process proc, CancellationToken ct)
        {
            _log.Info($"Health check monitor active: {_cfg.HealthCheckUrl} every {_cfg.HealthCheckIntervalSeconds}s, timeout {_cfg.HeartbeatTimeoutSeconds}s");
            DateTime lastSuccess = DateTime.UtcNow;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(_cfg.HealthCheckIntervalSeconds * 1000, ct);
                    if (proc.HasExited) break;

                    bool ok = await DoHealthCheck();
                    if (ok)
                    {
                        lastSuccess = DateTime.UtcNow;
                        _log.Debug($"Health check OK");
                    }
                    else
                    {
                        double elapsed = (DateTime.UtcNow - lastSuccess).TotalSeconds;
                        _log.Warn($"Health check failed. Unhealthy for {elapsed:F0}s / {_cfg.HeartbeatTimeoutSeconds}s timeout.");

                        if (elapsed >= _cfg.HeartbeatTimeoutSeconds)
                        {
                            _log.Error($"Health check timeout exceeded. Killing process.");
                            KillProcessSafely(proc);
                            break;
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (InvalidOperationException) { break; }
                catch (Exception ex) { _log.Warn($"Health check error: {ex.Message}"); }
            }
        }

        private async Task<bool> DoHealthCheck()
        {
            try
            {
                var resp = await _http.GetAsync(_cfg.HealthCheckUrl);
                return resp.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        private async Task RunAttachMode(CancellationToken ct)
        {
            _log.Info($"Attaching to PID: {_cfg.TargetPid}");
            Process proc;

            try
            {
                proc = Process.GetProcessById(_cfg.TargetPid);
            }
            catch
            {
                _log.Error($"Could not find process with PID {_cfg.TargetPid}");
                return;
            }

            _log.Info($"Watching: {proc.ProcessName} (PID {proc.Id})");

            var tcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
            proc.EnableRaisingEvents = true;
            proc.Exited += (s, e) => tcs.TrySetResult(proc.ExitCode);

            if (proc.HasExited)
            {
                _log.Warn($"Process already exited with code {proc.ExitCode}.");
                return;
            }

            using var ctReg = ct.Register(() => tcs.TrySetCanceled());

            int exitCode;
            try { exitCode = await tcs.Task; }
            catch (OperationCanceledException) { return; }

            _log.Warn($"Watched process exited with code {exitCode}.");
            FireCrashScript(exitCode);
        }

        private void FireCrashScript(int exitCode)
        {
            if (string.IsNullOrWhiteSpace(_cfg.OnCrashScript)) return;
            try
            {
                _log.Info($"Running crash script: {_cfg.OnCrashScript}");
                Process.Start(new ProcessStartInfo
                {
                    FileName = _cfg.OnCrashScript,
                    Arguments = exitCode.ToString(),
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                _log.Warn($"Failed to run crash script: {ex.Message}");
            }
        }

        private bool IsRestartThrottled()
        {
            if (_cfg.MaxRestartsInWindow <= 0 || _cfg.MaxRestartWindowSeconds <= 0) return false;

            var cutoff = DateTime.UtcNow.AddSeconds(-_cfg.MaxRestartWindowSeconds);
            while (_restartWindow.Count > 0 && _restartWindow.Peek() < cutoff)
                _restartWindow.Dequeue();

            return _restartWindow.Count >= _cfg.MaxRestartsInWindow;
        }

        private void KillProcessSafely(Process proc)
        {
            try
            {
                if (!proc.HasExited)
                {
                    proc.Kill(entireProcessTree: true);
                    _log.Info("Process killed.");
                }
            }
            catch (Exception ex)
            {
                _log.Warn($"Kill failed: {ex.Message}");
            }
        }

        public void Dispose()
        {
            _proc?.Dispose();
            _http.Dispose();
            _log.Dispose();
        }
    }
}
