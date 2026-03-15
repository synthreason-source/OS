using System;
using System.Threading;

namespace AntiCrash
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "AntiCrash Watchdog";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("===========================================");
            Console.WriteLine("       AntiCrash Process Watchdog");
            Console.WriteLine("===========================================");
            Console.ResetColor();

            if (args.Length == 0)
            {
                Console.WriteLine("\nUsage:");
                Console.WriteLine("  AntiCrash.exe <executable> [arguments]   - launch + watchdog");
                Console.WriteLine("  AntiCrash.exe --pid <process_id>         - watchdog an existing process");
                Console.WriteLine("  AntiCrash.exe --debug <process_id>       - attach debugger, skip crashes");
                Console.WriteLine("  AntiCrash.exe --config <config.json>     - use config file");
                Console.WriteLine("\nExamples:");
                Console.WriteLine("  AntiCrash.exe myapp.exe --port 8080");
                Console.WriteLine("  AntiCrash.exe --pid 1234");
                Console.WriteLine("  AntiCrash.exe --debug 1234");
                Console.WriteLine("  AntiCrash.exe --config watchdog.json");
                return;
            }

            // --debug mode: attach as debugger, skip faulting instructions
            if (args[0] == "--debug" && args.Length >= 2)
            {
                if (!uint.TryParse(args[1], out uint debugPid))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Invalid PID: {args[1]}");
                    Console.ResetColor();
                    return;
                }

                var log = new WatchdogLogger("anticrash-debug.log");
                var dbg = new DebugRecovery(debugPid, log);

                Console.CancelKeyPress += (s, e) => { e.Cancel = true; dbg.Stop(); };

                try { dbg.Attach(); }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[Debug] {ex.Message}");
                    Console.ResetColor();
                }
                return;
            }

            WatchdogConfig config;

            if (args[0] == "--config" && args.Length >= 2)
            {
                config = WatchdogConfig.LoadFromFile(args[1]);
            }
            else if (args[0] == "--pid" && args.Length >= 2)
            {
                if (!int.TryParse(args[1], out int pid))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Invalid PID: {args[1]}");
                    Console.ResetColor();
                    return;
                }
                config = new WatchdogConfig
                {
                    Mode = WatchdogMode.AttachPid,
                    TargetPid = pid,
                    MaxRestarts = 0
                };
            }
            else
            {
                config = new WatchdogConfig
                {
                    Mode = WatchdogMode.Launch,
                    ExecutablePath = args[0],
                    Arguments = args.Length > 1 ? string.Join(" ", args, 1, args.Length - 1) : "",
                    MaxRestarts = 10,
                    RestartDelayMs = 2000,
                    MaxRestartWindowSeconds = 60,
                    MaxRestartsInWindow = 5,
                    MemoryLimitMb = 0,
                    CpuThresholdPercent = 0,
                    HeartbeatTimeoutSeconds = 0
                };
            }

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\n[Watchdog] Shutdown requested...");
                Console.ResetColor();
                cts.Cancel();
            };

            var watchdog = new ProcessWatchdog(config);
            watchdog.Run(cts.Token).GetAwaiter().GetResult();

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[Watchdog] Exited.");
            Console.ResetColor();
        }
    }
}
