using System;
using System.IO;

namespace AntiCrash
{
    public class WatchdogLogger : IDisposable
    {
        private readonly StreamWriter? _writer;
        private readonly object _lock = new();

        public WatchdogLogger(string? logFilePath)
        {
            if (!string.IsNullOrWhiteSpace(logFilePath))
            {
                try
                {
                    _writer = new StreamWriter(logFilePath, append: true) { AutoFlush = true };
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"[Logger] Could not open log file: {ex.Message}");
                    Console.ResetColor();
                }
            }
        }

        public void Info(string msg) => Write("INFO ", ConsoleColor.Cyan, msg);
        public void Warn(string msg) => Write("WARN ", ConsoleColor.Yellow, msg);
        public void Error(string msg) => Write("ERROR", ConsoleColor.Red, msg);
        public void Debug(string msg) => Write("DEBUG", ConsoleColor.DarkGray, msg);

        private void Write(string level, ConsoleColor color, string msg)
        {
            string ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string line = $"[{ts}] [{level}] {msg}";

            lock (_lock)
            {
                Console.ForegroundColor = color;
                Console.WriteLine(line);
                Console.ResetColor();
                _writer?.WriteLine(line);
            }
        }

        public void Dispose()
        {
            _writer?.Flush();
            _writer?.Dispose();
        }
    }
}
