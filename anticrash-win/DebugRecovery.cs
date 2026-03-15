using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace AntiCrash
{
    /// <summary>
    /// Attaches to a process as a debugger, catches exceptions/crashes,
    /// and advances the instruction pointer past the faulting instruction
    /// so the process can continue running instead of dying.
    /// 
    /// Uses Windows Debug API: DebugActiveProcess / WaitForDebugEvent / ContinueDebugEvent.
    /// </summary>
    public class DebugRecovery
    {
        #region Win32 Imports

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DebugActiveProcess(uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DebugActiveProcessStop(uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WaitForDebugEvent(out DEBUG_EVENT lpDebugEvent, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ContinueDebugEvent(uint dwProcessId, uint dwThreadId, uint dwContinueStatus);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwAccess, bool bInherit, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBase,
            byte[] lpBuffer, int nSize, out int lpRead);

        // Thread access rights
        const uint THREAD_GET_CONTEXT    = 0x0008;
        const uint THREAD_SET_CONTEXT    = 0x0010;
        const uint THREAD_SUSPEND_RESUME = 0x0002;
        const uint THREAD_ALL_ACCESS     = 0x1FFFFF;

        // Process access
        const uint PROCESS_VM_READ = 0x0010;

        // Debug continue codes
        const uint DBG_CONTINUE              = 0x00010002;
        const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;

        // Debug event codes
        const uint EXCEPTION_DEBUG_EVENT     = 1;
        const uint CREATE_THREAD_DEBUG_EVENT = 2;
        const uint CREATE_PROCESS_DEBUG_EVENT= 3;
        const uint EXIT_THREAD_DEBUG_EVENT   = 4;
        const uint EXIT_PROCESS_DEBUG_EVENT  = 5;
        const uint LOAD_DLL_DEBUG_EVENT      = 6;
        const uint UNLOAD_DLL_DEBUG_EVENT    = 7;
        const uint OUTPUT_DEBUG_STRING_EVENT = 8;
        const uint RIP_EVENT                 = 9;

        // Exception codes
        const uint EXCEPTION_ACCESS_VIOLATION     = 0xC0000005;
        const uint EXCEPTION_ARRAY_BOUNDS         = 0xC000008C;
        const uint EXCEPTION_BREAKPOINT           = 0x80000003;
        const uint EXCEPTION_DATATYPE_MISALIGN    = 0x80000002;
        const uint EXCEPTION_FLT_DIVIDE_BY_ZERO   = 0xC000008E;
        const uint EXCEPTION_FLT_OVERFLOW         = 0xC0000091;
        const uint EXCEPTION_ILLEGAL_INSTRUCTION  = 0xC000001D;
        const uint EXCEPTION_INT_DIVIDE_BY_ZERO   = 0xC0000094;
        const uint EXCEPTION_INT_OVERFLOW         = 0xC0000095;
        const uint EXCEPTION_PRIV_INSTRUCTION     = 0xC0000096;
        const uint EXCEPTION_STACK_OVERFLOW       = 0xC00000FD;
        const uint EXCEPTION_SINGLE_STEP          = 0x80000004;

        // CONTEXT flags
        const uint CONTEXT_AMD64    = 0x00100000;
        const uint CONTEXT_CONTROL  = CONTEXT_AMD64 | 0x01;
        const uint CONTEXT_INTEGER  = CONTEXT_AMD64 | 0x02;
        const uint CONTEXT_FULL     = CONTEXT_CONTROL | CONTEXT_INTEGER | 0x04;

        #endregion

        #region Structures

        [StructLayout(LayoutKind.Sequential)]
        struct EXCEPTION_RECORD
        {
            public uint   ExceptionCode;
            public uint   ExceptionFlags;
            public IntPtr ExceptionRecord;
            public IntPtr ExceptionAddress;
            public uint   NumberParameters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)]
            public ulong[] ExceptionInformation;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct EXCEPTION_DEBUG_INFO
        {
            public EXCEPTION_RECORD ExceptionRecord;
            public uint             dwFirstChance;
        }

        [StructLayout(LayoutKind.Explicit, Size = 176)]
        struct DEBUG_EVENT
        {
            [FieldOffset(0)]  public uint dwDebugEventCode;
            [FieldOffset(4)]  public uint dwProcessId;
            [FieldOffset(8)]  public uint dwThreadId;
            [FieldOffset(16)] public EXCEPTION_DEBUG_INFO Exception;
        }

        // x64 CONTEXT (simplified — only fields we use)
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        struct CONTEXT
        {
            public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
            public uint  ContextFlags;
            public uint  MxCsr;
            public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
            public uint  EFlags;
            public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
            public ulong R8,  R9,  R10, R11, R12, R13, R14, R15;
            public ulong Rip;   // ← instruction pointer we advance
            // (Floating point / vector state omitted — not needed for skip)
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] FloatSave;
        }

        #endregion

        // ── Public API ───────────────────────────────────────────────────────

        private readonly uint _pid;
        private readonly WatchdogLogger _log;
        private bool _attached;
        private int _skipCount;
        private int _totalExceptions;

        public DebugRecovery(uint pid, WatchdogLogger log)
        {
            _pid  = pid;
            _log  = log;
        }

        /// <summary>
        /// Attach to the target process as a debugger and enter the debug event loop.
        /// On each unhandled exception: log it, advance RIP past the faulting instruction,
        /// and let the thread continue. Call Stop() or Ctrl+C to detach.
        /// </summary>
        public void Attach()
        {
            if (!DebugActiveProcess(_pid))
                throw new InvalidOperationException(
                    $"DebugActiveProcess failed: {Marshal.GetLastWin32Error()}. " +
                    "Run as Administrator, or ensure the target process is not already being debugged.");

            _attached = true;
            _log.Info($"Attached as debugger to PID {_pid}. Entering event loop.");
            _log.Info("Press Ctrl+C to detach.");

            try
            {
                EventLoop();
            }
            finally
            {
                Detach();
            }
        }

        public void Stop() => _attached = false;

        // ── Debug event loop ─────────────────────────────────────────────────

        void EventLoop()
        {
            var hProc = OpenProcess(PROCESS_VM_READ, false, _pid);

            while (_attached)
            {
                if (!WaitForDebugEvent(out var evt, 500))
                    continue; // timeout — loop and check _attached

                switch (evt.dwDebugEventCode)
                {
                    case EXCEPTION_DEBUG_EVENT:
                        HandleException(ref evt, hProc);
                        break;

                    case EXIT_PROCESS_DEBUG_EVENT:
                        _log.Info($"Target process {_pid} exited. Detaching.");
                        _attached = false;
                        ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE);
                        goto done;

                    default:
                        // Thread/DLL load events — just continue
                        ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE);
                        break;
                }
            }
            done:
            if (hProc != IntPtr.Zero) CloseHandle(hProc);

            _log.Info($"Debug session ended. Total exceptions seen: {_totalExceptions}, skipped: {_skipCount}");
        }

        void HandleException(ref DEBUG_EVENT evt, IntPtr hProc)
        {
            var ex  = evt.Exception.ExceptionRecord;
            bool firstChance = evt.Exception.dwFirstChance != 0;
            _totalExceptions++;

            string name = ExceptionName(ex.ExceptionCode);
            _log.Warn($"[{(firstChance ? "1st" : "2ND")}] {name} (0x{ex.ExceptionCode:X8}) " +
                      $"@ 0x{ex.ExceptionAddress:X16}  TID={evt.dwThreadId}");

            // First-chance: pass to the process — it may have its own handler
            if (firstChance)
            {
                ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
                return;
            }

            // Second-chance (unhandled) — process would crash here.
            // Read the faulting instruction bytes for logging, then skip past it.
            int instrLen = ReadInstructionLength(hProc, ex.ExceptionAddress);
            _log.Warn($"Unhandled exception — skipping {instrLen} byte(s) at 0x{ex.ExceptionAddress:X16}");

            bool skipped = AdvanceRip(evt.dwThreadId, (ulong)ex.ExceptionAddress + (ulong)instrLen);
            if (skipped)
            {
                _skipCount++;
                _log.Info($"RIP advanced to 0x{(ulong)ex.ExceptionAddress + (ulong)instrLen:X16}. " +
                          $"Thread resuming. (total skips: {_skipCount})");
                ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE);
            }
            else
            {
                _log.Error("Failed to advance RIP. Passing exception back (process may crash).");
                ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
            }
        }

        // ── RIP manipulation ─────────────────────────────────────────────────

        bool AdvanceRip(uint threadId, ulong newRip)
        {
            IntPtr hThread = OpenThread(THREAD_ALL_ACCESS, false, threadId);
            if (hThread == IntPtr.Zero)
            {
                _log.Error($"OpenThread failed: {Marshal.GetLastWin32Error()}");
                return false;
            }

            try
            {
                SuspendThread(hThread);

                var ctx = new CONTEXT
                {
                    ContextFlags = CONTEXT_FULL,
                    FloatSave    = new byte[512]
                };

                if (!GetThreadContext(hThread, ref ctx))
                {
                    _log.Error($"GetThreadContext failed: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                ulong oldRip = ctx.Rip;
                ctx.Rip = newRip;

                if (!SetThreadContext(hThread, ref ctx))
                {
                    _log.Error($"SetThreadContext failed: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                _log.Info($"  RIP: 0x{oldRip:X16} -> 0x{newRip:X16}");
                return true;
            }
            finally
            {
                ResumeThread(hThread);
                CloseHandle(hThread);
            }
        }

        // ── Instruction length heuristic ─────────────────────────────────────
        // We read up to 15 bytes at the fault address and use a minimal x86-64
        // length disassembler so we advance by the correct number of bytes.
        // Falls back to 1 if we can't read memory.

        int ReadInstructionLength(IntPtr hProc, IntPtr addr)
        {
            byte[] buf = new byte[15];
            if (hProc == IntPtr.Zero ||
                !ReadProcessMemory(hProc, addr, buf, buf.Length, out int read) || read == 0)
                return 1;

            return X64InstrLen(buf);
        }

        /// <summary>
        /// Minimal x86-64 instruction length decoder.
        /// Handles the most common encodings seen at crash sites.
        /// For a production tool you'd link against a proper disassembler (e.g. Zydis via P/Invoke).
        /// </summary>
        static int X64InstrLen(byte[] b)
        {
            int i = 0, len = b.Length;
            if (len == 0) return 1;

            // Skip legacy prefixes (up to 4)
            for (int p = 0; p < 4 && i < len; p++)
            {
                byte pb = b[i];
                if (pb == 0xF0 || pb == 0xF2 || pb == 0xF3 ||  // LOCK, REPNE, REP
                    pb == 0x26 || pb == 0x2E || pb == 0x36 ||   // segment overrides
                    pb == 0x3E || pb == 0x64 || pb == 0x65 ||
                    pb == 0x66 || pb == 0x67)                    // operand/addr size
                    i++;
                else
                    break;
            }
            if (i >= len) return i;

            // REX prefix (40-4F)
            bool rex  = false;
            bool rexW = false;
            if ((b[i] & 0xF0) == 0x40) { rex = true; rexW = (b[i] & 0x08) != 0; i++; }
            if (i >= len) return i;

            byte op = b[i++];

            // Two-byte escape 0F xx
            if (op == 0x0F)
            {
                if (i >= len) return i;
                byte op2 = b[i++];
                // 0F xx ModRM [SIB] [disp]
                return i + ModRmExtra(b, i, len);
            }

            // Single-byte opcodes with known fixed lengths (no ModRM)
            // NOP, RET, HLT, INT3, PUSHF, POPF, etc.
            if (op == 0x90 || op == 0xC3 || op == 0xCB || op == 0xF4 ||
                op == 0xCC || op == 0xCD || op == 0x9C || op == 0x9D)
                return i + (op == 0xCD ? 1 : 0); // INT imm8

            // PUSH/POP reg (50-5F)
            if ((op & 0xF0) == 0x50) return i;

            // MOV reg,imm (B0-BF)
            if ((op & 0xF0) == 0xB0)
                return i + (((op & 0x08) != 0 || rexW) ? 8 : 4); // B8-BF = 64/32-bit imm

            // Short Jcc (70-7F) — 1-byte rel
            if ((op & 0xF0) == 0x70) return i + 1;

            // JMP rel8 (EB), Jcc rel8
            if (op == 0xEB) return i + 1;

            // JMP rel32 (E9), CALL rel32 (E8)
            if (op == 0xE9 || op == 0xE8) return i + 4;

            // JMP/CALL far — skip
            if (op == 0xEA || op == 0x9A) return i + 6;

            // RET imm16
            if (op == 0xC2 || op == 0xCA) return i + 2;

            // MOV r/m, imm  (C6/C7)
            if (op == 0xC6) return i + ModRmExtra(b, i, len) + 1;
            if (op == 0xC7) return i + ModRmExtra(b, i, len) + (rexW ? 4 : 4);

            // IMUL r,r/m,imm32 (69) / imm8 (6B)
            if (op == 0x69) return i + ModRmExtra(b, i, len) + 4;
            if (op == 0x6B) return i + ModRmExtra(b, i, len) + 1;

            // ADD/OR/ADC/SBB/AND/SUB/XOR/CMP  r/m,imm8 (83)
            if (op == 0x83) return i + ModRmExtra(b, i, len) + 1;

            // ADD/OR/.../CMP r/m,imm32 (81)
            if (op == 0x81) return i + ModRmExtra(b, i, len) + 4;

            // TEST r/m,imm (F6/F7)
            if (op == 0xF6) return i + ModRmExtra(b, i, len) + 1;
            if (op == 0xF7) return i + ModRmExtra(b, i, len) + 4;

            // Everything else: assume ModRM present
            return i + ModRmExtra(b, i, len);
        }

        /// <summary>
        /// Consume ModRM byte + optional SIB + displacement and return total extra bytes.
        /// </summary>
        static int ModRmExtra(byte[] b, int i, int len)
        {
            if (i >= len) return 0;
            byte modrm = b[i++];
            int mod = (modrm >> 6) & 0x03;
            int rm  = modrm & 0x07;
            int extra = 0;

            if (mod == 3) return 1; // register — no disp

            // SIB follows when rm==4 and mod != 3
            bool hasSib = (rm == 4);
            if (hasSib) { extra++; i++; }

            // Displacement
            if (mod == 1) extra++;          // disp8
            else if (mod == 2) extra += 4;  // disp32
            else if (mod == 0 && rm == 5)   // RIP-relative disp32
                extra += 4;

            return 1 + extra; // 1 for the ModRM byte itself
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        static string ExceptionName(uint code) => code switch
        {
            EXCEPTION_ACCESS_VIOLATION    => "ACCESS_VIOLATION",
            EXCEPTION_ARRAY_BOUNDS        => "ARRAY_BOUNDS_EXCEEDED",
            EXCEPTION_BREAKPOINT          => "BREAKPOINT",
            EXCEPTION_DATATYPE_MISALIGN   => "DATATYPE_MISALIGNMENT",
            EXCEPTION_FLT_DIVIDE_BY_ZERO  => "FLT_DIVIDE_BY_ZERO",
            EXCEPTION_FLT_OVERFLOW        => "FLT_OVERFLOW",
            EXCEPTION_ILLEGAL_INSTRUCTION => "ILLEGAL_INSTRUCTION",
            EXCEPTION_INT_DIVIDE_BY_ZERO  => "INT_DIVIDE_BY_ZERO",
            EXCEPTION_INT_OVERFLOW        => "INT_OVERFLOW",
            EXCEPTION_PRIV_INSTRUCTION    => "PRIV_INSTRUCTION",
            EXCEPTION_STACK_OVERFLOW      => "STACK_OVERFLOW",
            EXCEPTION_SINGLE_STEP         => "SINGLE_STEP",
            _                             => $"0x{code:X8}"
        };

        void Detach()
        {
            if (!_attached) return;
            _log.Info($"Detaching from PID {_pid}...");
            DebugActiveProcessStop(_pid);
            _attached = false;
        }
    }
}
