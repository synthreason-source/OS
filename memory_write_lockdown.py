"""
memory_write_lockdown.py
────────────────────────
Deny foreign .exe processes write access to a target process's memory on Windows.
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import logging
import os
import sys
import time

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008

PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100

MEM_COMMIT = 0x1000

ProcessDynamicCodePolicy = 2
ProcessSignaturePolicy = 8

TH32CS_SNAPPROCESS = 0x00000002

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

log = logging.getLogger(__name__)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


class PROCESS_MITIGATION_DYNAMIC_CODE_POLICY(ctypes.Structure):
    _fields_ = [("Flags", wt.DWORD)]


class PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY(ctypes.Structure):
    _fields_ = [("Flags", wt.DWORD)]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wt.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wt.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", wt.LONG),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.CHAR * 260),
    ]


SE_PRIVILEGE_ENABLED = 0x2
TOKEN_ADJUST_PRIVILEGES = 0x20
TOKEN_QUERY = 0x8


def require_admin():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Administrator privileges required.")
        sys.exit(1)


def enable_sedebug_privilege():
    token = wt.HANDLE()

    advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(token),
    )

    luid = LUID()

    advapi32.LookupPrivilegeValueW(
        None,
        "SeDebugPrivilege",
        ctypes.byref(luid),
    )

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

    advapi32.AdjustTokenPrivileges(
        token,
        False,
        ctypes.byref(tp),
        0,
        None,
        None,
    )

    kernel32.CloseHandle(token)


def harden_self():
    log.info("Applying self-hardening to PID %d", os.getpid())

    dcp = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY()
    dcp.Flags = 0x1

    kernel32.SetProcessMitigationPolicy(
        ProcessDynamicCodePolicy,
        ctypes.byref(dcp),
        ctypes.sizeof(dcp),
    )

    spp = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY()
    spp.Flags = 0x1

    kernel32.SetProcessMitigationPolicy(
        ProcessSignaturePolicy,
        ctypes.byref(spp),
        ctypes.sizeof(spp),
    )


def is_writable(protect: int) -> bool:
    base = protect & 0xFF
    return base in {
        PAGE_READWRITE,
        PAGE_WRITECOPY,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY,
    }


def iter_writable_regions(hProcess):
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()

    while True:
        result = kernel32.VirtualQueryEx(
            hProcess,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )

        if not result:
            break

        if (
            mbi.State == MEM_COMMIT
            and is_writable(mbi.Protect)
            and not (mbi.Protect & PAGE_GUARD)
        ):
            yield mbi.BaseAddress, mbi.RegionSize, mbi.Protect

        next_addr = (mbi.BaseAddress or 0) + mbi.RegionSize

        if next_addr <= address:
            break

        address = next_addr


def lock_writable_regions(hProcess):
    old_protect = wt.DWORD()

    for base, size, protect in iter_writable_regions(hProcess):

        if protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY):
            new_protect = PAGE_EXECUTE_READ
        else:
            new_protect = PAGE_READONLY

        kernel32.VirtualProtectEx(
            hProcess,
            ctypes.c_void_p(base),
            size,
            new_protect,
            ctypes.byref(old_protect),
        )


def harden_pid(pid):
    hProcess = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE
        | PROCESS_VM_OPERATION,
        False,
        pid,
    )

    if not hProcess:
        return

    try:
        lock_writable_regions(hProcess)
        log.info("PID %d hardened", pid)
    finally:
        kernel32.CloseHandle(hProcess)


def enumerate_pids():
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

    pids = []

    if kernel32.Process32First(snapshot, ctypes.byref(entry)):
        while True:
            if entry.th32ProcessID > 4:
                pids.append(entry.th32ProcessID)

            if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                break

    kernel32.CloseHandle(snapshot)

    return pids


def guardian_loop_single(pid, interval):
    while True:
        harden_pid(pid)
        time.sleep(interval)


def guardian_loop_all(interval):
    while True:
        for pid in enumerate_pids():
            try:
                harden_pid(pid)
            except Exception:
                pass

        time.sleep(interval)


def main():
    if sys.platform != "win32":
        print("Windows only.")
        return

    require_admin()
    enable_sedebug_privilege()

    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("--self", action="store_true")
    group.add_argument("--pid", type=int)
    group.add_argument("--all", action="store_true")

    parser.add_argument("--interval", type=float, default=2.0)

    args = parser.parse_args()

    if args.self:
        harden_self()

    elif args.pid:
        guardian_loop_single(args.pid, args.interval)

    elif args.all:
        guardian_loop_all(args.interval)


if __name__ == "__main__":
    main()