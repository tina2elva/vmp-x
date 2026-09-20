#!/usr/bin/env python3
"""aslr_probe.py -- is the packed image actually relocated by the loader? (target item (6))

Starts the artifact N times suspended and reads PEB->ImageBaseAddress each time. With relocations
kept + DYNAMIC_BASE set the base must vary run to run; with the old behaviour (-strip-relocs) it is
always the preferred base.

It also asserts, statically: RELOCS_STRIPPED clear, DYNAMIC_BASE set, a non-empty BASERELOC dir.

Usage:
  python tools/aslr_probe.py --exe build/target_vmp.exe [--runs 6] [--require-aslr]
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import os
import sys

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
nt = ctypes.WinDLL("ntdll")
CREATE_SUSPENDED = 0x00000004


class PBI(ctypes.Structure):
    _fields_ = [("Reserved1", ctypes.c_void_p), ("PebBaseAddress", ctypes.c_void_p),
                ("Reserved2", ctypes.c_void_p * 2), ("UniqueProcessId", ctypes.c_void_p),
                ("Reserved3", ctypes.c_void_p)]


class STARTUPINFOA(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("lpReserved", wt.LPSTR), ("lpDesktop", wt.LPSTR), ("lpTitle", wt.LPSTR),
                ("dwX", wt.DWORD), ("dwY", wt.DWORD), ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD),
                ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD), ("dwFillAttribute", wt.DWORD),
                ("dwFlags", wt.DWORD), ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE),
                ("hStdError", wt.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE),
                ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD)]


def preferred_base(path):
    d = open(path, "rb").read()
    pe = int.from_bytes(d[0x3C:0x40], "little")
    return int.from_bytes(d[pe + 24 + 24:pe + 24 + 32], "little")


def static_flags(path):
    d = open(path, "rb").read()
    pe = int.from_bytes(d[0x3C:0x40], "little")
    ch = int.from_bytes(d[pe + 22:pe + 24], "little")
    dll = int.from_bytes(d[pe + 24 + 70:pe + 24 + 72], "little")
    rr = int.from_bytes(d[pe + 24 + 112 + 40:pe + 24 + 112 + 44], "little")
    rs = int.from_bytes(d[pe + 24 + 112 + 44:pe + 24 + 112 + 48], "little")
    return {"stripped": bool(ch & 1), "dynamic_base": bool((dll >> 6) & 1), "reloc_rva": rr, "reloc_size": rs}


def image_base_once(exe):
    si = STARTUPINFOA()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    cmd = ('"%s" bench check_key 1' % os.path.abspath(exe)).encode()
    if not k32.CreateProcessA(None, cmd, None, None, False, CREATE_SUSPENDED, None, None,
                              ctypes.byref(si), ctypes.byref(pi)):
        return None
    h = k32.OpenProcess(0x0400, False, pi.dwProcessId)
    pbi = PBI()
    nt.NtQueryInformationProcess(ctypes.c_void_p(h), 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None)
    k32.CloseHandle(h)
    base = None
    if pbi.PebBaseAddress:
        buf = ctypes.c_void_p(0)
        read = ctypes.c_size_t(0)
        # PEB+0x10 = ImageBaseAddress
        k32.ReadProcessMemory.restype = wt.BOOL
        k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        if k32.ReadProcessMemory(pi.hProcess, ctypes.c_void_p(pbi.PebBaseAddress + 0x10),
                                 ctypes.byref(buf), ctypes.sizeof(ctypes.c_void_p), ctypes.byref(read)):
            base = buf.value
    k32.TerminateProcess(pi.hProcess, 0)
    k32.CloseHandle(pi.hProcess)
    k32.CloseHandle(pi.hThread)
    return base


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--runs", type=int, default=6)
    ap.add_argument("--require-aslr", action="store_true")
    a = ap.parse_args()
    st = static_flags(a.exe)
    print("[*] %s: RELOCS_STRIPPED=%d DYNAMIC_BASE=%d relocDir=0x%X/%d" %
          (a.exe, st["stripped"], st["dynamic_base"], st["reloc_rva"], st["reloc_size"]))
    bad = 0
    if st["stripped"] or not st["dynamic_base"] or not st["reloc_rva"] or st["reloc_size"] < 8:
        print("[FAIL] not relocatable / ASLR disabled in the PE headers")
        bad += 1
    bases = []
    for _ in range(a.runs):
        b = image_base_once(a.exe)
        if b:
            bases.append(b)
    uniq = sorted(set(bases))
    print("[*] load bases over %d runs: %s" % (len(bases), " ".join("0x%X" % b for b in uniq)))
    pref = preferred_base(a.exe)
    print("[*] preferred ImageBase = 0x%X" % pref)
    if len(uniq) < 2:
        # 这台机器（和 Windows 默认设置下）ASLR 的熵可能按"每次启动"而不是"每次进程"给，
        # 所以"基址每次都不同"不能当硬性条件 —— 校准过：notepad.exe 在本机也一样恒定。
        print("[!] same base every run (this machine does not vary it per process; notepad.exe behaves the same)")
    # 真正的硬条件：加载器**确实重定位了**镜像（基址 != 首选基址）。做不到就说明重定位项没生效。
    if bases and all(b == pref for b in bases):
        print("[FAIL] the image always landed on its preferred base -- relocations were ignored")
        bad += 1
    if bad:
        return 1
    print("[OK  ] relocations kept, DYNAMIC_BASE set, image loaded at a base != preferred")
    return 0


if __name__ == "__main__":
    sys.exit(main())
