#!/usr/bin/env python3
r"""rip_probe.py -- sample the instruction pointers of a RUNNING 32-bit process and
classify them: interpreter (RIP stays in the mapped runtime image) or JIT (RIP lands in
private executable pages that were allocated at runtime)?

Usage:
  python tools/rip_probe.py --run "D:\other\demo32.exe --loop --hold 60" --delay 8 --samples 400
  python tools/rip_probe.py --run "D:\demo_exe\demo32.exe --loop --hold 60" --delay 3 --samples 400 --tag control
"""
import argparse, ctypes, ctypes.wintypes as wt, subprocess, sys, time
from collections import Counter

MAX_ADDR = 0x7FFFFFFF0000
MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE, MEM_MAPPED = 0x1000, 0x1000000, 0x20000, 0x40000
PAGE_EXECUTE = 0x10
PROCESS_QUERY_INFORMATION, PROCESS_VM_READ = 0x0400, 0x0010
TH32CS_SNAPTHREAD = 0x4
CONTEXT_i386, CONTEXT_CONTROL = 0x00010000, 0x00010001


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_ulonglong), ("AllocationBase", ctypes.c_ulonglong),
                ("AllocationProtect", wt.DWORD), ("__a1", wt.DWORD),
                ("RegionSize", ctypes.c_ulonglong), ("State", wt.DWORD),
                ("Protect", wt.DWORD), ("Type", wt.DWORD), ("__a2", wt.DWORD)]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ThreadID", wt.DWORD),
                ("th32OwnerProcessID", wt.DWORD), ("tpBasePri", ctypes.c_long),
                ("tpDeltaPri", ctypes.c_long), ("dwFlags", wt.DWORD)]


class FLOATSAVE(ctypes.Structure):
    _fields_ = [("ControlWord", wt.DWORD), ("StatusWord", wt.DWORD), ("TagWord", wt.DWORD),
                ("ErrorOffset", wt.DWORD), ("ErrorSelector", wt.DWORD), ("DataOffset", wt.DWORD),
                ("DataSelector", wt.DWORD), ("RegisterArea", ctypes.c_byte * 80),
                ("Cr0NpxState", wt.DWORD)]


class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [("ContextFlags", wt.DWORD), ("Dr0", wt.DWORD), ("Dr1", wt.DWORD), ("Dr2", wt.DWORD),
                ("Dr3", wt.DWORD), ("Dr6", wt.DWORD), ("Dr7", wt.DWORD), ("FloatSave", FLOATSAVE),
                ("SegGs", wt.DWORD), ("SegFs", wt.DWORD), ("SegEs", wt.DWORD), ("SegDs", wt.DWORD),
                ("Edi", wt.DWORD), ("Esi", wt.DWORD), ("Ebx", wt.DWORD), ("Edx", wt.DWORD),
                ("Ecx", wt.DWORD), ("Eax", wt.DWORD), ("Ebp", wt.DWORD), ("Eip", wt.DWORD),
                ("SegCs", wt.DWORD), ("EFlags", wt.DWORD), ("Esp", wt.DWORD), ("SegSs", wt.DWORD),
                ("ExtendedRegisters", ctypes.c_byte * 512)]


k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
k32.Thread32First.argtypes = [wt.HANDLE, ctypes.POINTER(THREADENTRY32)]
k32.Thread32Next.argtypes = [wt.HANDLE, ctypes.POINTER(THREADENTRY32)]
k32.OpenThread.restype = wt.HANDLE
k32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.Wow64GetThreadContext.argtypes = [wt.HANDLE, ctypes.POINTER(WOW64_CONTEXT)]
try:
    k32.Wow64GetThreadContext.restype = wt.BOOL
except Exception:
    pass

THREAD_GET_CONTEXT, THREAD_SUSPEND_RESUME = 0x0008, 0x0002


def regions(h):
    out, addr, mbi = [], 0, MBI()
    while addr < MAX_ADDR:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        size = mbi.RegionSize or 0x1000
        if mbi.State == MEM_COMMIT:
            out.append((mbi.BaseAddress, size, mbi.Type, mbi.Protect))
        addr = mbi.BaseAddress + size
    return out


def classify(rs, eip):
    for base, size, typ, prot in rs:
        if base <= eip < base+size:
            kind = {MEM_IMAGE: 'image(module)', MEM_PRIVATE: 'private', MEM_MAPPED: 'mapped'}.get(typ, hex(typ))
            return kind, bool(prot & 0xF0)
    return 'unmapped', False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--run', required=True)
    ap.add_argument('--delay', type=float, default=8.0)
    ap.add_argument('--samples', type=int, default=400)
    ap.add_argument('--interval', type=float, default=0.01)
    ap.add_argument('--tag', default='')
    a = ap.parse_args()

    proc = subprocess.Popen(a.run.split(' '), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(a.delay)
        h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, proc.pid)
        if not h:
            raise SystemExit("OpenProcess failed %d" % ctypes.get_last_error())
        rs = regions(h)
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        tids = []
        e = THREADENTRY32(); e.dwSize = ctypes.sizeof(THREADENTRY32)
        ok = k32.Thread32First(snap, ctypes.byref(e))
        while ok:
            if e.th32OwnerProcessID == proc.pid:
                tids.append(e.th32ThreadID)
            ok = k32.Thread32Next(snap, ctypes.byref(e))
        k32.CloseHandle(snap)
        print("[*] %s pid=%d threads=%d regions=%d" % (a.tag, proc.pid, len(tids), len(rs)))
        # 内存类型普查：JIT 出来的代码必须住在 "private + executable" 区。
        cen, jit = Counter(), []
        for base, size, typ, prot in rs:
            kind = {MEM_IMAGE: 'image', MEM_PRIVATE: 'private', MEM_MAPPED: 'mapped'}.get(typ, hex(typ))
            ex = bool(prot & 0xF0)
            wr = bool(prot & (0x04 | 0x08 | 0x40 | 0x80))
            cen["%s/%s%s" % (kind, "X" if ex else "-", "W" if wr else "-")] += size
            if kind == 'private' and ex:
                jit.append((base, size, prot))
        for k, v in sorted(cen.items(), key=lambda kv: -kv[1]):
            print("      mem %-16s %8.2f MB" % (k, v/1048576.0))
        print("    private+executable regions (JIT candidates): %d" %
              len(jit) + ("" if not jit else " -> " + ", ".join("0x%X(%dKB)" % (b, s//1024) for b, s, _ in jit[:8])))
        hist, addrs = Counter(), Counter()
        got = 0
        for k in range(a.samples):
            for tid in tids:
                th = k32.OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, False, tid)
                if not th:
                    continue
                ctx = WOW64_CONTEXT(); ctx.ContextFlags = CONTEXT_CONTROL
                if k32.Wow64GetThreadContext(th, ctypes.byref(ctx)):
                    kind, exec_ok = classify(rs, ctx.Eip)
                    hist["%s%s" % (kind, "/exec" if exec_ok else "/noexec")] += 1
                    addrs[ctx.Eip] += 1
                    got += 1
                k32.CloseHandle(th)
            time.sleep(a.interval)
        print("    samples=%d" % got)
        for k, v in hist.most_common():
            print("      %-24s %5d  (%.1f%%)" % (k, v, 100.0*v/max(got, 1)))
        print("    hottest EIPs:")
        for ip, c in addrs.most_common(8):
            kind, _ = classify(rs, ip)
            print("      0x%08X  %4d  %s" % (ip, c, kind))
    finally:
        try: proc.kill()
        except Exception: pass


if __name__ == '__main__':
    main()
