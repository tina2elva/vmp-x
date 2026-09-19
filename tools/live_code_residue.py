#!/usr/bin/env python3
r"""live_code_residue.py -- is the ORIGINAL machine code of a function present ANYWHERE
in the address space of a running (protected) process?

Answers the question at full strength:
  * whole-function match with load-time relocation dwords as wildcards;
  * repeated passes (catch a transient plaintext copy while the function executes);
  * scans child processes too (in case the runtime is a helper process);
  * coverage accounting: how much memory was unreadable, and WHY;
  * near-miss diagnostic: the best partial match anywhere (how many constrained bytes
    of the function matched at one place). A low best-partial is positive evidence
    that no decrypted copy exists.

Usage:
  python tools/live_code_residue.py --src D:\demo_exe\demo32.exe --gt D:\demo_exe\ground_truth_exe.txt \
      --run "D:\other\demo32.exe --loop --hold 30" --delay 8 --tag protected \
      --passes 20 --interval 0.25 --children
"""
import argparse, ctypes, ctypes.wintypes as wt, re, struct, subprocess, sys, time

MEM_COMMIT, PAGE_NOACCESS, PAGE_GUARD, MEM_FREE, MEM_RESERVE = 0x1000, 0x01, 0x100, 0x10000, 0x2000
PROCESS_QUERY_INFORMATION, PROCESS_VM_READ = 0x0400, 0x0010
TH32CS_SNAPPROCESS = 0x2
MAX_ADDR = 0x7FFFFFFF0000


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_ulonglong), ("AllocationBase", ctypes.c_ulonglong),
                ("AllocationProtect", wt.DWORD), ("__a1", wt.DWORD),
                ("RegionSize", ctypes.c_ulonglong), ("State", wt.DWORD),
                ("Protect", wt.DWORD), ("Type", wt.DWORD), ("__a2", wt.DWORD)]


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)), ("th32ModuleID", wt.DWORD),
                ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
                ("szExeFile", ctypes.c_char * 260)]


k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
k32.ReadProcessMemory.restype = wt.BOOL
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
k32.Process32First.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
k32.Process32Next.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32)]


def children_of(pid):
    out = []
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == wt.HANDLE(-1).value or not snap:
        return out
    e = PROCESSENTRY32(); e.dwSize = ctypes.sizeof(PROCESSENTRY32)
    ok = k32.Process32First(snap, ctypes.byref(e))
    while ok:
        if e.th32ParentProcessID == pid:
            out.append((e.th32ProcessID, e.szExeFile.decode('latin1', 'replace')))
        ok = k32.Process32Next(snap, ctypes.byref(e))
    k32.CloseHandle(snap)
    return out


def pe_parts(d):
    o = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, o+6)[0]
    optsz = struct.unpack_from('<H', d, o+20)[0]
    sb = o+24+optsz
    ss = []
    for i in range(nsec):
        p = sb+i*40
        name = d[p:p+8].rstrip(b'\x00').decode('latin1')
        vsz, va, rsz, raw = struct.unpack_from('<IIII', d, p+8)
        ss.append((name, va, vsz, raw, rsz))
    return ss


def rva2off(ss, rva):
    for name, va, vsz, raw, rsz in ss:
        if va <= rva < va+max(vsz, rsz):
            return raw+(rva-va)
    return None


def reloc_offsets(d, ss):
    out = set()
    for name, va, vsz, raw, rsz in ss:
        if name != '.reloc':
            continue
        body = d[raw:raw+rsz]
        i = 0
        while i+8 <= len(body):
            page, size = struct.unpack_from('<II', body, i)
            if size < 8:
                break
            for j in range(i+8, min(i+size, len(body)), 2):
                if j+2 > len(body):
                    break
                ent = struct.unpack_from('<H', body, j)[0]
                if ent & 0x3000 == 0x3000:
                    o2 = rva2off(ss, page + (ent & 0xFFF))
                    if o2 is not None:
                        for k in range(4):
                            out.add(o2+k)
            i += size
    return out


def parse_gt(path, want='014C'):
    funcs, active = [], False
    for line in open(path, encoding='utf-8', errors='replace'):
        if line.startswith('###'):
            active = ('machine=%s' % want) in line
            continue
        if active:
            m = re.match(r'\s+(\S.*?)\s+RVA=([0-9A-Fa-f]{8})\s+size=(\S+)', line)
            if m:
                funcs.append((m.group(1).strip(), int(m.group(2), 16), int(m.group(3), 0)))
    return funcs


def read(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)):
        return buf.raw[:got.value]
    return None


def one_pass(h, jobs, wild_of):
    """returns (hits{name:[addr]}, best_partial{name:(matched,total,addr)}, cov)"""
    hits = {n: [] for n, *_ in jobs}
    bestp = {n: (0, 0, 0) for n, *_ in jobs}
    cov = {'readable': 0, 'readfail': 0, 'noaccess': 0, 'guard': 0, 'free': 0, 'other': 0}
    addr, mbi = 0, MBI()
    while addr < MAX_ADDR:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        size = mbi.RegionSize or 0x1000
        if mbi.State == MEM_COMMIT:
            if mbi.Protect & PAGE_GUARD:
                cov['guard'] += size
            elif mbi.Protect & PAGE_NOACCESS:
                cov['noaccess'] += size
            else:
                off = 0
                while off < size:
                    n = min(1 << 20, size-off)
                    b = read(h, mbi.BaseAddress+off, n)
                    if b:
                        cov['readable'] += len(b)
                        for name, rva, fsize, src, wild, boff, blen in jobs:
                            key = src[boff:boff+blen]
                            pos = b.find(key)
                            while pos >= 0:
                                cand = mbi.BaseAddress+off+pos-boff
                                base = mbi.BaseAddress+off
                                if base <= cand and cand+fsize <= base+len(b):
                                    mem = b[cand-base:cand-base+fsize]
                                else:
                                    mem = read(h, cand, fsize)
                                if mem and len(mem) == fsize:
                                    matched = sum(1 for i in range(fsize)
                                                  if i in wild or mem[i] == src[i])
                                    if matched > bestp[name][0]:
                                        bestp[name] = (matched, fsize, cand)
                                    if matched == fsize:
                                        hits[name].append(cand)
                                        break
                                pos = b.find(key, pos+1)
                    else:
                        cov['readfail'] += n
                    off += n
        elif mbi.State == MEM_FREE:
            cov['free'] += size
        else:
            cov['other'] += size
        addr = mbi.BaseAddress + size
    return hits, bestp, cov


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--src', required=True)
    ap.add_argument('--gt', required=True)
    ap.add_argument('--run', required=True)
    ap.add_argument('--delay', type=float, default=8.0)
    ap.add_argument('--tag', default='')
    ap.add_argument('--func', default='')
    ap.add_argument('--passes', type=int, default=1)
    ap.add_argument('--interval', type=float, default=0.3)
    ap.add_argument('--children', action='store_true')
    a = ap.parse_args()

    d = open(a.src, 'rb').read()
    ss = pe_parts(d)
    rl = reloc_offsets(d, ss)
    want = set(x for x in a.func.split(',') if x)
    jobs = []
    for name, rva, size in parse_gt(a.gt):
        if want and name not in want:
            continue
        off = rva2off(ss, rva)
        if off is None or size < 16:
            continue
        src = d[off:off+size]
        wild = set(i for i in range(size) if (off+i) in rl)
        boff = blen = cur = 0
        run_start = 0
        for i in range(size+1):
            if i == size or i in wild:
                if cur > blen:
                    boff, blen = run_start, cur
                cur = 0
            else:
                if cur == 0:
                    run_start = i
                cur += 1
        if blen < 8:
            continue
        jobs.append((name, rva, size, src, frozenset(wild), boff, blen))

    print("[*] %s: %d functions, %d reloc-wildcard bytes" % (a.tag, len(jobs), len(rl)))
    proc = subprocess.Popen(a.run.split(' '), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(a.delay)
        kids = children_of(proc.pid) if a.children else []
        targets = [(proc.pid, 'main')] + [(p, n) for p, n in kids]
        if kids:
            print("    child processes: %s" % ", ".join("%s(pid=%d)" % (n, p) for p, n in kids))
        agg = {n: [] for n, *_ in jobs}
        aggbest = {n: (0, 0, 0) for n, *_ in jobs}
        covtot = None
        for t, label in targets:
            h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, t)
            if not h:
                print("    [!] cannot open %s (pid=%d)" % (label, t)); continue
            for k in range(a.passes):
                hits, bestp, cov = one_pass(h, jobs, None)
                covtot = cov
                for n in agg:
                    agg[n].extend(hits[n])
                    if bestp[n][0] > aggbest[n][0]:
                        aggbest[n] = bestp[n]
                time.sleep(a.interval)
            k32.CloseHandle(h)
        print("    coverage: readable=%.1fMB read-fail=%.1fMB noaccess=%.1fMB guard=%.1fMB"
              % (covtot['readable']/1048576.0, covtot['readfail']/1048576.0,
                 covtot['noaccess']/1048576.0, covtot['guard']/1048576.0))
        present = 0
        for name, rva, size, src, wild, boff, blen in jobs:
            hs = sorted(set(agg[name]))
            m, tot, at = aggbest[name]
            if hs:
                present += 1
                print("    %-30s size=%-4d PRESENT at %s" % (name, size, " ".join("0x%X" % x for x in hs[:3])))
            else:
                print("    %-30s size=%-4d ABSENT   best partial match anywhere = %d/%d constrained bytes (@0x%X)"
                      % (name, size, m, tot, at))
        print("[*] %s: passes=%d  present=%d/%d" % (a.tag, a.passes, present, len(jobs)))
    finally:
        try: proc.kill()
        except Exception: pass


if __name__ == '__main__':
    main()
