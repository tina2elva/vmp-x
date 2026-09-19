#!/usr/bin/env python3
r"""live_code_map.py -- read the protected process' memory AT THE ORIGINAL MODULE LAYOUT
and compare every function byte-by-byte with the source image.

Answers, per function:
  identical      : whole body is byte-identical to the source file
  body-intact    : identical except the first PATCH bytes -> original code IS in memory,
                   only the entry was overwritten (classic entry trampoline)
  body-differs   : the body itself is not the original -> really replaced/erased

Usage:
  python tools/live_code_map.py --src D:\demo_exe\demo32.exe --gt D:\demo_exe\ground_truth_exe.txt \
      --run "D:\other\demo32.exe --hold 40" --delay 8 [--patch 5]
"""
import argparse, ctypes, ctypes.wintypes as wt, re, struct, subprocess, sys, time

MEM_COMMIT, PAGE_NOACCESS, PAGE_GUARD = 0x1000, 0x01, 0x100
PROCESS_QUERY_INFORMATION, PROCESS_VM_READ = 0x0400, 0x0010
MAX_ADDR = 0x7FFFFFFF0000


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_ulonglong), ("AllocationBase", ctypes.c_ulonglong),
                ("AllocationProtect", wt.DWORD), ("__a1", wt.DWORD),
                ("RegionSize", ctypes.c_ulonglong), ("State", wt.DWORD),
                ("Protect", wt.DWORD), ("Type", wt.DWORD), ("__a2", wt.DWORD)]


k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
k32.ReadProcessMemory.restype = wt.BOOL
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]


def pe_parts(d):
    o = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, o+6)[0]
    optsz = struct.unpack_from('<H', d, o+20)[0]
    plus = struct.unpack_from('<H', d, o+24)[0] == 0x20B
    ib = struct.unpack_from('<Q', d, o+24+24)[0] if plus else struct.unpack_from('<I', d, o+24+28)[0]
    sb = o+24+optsz
    ss = []
    for i in range(nsec):
        p = sb+i*40
        name = d[p:p+8].rstrip(b'\x00').decode('latin1')
        vsz, va, rsz, raw = struct.unpack_from('<IIII', d, p+8)
        ss.append((name, va, vsz, raw, rsz))
    return ib, ss


def rva2off(ss, rva):
    for name, va, vsz, raw, rsz in ss:
        if va <= rva < va+max(vsz, rsz):
            return raw+(rva-va)
    return None


def relocs(d, ss):
    out = set()
    for name, va, vsz, raw, rsz in ss:
        if name != '.reloc':
            continue
        body = d[raw:raw+rsz]
        i = 0
        while i+8 <= len(body):
            page, size = struct.unpack_from('<II', body, i)
            if size < 8 or page == 0:
                break
            for j in range(i+8, min(i+size, len(body)), 2):
                if j+2 > len(body):
                    break
                ent = struct.unpack_from('<H', body, j)[0]
                if ent & 0x3000 == 0x3000:
                    o2 = rva2off(ss, page + (ent & 0xFFF))   # page/offset 都是 RVA
                    if o2 is not None:
                        for k in range(4):                   # 改写的是 4 字节 dword
                            out.add(o2 + k)
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


def find_all(h, needles, cap=6):
    """needles: list of (bytes, rva_of_needle_start). Returns list of (base, which, addr)."""
    hits, scanned, regions, mz = [], 0, 0, []
    addr, mbi = 0, MBI()
    while addr < MAX_ADDR:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        size = mbi.RegionSize or 0x1000
        if mbi.State == MEM_COMMIT and not (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)):
            b = read(h, mbi.BaseAddress, min(size, 1 << 20))
            if b:
                scanned += len(b); regions += 1
                if len(mz) < 6:
                    p = b.find(b'MZ')
                    while p >= 0 and len(mz) < 6:
                        mz.append(mbi.BaseAddress + p)
                        p = b.find(b'MZ', p+1)
                for k, (nd, rva) in enumerate(needles):
                    if len(hits) >= cap:
                        break
                    pos = b.find(nd)
                    if pos >= 0:
                        hits.append((mbi.BaseAddress + pos - rva, k, mbi.BaseAddress + pos))
        addr = mbi.BaseAddress + size
    print("    [scan] regions=%d bytes=%.1fMB ; first MZ at: %s"
          % (regions, scanned/1048576.0, " ".join("0x%X" % x for x in mz)))
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--src', required=True)
    ap.add_argument('--gt', required=True)
    ap.add_argument('--run', required=True)
    ap.add_argument('--delay', type=float, default=8.0)
    ap.add_argument('--patch', type=int, default=5)
    ap.add_argument('--tag', default='')
    a = ap.parse_args()

    d = open(a.src, 'rb').read()
    ib, ss = pe_parts(d)
    rl = relocs(d, ss)
    funcs = parse_gt(a.gt)
    print("[*] %s  src=%s imagebase=0x%X funcs=%d relocs=%d" % (a.tag, a.src, ib, len(funcs), len(rl)))

    proc = subprocess.Popen(a.run.split(' '), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(a.delay)
        h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, proc.pid)
        if not h:
            raise SystemExit("OpenProcess failed %d" % ctypes.get_last_error())
        needles = [(d[:0x200], 0)]
        for name, rva, size in funcs:
            off = rva2off(ss, rva)
            if off is None or size <= 0:
                continue
            run = b''
            for i in range(size):
                if (off+i) in rl:
                    if len(run) >= 24:
                        needles.append((run, rva + (i - len(run))))
                    run = b''
                else:
                    run += bytes([d[off+i]])
            if len(run) >= 24:
                needles.append((run, rva + size - len(run)))
            if len(needles) > 14:
                break
        hits = find_all(h, needles)
        print("    target alive=%s ; anchors: %s" % (proc.poll() is None,
              " ".join("base=0x%X(a%d@0x%X)" % x for x in hits[:4])))
        if not hits:
            print("    [!] no anchor found in memory")
            return
        base = hits[0][0]
        probe = read(h, base, 32)
        print("    mem@base=%s" % (probe.hex(' ') if probe else 'UNREADABLE'))
        print("    file[0:32]=%s" % d[:32].hex(' '))
        # sanity: 命中地址应与 base+RVA 对应
        identical = intact = differ = 0
        rows = []
        for name, rva, size in funcs:
            if size <= 0:
                continue
            off = rva2off(ss, rva)
            src = d[off:off+size]
            mem = read(h, base + rva, size)
            if mem is None or len(mem) < size:
                rows.append((name, rva, size, 'UNREADABLE', 0, b'', b''))
                differ += 1
                continue
            # 比较时跳过被重定位改写的 dword
            mm = sum(1 for i in range(size) if (off+i) in rl)
            mism = [i for i in range(size) if mem[i] != src[i] and (off+i) not in rl]
            if not mism:
                identical += 1
                st = 'identical'
            elif len(mism) <= a.patch and mism[0] == 0:
                intact += 1
                st = 'body-intact(entry patched)'
            else:
                differ += 1
                st = 'BODY-DIFFERS'
            rows.append((name, rva, size, st, len(mism), mem[:min(16, size)], src[:min(16, size)]))
        print("    base=0x%X  identical=%d  body-intact=%d  body-differs=%d  (masked reloc dwords: skipped)"
              % (base, identical, intact, differ))
        for name, rva, size, st, nm, mb, sb in rows:
            extra = ""
            if st == 'BODY-DIFFERS':
                extra = "  mem=%s src=%s" % (mb.hex(' '), sb.hex(' '))
            elif st.startswith('body-intact'):
                extra = "  mem=%s" % mb.hex(' ')
            print("    %-34s RVA=0x%-5X size=%-5d %-26s mismatched=%d%s" % (name, rva, size, st, nm, extra))
    finally:
        try: proc.kill()
        except Exception: pass


if __name__ == '__main__':
    main()
