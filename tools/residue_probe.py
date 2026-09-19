#!/usr/bin/env python3
"""residue_probe.py -- scan a RUNNING protected process for bytes that must not be there.

"Whole-function replacement" is not only about the file: PE/ELF map the image into
memory, so anything left in the file is also in memory. This tool scans the whole
address space of a protected process and answers two questions:

  1) is the native machine code of the protected function (past the entry patch)
     still present in memory?
  2) is the *plaintext* VM bytecode (vmpack -dumpbytecode output) present in memory?

Output is ASCII on purpose (Windows consoles here are not UTF-8).

Usage:
  python tools/residue_probe.py --pe build/target.exe --report build/target_vmp.json \
      --run "build/target_vmp.exe bench check_key 100000000" \
      --func check_key,sum_to [--bytecode-dir build/_bc] [--fail-on-native]
"""
import argparse, ctypes, ctypes.wintypes as wt, json, os, struct, subprocess, sys, time

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


def rva_to_off(data, rva):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt = struct.unpack_from("<H", data, pe + 20)[0]
    base = pe + 24 + opt
    for i in range(nsec):
        o = base + i * 40
        vsize, va, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
        if va <= rva < va + max(vsize, rsize):
            return roff + (rva - va)
    raise SystemExit("RVA 0x%X is not inside any section" % rva)


def native_patterns(pe_path, report_path, names, patch_len):
    data = open(pe_path, "rb").read()
    rep = json.load(open(report_path, "r", encoding="utf-8"))
    out = []
    for p in rep["placements"]:
        if names and p["name"] not in names:
            continue
        n = int(p["nativeBytes"])
        if n <= patch_len:
            continue
        off = rva_to_off(data, int(p["funcRVA"]) + patch_len)
        out.append(("native:" + p["name"], data[off:off + n - patch_len]))
    return out


def scan(pid, patterns):
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        raise SystemExit("OpenProcess failed: %d" % ctypes.get_last_error())
    hits = {name: [] for name, _ in patterns}
    addr, mbi, got = 0, MBI(), ctypes.c_size_t(0)
    scanned = 0
    while addr < MAX_ADDR:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        size = mbi.RegionSize or 0x1000
        if mbi.State == MEM_COMMIT and not (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)):
            off = 0
            while off < size:
                want = min(1 << 20, size - off)
                buf = ctypes.create_string_buffer(want)
                if k32.ReadProcessMemory(h, ctypes.c_void_p(mbi.BaseAddress + off), buf, want,
                                         ctypes.byref(got)):
                    b = buf.raw[:got.value]
                    scanned += len(b)
                    for name, pat in patterns:
                        pos = b.find(pat)
                        while pos >= 0 and len(hits[name]) <= 8:
                            hits[name].append(mbi.BaseAddress + off + pos)
                            pos = b.find(pat, pos + 1)
                off += want
        addr = mbi.BaseAddress + size
    k32.CloseHandle(h)
    return hits, scanned


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pe", required=True, help="the ORIGINAL (unpacked) image, for RVA -> offset")
    ap.add_argument("--report", required=True, help="vmpack -report JSON of the packed image")
    ap.add_argument("--run", required=True, help="command line of the protected program to launch")
    ap.add_argument("--func", default="", help="comma separated names; empty = all placements")
    ap.add_argument("--bytecode-dir", default="", help="vmpack -dumpbytecode output dir (placement order)")
    ap.add_argument("--delay", type=float, default=2.0, help="seconds to wait before scanning")
    ap.add_argument("--patch-len", type=int, default=5, help="entry patch length (5 x64 / 8 arm64)")
    ap.add_argument("--fail-on-native", action="store_true", help="exit 2 if any native pattern is found")
    ap.add_argument("--fail-on-bytecode", action="store_true",
                    help="exit 2 if any plaintext VM bytecode pattern is found")
    a = ap.parse_args()

    names = [s for s in a.func.split(",") if s]
    patterns = native_patterns(a.pe, a.report, names, a.patch_len)

    if a.bytecode_dir:
        rep = json.load(open(a.report, "r", encoding="utf-8"))
        for i, p in enumerate(rep["placements"]):
            if names and p["name"] not in names:
                continue
            f = os.path.join(a.bytecode_dir, "bytecode_%02d.bin" % i)
            if os.path.exists(f):
                patterns.append(("bytecode:" + p["name"], open(f, "rb").read()))

    print("[*] patterns: " + ", ".join("%s(%dB)" % (n, len(p)) for n, p in patterns))
    proc = subprocess.Popen(a.run.split(" "), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(a.delay)
        if proc.poll() is not None:
            print("[!] target already exited (rc=%s); increase --delay" % proc.returncode)
        hits, scanned = scan(proc.pid, patterns)
    finally:
        try:
            proc.kill()
        except Exception:
            pass

    print("[*] scanned %.1f MB of readable memory" % (scanned / 1048576.0))
    native_bad = 0
    for name, _ in patterns:
        h = hits[name]
        if h and name.startswith("native:"):
            native_bad += 1
        print("    %-24s %-8s %s" % (name, "FOUND" if h else "absent",
                                     " ".join("0x%X" % x for x in h[:4])))
    bc_bad = sum(1 for n, _ in patterns if n.startswith("bytecode:") and hits[n])
    print("[*] patterns with residue: %d / %d (native residue: %d, plaintext-bytecode residue: %d)"
          % (sum(1 for n, _ in patterns if hits[n]), len(patterns), native_bad, bc_bad))
    if (a.fail_on_native and native_bad) or (a.fail_on_bytecode and bc_bad):
        sys.exit(2)


if __name__ == "__main__":
    main()
