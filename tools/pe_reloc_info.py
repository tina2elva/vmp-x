#!/usr/bin/env python3
"""pe_reloc_info.py -- what did the packer do with relocations / DYNAMIC_BASE?

Prints, for one or more PE files: the COFF/DllCharacteristics flags that matter for ASLR,
the BASERELOC directory and how the relocation entries are distributed over the sections.

Usage:
  python tools/pe_reloc_info.py build/target.exe build/target_vmp.exe [--expect-aslr]
"""
import argparse
import struct
import sys


def parse(path):
    d = open(path, "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    optsz = struct.unpack_from("<H", d, pe + 20)[0]
    ch = struct.unpack_from("<H", d, pe + 22)[0]
    magic = struct.unpack_from("<H", d, pe + 24)[0]
    dll = struct.unpack_from("<H", d, pe + 24 + 70)[0]
    rr, rs = struct.unpack_from("<II", d, pe + 24 + 112 + 5 * 8)
    base = pe + 24 + optsz
    secs = []
    for i in range(nsec):
        o = base + i * 40
        name = d[o:o + 8].rstrip(b"\x00").decode("latin1")
        vsz, va, rsz, roff = struct.unpack_from("<IIII", d, o + 8)
        secs.append((name, va, max(vsz, rsz), roff, rsz))

    def rva2off(rva):
        for name, va, span, roff, rsz in secs:
            if va <= rva < va + span and rva - va < rsz:
                return roff + (rva - va)
        return None

    dist = {}
    if rr and rs:
        off = rva2off(rr)
        if off is not None:
            end = off + rs
            p = off
            while p + 8 <= end:
                page, blk = struct.unpack_from("<II", d, p)
                if blk < 8 or p + blk > end:
                    break
                for o in range(p + 8, p + blk - 1, 2):
                    v = struct.unpack_from("<H", d, o)[0]
                    t = v >> 12
                    if not t:
                        continue
                    rva = page + (v & 0xFFF)
                    for name, va, span, roff, rsz in secs:
                        if va <= rva < va + span:
                            dist.setdefault(name, [0, {}])
                            dist[name][0] += 1
                            dist[name][1][t] = dist[name][1].get(t, 0) + 1
                            break
                p += blk
    return {
        "path": path, "magic": magic, "relocs_stripped": bool(ch & 1), "dynamic_base": bool((dll >> 6) & 1),
        "reloc_rva": rr, "reloc_size": rs, "secs": secs, "dist": dist,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--expect-aslr", action="store_true",
                    help="fail unless RELOCS_STRIPPED is clear, DYNAMIC_BASE is set and a reloc dir exists")
    a = ap.parse_args()
    bad = 0
    for f in a.files:
        r = parse(f)
        print("%s: RELOCS_STRIPPED=%d DYNAMIC_BASE=%d relocDir=0x%X/%d" %
              (f, r["relocs_stripped"], r["dynamic_base"], r["reloc_rva"], r["reloc_size"]))
        for name, (n, types) in sorted(r["dist"].items()):
            print("    %-10s %5d reloc(s) types=%s" % (name, n, sorted(types)))
        if a.expect_aslr:
            if r["relocs_stripped"] or not r["dynamic_base"] or not r["reloc_rva"]:
                print("[FAIL] %s is not relocatable/ASLR-enabled" % f)
                bad += 1
    if bad:
        return 1
    if a.expect_aslr:
        print("[OK  ] relocations kept and DYNAMIC_BASE set")
    return 0


if __name__ == "__main__":
    sys.exit(main())
