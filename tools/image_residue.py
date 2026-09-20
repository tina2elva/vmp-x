#!/usr/bin/env python3
"""image_residue.py -- assert the PACKED image does not carry the original code.

The whole-image encryption (-enc-image) must leave nothing of the original sections
readable on disk. This walks every 64-byte chunk of each named original section and
looks for it anywhere in the packed file. All-zero chunks are counted but excluded:
plain padding matches the packed file's own padding and proves nothing.

Exit: 0 = clean, 2 = original code still readable (or a usage error).

Usage:
  python tools/image_residue.py --src build/target.exe --packed build/target_vmp.exe \
      [--section .text,.rdata,.data] [--chunk 64]
"""
import argparse, math, struct, sys
from collections import Counter


def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def section_bytes(data, name):
    lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, lfanew + 6)[0]
    optsz = struct.unpack_from("<H", data, lfanew + 20)[0]
    sb = lfanew + 24 + optsz
    for i in range(nsec):
        o = sb + i * 40
        nm = data[o:o + 8].rstrip(b"\x00").decode("latin1")
        if nm == name:
            vsz, va, rsz, raw = struct.unpack_from("<IIII", data, o + 8)
            return data[raw:raw + rsz], va, rsz
    return None, 0, 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="original (unpacked) PE")
    ap.add_argument("--packed", required=True, help="packed PE")
    ap.add_argument("--section", default=".text,.rdata,.data",
                    help="comma separated section names to check")
    ap.add_argument("--chunk", type=int, default=64)
    ap.add_argument("--allow-missing", action="store_true",
                    help="skip a section that the ORIGINAL does not have (freestanding targets often have no .data); a section that exists is still checked strictly")
    a = ap.parse_args()

    orig = open(a.src, "rb").read()
    pack = open(a.packed, "rb").read()
    bad_sections = []
    for name in [s.strip() for s in a.section.split(",") if s.strip()]:
        body, rva, size = section_bytes(orig, name)
        if body is None:
            if a.allow_missing:
                print("[*] %-8s not present in the original -> skipped (--allow-missing)" % name)  # ASCII only: Windows runners are cp1252
                continue
            print("[!] %s: no section %s" % (a.src, name))
            sys.exit(2)
        pbody, _, _ = section_bytes(pack, name)
        total = zeros = matched = 0
        examples = []
        for off in range(0, len(body) - a.chunk + 1, a.chunk):
            c = body[off:off + a.chunk]
            total += 1
            if set(c) == {0}:
                zeros += 1
                continue
            if pack.find(c) >= 0:
                matched += 1
                if len(examples) < 4:
                    examples.append(off)
        print("[*] %-8s RVA=0x%-6X size=%-7d H=%.2f -> packed H=%.2f | chunks=%d all-zero(excluded)=%d NON-ZERO FOUND=%d"
              % (name, rva, size, entropy(body), entropy(pbody or b""), total, zeros, matched))
        if examples:
            print("    first offsets: %s" % " ".join("+0x%X" % o for o in examples))
        if matched:
            bad_sections.append(name)
    if bad_sections:
        print("[!] original code is still readable in the packed image: %s" % ", ".join(bad_sections))
        sys.exit(2)
    print("[+] no original code readable in the packed image")


if __name__ == "__main__":
    main()
