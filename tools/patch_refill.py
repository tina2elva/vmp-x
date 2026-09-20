#!/usr/bin/env python3
"""patch_refill.py -- write a protected function's entry bytes back to the ORIGINAL ones.

This is the "refill" bypass from the static-analysis report: the packer overwrites the first
N bytes of each protected function with a jmp (E9 <rel32>) into the VM thunk. An attacker can
put the original bytes back so the function runs natively again -- unless the integrity check
notices. Two places check it (both use the same keyed MAC, see internal/inject/patchmac.go):
  * the descriptor's pad[0..3]   -- verified on every vm_run (VM_INVM_PATCHCHECK)
  * the load-time verify table   -- verified by the entry trampoline before main()

So the packed image must refuse to run after a refill. This tool produces that image.

Output is ASCII only (Windows runner stdout is cp1252).

Usage:
  python tools/patch_refill.py --orig build/target.exe --packed build/target_vmp.exe \
      --report build/target_vmp.json --out build/target_refill.exe [--func check_key]
"""
import argparse
import json
import struct
import sys


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--orig", required=True, help="unpacked reference binary")
    ap.add_argument("--packed", required=True, help="packed binary to refill")
    ap.add_argument("--report", required=True, help="vmpack -report JSON (has placements)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--func", default="", help="comma separated names; empty = all placements")
    a = ap.parse_args()

    orig = open(a.orig, "rb").read()
    data = bytearray(open(a.packed, "rb").read())
    rep = json.load(open(a.report, "r", encoding="utf-8"))
    want = set(x for x in a.func.split(",") if x)

    done = 0
    for p in rep.get("placements", []):
        if want and p.get("name") not in want:
            continue
        rva = int(p["funcRVA"])
        off = rva_to_off(data, rva)
        # patch length: flags bits 8..15 live at descriptor offset 20
        doff = rva_to_off(data, int(p["descRVA"]))
        plen = (struct.unpack_from("<I", data, doff + 20)[0] >> 8) & 0xFF
        if plen == 0:
            print("[!] %s has no entry patch recorded" % p.get("name"))
            continue
        data[off:off + plen] = orig[off:off + plen]
        done += 1

    if done == 0:
        print("[!] nothing refilled (no matching placement)")
        return 2
    open(a.out, "wb").write(bytes(data))
    print("[OK  ] refilled %d function(s) -> %s" % (done, a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
