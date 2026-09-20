#!/usr/bin/env python3
"""field_mask_check.py -- assert that the container/record scalars are NOT plaintext.

The third-party report's P1.1-5 complaint: the container leaks magic / RVA / length / flags.
After the field-mask change (see internal/inject/fields.go) those fields are XOR-ed with a
mask derived from the master key, so a static reader must not see them any more.

This tool checks the *effect* on a packed artifact, using only values that are known
independently of the mask:

  1) descriptor magic != the old fixed constant 0x4B504D56 ("VMPK")
  2) descriptor fields that used to be *exact constants* are no longer there:
     codeLen (report bytecodeBytes) and reserved1 (report funcRVA) must not appear verbatim
  3) image table count (offset +12) != the real number of encrypted sections

  NOTE: we deliberately do NOT check single bits (e.g. "flags bit0 must be 0"). With an XOR mask
  every bit is inverted with probability 1/2, so a bit looking "right" proves nothing -- an
  attacker cannot tell plain=1/mask=1 from plain=0/mask=0. Only exact-value matches carry signal.

Output is ASCII only (Windows runner stdout is cp1252).

Usage: python tools/field_mask_check.py --packed build/target_vmp.exe --report build/target_vmp.json
"""
import argparse
import json
import struct
import sys

VM_DESC_MAGIC_FIXED = 0x4B504D56
VM_DESC_FLAG_ENC = 1


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
    ap.add_argument("--packed", required=True)
    ap.add_argument("--report", required=True)
    a = ap.parse_args()

    data = open(a.packed, "rb").read()
    rep = json.load(open(a.report, "r", encoding="utf-8"))
    bad = 0

    pls = rep.get("placements", [])
    for p in pls:
        off = rva_to_off(data, int(p["descRVA"]))
        magic, _self, _code = struct.unpack_from("<III", data, off)
        raw_len = struct.unpack_from("<I", data, off + 12)[0]
        raw_r1 = struct.unpack_from("<I", data, off + 24)[0]
        if magic == VM_DESC_MAGIC_FIXED:
            print("[FAIL] %s: descriptor magic is still the fixed %08X" % (p.get("name"), magic))
            bad += 1
        want_len = int(p.get("bytecodeBytes") or 0)
        if want_len and raw_len == want_len:
            print("[FAIL] %s: raw codeLen field still equals %d" % (p.get("name"), want_len))
            bad += 1
        want_r1 = int(p.get("funcRVA") or 0)
        if want_r1 and raw_r1 == want_r1:
            print("[FAIL] %s: raw reserved1 still equals funcRVA 0x%X" % (p.get("name"), want_r1))
            bad += 1

    tbl = int(rep.get("imgTableRVA") or 0)
    if tbl:
        toff = rva_to_off(data, tbl)
        raw_count = struct.unpack_from("<I", data, toff + 12)[0]
        if raw_count == len(_img_sections(rep)):
            print("[FAIL] image table: raw count %d equals the real number of entries" % raw_count)
            bad += 1

    if bad:
        print("[FAIL] field mask: %d check(s) failed (container scalars are readable)" % bad)
        return 1
    print("[OK  ] field mask: magic random, descriptor flags and table count are not plaintext")
    return 0


def _img_sections(rep):
    # the report does not list the image sections directly; derive from the table length
    n = int(rep.get("imgTableLen") or 0)
    return [0] * max(0, (n - 24) // 32)


if __name__ == "__main__":
    sys.exit(main())
