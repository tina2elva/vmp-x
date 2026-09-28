#!/usr/bin/env python3
"""check_elf_layout.py -- layout-consistency gate for a PACKED ELF (Linux counterpart of
tools/check_symmap.py, which does the same job for PE).

Everything is derived from the PRODUCT FILE plus the same build's blob manifest and pack report.

  E1 program-header inventory
        every PT_LOAD is file-backed inside the file, satisfies p_offset == p_vaddr (mod p_align),
        has p_memsz >= p_filesz, and the only allowed VA overlap is the injector's RW overlay:
        an RW segment fully inside an earlier RX segment and listed AFTER it. The loader maps in
        table order and later mappings win, so inverting that order silently kills the
        interpreter's writable window (internal/inject/elf.go documents the measured failure).
  E2 payload segments vs the report
        one PT_LOAD at exactly report.sectionRVA carrying the payload, plus (when bssSize > 0) an
        RW PT_LOAD at sectionRVA + bssOff of exactly bssSize.
  E3 payload byte identity
        file bytes at (sectionRVA + o) == blob[o] for every o in [0, blobSize).
  E4 bss mapping invariant (STATUS #585)
        the kernel maps bss as ONE global range: set_brk(PAGEALIGN(max(vaddr+filesz)),
        PAGEALIGN(max(vaddr+memsz))). A segment with memsz > filesz therefore keeps its bss only
        when its own PAGEALIGN(vaddr+filesz) IS that maximum; anything else loses its bss entirely
        and dies on the first global write ("error 6" = not present + write). Assert none exists.
  E5 relocation coverage (ET_DYN only)
        for a PIE, every preferred-base absolute VA in the payload must be covered by an
        R_*_RELATIVE entry; for ET_EXEC (the supported case) nothing applies and it says so.

--selftest mutates copies and requires every check to catch its own mutation.

Usage:
  python3 tools/check_elf_layout.py --packed build/linux_target.vmp \
      --manifest build/vm_interp_linux.json --blob build/vm_interp_linux.bin \
      --report build/linux_vmp.json --selftest
"""
import argparse
import json
import os
import shutil
import struct
import sys
import tempfile

PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_PHDR = 6
PF_X = 1
PF_W = 2
PF_R = 4
SHT_RELA = 4
R_RELATIVE = {62: 8, 183: 1027}  # EM_X86_64 / EM_AARCH64
ET_EXEC, ET_DYN = 2, 3


def align_up(v, a):
    if a <= 1:
        return v
    return (v + a - 1) // a * a


class ELF:
    def __init__(self, data):
        self.data = data
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF")
        if data[4] != 2 or data[5] != 1:
            raise ValueError("only ELFCLASS64 + little endian are supported")
        self.etype = struct.unpack_from("<H", data, 16)[0]
        self.machine = struct.unpack_from("<H", data, 18)[0]
        self.entry = struct.unpack_from("<Q", data, 24)[0]
        self.phoff = struct.unpack_from("<Q", data, 32)[0]
        self.shoff = struct.unpack_from("<Q", data, 40)[0]
        self.phentsize, self.phnum = struct.unpack_from("<HH", data, 54)
        self.shentsize, self.shnum, self.shstrndx = struct.unpack_from("<HHH", data, 58)
        self.progs = []
        for i in range(self.phnum):
            o = self.phoff + i * self.phentsize
            t, fl, off, va, pa, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", data, o)
            self.progs.append(dict(i=i, hdr=o, type=t, flags=fl, off=off, vaddr=va,
                                   paddr=pa, filesz=fsz, memsz=msz, align=al))
        self.loads = [p for p in self.progs if p["type"] == PT_LOAD]
        # ELF 的 report.sectionRVA 与 placements 用的是**相对镜像基址的 RVA**
        # （Go 侧 Result.SectionRVA = baseVA - imageBase），而程序头里是 VA ⇒ 这里换算一次。
        self.image_base = min((p["vaddr"] & ~0xFFF for p in self.loads), default=0)
        self.sections = []
        for i in range(self.shnum):
            o = self.shoff + i * self.shentsize
            name, typ, flags, addr, off, size, link, info, al, ent = struct.unpack_from(
                "<IIQQQQIIQQ", data, o)
            self.sections.append(dict(name=name, type=typ, addr=addr, off=off, size=size, ent=ent))

    def va_to_off(self, va):
        for p in self.loads:
            if p["vaddr"] <= va < p["vaddr"] + p["filesz"]:
                off = p["off"] + (va - p["vaddr"])
                if off < len(self.data):
                    return off
        return None

    def read(self, va, n):
        o = self.va_to_off(va)
        if o is None or o + n > len(self.data):
            return None
        return self.data[o:o + n]

    def rela_entries(self):
        """[(r_offset, type)] from every SHT_RELA section"""
        out = []
        for s in self.sections:
            if s["type"] != SHT_RELA or s["ent"] == 0:
                continue
            for k in range(s["size"] // s["ent"]):
                o = s["off"] + k * s["ent"]
                if o + 24 > len(self.data):
                    break
                r_off, r_info = struct.unpack_from("<QQ", self.data, o)
                out.append((r_off, r_info & 0xFFFFFFFF))
        return out

    def top_bss_edge(self):
        return max((align_up(p["vaddr"] + p["filesz"], 4096) for p in self.loads), default=0)


class Fail(Exception):
    pass


class Report:
    def __init__(self):
        self.lines = []
        self.failed = 0

    def ok(self, c, m):
        self.lines.append("[OK  ] %-3s %s" % (c, m))

    def info(self, c, m):
        self.lines.append("[INFO] %-3s %s" % (c, m))

    def fail(self, c, m):
        self.lines.append("[FAIL] %-3s %s" % (c, m))
        self.failed += 1
        raise Fail(m)


def check_inventory(elf, rep):
    if not elf.loads:
        rep.fail("E1", "no PT_LOAD at all")
    n = len(elf.data)
    for p in elf.loads:
        if p["memsz"] < p["filesz"]:
            rep.fail("E1", "LOAD vaddr=0x%X has memsz(0x%X) < filesz(0x%X)" % (p["vaddr"], p["memsz"], p["filesz"]))
        if p["off"] + p["filesz"] > n:
            rep.fail("E1", "LOAD vaddr=0x%X runs past EOF (0x%X > 0x%X)" % (p["vaddr"], p["off"] + p["filesz"], n))
        al = p["align"]
        if al > 1:
            if al & (al - 1):
                rep.fail("E1", "LOAD vaddr=0x%X has non-power-of-two p_align 0x%X" % (p["vaddr"], al))
            if p["off"] % al != p["vaddr"] % al:
                rep.fail("E1", "LOAD vaddr=0x%X: p_offset(0x%X) != p_vaddr (mod 0x%X)"
                         % (p["vaddr"], p["off"], al))
    # the injector's overlay is the only allowed overlap: RW, fully inside the earlier RX segment,
    # and listed AFTER it (table order decides which mapping wins).
    for a in elf.loads:
        for b in elf.loads:
            if b["i"] <= a["i"]:
                continue
            if b["vaddr"] >= a["vaddr"] + a["memsz"] or a["vaddr"] >= b["vaddr"] + b["memsz"]:
                continue  # disjoint
            inside = b["vaddr"] >= a["vaddr"] and b["vaddr"] + b["memsz"] <= a["vaddr"] + a["memsz"]
            if not (inside and (b["flags"] & PF_W) and not (b["flags"] & PF_X)):
                rep.fail("E1", "LOAD[%d] (vaddr=0x%X flags=0x%X) overlaps LOAD[%d] (vaddr=0x%X flags=0x%X) "
                               "and is not the injector's inner RW overlay"
                         % (b["i"], b["vaddr"], b["flags"], a["i"], a["vaddr"], a["flags"]))
    rep.ok("E1", "%d PT_LOAD in range, congruence/order constraints hold" % len(elf.loads))


def check_payload(elf, manifest, report, rep):
    sec_rva = int(report["sectionRVA"])
    sec_va = elf.image_base + sec_rva
    sec_size = int(report["sectionSize"])
    p = None
    for q in elf.loads:
        if q["vaddr"] == sec_va:
            p = q
    if p is None:
        rep.fail("E2", "no PT_LOAD at imageBase(0x%X) + report.sectionRVA(0x%X) = 0x%X"
                 % (elf.image_base, sec_rva, sec_va))
    if p["filesz"] != sec_size:
        rep.fail("E2", "payload LOAD filesz 0x%X != report.sectionSize 0x%X" % (p["filesz"], sec_size))
    if not (p["flags"] & PF_X):
        rep.fail("E2", "payload LOAD at 0x%X is not executable (flags=0x%X)" % (sec_va, p["flags"]))
    if p["flags"] & PF_W:
        rep.info("E2", "payload LOAD is RWX (the injector fell back to one segment: no W+X-free split)")
    bss_off, bss_size = int(manifest["bssOff"]), int(manifest["bssSize"])
    if bss_size > 0:
        want = sec_va + bss_off
        w = None
        for q in elf.loads:
            if q["vaddr"] == want:
                w = q
        if w is None:
            rep.fail("E2", "no RW overlay PT_LOAD at sectionRVA+bssOff = 0x%X" % want)
        if not (w["flags"] & PF_W):
            rep.fail("E2", "overlay LOAD at 0x%X is not writable (flags=0x%X)" % (want, w["flags"]))
        if w["filesz"] != bss_size or w["memsz"] != bss_size:
            rep.fail("E2", "overlay LOAD at 0x%X is 0x%X/0x%X, expected 0x%X" % (want, w["filesz"], w["memsz"], bss_size))
    rep.ok("E2", "payload @0x%X (RVA 0x%X, 0x%X bytes) + overlay @0x%X (0x%X)"
           % (sec_va, sec_rva, sec_size, sec_va + bss_off, bss_size))


def check_identity(elf, manifest, report, blob, rep):
    sec_rva = elf.image_base + int(report["sectionRVA"])
    blob_size = int(manifest["blobSize"])
    if len(blob) < blob_size:
        rep.fail("E3", "blob is 0x%X bytes, manifest says blobSize 0x%X" % (len(blob), blob_size))
    diffs = []
    for o in range(blob_size):
        got = elf.read(sec_rva + o, 1)
        if got is None:
            rep.fail("E3", "blob offset 0x%X (vaddr 0x%X) is not file-backed" % (o, sec_rva + o))
        if got[0] != blob[o]:
            diffs.append(o)
            if len(diffs) <= 8:
                rep.lines.append("[----] E3  blob 0x%06X: product 0x%02X != blob 0x%02X" % (o, got[0], blob[o]))
    if diffs:
        rep.fail("E3", "%d of %d blob byte(s) differ inside the payload (first at 0x%X)"
                 % (len(diffs), blob_size, diffs[0]))
    rep.ok("E3", "all 0x%X payload byte(s) match the blob" % blob_size)


def check_bss(elf, rep):
    top = elf.top_bss_edge()
    bad = [p for p in elf.loads if p["memsz"] > p["filesz"]
           and align_up(p["vaddr"] + p["filesz"], 4096) < top]
    for p in bad[:8]:
        rep.lines.append("[----] E4  LOAD vaddr=0x%X filesz=0x%X memsz=0x%X: its bss [0x%X,0x%X) "
                         "is below the global bss edge 0x%X"
                         % (p["vaddr"], p["filesz"], p["memsz"],
                            align_up(p["vaddr"] + p["filesz"], 4096), align_up(p["vaddr"] + p["memsz"], 4096), top))
    if bad:
        rep.fail("E4", "%d LOAD(s) would lose their bss: the kernel maps bss as one global range "
                       "[PAGEALIGN(max(vaddr+filesz)), PAGEALIGN(max(vaddr+memsz))), so a segment below "
                       "that edge never gets its bss mapped (STATUS #585)" % len(bad))
    withbss = [p for p in elf.loads if p["memsz"] > p["filesz"]]
    if withbss:
        rep.ok("E4", "%d bss-carrying LOAD(s), all at/above the global bss edge 0x%X" % (len(withbss), top))
    else:
        rep.ok("E4", "no LOAD carries bss beyond its file image (every bss is file-backed or absent)")


def check_relocs(elf, report, rep):
    if elf.etype != ET_DYN:
        rep.info("E5", "ET_EXEC: no relocations apply, the payload's VAs are link-time absolute")
        return
    rel = elf.rela_entries()
    kinds = R_RELATIVE.get(elf.machine, 8)
    covered = set(r for r, t in rel if t == kinds)
    sec_rva = elf.image_base + int(report["sectionRVA"])
    cands = []
    p = None
    for q in elf.loads:
        if q["vaddr"] == sec_rva:
            p = q
    if p is None:
        rep.fail("E5", "payload LOAD missing (see E2)")
    for rel_off in range(0, p["filesz"] - 7, 8):
        raw = elf.read(sec_rva + rel_off, 8)
        if raw is None:
            continue
        v = struct.unpack("<Q", raw)[0]
        # for a PIE the stored value is the link-time (preferred) base + rva
        if v and v >> 32:
            cands.append((sec_rva + rel_off, v))
    uncovered = [r for r, v in cands if r not in covered]
    for r in uncovered[:8]:
        rep.lines.append("[----] E5  vaddr 0x%X holds a VA but no RELATIVE entry covers it" % r)
    if uncovered:
        rep.fail("E5", "%d of %d absolute VA(s) in the payload have no RELATIVE relocation"
                 % (len(uncovered), len(cands)))
    rep.ok("E5", "%d absolute VA(s) covered by %d RELATIVE entries" % (len(cands), len(covered)))


def run_checks(path, manifest, report, blob, quiet=False):
    elf = ELF(open(path, "rb").read())
    rep = Report()
    for fn, args in ((check_inventory, (elf, rep)),
                     (lambda e, r: check_payload(e, manifest, report, r), (elf, rep)),
                     (lambda e, r: check_identity(e, manifest, report, blob, r), (elf, rep)),
                     (check_bss, (elf, rep)),
                     (lambda e, r: check_relocs(e, report, r), (elf, rep))):
        try:
            fn(*args)
        except Fail:
            pass
    if not quiet:
        for line in rep.lines:
            print(line)
    return rep


def failed_names(rep):
    return sorted({l.split()[1] for l in rep.lines if l.startswith("[FAIL]")})


def _expect_fail(rep, check):
    hit = check in failed_names(rep)
    return (hit, "" if hit else "expected %s to fail, it passed" % check)


def mutate(src, patch, tmp, tag):
    d = bytearray(open(src, "rb").read())
    patch(d)
    p = os.path.join(tmp, "mut_%s.elf" % tag)
    open(p, "wb").write(bytes(d))
    return p


def selftest(path, manifest, report, blob):
    tmp = tempfile.mkdtemp(prefix="elf_layout_cal_")
    results = []
    try:
        rep = run_checks(path, manifest, report, blob, quiet=True)
        results.append(("pristine", rep.failed == 0, failed_names(rep)))
        elf = ELF(open(path, "rb").read())

        # M1 (E1): break p_offset == p_vaddr (mod p_align) on the payload LOAD
        pl = [p for p in elf.loads if p["vaddr"] == elf.image_base + int(report["sectionRVA"])][0]

        def m1(d):
            struct.pack_into("<Q", d, pl["hdr"] + 8, pl["off"] + 1)
        results.append(("E1", *_expect_fail(run_checks(mutate(path, m1, tmp, "e1"), manifest, report, blob, True), "E1")))

        # M2 (E2): the report's payload base drifts away from the segment it names
        rep2 = dict(report)
        rep2["sectionRVA"] = int(report["sectionRVA"]) + 0x1000
        results.append(("E2", *_expect_fail(run_checks(path, manifest, rep2, blob, True), "E2")))

        # M3 (E3): flip one byte inside the mapped blob range
        off = elf.va_to_off(elf.image_base + int(report["sectionRVA"]) + 0x40)

        def m3(d):
            d[off] ^= 0xFF
        results.append(("E3", *_expect_fail(run_checks(mutate(path, m3, tmp, "e3"), manifest, report, blob, True), "E3")))

        # M4 (E4): PLANT the #585 defect -- give a non-top LOAD a bss beyond its file image.
        # Shape-independent: after the fix no LOAD carries bss at all, so "remove an existing bss"
        # would have no input (that is exactly how the analogous PE calibration went wrong once).
        planted = None
        for p in elf.loads:
            if p["filesz"] > 0x2000 and align_up(p["vaddr"] + p["filesz"], 4096) < elf.top_bss_edge():
                planted = p
                break
        if planted is None:
            results.append(("E4", False, "no non-top LOAD to plant a bss on"))
        else:
            def m4(d, p=planted):
                struct.pack_into("<Q", d, p["hdr"] + 32, p["filesz"] - 0x1000)  # shrink filesz
            results.append(("E4", *_expect_fail(run_checks(mutate(path, m4, tmp, "e4"), manifest, report, blob, True), "E4")))

        # M5 (E1, the ordering rule): list the RW overlay BEFORE the payload segment
        if int(manifest["bssSize"]) > 0:
            ov = [p for p in elf.loads
                  if p["vaddr"] == elf.image_base + int(report["sectionRVA"]) + int(manifest["bssOff"])][0]
            a, b = pl["hdr"], ov["hdr"]

            def m5(d):
                ea = bytes(d[a:a + 56])
                eb = bytes(d[b:b + 56])
                d[a:a + 56] = eb
                d[b:b + 56] = ea
            results.append(("E1-order", *_expect_fail(run_checks(mutate(path, m5, tmp, "e1o"), manifest, report, blob, True), "E1")))
        else:
            print("[SKIP] CAL  E1-order: this product has no RW overlay segment")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    bad = 0
    for name, good, detail in results:
        if good:
            print("[OK  ] CAL  mutation caught by %s" % name)
        else:
            print("[FAIL] CAL  mutation NOT caught by %s (%s)" % (name, detail))
            bad += 1
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--packed", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--blob", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    manifest = json.load(open(a.manifest))
    report = json.load(open(a.report))
    blob = open(a.blob, "rb").read()
    try:
        rep = run_checks(a.packed, manifest, report, blob)
    except ValueError as e:
        print("[FAIL] cannot parse %s: %s" % (a.packed, e))
        return 1
    bad = rep.failed
    if a.selftest:
        if bad:
            print("[!] skipping calibration: the product already fails")
        else:
            bad += selftest(a.packed, manifest, report, blob)
    if bad:
        print("[FAIL] check_elf_layout: %d problem(s)" % bad)
        return 1
    print("[OK  ] check_elf_layout: program headers, payload mapping, byte identity, "
          "bss coverage and relocations all consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
