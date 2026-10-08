#!/usr/bin/env python3
"""check_elf_layout.py -- layout-consistency gate for a PACKED ELF (Linux counterpart of
tools/check_symmap.py, which does the same job for PE).

Everything is derived from the PRODUCT FILE plus the same build's blob manifest and pack report.

  E1 program-header inventory
        every PT_LOAD is file-backed inside the file, satisfies p_offset == p_vaddr (mod p_align),
        has p_memsz >= p_filesz, and NO PT_LOAD overlaps another one. The injector used to emit one
        allowed overlap ("RX payload segment + an RW segment overlaying its bss"); that shape is the
        M5 defect (STATUS #597) and is rejected here on purpose -- the injector now emits only
        ADJACENT segments, or one wholly writable payload segment (E2 below names all three shapes).
        E1 also carries the DIRECT M5 assertion (independent of E2's shape logic).
  E2 payload segments vs the report + the M5 no-overlap invariant
        one PT_LOAD at exactly report.sectionRVA carrying the payload. The injector emits three
        shapes, in preference order (each is a fact about the PRODUCT's program headers, never about
        the packer's wording):
          (1) THREE ADJACENT segments (needs 3 reusable program headers): RX prefix
              filesz == memsz == bssOff, then the RW window at sectionRVA+bssOff
              (filesz == memsz == bssSize), then an R+X tail for the rest of the payload
              (filesz == memsz == sectionSize-bssOff-bssSize);
          (2) PREFIX + ONE W+X "window+tail" SEGMENT (2 reusable headers and the payload has a
              tail): the same RX prefix (filesz == memsz == bssOff), plus one writable+executable
              segment at sectionRVA+bssOff with filesz == memsz == bssSize+tail -- the code page
              stays read-only, but that one span is W+X;
          (3) ONE W+X SEGMENT (fewer than 2 reusable headers, e.g. the 1-PT_NOTE aarch64 fixtures
              that CI run 37128895442 used): the payload LOAD itself is writable and executable
              with filesz == memsz == sectionSize, the window file-backed inside it;
          and, when manifest bssSize == 0, one RX segment with no writable window at all.
        The payload LOAD's filesz is therefore either report.sectionSize (whole payload) or bssOff
        (the split prefix). The report's payloadWXFallback flag must agree with whether the program
        headers really show (2)/(3) or the all-readonly (1).
        On top of the layout, E2 asserts the M5 invariant on every product:
        NO NON-WRITABLE PT_LOAD MAY INTERSECT THE WRITABLE WINDOW [bss_va, bss_va+bss_size), compared
        per 4 KiB page (the granularity the kernel and glibc's mprotect work at). glibc re-protects
        each PT_LOAD on the DT_TEXTREL path; when the payload's RX segment covers the window's page
        the window turns read-only and the interpreter SIGSEGVs on its first write (measured).
        When there is no writable window the invariant has no input and E2 says so explicitly.
  E3 payload byte identity
        file bytes at (sectionRVA + o) == blob[o] for every o in [0, blobSize).
  E4 bss mapping invariant (STATUS #585)
        the kernel maps bss as ONE global range: set_brk(PAGEALIGN(max(vaddr+filesz)),
        PAGEALIGN(max(vaddr+memsz))). A segment with memsz > filesz therefore keeps its bss only
        when its own PAGEALIGN(vaddr+filesz) IS that maximum; anything else loses its bss entirely
        and dies on the first global write ("error 6" = not present + write). Assert none exists.
  E5 relocation coverage (ET_DYN only)
        (a) every preferred-base absolute VA stored in the payload must be covered by an
            R_*_RELATIVE entry (candidates are filtered by the plausible-VA window, not by
            "value >> 32", which matches nearly every random word). When the scan finds no
            candidate at all the gate says so with an explicit INFO (plus a full unaligned
            sweep as evidence) instead of reporting a pass it did not earn: for products this
            packer generates the payload genuinely holds no preferred-base VA, so the
            load-bearing checks are E3 (payload == blob), (a2) and (b) below, plus the e2e PIE
            run that really lets ld.so relocate the image.
        (a2) the payload's image-decryption table must not declare a preferred base
            (report.imgTableRVA + 0 = wantBase). That is the one slot where the ELF payload
            could carry an absolute VA; vm_unpack_image fails ("basemismatch") on a nonzero
            value the moment ld.so relocates the image, so this is a real ASLR assertion and
            not a blind word scan (it reads the product's own declared field).
        (b) every R_*_RELATIVE whose target sits inside a range the report declares as
            image-encrypted must be recorded (report.imgRelocCount) and have an apply table
            (report.imgRelocTableRVA) -- ld.so writes those slots before the entry hook, so a
            missing record is either an AEAD verify failure or a silently corrupted slot.
        ET_EXEC keeps its INFO line (the image never moves).

  E5 coverage gap on aarch64 (partly closed by #597; updated after measuring the real root cause):
    * What used to forbid it: docs/STATUS.md #376/#377 keep ELF read-only-data-section encryption
      off on aarch64 (AGENTS.md forbids turning it on), so the only range type left is the
      executable one -- and a reloc slot inside an encrypted *executable* range made the product
      SIGSEGV. The real cause was NOT the relocation applier: the aarch64 linker puts PT_DYNAMIC
      (and the tables it points at) INSIDE that executable segment, so the loader read ciphertext.
      The #597 guards in cmd/vmpack/main.go now (1) exclude any range that carries PT_DYNAMIC
      ("载着 PT_DYNAMIC") and (2) refuse to pack when a non-R_*_RELATIVE relocation lands inside a
      range that IS encrypted (the apply table cannot restore what ld.so wrote).
    * Which bytes stay unverifiable: every R_AARCH64_RELATIVE target inside a range the packer
      would have to encrypt (i.e. exactly the slots the runtime applier would rewrite). On
      aarch64 today that means the whole executable range of a normal C PIE is left plaintext --
      the product must then answer exactly like native, which tools/e2e_elf_image.sh asserts.
    * What covers the rest: tools/e2e_elf_image.sh's x86-64 PIE_RELOCS case and the committed
      DT_TEXTREL case (relocations inside an encrypted *executable* range, applied by the runtime
      applier and byte-compared with native) are the applier's end-to-end acceptance points --
      vm_reloc_fix is ONE arch-independent function and the packer copies the target's own reloc
      type into the table -- while this gate re-derives the recorded count/targets from a
      product's own PT_DYNAMIC, so the packing half stays checked from the artifact.

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
PT_DYNAMIC = 2
DT_NULL, DT_RELA, DT_RELASZ, DT_RELAENT = 0, 7, 8, 9
DT_REL, DT_RELSZ, DT_RELENT = 17, 18, 19


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
        """File offset of a VA according to ANY PT_LOAD (None when nothing maps it).

        The injector's split layout maps the payload with SEVERAL separate segments (RX prefix,
        RW window, R+X tail), so the offset must come from whichever PT_LOAD really carries that
        address -- looking only at the FIRST segment's p_filesz would report "not file-backed"
        for bytes the product genuinely has. (There used to be two definitions here; the first
        one silently shadowed the second and was deleted.)
        """
        for p in self.progs:
            if p["type"] != PT_LOAD:
                continue
            if p["vaddr"] <= va < p["vaddr"] + p["filesz"]:
                off = p["off"] + (va - p["vaddr"])
                if off < len(self.data):
                    return off
                return None
        return None

    def read(self, va, n):
        o = self.va_to_off(va)
        if o is None or o + n > len(self.data):
            return None
        return self.data[o:o + n]

    def dyn_relocs(self):
        """[(r_offset, type, addend)] from PT_DYNAMIC (DT_RELA/DT_REL), or None if there is none.

        Read through PT_DYNAMIC on purpose: the packer MOVES segment payloads to the end of
        the file (MakeBssFileBacked) without fixing sh_offset, so the section table can point
        at dead copies -- and ld.so (the thing that actually applies these relocations) only
        ever looks at PT_DYNAMIC.
        """
        dyn = [p for p in self.progs if p["type"] == PT_DYNAMIC]
        if not dyn:
            return None
        tags = {}
        p = dyn[0]
        for o in range(p["off"], p["off"] + p["filesz"], 16):
            if o + 16 > len(self.data):
                break
            tag, val = struct.unpack_from("<QQ", self.data, o)
            if tag == DT_NULL:
                break
            tags.setdefault(tag, val)
        with_addend = tags.get(DT_RELASZ, 0) != 0
        addr = tags.get(DT_RELA, 0) if with_addend else tags.get(DT_REL, 0)
        size = tags.get(DT_RELASZ, 0) if with_addend else tags.get(DT_RELSZ, 0)
        ent = tags.get(DT_RELAENT, 0) if with_addend else tags.get(DT_RELENT, 0)
        if size == 0:
            return None
        if ent == 0:
            ent = 24 if with_addend else 16
        off = self.va_to_off(addr)
        if off is None or off + size > len(self.data):
            return None
        out = []
        for k in range(size // ent):
            o = off + k * ent
            r_off, r_info = struct.unpack_from("<QQ", self.data, o)
            add = struct.unpack_from("<q", self.data, o + 16)[0] if with_addend else 0
            out.append((r_off, r_info & 0xFFFFFFFF, add))
        return out

    def va_ceiling(self):
        """Highest mapped VA (end of the last PT_LOAD) -- upper bound of a plausible absolute VA."""
        return max((p["vaddr"] + p["memsz"] for p in self.loads), default=0)

    # 注意：这里**没有**按节头表读 .rela.dyn 的版本。打包端会把某些段整段搬到文件尾
    # （MakeBssFileBacked，只改程序头不改 sh_offset），节头表可能指向死副本；ld.so 与运行期
    # 应用器都只认 PT_DYNAMIC，所以本门禁也只走 dyn_relocs()。

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


def payload_window_va(elf, manifest, report):
    """The writable window's VA (manifest bssOff relative to report.sectionRVA), or None."""
    if elf is None or manifest is None or report is None:
        return None
    if int(manifest.get("bssSize") or 0) <= 0:
        return None
    return elf.image_base + int(report["sectionRVA"]) + int(manifest.get("bssOff") or 0)


def check_inventory(elf, rep, manifest=None, report=None):
    """E1 also carries the DIRECT M5 test: an RX payload segment whose vaddr range swallows the
    writable window is the measured cause of the SIGSEGV (STATUS #597), whatever the rest of the
    program-header table looks like. It is asserted here -- not only in E2 -- so that the invariant
    survives any future legal-shape relaxation in E2, and it is derived from report+manifest, not
    from "does this segment look like a payload segment"."""
    win = payload_window_va(elf, manifest, report)
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
    # The injector's OLD shape used to be "one RX payload LOAD + an RW segment overlapping it".
    # That shape is the M5 defect (glibc re-protects the page from the RX segment on the DT_TEXTREL
    # path and the interpreter's writable window turns read-only -> SIGSEGV, STATUS #597), so the
    # injector must not emit it any more; keep rejecting it here. The injector's CURRENT shapes are
    # either ADJACENT segments (three-segment split, or prefix + W+X window+tail) or one wholly W+X
    # payload segment -- none of them overlaps anything, so no overlap exemption is needed at all.
    # Direct M5 assertion (see the docstring): the interpreter's writable window must not sit inside
    # ANY non-writable PT_LOAD's vaddr range. This one does not care what the table looks like, so a
    # later "this overlap is allowed" relaxation in the loop above cannot silently disable it.
    # The comparison is PER PAGE, which is the granularity the kernel maps at: a segment whose
    # PAGE-RANGE covers the window's page is what makes glibc re-protect that page read-only -- even
    # if its last bytes land just short of the window's first byte. Page rounding does NOT false-red
    # the correct split shape: there the prefix ends exactly at the window (0x...C3000), whose
    # page-aligned end is the window's own first page, so the ranges stay disjoint.
    if win is not None and int(manifest.get("bssSize") or 0) > 0:
        wend = win + int(manifest["bssSize"])
        wlo, whi = win // 4096, (wend - 1) // 4096
        for q in elf.loads:
            if q["flags"] & PF_W or q["memsz"] == 0:
                continue
            qlo = q["vaddr"] // 4096
            qhi = (q["vaddr"] + q["memsz"] - 1) // 4096
            if qlo <= whi and wlo <= qhi:
                rep.fail("E1", "non-writable LOAD (vaddr=0x%X memsz=0x%X flags=0x%X) covers the "
                               "interpreter's writable window [0x%X,0x%X): glibc re-protects the page "
                               "from that LOAD on the DT_TEXTREL path, so the window turns read-only "
                               "and the product SIGSEGVs on its first write (STATUS #597)"
                         % (q["vaddr"], q["memsz"], q["flags"], win, wend))
    for a in elf.loads:
        for b in elf.loads:
            if b["i"] <= a["i"]:
                continue
            if b["vaddr"] >= a["vaddr"] + a["memsz"] or a["vaddr"] >= b["vaddr"] + b["memsz"]:
                continue  # disjoint
            inside = b["vaddr"] >= a["vaddr"] and b["vaddr"] + b["memsz"] <= a["vaddr"] + a["memsz"]
            if inside and (a["flags"] & PF_W) and (b["flags"] & a["flags"]) == a["flags"]:
                # A segment nested inside an EARLIER WRITABLE segment whose permissions are a
                # subset of it: the later mapping wins and grants nothing new, so the effective
                # permissions are identical over that page range. Harmless -- and it must stay
                # legal because a link-editor product can legitimately carry one (PT_GNU_RELRO
                # nested in the RW LOAD).
                continue
            if inside and (b["flags"] & PF_W) and not (b["flags"] & PF_X):
                rep.fail("E1", "the RX payload LOAD at 0x%X is OVERLAPPED by a later RW segment at 0x%X: "
                               "this is the M5 defect shape -- glibc re-protects that page from the RX "
                               "segment on the DT_TEXTREL path and the writable window turns read-only "
                               "(STATUS #597); split the payload into ADJACENT segments or make the whole "
                               "payload RWX instead"
                         % (a["vaddr"], b["vaddr"]))
            rep.fail("E1", "LOAD[%d] (vaddr=0x%X flags=0x%X) overlaps LOAD[%d] (vaddr=0x%X flags=0x%X) "
                           "and is not an allowed shape"
                     % (b["i"], b["vaddr"], b["flags"], a["i"], a["vaddr"], a["flags"]))
    rep.ok("E1", "%d PT_LOAD in range, congruence/order constraints hold" % len(elf.loads))


def check_payload(elf, manifest, report, rep):
    """E2 -- payload segments vs the report, and the M5 no-overlap invariant.

    Legal layouts (all of them are facts about the PRODUCT's program headers; the module docstring
    above lists the same three tiers with the same numbering):

      (1) THREE ADJACENT segments (the preferred shape; needs 3 reusable program headers):
            [1] PT_LOAD sec_va                  RX   filesz == memsz == bssOff
            [2] PT_LOAD sec_va + bssOff         RW   filesz == memsz == bssSize
            [3] PT_LOAD sec_va + bssOff+bssSize R+X  filesz == memsz == the rest of the payload
      (2) TWO ADJACENT segments (2 reusable headers, payload has a tail): the RX prefix above, plus
          ONE W+X segment covering the writable window AND the tail that follows it. Legal because
          that segment is itself writable, so no non-writable LOAD can cover the window.
      (3) ONE segment: the payload LOAD is W+X and filesz == memsz == report.sectionSize (fewer than
          2 reusable headers).
      and: one RX segment with no writable window at all (manifest bssSize == 0).

    The payload LOAD's filesz is therefore allowed to be report.sectionSize (whole payload) or
    bssOff (the split prefix in (1)/(2)).

    On top of the layout, E2 asserts the M5 invariant on every product:
      NO NON-WRITABLE PT_LOAD MAY INTERSECT THE WRITABLE WINDOW [bss_va, bss_va+bss_size),
    compared per 4 KiB page (the granularity the kernel and glibc's mprotect work at). glibc
    re-protects each PT_LOAD on the DT_TEXTREL path; when the payload's RX segment covers the
    window's page the window turns read-only and the interpreter SIGSEGVs on its first write
    (STATUS #597, measured). When there is no writable window the invariant has no input and E2
    says so explicitly.
    """
    sec_rva = int(report["sectionRVA"])
    sec_va = elf.image_base + sec_rva
    sec_size = int(report["sectionSize"])
    bss_off, bss_size = int(manifest["bssOff"]), int(manifest["bssSize"])
    bss_va = sec_va + bss_off
    bss_end = bss_va + bss_size

    p = None
    for q in elf.loads:
        if q["vaddr"] == sec_va:
            p = q
    if p is None:
        rep.fail("E2", "no PT_LOAD at imageBase(0x%X) + report.sectionRVA(0x%X) = 0x%X"
                 % (elf.image_base, sec_rva, sec_va))
    if not (p["flags"] & PF_X):
        rep.fail("E2", "payload LOAD at 0x%X is not executable (flags=0x%X)" % (sec_va, p["flags"]))
    # NOTE: a filesz mismatch is recorded as a soft error instead of failing immediately. Every
    # other E2 assertion still runs, because the M5 window invariant below is the one that must
    # never be skippable -- and the calibration "grow the payload segment over the window" changes
    # p_memsz (not p_filesz), so it can only trip that invariant if the checks after this point
    # still execute.
    soft = []
    if p["filesz"] != sec_size and p["filesz"] != bss_off:
        soft.append("payload LOAD filesz 0x%X is neither report.sectionSize (0x%X, one segment) "
                    "nor manifest bssOff (0x%X, split prefix)" % (p["filesz"], sec_size, bss_off))

    def at(va):
        for q in elf.loads:
            if q["vaddr"] == va:
                return q
        return None

    tail_size = sec_size - bss_off - bss_size
    if tail_size < 0:
        rep.fail("E2", "manifest bssOff(0x%X) + bssSize(0x%X) exceeds report.sectionSize (0x%X): the "
                       "interpreter's writable window would run past the payload"
                 % (bss_off, bss_size, sec_size))

    if p["filesz"] == bss_off and p["flags"] & PF_W:
        rep.fail("E2", "split' payload prefix at 0x%X is writable (flags=0x%X): the RX prefix must "
                       "stop at the writable window, not carry the write bit itself"
                 % (sec_va, p["flags"]))

    if p["filesz"] == sec_size:
        # tier (3) / no-window: the whole payload in one segment.
        if bss_size > 0 and not (p["flags"] & PF_W):
            rep.fail("E2", "payload LOAD at 0x%X maps the whole payload (filesz == sectionSize) but is "
                           "NOT writable (flags=0x%X), so nothing maps the interpreter's writable window"
                     % (sec_va, p["flags"]))
        if p["memsz"] != sec_size:
            rep.fail("E2", "one-segment payload LOAD at 0x%X is 0x%X/0x%X, expected filesz == memsz "
                           "== sectionSize 0x%X" % (sec_va, p["filesz"], p["memsz"], sec_size))
        if bss_size > 0:
            if bss_end > sec_va + p["memsz"] or bss_off + bss_size > p["filesz"]:
                rep.fail("E2", "the writable window [0x%X,0x%X) is not inside the one-segment payload "
                               "LOAD (filesz 0x%X memsz 0x%X)" % (bss_va, bss_end, p["filesz"], p["memsz"]))
            shape = ("one W+X payload LOAD @0x%X (flags=0x%X filesz=0x%X memsz=0x%X), window "
                     "[0x%X,0x%X) file-backed inside it"
                     % (sec_va, p["flags"], p["filesz"], p["memsz"], bss_va, bss_end))
            rep.info("E2", "payload LOAD is W+X (flags=0x%X): the injector fell back to ONE segment "
                           "(fewer than 2 reusable program-header slots); the whole payload is writable, "
                           "so no non-writable LOAD can cover the window (the M5 defect shape is "
                           "impossible). Report declares payloadWXFallback." % p["flags"])
        else:
            shape = "one RX payload LOAD @0x%X (flags=0x%X filesz=0x%X), no writable window" \
                    % (sec_va, p["flags"], p["filesz"])
    else:
        # tier (1)/(2): the injector split the payload. Every piece must be ADJACENT and page-aligned.
        if p["filesz"] != bss_off or p["memsz"] != bss_off:
            rep.fail("E2", "split payload prefix at 0x%X is 0x%X/0x%X, expected filesz == memsz == bssOff 0x%X "
                           "(the RX prefix must STOP at the writable window)"
                     % (sec_va, p["filesz"], p["memsz"], bss_off))
        if bss_size > 0 and (bss_off % 4096 or bss_size % 4096):
            rep.fail("E2", "split payload has a non-page-aligned window (bssOff=0x%X bssSize=0x%X): the "
                           "kernel maps whole pages, so such a window cannot be split off on its own"
                     % (bss_off, bss_size))
        win = at(bss_va) if bss_size > 0 else None
        if bss_size > 0:
            if win is None:
                rep.fail("E2", "no PT_LOAD at the writable window start 0x%X (manifest bssOff=0x%X): the "
                               "interpreter's writable window is not mapped" % (bss_va, bss_off))
            if not (win["flags"] & PF_W):
                rep.fail("E2", "the window segment at 0x%X is not writable (flags=0x%X)"
                         % (bss_va, win["flags"]))
            if win["filesz"] != win["memsz"]:
                rep.fail("E2", "the window segment at 0x%X is 0x%X/0x%X: a file image shorter than "
                               "memsz would lose its anonymous tail (the kernel maps bss as ONE global "
                               "range, STATUS #585)" % (bss_va, win["filesz"], win["memsz"]))
            if tail_size > 0:
                # tier (1): separate R+X tail  |  tier (2): the tail is inside the same W+X segment
                if win["filesz"] == bss_size:
                    tail = at(bss_end)
                    if tail is not None and tail["vaddr"] + tail["memsz"] == sec_va + sec_size:
                        if tail["filesz"] != tail_size or tail["memsz"] != tail_size:
                            rep.fail("E2", "payload tail at 0x%X is 0x%X/0x%X, expected filesz == memsz "
                                           "== 0x%X" % (bss_end, tail["filesz"], tail["memsz"], tail_size))
                        if (tail["flags"] & PF_X) and not (tail["flags"] & PF_W):
                            shape = ("RX prefix @0x%X (flags=0x%X filesz=0x%X) + RW window [0x%X,0x%X) "
                                     "(flags=0x%X filesz=0x%X) + R+X tail @0x%X (flags=0x%X filesz=0x%X)"
                                     % (sec_va, p["flags"], bss_off, bss_va, bss_end, win["flags"],
                                        win["filesz"], bss_end, tail["flags"], tail["filesz"]))
                        elif tail["flags"] & PF_W:
                            shape = ("RX prefix @0x%X (flags=0x%X filesz=0x%X) + RW window [0x%X,0x%X) "
                                     "(flags=0x%X filesz=0x%X) + W+X tail @0x%X (flags=0x%X filesz=0x%X)"
                                     % (sec_va, p["flags"], bss_off, bss_va, bss_end, win["flags"],
                                        win["filesz"], bss_end, tail["flags"], tail["filesz"]))
                        else:
                            rep.fail("E2", "payload tail at 0x%X is neither executable nor writable "
                                           "(flags=0x%X): those bytes are unmappable as code or data"
                                     % (bss_end, tail["flags"]))
                    else:
                        rep.fail("E2", "payload byte(s) after the writable window are not mapped by a "
                                       "single adjacent LOAD (expected one at 0x%X covering 0x%X bytes): "
                                       "the two-segment version merged them into the RW window and both "
                                       "the normal and the textrel fixture died on their first write "
                                       "(the tail holds executable trampolines)"
                                 % (bss_end, tail_size))
                elif win["filesz"] == bss_size + tail_size:
                    if not (win["flags"] & PF_X):
                        rep.fail("E2", "the RWX window+tail segment at 0x%X is not executable "
                                       "(flags=0x%X): the tail bytes hold executable trampolines"
                                 % (bss_va, win["flags"]))
                    shape = ("RX prefix @0x%X (flags=0x%X filesz=0x%X) + **W+X window+tail** segment "
                             "[0x%X,0x%X) (flags=0x%X filesz=0x%X memsz=0x%X) covering 0x%X + 0x%X "
                             "bytes (two adjacent segments, the 2-reusable-header route)"
                             % (sec_va, p["flags"], bss_off, bss_va, bss_end + tail_size, win["flags"],
                                win["filesz"], win["memsz"], bss_size, tail_size))
                    rep.info("E2", "the window and the following tail live in ONE **W+X** segment "
                                   "(flags=0x%X): the injector had exactly 2 reusable program-header "
                                   "slots (a third would have let it keep the code page non-writable). "
                                   "Report declares payloadWXFallback." % win["flags"])
                else:
                    rep.fail("E2", "the window segment at 0x%X is 0x%X/0x%X, expected filesz == memsz == "
                                   "bssSize (0x%X) for a separate window, or the window+tail (0x%X) for "
                                   "the 2-slot route" % (bss_va, win["filesz"], win["memsz"], bss_size,
                                                        bss_size + tail_size))
            else:
                if win["filesz"] != bss_size:
                    rep.fail("E2", "the window segment at 0x%X is 0x%X/0x%X, expected 0x%X (== bssSize)"
                             % (bss_va, win["filesz"], win["memsz"], bss_size))
                shape = ("RX prefix @0x%X (flags=0x%X filesz=0x%X) + RW window [0x%X,0x%X) "
                         "(flags=0x%X filesz=0x%X) (adjacent; the payload ends at the window edge so "
                         "there is no tail)"
                         % (sec_va, p["flags"], bss_off, bss_va, bss_end, win["flags"], win["filesz"]))
        else:
            shape = ("RX prefix @0x%X (flags=0x%X filesz=0x%X), no writable window"
                     % (sec_va, p["flags"], p["filesz"]))

    # ---- M5 invariant, checked on whatever shape the product really has ----
    if bss_size > 0:
        win_lo, win_hi = bss_va, bss_end
        offenders = []
        for q in elf.loads:
            if q["flags"] & PF_W:
                continue  # writable segments are allowed to hold the window
            lo = max(win_lo // 4096, q["vaddr"] // 4096)
            hi = min((win_hi + 4095) // 4096, (q["vaddr"] + q["memsz"] + 4095) // 4096)
            if lo < hi:
                offenders.append((q, lo, hi))
        if offenders:
            for q, lo, hi in offenders[:4]:
                rep.lines.append("[----] E2  non-writable LOAD vaddr=0x%X memsz=0x%X flags=0x%X shares "
                                 "page(s) [0x%X,0x%X) with the writable window [0x%X,0x%X)"
                                 % (q["vaddr"], q["memsz"], q["flags"], lo * 4096, hi * 4096, win_lo, win_hi))
            q = offenders[0][0]
            rep.fail("E2", "non-writable LOAD (vaddr=0x%X flags=0x%X) intersects the writable window "
                           "[0x%X,0x%X): glibc re-protects that page from this LOAD on the DT_TEXTREL "
                           "path, the interpreter's writable window turns read-only and the product "
                           "SIGSEGVs on its first write (STATUS #597)"
                     % (q["vaddr"], q["flags"], win_lo, win_hi))
        rep.ok("E2", "no non-writable LOAD intersects the writable window [0x%X,0x%X)" % (win_lo, win_hi))
    else:
        rep.info("E2", "no writable window in this payload (manifest bssSize=0): the "
                       "\"non-writable LOAD must not cover the window\" invariant is vacuous here")

    # every payload byte must be file-backed (through whichever PT_LOAD maps it)
    if elf.va_to_off(sec_va + sec_size - 1) is None:
        soft.append("the last payload byte (vaddr 0x%X) is not file-backed" % (sec_va + sec_size - 1))
    if soft:
        rep.fail("E2", "; ".join(soft))

    # ---- the report's declared shape must match the program headers (M5 fallback bookkeeping) ----
    # The packer records whether it had to fall back to a writable+executable payload segment
    # (report.payloadWXFallback). Comparing that flag against the product is what turns "the injector
    # says it split the payload" into an assertion: a target with enough reusable program-header slots
    # must NOT be declared (or emitted) as a fallback, and a fallback product must not be declared as
    # a clean split. Without this, a regression could silently make every product take the RWX route
    # (code page writable) while every other check still passed.
    payload_wx = False
    for q in elf.loads:
        if q["vaddr"] < sec_va + sec_size and sec_va < q["vaddr"] + q["memsz"]:
            if (q["flags"] & PF_W) and (q["flags"] & PF_X):
                payload_wx = True
    declared = report.get("payloadWXFallback")
    if declared is None:
        rep.info("E2", "report has no payloadWXFallback field: cannot cross-check the declared payload "
                       "shape against the program headers (this product's payload %s a W+X segment)"
                 % ("HAS" if payload_wx else "has no"))
    elif bool(declared) != payload_wx:
        rep.fail("E2", "report.payloadWXFallback=%s but the product's payload %s a writable-executable "
                       "segment: the declared shape contradicts the program headers (a target with "
                       "enough reusable slots must not be declared/emitted as the RWX fallback)"
                 % (declared, "HAS" if payload_wx else "has NO"))
    else:
        rep.ok("E2", "declared payload shape matches the program headers (payloadWXFallback=%s, W+X "
                     "payload segment present: %s)" % (bool(declared), payload_wx))
    rep.ok("E2", "payload @0x%X (RVA 0x%X, 0x%X bytes) + %s" % (sec_va, sec_rva, sec_size, shape))


def check_identity(elf, manifest, report, blob, rep):
    sec_rva = elf.image_base + int(report["sectionRVA"])
    blob_size = int(manifest["blobSize"])
    if len(blob) < blob_size:
        rep.fail("E3", "blob is 0x%X bytes, manifest says blobSize 0x%X" % (len(blob), blob_size))
    diffs = []
    for o in range(blob_size):
        # Every payload byte must be file-backed -- through whichever PT_LOAD maps it. The
        # injector's split layout maps [bssOff, sectionSize) with its own segments (RW window,
        # R+X tail), so reading through the FIRST segment alone would falsely report "not
        # file-backed" for bytes the product really does carry (that was a hole the two-segment
        # version of this gate had).
        if elf.va_to_off(sec_rva + o) is None:
            rep.fail("E3", "blob offset 0x%X (vaddr 0x%X) is not file-backed" % (o, sec_rva + o))
        got = elf.read(sec_rva + o, 1)
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
    """E5 (ET_DYN/PIE only) -- two independent assertions:

    (a) payload absolute-VA coverage: for a PIE the payload must be base-independent. Every
        preferred-base VA stored in the payload segment needs an R_*_RELATIVE entry covering
        it, otherwise the product breaks as soon as ASLR really moves the image. Candidates are
        filtered by the "plausible VA" window [imageBase, end of last LOAD) -- the old
        "value >> 32" heuristic matches essentially EVERY random 8-byte word (the encrypted
        byte code and the AEAD tags are random), so it could never be a real gate.
    (b) encrypted-range bookkeeping: every R_*_RELATIVE whose target lies inside a range the
        report declares as image-encrypted must be recorded (report.imgRelocCount) and must
        have an apply table in the payload. ld.so writes those slots BEFORE the entry hook runs,
        so missing one = AEAD verify failure or a corrupted slot (STATUS #390 / the packer's
        -enc-image-elf-pie[-relocs]).
    """
    if elf.etype != ET_DYN:
        rep.info("E5", "ET_EXEC: the image stays at its link-time base, no relocation applies")
        return
    rel = elf.dyn_relocs()
    if rel is None:
        rep.fail("E5", "ET_DYN product has no readable PT_DYNAMIC relocation table")
    kinds = R_RELATIVE.get(elf.machine, 8)
    covered = set(off for off, ty, _a in rel if ty == kinds)
    pref = elf.image_base
    ceiling = elf.va_ceiling()

    sec_rva = pref + int(report["sectionRVA"])
    sec_size = int(report["sectionSize"])   # the (a) scan below covers the WHOLE payload
    p = None
    for q in elf.loads:
        if q["vaddr"] == sec_rva:
            p = q
    if p is None:
        rep.fail("E5", "payload LOAD missing (see E2)")

    # (a) payload absolute VAs
    if pref == 0:
        # RVA 与 VA 在基址 0 的 PIE 里无法区分（可执行段从 vaddr 0 开始），
        # 载荷里的 RVA 字段会全部落进窗口 —— 这条检查对这种目标没有分辨力，如实说清楚。
        rep.info("E5", "preferred base is 0: RVA and VA are indistinguishable, payload VA coverage check skipped")
    else:
        cands = []
        # Scan the WHOLE payload (report.sectionSize) rather than the payload LOAD's p_filesz: after
        # the M5 split that first segment is only the RX prefix, so bounding the scan by p_filesz
        # would silently skip the writable window and the R+X tail -- a coverage regression of exactly
        # the kind the split introduced. elf.read()/EF.va_to_off() resolve each address through
        # whichever PT_LOAD really carries it, so the wider range costs nothing but reaches it.
        for off in range(0, sec_size - 7, 8):
            raw = elf.read(sec_rva + off, 8)
            if raw is None:
                continue
            v = struct.unpack("<Q", raw)[0]
            if pref <= v < ceiling:
                cands.append((sec_rva + off, v))
        uncovered = [(r, v) for r, v in cands if r not in covered]
        for r, v in uncovered[:8]:
            rep.lines.append("[----] E5  vaddr 0x%X holds a preferred-base VA (0x%X) but no RELATIVE entry covers it" % (r, v))
        if uncovered:
            rep.fail("E5", "%d of %d payload absolute VA(s) have no RELATIVE relocation (first at 0x%X holding 0x%X)"
                     % (len(uncovered), len(cands), uncovered[0][0], uncovered[0][1]))
        if cands:
            rep.ok("E5", "payload [0x%X,0x%X) (sectionSize 0x%X): %d absolute VA(s), all covered by %d "
                         "RELATIVE entries" % (sec_rva, sec_rva + sec_size, sec_size, len(cands), len(covered)))
        else:
            # No candidate = this half of E5 had no input. Saying "OK" here would claim a pass the
            # check did not earn, so report the downgrade explicitly and back it with a sweep at
            # EVERY byte offset (not just the 8-byte stride) -- otherwise the emptiness could be
            # an artefact of where the scan looks.
            any_off = 0
            for off in range(0, sec_size - 7):   # same full-payload range as the stride scan above
                raw = elf.read(sec_rva + off, 8)
                if raw is None:
                    break
                v = struct.unpack("<Q", raw)[0]
                if pref <= v < ceiling:
                    any_off += 1
            rep.info("E5", "payload [0x%X,0x%X) (sectionSize 0x%X, scanned in full: 8-byte stride plus a "
                           "sweep at every byte offset) carries no preferred-base VA in [0x%X,0x%X): 0 "
                           "candidate(s), %d raw hits -> the \"VA must be covered\" half of E5 has no input on "
                           "this product (base-independence there is carried by E3 payload==blob, E5(a2) below "
                           "and the e2e run that really relocates the image), NOT by this scan"
                     % (sec_rva, sec_rva + sec_size, sec_size, pref, ceiling, any_off))

    # (a2) the payload's own declared VA slot: the image table's wantBase field. It is the one place
    # the ELF payload could hold an absolute preferred-base VA, and it is read from the PRODUCT (not
    # from a magic value), so this half keeps its discriminating power on real PIE products.
    img_tbl = int(report.get("imgTableRVA") or 0)
    if img_tbl == 0:
        rep.info("E5", "no image table in this product (report.imgTableRVA=0): no declared VA slot to check")
    else:
        want = elf.read(pref + img_tbl, 8)
        if want is None:
            rep.fail("E5", "report.imgTableRVA=0x%X is not file-backed in the product" % img_tbl)
        wantbase = struct.unpack("<Q", want)[0]
        if wantbase != 0:
            rep.fail("E5", "payload image table at RVA 0x%X declares wantBase=0x%X; an ET_DYN image is loaded "
                           "at an ASLR-chosen base, so a nonzero wantBase makes vm_unpack_image fail "
                           "(VMPELF basemismatch) as soon as the image actually moves"
                     % (img_tbl, wantbase))
        rep.ok("E5", "payload image table wantBase=0: the payload relies on no absolute preferred-base VA")

    # (b) encrypted ranges vs the recorded relocations
    secs = report.get("imgSections")
    if not secs:
        # The report carries imgSections=null (or an empty list) when the packer did not encrypt any
        # image range on purpose -- a plain pack of an ET_DYN target skips the image unless
        # -enc-image-elf-pie is given. Anything that iterates this field must handle null, not just
        # its absence: the field IS present in that report.
        rep.info("E5", "report declares no encrypted range (imgSections=%r): there is no relocation "
                       "bookkeeping to cross-check on this product" % (secs,))
        return
    found = 0
    where = []
    for s in secs:
        lo = pref + int(s["rva"])
        hi = lo + int(s["size"])
        n = sum(1 for off, ty, _a in rel if ty == kinds and lo <= off < hi)
        if n:
            found += n
            where.append("0x%X:%d" % (int(s["rva"]), n))
    recorded = int(report.get("imgRelocCount") or 0)
    if found != recorded:
        rep.fail("E5", "report.imgRelocCount=%d but the product holds %d RELATIVE reloc(s) inside the "
                       "declared encrypted ranges (%s); a missing record makes the runtime applier "
                       "skip a slot ld.so already wrote" % (recorded, found, ",".join(where) or "-"))
    if found > 0 and not int(report.get("imgRelocTableRVA") or 0):
        rep.fail("E5", "%d in-range RELATIVE reloc(s) recorded but no apply table was emitted "
                       "(imgRelocTableRVA=0)" % found)
    if found == 0:
        rep.ok("E5", "bookkeeping: %d encrypted range(s), none holds a relative relocation" % len(secs))
    else:
        rep.ok("E5", "bookkeeping: %d in-range RELATIVE reloc(s) recorded (%s), apply table at RVA 0x%X"
               % (found, ",".join(where), int(report["imgRelocTableRVA"])))
    # aarch64: state exactly which half was verified HERE. A NOTE, not an assertion: the remaining gap
    # is architectural (#376/#377 keep read-only-data encryption off on aarch64), not a property of the
    # product, and the task contract forbids shape-dependent assertions. #597 closed the part that used
    # to make this gap dangerous: a range carrying PT_DYNAMIC is never encrypted, and a range that IS
    # encrypted may only contain R_*_RELATIVE relocations (cmd/vmpack/main.go guards 1/2).
    if elf.machine == 183:  # EM_AARCH64
        if found > 0:
            rep.info("E5", "aarch64: the recorded relocations above live in an executable range whose "
                           "tail carries PT_DYNAMIC; #597 guard 1 encrypted the part before it (never the "
                           "dynamic data itself), and tools/e2e_elf_image.sh asserts end-to-end that this "
                           "product answers exactly what native answers under qemu")
        else:
            rep.info("E5", "aarch64: no range carrying R_AARCH64_RELATIVE was encrypted on this product "
                           "(#376/#377 keep read-only-data encryption off, and #597 guard 1 leaves any "
                           "executable range that carries PT_DYNAMIC plaintext); what still needs a "
                           "runnable case here is therefore the *data*-section variant, not the applier "
                           "itself: vm_reloc_fix is one arch-independent function and the x86-64 "
                           "PIE_RELOCS + DT_TEXTREL e2e cases drive it end-to-end")


def run_checks(path, manifest, report, blob, quiet=False):
    elf = ELF(open(path, "rb").read())
    rep = Report()
    for fn, args in ((check_inventory, (elf, rep, manifest, report)),
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


def _expect_fail(rep, check, needle=None):
    """Require the given check to fail -- and, when a needle is given, that its OWN failure line
    carries it. Without the needle a mutation that trips several checks would prove the wrong one."""
    fails = [l for l in rep.lines if l.startswith("[FAIL]") and l.split()[1] == check]
    if not fails:
        return (False, "expected %s to fail, it passed" % check)
    # The needle may live in ANY of that check's failure lines: one mutation can legitimately trip
    # several assertions of the SAME check (e.g. an invalid payload prefix shape also puts the
    # segment's page range over the window). Requiring it in fails[0] would report "caught for the
    # wrong reason" while the planted reason IS present further down the list.
    if needle is not None and not any(needle in l for l in fails):
        return (False, "%s failed but not for the planted reason (want %r in %r)" % (check, needle, fails))
    return (True, fails[0])


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
        #
        # The mutation needs a non-top LOAD with a file image bigger than a page. Legal products can
        # genuinely have none: in tier (3) the payload segment IS the page-aligned top, and a minimal
        # original image has every other LOAD one page or smaller. That is "no input", not
        # "the calibration failed" -- so it is a deliberate SKIP, said out loud, exactly like the
        # window-shaped calibrations below (t2 found this line failing the whole --selftest, exit 1).
        # E4 ITSELF is not weakened: it still fails a real planted bss, and that is calibrated here
        # on every shape that has somewhere to plant it.
        planted = None
        for p in elf.loads:
            if p["filesz"] > 0x2000 and align_up(p["vaddr"] + p["filesz"], 4096) < elf.top_bss_edge():
                planted = p
                break
        if planted is None:
            print("[SKIP] CAL  E4: no plantable non-top LOAD on this product (every LOAD is either "
                  "one page or smaller, or IS the page-aligned top) -- there is nothing to inject a "
                  "bss into, so this calibration is deliberately skipped, NOT counted as a pass; "
                  "E4 itself still fails a real planted bss (see the shapes that have one)")
        else:
            def m4(d, p=planted):
                struct.pack_into("<Q", d, p["hdr"] + 32, p["filesz"] - 0x1000)  # shrink filesz
            results.append(("E4", *_expect_fail(run_checks(mutate(path, m4, tmp, "e4"), manifest, report, blob, True), "E4")))

        # E5 is a PIE-only check (an ET_EXEC image never moves, so there is nothing to cover).
        # Say that out loud instead of reporting a "not caught" calibration failure.
        if elf.etype != ET_DYN:
            print("[SKIP] CAL  E5-*: this product is ET_EXEC; E5 only applies to ET_DYN(PIE)")

        # M5b (E5, encrypted-range bookkeeping): the report claims one more in-range reloc than
        # the product actually holds. Report-side mutation on purpose: it is shape-independent
        # (works whether the product has 0 or many in-range relocs) and ONLY E5 reads that field.
        elif report.get("imgSections"):
            rep5 = dict(report)
            rep5["imgRelocCount"] = int(report.get("imgRelocCount") or 0) + 1
            results.append(("E5-bookkeeping", *_expect_fail(
                run_checks(path, manifest, rep5, blob, True), "E5", "imgRelocCount=")))
        else:
            # "No input" -- this product was packed WITHOUT image encryption (that is exactly why
            # report.imgSections is absent), so there is no encrypted range whose relocation
            # bookkeeping could be cross-checked. Reporting a bare OK would be the fake-green this
            # file exists to avoid, so it is recorded as a deliberate SKIP and SAID OUT LOUD in the
            # summary. The calibration does run on the products that really carry imgSections
            # (elf_enc_pie.json / elf_enc_pierel*.json in tools/wsl_linux.sh).
            results.append(("E5-bookkeeping", None,
                            "this product was packed without image encryption (report has no "
                            "imgSections): no encrypted range exists to cross-check"))

        # M6 (E5, payload absolute-VA coverage): plant a preferred-base VA inside the payload
        # segment where no RELATIVE entry covers it. E3 also trips on this byte (the payload no
        # longer matches the blob), so the calibration additionally requires E5''s own failure
        # line to name the planted address -- otherwise E3 would be doing the work.
        pref = elf.image_base
        # Only two things can make this calibration a no-op, and BOTH are about E5 itself, not about
        # the report's encrypted ranges:
        #   * ET_EXEC -- check_relocs() returns before any assertion, so there is no E5 line to trip;
        #   * preferred base 0 -- E5(a) cannot tell an RVA from a VA, so the planted VA proves nothing.
        # NOTE: do NOT add a guard for "report has no imgSections" here. E5's (a) payload-VA scan runs
        # BEFORE its (b) bookkeeping half returns early, so a plain-pack PIE product still has that
        # input -- measured: planting a VA in one makes E5 fail with "1 of 1 payload absolute VA(s)
        # have no RELATIVE relocation". An imgSections guard was added for one round and withdrawn as
        # over-skipping (t3/F1).
        if elf.etype != ET_DYN:
            print("[SKIP] CAL  E5-payload: this product is ET_EXEC, so E5 does not run at all -- "
                  "there is no VA-coverage assertion for the planted VA to trip; deliberate SKIP, "
                  "NOT counted as a pass")
        elif pref == 0:
            print("[SKIP] CAL  E5-payload: preferred base is 0, RVA and VA cannot be told apart")
        else:
            planted = None
            # Scan the WHOLE payload (report.sectionSize), not just the payload LOAD's p_filesz:
            # after the M5 split the first segment is only the RX prefix, so a p_filesz-bounded scan
            # silently skips the window and the tail (E5(a) scans the same full range for the same
            # reason). NOTE: this block runs BEFORE the shape preamble below, so it must not use the
            # sec_size name defined there.
            full = int(report["sectionSize"])
            for off in range(0, full - 7, 8):
                raw = elf.read(pref + int(report["sectionRVA"]) + off, 8)
                if raw is None:
                    continue
                if pref <= struct.unpack("<Q", raw)[0] < elf.va_ceiling():
                    continue
                planted = (off, pref + 0x1000)
                break
            if planted is None:
                print("[SKIP] CAL  E5-payload: no free 8-byte slot in [0, sectionSize) (0x%X) to plant a "
                      "VA" % full)
            else:
                off, va = planted

                def m6(d, off=off, va=va):
                    struct.pack_into("<Q", d, pl["off"] + off, va)
                results.append(("E5-payload", *_expect_fail(
                    run_checks(mutate(path, m6, tmp, "e5"), manifest, report, blob, True), "E5",
                    "holding 0x%X" % va)))

        # M7 (E5, the payload's declared VA slot): make the payload's own image table claim a
        # preferred base. Report-independent -- it is a plain field inside the product's payload table
        # (report.imgTableRVA + 0), and only E5(a2) reads it. E3 also trips (the payload no longer
        # matches the blob), so the calibration additionally requires E5's OWN line to name the value.
        img_tbl = int(report.get("imgTableRVA") or 0)
        if elf.etype != ET_DYN or img_tbl == 0:
            print("[SKIP] CAL  E5-imgtable: this product has no image table (or is not ET_DYN)")
        else:
            t_off = elf.va_to_off(elf.image_base + img_tbl)
            # Plant a base that is deliberately OUTSIDE the plausible-VA window: E5(a) must stay
            # silent so the calibration can only be caught by E5(a2)'s own line. (Planting the link
            # base would make both halves fail and the needle would prove the wrong one -- that is
            # exactly the mistake the first version of this calibration made on the Go PIE, whose
            # image base 0x400000 lies inside its own VA window.)
            planted_slot = 0x7F0000000000

            def m7(d, off=t_off, va=planted_slot):
                struct.pack_into("<Q", d, off, va)
            results.append(("E5-imgtable", *_expect_fail(
                run_checks(mutate(path, m7, tmp, "e5t"), manifest, report, blob, True), "E5",
                "wantBase=0x%X" % planted_slot)))

        # E2's legal shapes decide which calibrations are possible. Resolve the two payload
        # pieces of the SPLIT shape once, shape-independently; on the tier-(3) fallback
        # there is no window segment at all and the window-shaped calibrations SKIP loudly
        # (they would have no input, and faking a red on a legal product is worse than a SKIP).
        sec_va = elf.image_base + int(report["sectionRVA"])
        sec_size = int(report["sectionSize"])
        bss_off, bss_size = int(manifest["bssOff"]), int(manifest["bssSize"])
        win_va = sec_va + bss_off
        win_end = win_va + bss_size          # 窗口末尾（= 尾部起点）
        tail_size = sec_size - bss_off - bss_size
        pl_hdr = pl["hdr"]

        def phdr(va):
            for q in elf.loads:
                if q["vaddr"] == va:
                    return q
            return None

        # A segment is identified by (vaddr, write bit) -- NOT by vaddr alone: after a calibration
        # moves the window's p_vaddr onto the payload base, a vaddr-only lookup would silently return
        # the payload segment and every later mutation would be applied to the wrong program header
        # (that happened; the calibration then "failed" for a reason nobody planted).
        win = None
        if bss_size > 0:
            for q in elf.loads:
                if q["vaddr"] == win_va and (q["flags"] & PF_W):
                    win = q
                    break
        pl_is_rwx_split = win is None and (pl["flags"] & PF_W) and bss_size > 0

        # M8 (E2 tiers (1)/(2)): delete the RW window segment. The window is then neither mapped by
        # its own segment nor inside a writable one, so E2 must catch it.
        if win is None:
            print("[SKIP] CAL  E2-window: this product has no separate RW window segment (the injector "
                  "took the whole-payload W+X fallback, tier (3): the whole payload is writable, so the "
                  "window-removal mutation has no input -- the SKIP is deliberate, not a pass)")
        else:
            def m8(d, ho=win["hdr"]):
                struct.pack_into("<I", d, ho, 0)  # p_type = PT_NULL
            results.append(("E2-window", *_expect_fail(
                run_checks(mutate(path, m8, tmp, "e2w"), manifest, report, blob, True), "E2")))

        # M9 (E2 tier (3)): only meaningful on a product that really uses tier (3). Declare a bigger
        # writable window than the payload LOAD's file image carries; E2 must catch it with one of its
        # own window lines.
        if win is not None or bss_size <= 0:
            print("[SKIP] CAL  E2-filebacked: this product does not use the whole-payload W+X shape "
                  "(tier (3)), so there is nothing to over-extend")
        else:
            man9 = dict(manifest)
            man9["bssSize"] = bss_size + 0x2000
            results.append(("E2-filebacked", *_expect_fail(
                run_checks(path, man9, report, blob, True), "E2", "writable window")))

        # M10 (THE M5 INVARIANT, both the direct E1 test and E2's own): grow the payload prefix's
        # p_memsz over the writable window while leaving p_filesz alone. That is EXACTLY the defect
        # geometry -- an RX segment whose mapped pages cover the window's page -- so E1's direct
        # assertion must fire with its own wording (STATUS #597), and E2's independent invariant must
        # fire on the same product. Both are required: if either check is ever relaxed into a no-op
        # this calibration goes red instead of silently passing.
        if win is None or pl["filesz"] > sec_size:
            print("[SKIP] CAL  E1/E2-M5-window: this product has no separate window segment whose page "
                  "the payload prefix could be grown over (the whole payload is already one writable "
                  "segment, so growing it adds nothing) -- the SKIP is deliberate, not a pass")
        else:
            def m10(d, ho=pl["hdr"]):
                struct.pack_into("<Q", d, ho + 40, sec_size)  # p_memsz = whole payload (>= window)
            mut = mutate(path, m10, tmp, "e2m5")
            results.append(("E1-M5-window-covers", *_expect_fail(
                run_checks(mut, manifest, report, blob, True), "E1",
                "covers the interpreter's writable window")))
            # E2's own reaction to the SAME mutation is its SHAPE check (the prefix no longer stops at
            # bssOff), not its M5 invariant: check_payload() fails on the shape and returns before the
            # invariant loop. So this calibration must name that shape check -- calling it
            # "E2-M5-window-covers" was misnaming (t3/F3). E2's invariant gets its own mutation below.
            results.append(("E2-prefix-not-stopped-at-window", *_expect_fail(
                run_checks(mut, manifest, report, blob, True), "E2",
                "expected filesz == memsz == bssOff")))

        # M10b (E2's OWN M5 INVARIANT, with E2's own wording): grow a NON-payload, NON-writable LOAD's
        # vaddr range over the writable window's page, leaving the payload shape untouched. That is the
        # case the invariant exists for: the payload still passes every shape check, so E2 reaches the
        # invariant and fails with "intersects the writable window" (its own sentence). This is the
        # calibration that proves E2's invariant -- as opposed to E1's -- still has teeth.
        # The SKIP text must name the REAL blocker, so each candidate is filtered through the three
        # criteria in order and the surviving count is reported per criterion (t7/G3: the old text
        # blamed "growing it runs past EOF" unconditionally, but on an aarch64 product there is usually
        # no non-payload, non-writable LOAD at all -- nothing to plant on, EOF never enters into it).
        victim = None
        n_alive = 0   # PT_LOADs that are neither the payload itself, nor writable, nor empty
        n_below = 0   # ...and whose vaddr range still ends at/below the window start
        n_fits = 0    # ...and growing them to the window's end stays inside the file
        for q in elf.loads:
            if q["vaddr"] == sec_va or (q["flags"] & PF_W) or q["memsz"] == 0:
                continue                      # criterion (a) fails: it IS the payload / is writable / empty
            n_alive += 1
            if q["vaddr"] + q["memsz"] > win_va:
                continue                      # criterion (b): it already reaches the window's start
            n_below += 1
            if q["off"] + (win_end - q["vaddr"]) > len(elf.data):
                continue                      # criterion (c): growing it would run past EOF
            n_fits += 1
            victim = q
            break
        if victim is None:
            print("[SKIP] CAL  E2-M5-window-covers: no PT_LOAD can host this mutation, so there is "
                  "nothing to plant the defect on (deliberate SKIP, NOT counted as a pass). Criteria, "
                  "applied in order over %d PT_LOAD(s):" % len(elf.loads))
            print("       (a) NOT the payload itself and NOT writable and memsz>0: %d LOAD(s) left"
                  % n_alive)
            print("       (b) ...and its vaddr range still ends at/below the window start 0x%X: %d left"
                  % (win_va, n_below))
            print("       (c) ...and growing it to the window's end (0x%X) stays inside the %d-byte file: "
                  "%d left" % (win_end, len(elf.data), n_fits))
        else:
            need = win_end - victim["vaddr"]

            def m10b(d, ho=victim["hdr"], n=need):
                struct.pack_into("<Q", d, ho + 32, n)   # p_filesz = reach the window's end
                struct.pack_into("<Q", d, ho + 40, n)   # p_memsz
            results.append(("E2-M5-window-covers", *_expect_fail(
                run_checks(mutate(path, m10b, tmp, "e2m5i"), manifest, report, blob, True), "E2",
                "intersects the writable window")))

        # M11 (E1, the M5 defect shape itself): put the window segment's program header back to the
        # OLD overlaying shape -- window start moved into the payload base and its size grown so it
        # swallows the window, i.e. an RW segment fully inside the earlier RX payload segment. That
        # shape must be rejected by E1 (it is the measured cause of the SIGSEGV).
        if win is None or pl["filesz"] > bss_off + 0x1000:
            print("[SKIP] CAL  E1-M5-overlap: no window segment to re-shape")
        else:
            def m11(d, ho=win["hdr"], base=sec_va, off=pl["off"]):
                # Rebuild this program header as the OLD overlaying segment:
                #   vaddr = the payload base, filesz == memsz == the payload size, flags = R|W.
                # It is then an RW segment fully inside the earlier RX payload segment -- the exact
                # shape whose page glibc re-protects read-only (STATUS #597).
                struct.pack_into("<I", d, ho + 4, PF_R | PF_W)   # p_flags
                struct.pack_into("<Q", d, ho + 8, off)           # p_offset = the payload's own image
                struct.pack_into("<Q", d, ho + 16, base)         # p_vaddr
                struct.pack_into("<Q", d, ho + 24, base)         # p_paddr
                struct.pack_into("<Q", d, ho + 32, sec_size)     # p_filesz = whole payload
                struct.pack_into("<Q", d, ho + 40, sec_size)     # p_memsz = whole payload
            # The needle is the shared rejection wording, not one specific message: this shape can
            # legitimately be reported either by the direct M5 assertion above or by the pair loop's
            # "not an allowed shape" line, depending on whether the RX segment's page range reaches
            # the window's page. What must hold is that E1 REJECTS the shape at all.
            results.append(("E1-M5-overlap", *_expect_fail(
                run_checks(mutate(path, m11, tmp, "e1m5"), manifest, report, blob, True), "E1",
                "is not an allowed shape")))

        # M12 (E2, the "two-segment merge" defect): merge the R+X tail INTO the writable window
        # (grow the window's filesz/memsz over the tail and make it RW only). That is the two-segment
        # version that made BOTH the normal and the textrel fixture die -- E2 must reject it.
        if win is None or tail_size <= 0:
            print("[SKIP] CAL  E2-tail-merged: this product has no separate window+tail split")
        else:
            def m12(d, ho=win["hdr"], sz=bss_size + tail_size):
                struct.pack_into("<I", d, ho + 4, PF_R | PF_W)  # drop PF_X
                struct.pack_into("<Q", d, ho + 32, sz)          # p_filesz = window + tail
                struct.pack_into("<Q", d, ho + 40, sz)          # p_memsz
            results.append(("E2-tail-merged", *_expect_fail(
                run_checks(mutate(path, m12, tmp, "e2tm"), manifest, report, blob, True), "E2",
                "not executable")))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    bad = 0
    for entry in results:
        name, good = entry[0], entry[1]
        detail = entry[2] if len(entry) > 2 else ""
        if good is None:
            print("[SKIP] CAL  %s: %s (deliberate -- not counted as a pass)" % (name, detail))
        elif good:
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
