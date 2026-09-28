#!/usr/bin/env python3
"""check_symmap.py -- layout-consistency gate for a PACKED PE product.

Every check below is derived from the PRODUCT FILE (its own headers and bytes) plus the
SAME build's blob manifest and pack report. Nothing is re-read from vmpack's bookkeeping
in a way that would make the check vacuous: the product is the object under test.

  C1  SizeOfImage / section inventory
        header math is self-consistent, every section lies inside SizeOfImage, the entry
        point is inside an executable section.
  C2  payload layout + symbol mapping
        the packer lays the blob out as  product RVA = sectionRVA + blobOffset  in three
        appended sections chained by SectionAlignment; the manifest's blob segments and
        the report's RVAs must agree with the section table the product actually has.
  C3  payload byte identity
        product bytes at (sectionRVA + o) == blob byte o for every o in [0, blobSize).
  C4  relocation coverage (both directions)
        while DYNAMIC_BASE is set: every preferred-base absolute VA (8-byte aligned u64 in
        [ImageBase, ImageBase+SizeOfImage)) stored anywhere in the payload must have a DIR64
        entry in .reloc -- the "an absolute VA was written but never registered" defect class
        (STATUS #507/#508/#520) that makes a product crash only when ASLR actually moves it --
        and every DIR64 entry inside the payload must cover a slot that really holds such a VA.
        A target that legitimately has none (crt without a TLS directory => nothing to write)
        is reported as INFO, but only after checking that the report did not emit a TLS copy.

Why this gate exists: the win/arm64 investigation (STATUS #580) reduced the remaining
failure to "the product's section mapping and the blob's internal address derivation
disagree -- whichever address is touched first is where it crashes". These are exactly the
invariants that must hold for the interpreter's own pointer arithmetic to be valid, and
none of them were machine-checked before. They are platform-general: they apply to every
PE target, not just arm64.

A probe that cannot fail is not a probe, so --selftest mutates copies of the given product
and requires each check to catch its own mutation.

Usage:
  python tools/check_symmap.py --packed build/symmap_vmp.exe --manifest build/vm_interp.json \
      --blob build/vm_interp.bin --report build/symmap_vmp.json --require-aslr --selftest
"""
import argparse
import json
import shutil
import struct
import sys
import tempfile
import os

ASCII = True  # all output must stay ASCII (Windows runner python stdout is cp1252)


def u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def u64(d, o):
    return struct.unpack_from("<Q", d, o)[0]


def align_up(v, a):
    if a <= 1:
        return v
    return (v + a - 1) // a * a


class PE:
    """Minimal PE reader: exactly the fields the checks below need."""

    def __init__(self, data):
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("not a PE (no MZ)")
        self.lfanew = u32(data, 0x3C)
        if data[self.lfanew:self.lfanew + 4] != b"PE\x00\x00":
            raise ValueError("not a PE (no PE signature)")
        self.nsec = u16(data, self.lfanew + 6)
        optsize = u16(data, self.lfanew + 20)
        self.chars = u16(data, self.lfanew + 22)
        self.opt = self.lfanew + 24
        self.sectalign = u32(data, self.opt + 32)
        self.filealign = u32(data, self.opt + 36)
        self.sizeofimage = u32(data, self.opt + 56)
        self.entry = u32(data, self.opt + 16)
        magic = u16(data, self.opt)
        self.pe32plus = magic == 0x20B
        if self.pe32plus:
            self.imagebase = u64(data, self.opt + 24)
            self.ddoff = self.opt + 112
        else:
            self.imagebase = u32(data, self.opt + 28)
            self.ddoff = self.opt + 96
        if self.pe32plus:
            nrva = u32(data, self.opt + 108)
        else:
            nrva = u32(data, self.opt + 92)
        self.dllchar = u16(data, self.opt + 70)
        self.reloc_rva = 0
        self.reloc_size = 0
        if nrva > 5:
            self.reloc_rva = u32(data, self.ddoff + 5 * 8)
            self.reloc_size = u32(data, self.ddoff + 5 * 8 + 4)
        self.secbase = self.opt + optsize
        self.sections = []
        for i in range(self.nsec):
            o = self.secbase + i * 40
            if o + 40 > len(data):
                raise ValueError("section table runs past EOF")
            name = data[o:o + 8].rstrip(b"\x00").decode("latin1")
            self.sections.append({
                "idx": i,
                "hdr": o,
                "name": name,
                "vsize": u32(data, o + 8),
                "va": u32(data, o + 12),
                "rawsize": u32(data, o + 16),
                "rawoff": u32(data, o + 20),
                "chars": u32(data, o + 36),
            })

    # --- flags ---
    @property
    def relocs_stripped(self):
        return bool(self.chars & 0x0001)

    @property
    def dynamic_base(self):
        return bool(self.dllchar & 0x0040)

    def by_name(self, name):
        for s in self.sections:
            if s["name"] == name:
                return s
        return None

    def by_va(self, rva):
        for s in self.sections:
            if s["va"] == rva:
                return s
        return None

    def va_to_off(self, rva):
        """File offset for an RVA, or None when the RVA is not file-backed."""
        for s in self.sections:
            if s["va"] <= rva < s["va"] + s["rawsize"] and rva - s["va"] < s["vsize"]:
                off = s["rawoff"] + (rva - s["va"])
                if 0 <= off < len(self.data):
                    return off
        return None

    def read(self, rva, n):
        off = self.va_to_off(rva)
        if off is None or off + n > len(self.data):
            return None
        return self.data[off:off + n]

    def reloc_entries(self):
        """[(rva, type)] for every non-ABSOLUTE entry in the .reloc directory."""
        out = []
        if not self.reloc_rva or not self.reloc_size:
            return out
        off = self.va_to_off(self.reloc_rva)
        if off is None:
            return out
        end = off + self.reloc_size
        if end > len(self.data):
            end = len(self.data)
        p = off
        while p + 8 <= end:
            page = u32(self.data, p)
            blk = u32(self.data, p + 4)
            if blk < 8 or p + blk > end:
                break
            for q in range(p + 8, p + blk - 1, 2):
                v = u16(self.data, q)
                t = v >> 12
                if t == 0:
                    continue
                out.append((page + (v & 0x0FFF), t))
            p += blk
        return out

    def reloc_covered_rvas(self, want_types=(10,)):
        cov = set()
        for rva, t in self.reloc_entries():
            if t in want_types:
                width = 8 if t == 10 else 4
                for k in range(width):
                    cov.add(rva + k)
        return cov


class Fail(Exception):
    pass


class Report:
    """Collects [OK]/[FAIL] lines; a check raises Fail on the first broken property."""

    def __init__(self):
        self.lines = []
        self.failed = 0

    def ok(self, check, msg):
        self.lines.append("[OK  ] %-4s %s" % (check, msg))

    def info(self, check, msg):
        self.lines.append("[INFO] %-4s %s" % (check, msg))

    def fail(self, check, msg):
        self.lines.append("[FAIL] %-4s %s" % (check, msg))
        self.failed += 1
        raise Fail(msg)


# --------------------------------------------------------------------------- C1
def check_size_of_image(pe, rep):
    sa, fa = pe.sectalign, pe.filealign
    if sa == 0 or (sa & (sa - 1)) != 0:
        rep.fail("C1", "SectionAlignment 0x%X is not a power of two" % sa)
    if fa == 0 or (fa & (fa - 1)) != 0:
        rep.fail("C1", "FileAlignment 0x%X is not a power of two" % fa)
    if fa > sa:
        rep.fail("C1", "FileAlignment 0x%X > SectionAlignment 0x%X" % (fa, sa))
    if pe.nsec == 0:
        rep.fail("C1", "no sections")
    # sections must be ordered by VA and must not overlap
    prev = None
    for s in pe.sections:
        if s["va"] % sa != 0:
            rep.fail("C1", "section %s VA 0x%X is not SectionAlignment-aligned" % (s["name"], s["va"]))
        if prev is not None:
            if s["va"] < prev["va"]:
                rep.fail("C1", "section table is not ordered by VA (%s after %s)" % (s["name"], prev["name"]))
            if s["va"] < prev["va"] + align_up(prev["vsize"], sa):
                rep.fail("C1", "sections %s and %s overlap in VA space" % (prev["name"], s["name"]))
        if s["va"] + align_up(s["vsize"], sa) > pe.sizeofimage:
            rep.fail("C1", "section %s ends (0x%X) beyond SizeOfImage 0x%X"
                     % (s["name"], s["va"] + align_up(s["vsize"], sa), pe.sizeofimage))
        if s["rawoff"] + s["rawsize"] > len(pe.data):
            rep.fail("C1", "section %s raw data ends (0x%X) beyond EOF (0x%X)"
                     % (s["name"], s["rawoff"] + s["rawsize"], len(pe.data)))
        if s["rawsize"] and s["rawoff"] % fa != 0:
            rep.fail("C1", "section %s PointerToRawData 0x%X is not FileAlignment-aligned" % (s["name"], s["rawoff"]))
        prev = s
    # SizeOfImage must be exactly what the section inventory implies
    last = pe.sections[-1]
    want = last["va"] + align_up(last["vsize"], sa)
    if want != pe.sizeofimage:
        rep.fail("C1", "SizeOfImage 0x%X != last section end 0x%X" % (pe.sizeofimage, want))
    # the entry point must live in an executable section
    ent = pe.by_va(pe.entry) or None
    esec = None
    for s in pe.sections:
        if s["va"] <= pe.entry < s["va"] + max(s["vsize"], 1):
            esec = s
            break
    if esec is None:
        rep.fail("C1", "entry point RVA 0x%X is in no section" % pe.entry)
    if not (esec["chars"] & 0x20000000):
        rep.fail("C1", "entry point section %s is not MEM_EXECUTE" % esec["name"])
    rep.ok("C1", "SizeOfImage 0x%X / %d sections consistent, entry RVA 0x%X in executable %s"
           % (pe.sizeofimage, pe.nsec, pe.entry, esec["name"]))


# --------------------------------------------------------------------------- C2
def check_mapping(pe, manifest, report, rep):
    names = report.get("sectionNames") or []
    if len(names) != 3:
        rep.fail("C2", "report has %d payload section name(s), expected 3" % len(names))
    secs = []
    for n in names:
        s = pe.by_name(n)
        if s is None:
            rep.fail("C2", "payload section %s from the report is not in the product's section table" % n)
        secs.append(s)

    bss_off = int(manifest["bssOff"])
    bss_size = int(manifest["bssSize"])
    blob_size = int(manifest["blobSize"])
    sec_rva = int(report["sectionRVA"])
    sec_size = int(report["sectionSize"])

    if secs[0]["va"] != sec_rva:
        rep.fail("C2", "payload base VA 0x%X != report sectionRVA 0x%X" % (secs[0]["va"], sec_rva))
    if secs[0]["vsize"] != bss_off:
        rep.fail("C2", "payload segment 0 size 0x%X != manifest bssOff 0x%X" % (secs[0]["vsize"], bss_off))
    if sec_size != bss_off:
        rep.fail("C2", "report sectionSize 0x%X != manifest bssOff 0x%X" % (sec_size, bss_off))

    # The manifest's own segment table must be ordered, non-overlapping and inside the blob.
    # It does NOT tile [0, blobSize) exactly: the merger aligns .bss (and may pad the tail),
    # so gaps are expected -- but .bss MUST start exactly at bssOff, and the code segment
    # MUST start at 0.
    segs = manifest.get("sections") or []
    if not segs:
        rep.fail("C2", "manifest has no sections")
    if int(segs[0]["blobOff"]) != 0:
        rep.fail("C2", "manifest code segment %s starts at 0x%X, expected 0" % (segs[0]["name"], segs[0]["blobOff"]))
    prev_end = None
    for s in segs:
        off, size = int(s["blobOff"]), int(s["size"])
        if off < 0 or size < 0 or off + size > blob_size:
            rep.fail("C2", "manifest segment %s [0x%X,+0x%X) is outside the blob (0x%X)" % (s["name"], off, size, blob_size))
        if prev_end is not None and off < prev_end:
            rep.fail("C2", "manifest segments overlap: %s starts at 0x%X, previous ended at 0x%X" % (s["name"], off, prev_end))
        prev_end = off + size
    if bss_off + bss_size != blob_size:
        rep.fail("C2", "manifest bssOff+bssSize = 0x%X != blobSize 0x%X" % (bss_off + bss_size, blob_size))
    named = {s["name"]: s for s in segs}
    if ".bss" in named:
        if int(named[".bss"]["blobOff"]) != bss_off:
            rep.fail("C2", "manifest .bss segment starts at 0x%X, expected bssOff 0x%X"
                     % (named[".bss"]["blobOff"], bss_off))
        # the RW window in the product is the aligned-up bss, so >= the segment size
        if int(named[".bss"]["size"]) > bss_size:
            rep.fail("C2", "manifest .bss segment (0x%X) is larger than bssSize 0x%X"
                     % (named[".bss"]["size"], bss_size))

    sa = pe.sectalign
    want1 = align_up(secs[0]["va"] + secs[0]["vsize"], sa)
    if secs[1]["va"] != want1:
        rep.fail("C2", "payload segment 1 VA 0x%X != expected chain value 0x%X" % (secs[1]["va"], want1))
    if secs[1]["vsize"] != bss_size:
        rep.fail("C2", "payload segment 1 size 0x%X != manifest bssSize 0x%X" % (secs[1]["vsize"], bss_size))
    if bss_size == 0:
        rep.fail("C2", "manifest bssSize is 0: the interpreter's writable segment is missing")
    want2 = align_up(secs[1]["va"] + secs[1]["vsize"], sa)
    if secs[2]["va"] != want2:
        rep.fail("C2", "payload segment 2 VA 0x%X != expected chain value 0x%X" % (secs[2]["va"], want2))
    if secs[0]["vsize"] + secs[1]["vsize"] != blob_size:
        rep.fail("C2", "segments 0+1 cover 0x%X bytes but blobSize is 0x%X"
                 % (secs[0]["vsize"] + secs[1]["vsize"], blob_size))
    # segment roles the packer promises (internal/inject/inject.go): 0 = R+X code/data,
    # 1 = R+W (.bss window), 2 = R+X descriptors/thunks/bytecode.
    want_chars = ((secs[0], 0x20000000 | 0x40000000, "MEM_EXECUTE|MEM_READ"),
                  (secs[1], 0x80000000 | 0x40000000, "MEM_WRITE|MEM_READ"),
                  (secs[2], 0x20000000 | 0x40000000, "MEM_EXECUTE|MEM_READ"))
    for s, mask, what in want_chars:
        if (s["chars"] & mask) != mask:
            rep.fail("C2", "payload section %s lacks %s (chars=0x%08X)" % (s["name"], what, s["chars"]))

    payload_start = secs[0]["va"]
    payload_end = secs[2]["va"] + align_up(secs[2]["vsize"], sa)

    # every RVA the packer reports must point INTO the payload region it describes
    def in_payload(rva, what):
        if not (payload_start <= rva < payload_end):
            rep.fail("C2", "%s RVA 0x%X is outside the payload region [0x%X,0x%X)"
                     % (what, rva, payload_start, payload_end))

    for key in ("sectionRVA", "stubEntryRVA", "imgTableRVA", "imgTlsArrayRVA", "tlsDirRVA"):
        if int(report.get(key) or 0):
            in_payload(int(report[key]), key)
    for pl in report.get("placements") or []:
        for key in ("descRVA", "thunkRVA", "codeRVA"):
            in_payload(int(pl[key]), "%s.%s" % (pl.get("name", "?"), key))
    if int(report.get("imgTableLen") or 0) and int(report["imgTableRVA"]) + int(report["imgTableLen"]) > payload_end:
        rep.fail("C2", "image table [0x%X,+0x%X) runs past the payload end 0x%X"
                 % (report["imgTableRVA"], report["imgTableLen"], payload_end))

    syms = manifest.get("symbols") or {}
    if not syms:
        rep.fail("C2", "manifest has no symbols")
    bad = [k for k, v in syms.items() if not (0 <= int(v) < blob_size)]
    if bad:
        rep.fail("C2", "%d manifest symbol(s) fall outside [0,blobSize): %s" % (len(bad), ", ".join(sorted(bad)[:5])))
    rep.ok("C2", "payload base 0x%X, blob range 0x%X, 3 segments chained, %d symbol(s) inside the blob"
           % (payload_start, blob_size, len(syms)))


# --------------------------------------------------------------------------- C3
def check_payload_identity(pe, manifest, report, blob, rep):
    sec_rva = int(report["sectionRVA"])
    blob_size = int(manifest["blobSize"])
    if len(blob) < blob_size:
        rep.fail("C3", "blob file is 0x%X bytes, manifest says blobSize 0x%X" % (len(blob), blob_size))
    diffs = []
    for o in range(blob_size):
        got = pe.read(sec_rva + o, 1)
        if got is None:
            rep.fail("C3", "blob offset 0x%X (RVA 0x%X) is not file-backed in the product" % (o, sec_rva + o))
        if got[0] != blob[o]:
            diffs.append(o)
            if len(diffs) <= 8:
                rep.lines.append("[----] C3    blob 0x%06X: product 0x%02X != blob 0x%02X"
                                 % (o, got[0], blob[o]))
    if diffs:
        rep.fail("C3", "%d of %d blob byte(s) differ inside the product payload (first at blob offset 0x%X)"
                 % (len(diffs), blob_size, diffs[0]))
    rep.ok("C3", "all 0x%X payload byte(s) match the blob byte for byte" % blob_size)


# --------------------------------------------------------------------------- C4
def check_reloc_coverage(pe, report, rep, require_aslr):
    names = report.get("sectionNames") or []
    secs = [pe.by_name(n) for n in names]
    secs = [s for s in secs if s is not None]
    if not secs:
        rep.fail("C4", "cannot locate the payload sections")
    lo = min(s["va"] for s in secs)
    hi = max(s["va"] + s["vsize"] for s in secs)

    cov = pe.reloc_covered_rvas((10,))
    # The image-decryption table (payload.go) deliberately starts with the PREFERRED BASE as a
    # raw u64: the runtime computes  delta = actualBase - wantBase  from it. That is a compare
    # constant, not a pointer, so it must NOT carry a relocation (relocating it would corrupt
    # the delta). It is the only value allowed to equal exactly ImageBase outside .reloc's cover.
    img_table_rva = int(report.get("imgTableRVA") or 0)
    base_consts = []
    cands = []
    for s in secs:
        base = s["va"]
        for rel in range(0, s["vsize"] - 7, 8):
            raw = pe.read(base + rel, 8)
            if raw is None:
                continue
            v = struct.unpack("<Q", raw)[0]
            if pe.imagebase <= v < pe.imagebase + pe.sizeofimage:
                if v == pe.imagebase and base + rel == img_table_rva:
                    base_consts.append(base + rel)
                    continue
                cands.append((base + rel, v))

    if not pe.dynamic_base:
        if require_aslr:
            rep.fail("C4", "DYNAMIC_BASE is clear: the product is not ASLR-relocatable (--require-aslr)")
        rep.info("C4", "DYNAMIC_BASE clear: %d absolute VA(s) in the payload require the preferred base 0x%X"
                 % (len(cands), pe.imagebase))
        return
    if pe.relocs_stripped:
        rep.fail("C4", "DYNAMIC_BASE is set but IMAGE_FILE_RELOCS_STRIPPED is also set")
    if not pe.reloc_rva or not pe.reloc_size:
        rep.fail("C4", "DYNAMIC_BASE is set but the product has no BASERELOC directory")
    # Both directions, so this stays meaningful on a target that happens to have no payload-level
    # absolute VAs at all (e.g. a crt that emits no TLS directory -- the CI runner's gcc does not):
    #   (a) every absolute VA stored in the payload must be covered by a DIR64 entry, else the
    #       loader will not fix it up and the product breaks as soon as ASLR moves it;
    #   (b) every DIR64 entry inside the payload must cover a slot that really holds an in-image VA,
    #       else the loader adds delta to something that is not an address.
    payload_relocs = [r for (r, t) in pe.reloc_entries() if t == 10 and lo <= r < hi]
    uncovered = [(r, v) for (r, v) in cands if r not in cov]
    for r, v in uncovered[:8]:
        rep.lines.append("[----] C4    RVA 0x%X holds 0x%X but no DIR64 entry covers it" % (r, v))
    if uncovered:
        rep.fail("C4", "%d of %d absolute VA(s) in the payload have no DIR64 relocation (the loader will not fix them)"
                 % (len(uncovered), len(cands)))
    cand_rvas = set(r for (r, _) in cands)
    bogus = [r for r in payload_relocs if r not in cand_rvas]
    for r in bogus[:8]:
        rep.lines.append("[----] C4    DIR64 entry at RVA 0x%X covers a slot that holds no in-image VA" % r)
    if bogus:
        rep.fail("C4", "%d of %d payload DIR64 entry(ies) cover a slot that is not an absolute VA"
                 % (len(bogus), len(payload_relocs)))
    if not cands and not payload_relocs:
        # Empty is legitimate ONLY when the packer had nothing to write. If the report says it
        # emitted a TLS directory copy, that copy holds VAs and they must have been registered.
        tls_dir = int(report.get("tlsDirRVA") or 0)
        tls_arr = int(report.get("imgTlsArrayRVA") or 0)
        if tls_dir or tls_arr:
            rep.fail("C4", "the report emitted a TLS copy (tlsDirRVA=0x%X imgTlsArrayRVA=0x%X) but the payload holds "
                           "no absolute VA and no DIR64 entry" % (tls_dir, tls_arr))
        rep.info("C4", "no payload absolute VA to relocate (imagebase=0x%X sizeofimage=0x%X, no TLS copy emitted): "
                       "nothing for the loader to fix" % (pe.imagebase, pe.sizeofimage))
        return
    rep.ok("C4", "%d payload absolute VA(s) all covered by DIR64 entries (%d payload entry(ies) of %d total, "
                 "%d base constant(s) exempt)" % (len(cands), len(payload_relocs), len(pe.reloc_entries()), len(base_consts)))


# --------------------------------------------------------------------------- driver
def run_checks(packed_path, manifest, report, blob, require_aslr, quiet=False):
    pe = PE(open(packed_path, "rb").read())
    rep = Report()
    try:
        check_size_of_image(pe, rep)
    except Fail:
        pass
    if manifest is not None and report is not None:
        try:
            check_mapping(pe, manifest, report, rep)
        except Fail:
            pass
    if manifest is not None and report is not None and blob is not None:
        try:
            check_payload_identity(pe, manifest, report, blob, rep)
        except Fail:
            pass
    if report is not None:
        try:
            check_reloc_coverage(pe, report, rep, require_aslr)
        except Fail:
            pass
    if not quiet:
        for line in rep.lines:
            print(line)
    return rep


def failed_names(rep):
    return sorted({l.split()[1] for l in rep.lines if l.startswith("[FAIL]")})


def mutate_copy(src, patch_fn, tmpdir, tag):
    data = bytearray(open(src, "rb").read())
    patch_fn(data)
    p = os.path.join(tmpdir, "mut_%s.exe" % tag)
    with open(p, "wb") as f:
        f.write(data)
    return p


def selftest(packed, manifest, report, blob, require_aslr):
    """Prove each check can fail: mutate a copy and require the target check to trip."""
    tmp = tempfile.mkdtemp(prefix="symmap_cal_")
    results = []
    try:
        # M0: the pristine product must pass everything
        rep = run_checks(packed, manifest, report, blob, require_aslr, quiet=True)
        results.append(("pristine", rep.failed == 0, failed_names(rep)))

        raw = open(packed, "rb").read()
        pe0 = PE(raw)

        # M1 (C1): SizeOfImage inflated by one section alignment
        sa = pe0.sectalign

        def m1(d):
            struct.pack_into("<I", d, pe0.opt + 56, pe0.sizeofimage + sa)
        results.append(("C1", *_expect_fail(run_checks(mutate_copy(packed, m1, tmp, "c1"), manifest, report, blob, require_aslr, True), "C1")))

        # M2 (C2): the report's payload base drifts from the section it names
        rep2 = dict(report)
        rep2["sectionRVA"] = int(report["sectionRVA"]) + 0x1000
        results.append(("C2", *_expect_fail(run_checks(packed, manifest, rep2, blob, require_aslr, True), "C2")))

        # M3 (C3): flip one byte inside the mapped blob range
        sec_rva = int(report["sectionRVA"])
        off = pe0.va_to_off(sec_rva + 0x40)

        def m3(d):
            d[off] ^= 0xFF
        results.append(("C3", *_expect_fail(run_checks(mutate_copy(packed, m3, tmp, "c3"), manifest, report, blob, require_aslr, True), "C3")))

        # M4 (C4, direction "every VA must be covered"): PLANT an absolute VA in a payload slot that
        # no DIR64 entry covers. Deliberately shape-independent: un-registering an existing entry is
        # impossible on a product whose payload never stores a VA at all (the CI runner's gcc target
        # has no TLS directory, so the packer writes none), and a calibration that cannot run is not
        # a calibration -- that is exactly how this gate went red on run 36383166041.
        names = report.get("sectionNames") or []
        secs = [pe0.by_name(n) for n in names]
        secs = [s for s in secs if s is not None]
        lo = min(s["va"] for s in secs)
        hi = max(s["va"] + s["vsize"] for s in secs)
        cov0 = pe0.reloc_covered_rvas((10,))
        img_table_rva = int(report.get("imgTableRVA") or 0)
        planted = None
        for s in secs:
            for rel in range(0, s["vsize"] - 7, 8):
                rva = s["va"] + rel
                if rva in cov0 or rva == img_table_rva:
                    continue
                if pe0.va_to_off(rva) is None:
                    continue
                planted = rva
                break
            if planted is not None:
                break
        if planted is None:
            results.append(("C4-plant", False, "no uncovered 8-aligned payload slot to plant a VA in"))
        else:
            poff = pe0.va_to_off(planted)
            # a VA that is inside the image but (a) not the exempt base constant and (b) not covered
            planted_val = pe0.imagebase + 0x1000

            def m4(d):
                struct.pack_into("<Q", d, poff, planted_val)
            results.append(("C4-plant", *_expect_fail(run_checks(mutate_copy(packed, m4, tmp, "c4"), manifest, report, blob, require_aslr, True), "C4")))

        # M5 (C4, the reverse direction): un-register one payload DIR64 entry, so the entry is gone
        # while the VA it covered remains. Needs an entry to exist; when the payload has none the
        # reverse predicate has no inputs at all, so skip LOUDLY instead of pretending to check.
        target = None
        for rva, t in pe0.reloc_entries():
            if t == 10 and lo <= rva < hi:
                target = rva
                break
        if target is None:
            print("[SKIP] CAL  C4-unreg: this product's payload has no DIR64 entry (nothing to un-register)")
        else:
            def m5(d):
                pe = PE(bytes(d))
                p = pe.va_to_off(pe.reloc_rva)
                end = p + pe.reloc_size
                q = p
                while q + 8 <= end:
                    blk = u32(bytes(d), q + 4)
                    for e in range(q + 8, q + blk - 1, 2):
                        v = u16(bytes(d), e)
                        if (v >> 12) != 0 and u32(bytes(d), q) + (v & 0x0FFF) == target:
                            struct.pack_into("<H", d, e, v & 0x0FFF)  # type -> ABSOLUTE
                            return
                    q += blk
            results.append(("C4-unreg", *_expect_fail(run_checks(mutate_copy(packed, m5, tmp, "c4"), manifest, report, blob, require_aslr, True), "C4")))
            # M6 (C4, reverse direction): blank a covered slot so a DIR64 entry now covers something
            # that is not an absolute VA any more
            slotoff = pe0.va_to_off(target)

            def m6(d):
                for k in range(8):
                    d[slotoff + k] = 0
            results.append(("C4-bogus", *_expect_fail(run_checks(mutate_copy(packed, m6, tmp, "c4b"), manifest, report, blob, require_aslr, True), "C4")))
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


def _expect_fail(rep, check):
    hit = check in failed_names(rep)
    return (hit, "" if hit else "expected %s to fail, it passed" % check)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--packed", required=True, help="the packed product under test")
    ap.add_argument("--manifest", help="blob manifest of the SAME build")
    ap.add_argument("--blob", help="blob of the SAME build (enables the byte-identity check)")
    ap.add_argument("--report", help="vmpack -report JSON of the SAME product")
    ap.add_argument("--require-aslr", action="store_true",
                    help="fail if DYNAMIC_BASE is clear (the production default keeps it set)")
    ap.add_argument("--selftest", action="store_true",
                    help="also mutate copies and require every check to catch its own mutation")
    a = ap.parse_args()

    manifest = json.load(open(a.manifest)) if a.manifest else None
    report = json.load(open(a.report)) if a.report else None
    blob = open(a.blob, "rb").read() if a.blob else None
    if (a.manifest is None) != (a.report is None):
        print("[FAIL] --manifest and --report must be given together (the mapping check needs both)")
        return 2

    try:
        rep = run_checks(a.packed, manifest, report, blob, a.require_aslr)
    except ValueError as e:
        print("[FAIL] cannot parse %s: %s" % (a.packed, e))
        return 1

    bad = rep.failed
    if a.selftest:
        if bad:
            print("[!] skipping calibration: the product already fails")
        else:
            bad += selftest(a.packed, manifest, report, blob, a.require_aslr)

    if bad:
        print("[FAIL] check_symmap: %d problem(s)" % bad)
        return 1
    print("[OK  ] check_symmap: layout, symbol mapping, payload identity and reloc coverage all consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
