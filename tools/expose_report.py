#!/usr/bin/env python3
"""expose_report.py -- measure how much of an image is readable in the clear.

Answers "what would a protector actually be hiding?" per section:
  * size / Shannon entropy (encrypted or compressed sections sit near 8.0)
  * readable-string bytes (>=6 and >=12 chars) -- strings are the cheapest RE input
  * optionally a before/after delta against another image.

PE and ELF are both supported (section-level). Output is ASCII only: Windows runners
are cp1252 and non-ASCII would raise UnicodeEncodeError mid-report.

Usage:
  python tools/expose_report.py --img build/target.exe [--compare build/target_vmp.exe]
       [--sections .text,.rdata,.data] [--minlen 6]
"""
import argparse, math, re, struct, sys
from collections import Counter

STR_RE = None


def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def str_bytes(b, minlen):
    return sum(len(m.group()) for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, b))


def pe_sections(d):
    lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, lfanew + 6)[0]
    optsz = struct.unpack_from("<H", d, lfanew + 20)[0]
    sb = lfanew + 24 + optsz
    out = []
    for i in range(nsec):
        o = sb + i * 40
        name = d[o:o + 8].rstrip(b"\x00").decode("latin1")
        vsz, va, rsz, raw = struct.unpack_from("<IIII", d, o + 8)
        out.append((name, d[raw:raw + min(rsz, vsz if vsz else rsz)]))
    return out


def elf_sections(d):
    shoff = struct.unpack_from("<Q", d, 0x28)[0]
    shentsize = struct.unpack_from("<H", d, 0x3A)[0]
    shnum = struct.unpack_from("<H", d, 0x3C)[0]
    shstrndx = struct.unpack_from("<H", d, 0x3E)[0]
    if not shoff or not shnum:
        return []
    def sh(i):
        return struct.unpack_from("<IIQQQQ", d, shoff + i * shentsize)
    _, _, _, _, stroff, strsize = sh(shstrndx)
    st = d[stroff:stroff + strsize]
    out = []
    for i in range(shnum):
        n = sh(i)[0]
        e = st.find(b"\x00", n)
        name = st[n:e].decode("latin1")
        _, typ, flags, addr, off, size = sh(i)
        if typ == 8:  # SHT_NOBITS (.bss)
            continue
        out.append((name, d[off:off + size]))
    return out


def sections(path):
    d = open(path, "rb").read()
    if d[:4] == b"\x7fELF":
        return d, elf_sections(d)
    if d[:2] == b"MZ":
        return d, pe_sections(d)
    raise SystemExit("[!] %s: neither PE nor ELF" % path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--img", required=True)
    ap.add_argument("--compare", default="", help="second image (e.g. the packed one) for a before/after delta")
    ap.add_argument("--sections", default="", help="only these sections (comma separated)")
    ap.add_argument("--minlen", type=int, default=6)
    ap.add_argument("--max-ratio", type=float, default=1.0,
                    help="with --compare: fail (exit 2) if the packed image keeps more than this fraction of the original >=12-byte readable strings")
    a = ap.parse_args()
    only = [s.strip() for s in a.sections.split(",") if s.strip()]

    d, secs = sections(a.img)
    print("[*] %s  (%d bytes)" % (a.img, len(d)))
    tot6 = tot12 = 0
    rows = []
    for name, body in secs:
        if only and name not in only:
            continue
        if not body:
            continue
        s6 = str_bytes(body, a.minlen)
        s12 = str_bytes(body, 12)
        tot6 += s6
        tot12 += s12
        rows.append((name, len(body), entropy(body), s6, s12))
    for name, size, h, s6, s12 in rows:
        print("    %-14s size=%-9d H=%.2f  readable>=%d: %-7d (>=12: %d)" % (name, size, h, a.minlen, s6, s12))
    print("    %-14s %-19s readable>=%d: %-7d (>=12: %d)" % ("TOTAL", "", a.minlen, tot6, tot12))

    if a.compare:
        d2, secs2 = sections(a.compare)
        m2 = dict(secs2)
        print("[*] vs %s (%d bytes)" % (a.compare, len(d2)))
        o6 = o12 = 0
        for name, size, h, s6, s12 in rows:
            b2 = m2.get(name, b"")
            n6, n12 = str_bytes(b2, a.minlen), str_bytes(b2, 12)
            o6 += n6
            o12 += n12
            print("    %-14s H=%.2f -> H=%.2f   readable>=%d: %d -> %d" % (name, h, entropy(b2), a.minlen, s6, n6))
        print("    %-14s H=%.2f -> H=%.2f   readable>=%d: %d -> %d  (hidden %.0f%%)"
              % ("TOTAL", entropy(d), entropy(d2), a.minlen, tot6, o6,
                 100.0 * (tot6 - o6) / max(tot6, 1)))
        if tot12 > 0 and o12 > int(tot12 * a.max_ratio):
            print("[!] packed image still exposes %d bytes of >=12-char readable strings (%.1f%% of original %d, limit %.1f%%)"
                  % (o12, 100.0 * o12 / tot12, tot12, 100.0 * a.max_ratio))
            sys.exit(2)
        print("[+] readable-string exposure is within the limit (packed %d bytes vs original %d)" % (o12, tot12))


if __name__ == "__main__":
    main()
