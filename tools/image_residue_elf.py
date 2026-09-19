#!/usr/bin/env python3
"""image_residue_elf.py -- assert an ELF's executable PT_LOAD is not readable in the packed file.

Only the ORIGINAL is parsed; every non-zero 64-byte chunk of its executable segment is
searched in the whole packed file (all-zero chunks are excluded: padding matches padding).

Exit: 0 = clean, 2 = residue found / usage error.
"""
import struct, sys

def exec_segment(path):
    d = open(path, 'rb').read()
    phoff = struct.unpack_from('<Q', d, 0x20)[0]
    phentsize = struct.unpack_from('<H', d, 0x36)[0]
    phnum = struct.unpack_from('<H', d, 0x38)[0]
    if phoff + phnum * phentsize > len(d):
        raise SystemExit('[!] program header table out of range')
    # 打包端会跳过 [0, align_up(程序头表末尾))：ELF 头/程序头表必须保持明文（加载器要从文件读）。
    # 这里必须用同一套口径，否则头部明文块会被当成"残留"。
    hdr_skip = (phoff + phnum * phentsize + 0xFFF) & ~0xFFF
    if hdr_skip < 0x1000:
        hdr_skip = 0x1000
    for i in range(phnum):
        o = phoff + i * phentsize
        p_type, p_flags = struct.unpack_from('<II', d, o)
        p_off, p_va, _pa, p_filesz, _memsz = struct.unpack_from('<QQQQQ', d, o + 8)
        if p_type == 1 and (p_flags & 1) and p_filesz:
            inner_skip = hdr_skip - p_off
            if inner_skip < 0:
                inner_skip = 0
            if inner_skip >= p_filesz:
                raise SystemExit('[!] executable segment is entirely inside the header page')
            return d[p_off + inner_skip:p_off + p_filesz], p_va + inner_skip, p_filesz - inner_skip
    raise SystemExit('[!] no executable PT_LOAD')

def main():
    if len(sys.argv) != 3:
        raise SystemExit('usage: image_residue_elf.py <original> <packed>')
    body, va, size = exec_segment(sys.argv[1])
    pack = open(sys.argv[2], 'rb').read()
    total = zeros = found = 0
    for o in range(0, len(body) - 64 + 1, 64):
        c = body[o:o + 64]
        total += 1
        if set(c) == {0}:
            zeros += 1
            continue
        if pack.find(c) >= 0:
            found += 1
    print("[*] ELF PT_LOAD(X) va=0x%X size=%d | chunks=%d all-zero(excluded)=%d NON-ZERO FOUND=%d"
          % (va, size, total, zeros, found))
    if found:
        print("[!] ELF code is still readable in the packed file")
        sys.exit(2)
    print("[+] no ELF code readable in the packed file")

if __name__ == '__main__':
    main()
