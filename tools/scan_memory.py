#!/usr/bin/env python3
"""scan_memory.py - 在加载了被打包模块的进程里搜明文字节码（(e) 的对抗复测）。

    python tools/scan_memory.py --dir <pyd 所在目录> --module example --needle-file <明文文件> \
        --expr "example.fibonacci(10)"

**重要（我第一版把这件事做错了）**：不能把待查字节当成 Python 字符串/bytes 拿在手里再扫自己 ——
那样一定会在自己的堆里命中，得出"内存里有明文"的假结论。这里：
  · 用 bytearray 读入，并记下它自己的地址，扫描时跳过包含它的那个区域；
  · 只扫 MEM_PRIVATE（不扫 file mapping，否则又会命中我们自己映射的文件）。
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import sys


class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', wt.DWORD), ('RegionSize', ctypes.c_size_t),
                ('State', wt.DWORD), ('Protect', wt.DWORD), ('Type', wt.DWORD)]


def scan(needle, skip_lo, skip_hi):
    k32 = ctypes.windll.kernel32
    MEM_COMMIT, MEM_PRIVATE = 0x1000, 0x20000
    READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
    hits = []
    addr = 0
    mbi = MBI()
    while True:
        if not k32.VirtualQuery(ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        size = mbi.RegionSize or 0x1000
        base = mbi.BaseAddress or 0
        if (mbi.State == MEM_COMMIT and mbi.Protect in READABLE and mbi.Type == MEM_PRIVATE
                and not (base <= skip_lo < base + size) and not (base <= skip_hi < base + size)):
            try:
                buf = ctypes.string_at(base, size)
                n = buf.count(bytes(needle))
                if n:
                    hits.append((base, size, n, mbi.Protect, buf.find(bytes(needle))))
            except Exception:
                pass
        addr += size
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dir', required=True)
    ap.add_argument('--module', required=True)
    ap.add_argument('--needle-file', required=True)
    ap.add_argument('--expr', default='example.fibonacci(10)')
    ap.add_argument('--label', default='')
    a = ap.parse_args()

    needle = bytearray(open(a.needle_file, 'rb').read())
    nbuf = (ctypes.c_char * len(needle)).from_buffer(needle)
    skip_lo = ctypes.addressof(nbuf)
    skip_hi = skip_lo + len(needle) - 1

    sys.path.insert(0, a.dir)
    __import__(a.module)
    mod = sys.modules[a.module]
    print('loaded %s' % getattr(mod, '__file__', '?'))
    ns = {a.module: mod}
    print('call ->', eval(a.expr, ns))
    hits = scan(needle, skip_lo, skip_hi)
    total = sum(h[2] for h in hits)
    print('needle len=%d  regions=%d  copies=%d  (skipped own buffer @0x%X)' %
          (len(needle), len(hits), total, skip_lo))
    for base, size, n, prot, off in hits[:6]:
        print('    base=0x%X size=0x%X copies=%d prot=0x%X first_off=0x%X' % (base, size, n, prot, off))
    print('VERDICT:', 'PLAINTEXT-IN-MEMORY' if total else 'not-found')
    for i in range(len(needle)):
        needle[i] = 0


if __name__ == '__main__':
    main()
