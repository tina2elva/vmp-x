#!/usr/bin/env python3
"""scan_memory.py - 在**加载了被打包模块的本进程**里搜明文字节码（(e) 的对抗复测）。

    python tools/scan_memory.py --dir <含 pyd 的目录> --module example --needle-hex <明文> \
        --expr "example.fibonacci(10)" [--python <python.exe>]

为什么要在独立进程里做：要证明的是"运行期内存里有没有明文"，所以必须真的把 pyd 加载进来、
调用被保护函数、再扫自己进程的已提交内存。输出 ASCII，直接给数字。
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import os
import sys


class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', wt.DWORD), ('RegionSize', ctypes.c_size_t),
                ('State', wt.DWORD), ('Protect', wt.DWORD), ('Type', wt.DWORD)]


def scan(needle):
    k32 = ctypes.windll.kernel32
    MEM_COMMIT = 0x1000
    READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}  # RO, RW, WC, EXEC_R, EXEC_RW, EXEC_WC
    hits = []
    addr = 0
    mbi = MBI()
    while True:
        r = k32.VirtualQuery(ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not r:
            break
        size = mbi.RegionSize or 0x1000
        if mbi.State == MEM_COMMIT and mbi.Protect in READABLE:
            try:
                buf = ctypes.string_at(mbi.BaseAddress, size)
                n = buf.count(needle)
                if n:
                    hits.append((mbi.BaseAddress, size, n, mbi.Protect))
            except Exception:
                pass
        addr += size
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dir', required=True)
    ap.add_argument('--module', required=True)
    ap.add_argument('--needle-hex', required=True)
    ap.add_argument('--expr', default='example.fibonacci(10)')
    ap.add_argument('--omit-call', action='store_true', help='只加载不调用（对照组）')
    a = ap.parse_args()

    needle = bytes.fromhex(a.needle_hex)
    sys.path.insert(0, a.dir)
    __import__(a.module)
    mod = sys.modules[a.module]
    print('loaded %s from %s' % (a.module, getattr(mod, '__file__', '?')))
    if not a.omit_call:
        ns = {a.module: mod}
        print('call ->', eval(a.expr, ns))
    hits = scan(needle)
    total = sum(h[2] for h in hits)
    print('needle len=%d  regions_with_needle=%d  total_copies=%d' % (len(needle), len(hits), total))
    for base, size, n, prot in hits[:6]:
        print('    base=0x%X size=0x%X copies=%d protect=0x%X' % (base, size, n, prot))
    print('VERDICT:', 'PLAINTEXT-IN-MEMORY' if total else 'not-found')


if __name__ == '__main__':
    main()
