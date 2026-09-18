#!/usr/bin/env python3
"""find_ring.py - 在成功调用被保护函数之后，于本进程里定位 payload 的环形缓冲并打印内容。

用途：**标定**环形缓冲的真实地址（不靠我手算的偏移），以便崩溃现场能读到真正有用的 pc 序列。
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import sys

MAGIC = bytes.fromhex('3130474e49524d56')  # "VMRING01" 在内存里的字节序


class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', wt.DWORD), ('RegionSize', ctypes.c_size_t),
                ('State', wt.DWORD), ('Protect', wt.DWORD), ('Type', wt.DWORD)]


def find_magic():
    k32 = ctypes.windll.kernel32
    MEM_COMMIT, MEM_PRIVATE = 0x1000, 0x20000
    addr, out = 0, []
    mbi = MBI()
    while True:
        if not k32.VirtualQuery(ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        size = mbi.RegionSize or 0x1000
        base = mbi.BaseAddress or 0
        if mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE:
            try:
                buf = ctypes.string_at(base, size)
                i = buf.find(MAGIC)
                if i >= 0:
                    out.append((base + i, mbi.AllocationBase or 0, base, size))
            except Exception:
                pass
        addr += size
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dir', required=True)
    ap.add_argument('--module', required=True)
    ap.add_argument('--expr', default='example.fibonacci(10)')
    a = ap.parse_args()
    sys.path.insert(0, a.dir)
    __import__(a.module)
    mod = sys.modules[a.module]
    print('loaded %s' % getattr(mod, '__file__', '?'))
    print('call ->', eval(a.expr, {a.module: mod}))
    hits = find_magic()
    print('VMRING01 hits: %d' % len(hits))
    for ring_addr, mod_base, region, size in hits:
        rva = ring_addr - mod_base
        print('    ring=0x%X  module_base=0x%X  ringRVA=0x%X  (region base 0x%X size 0x%X)' %
              (ring_addr, mod_base, rva, region, size))
        arr = (ctypes.c_uint64 * (2 + 32)).from_address(ring_addr)
        print('    hdr: magic=0x%X count=%d' % (arr[0], arr[1]))
        n = min(arr[1], 16)
        seq = ['pc=0x%X/op=0x%X' % (arr[2 + 2 * i], arr[3 + 2 * i]) for i in range(n)]
        print('    ' + ' '.join(seq))


if __name__ == '__main__':
    main()
