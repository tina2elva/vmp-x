#!/usr/bin/env python3
"""veh_ring.py - 在被保护函数崩掉时，把 payload 里的环形缓冲（最近执行的 pc/op）打出来。

    python tools/veh_ring.py --dir <含 pyd 的目录> --module example --expr "example.current_time_str()" \
        --vmpb-rva 0x14000 --ring-rva <ring 相对 .vmpb 的偏移> [--dump <json>]

用的是 Windows 的 VEH（AddVectoredExceptionHandler）：访问违例发生时先跑我们的回调，
把环形缓冲读出来打印，然后照常让进程死掉（EXCEPTION_CONTINUE_SEARCH）。
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import sys

EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_ILLEGAL_INSTRUCTION = 0xC000001D


class EXCEPTION_RECORD(ctypes.Structure):
    pass


EXCEPTION_RECORD._fields_ = [
    ('ExceptionCode', wt.DWORD),
    ('ExceptionFlags', wt.DWORD),
    ('ExceptionRecord', ctypes.POINTER(EXCEPTION_RECORD)),
    ('ExceptionAddress', ctypes.c_void_p),
    ('NumberParameters', wt.DWORD),
    ('ExceptionInformation', ctypes.c_size_t * 15),
]


class EXCEPTION_POINTERS(ctypes.Structure):
    _fields_ = [('ExceptionRecord', ctypes.POINTER(EXCEPTION_RECORD)),
                ('ContextRecord', ctypes.c_void_p)]


class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', wt.DWORD), ('RegionSize', ctypes.c_size_t),
                ('State', wt.DWORD), ('Protect', wt.DWORD), ('Type', wt.DWORD)]


CFG = {}
HANDLER = None

LOG = {'fd': None}


def hlog(msg):
    try:
        if LOG['fd'] is not None:
            os.write(LOG['fd'], (msg + chr(10)).encode('utf-8', 'replace'))
    except Exception:
        pass
    try:
        print(msg, flush=True)
    except Exception:
        pass


def handler(info):
  try:
    rec = info.contents.ExceptionRecord.contents
    code = rec.ExceptionCode
    addr = rec.ExceptionAddress or 0
    params = [rec.ExceptionInformation[i] for i in range(min(2, rec.NumberParameters))]
    hlog('[VEH] exception code=0x%08X at 0x%X params=%s' % (code, addr, [hex(p) for p in params]))
    mbi = MBI()
    ctypes.windll.kernel32.VirtualQuery(ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    base = mbi.AllocationBase or 0
    hlog('    module/allocation base=0x%X (region 0x%X size 0x%X)' % (base, mbi.BaseAddress or 0, mbi.RegionSize))
    mb = ctypes.windll.kernel32.GetModuleHandleW(CFG.get('module_name', ''))
    if mb:
        hlog('    GetModuleHandleW base=0x%X (VirtualQuery 的 AllocationBase=0x%X 不一定是我们的模块)' % (mb, base))
        base = mb
    probe_rva = CFG.get('probe_rva')
    if probe_rva is not None and base:
        try:
            v = (ctypes.c_uint64).from_address(base + probe_rva).value
            hlog('    last pc=0x%X  op=0x%X  (raw=0x%X)' % (v & 0xFFFFFFFF, v >> 32, v))
            if CFG.get('probe2_rva') is not None:
                v2 = (ctypes.c_uint64).from_address(base + CFG['probe2_rva']).value
                hlog('    last native call target=0x%X  (via %s)' % (v2 & 0x7FFFFFFFFFFFFFFF, 'CALLR' if (v2 >> 63) else 'CALLN'))
        except Exception as e:
            hlog('    probe read failed: %r' % (e,))
    ring_rva = CFG.get('ring_rva')
    vmpb_rva = CFG.get('vmpb_rva')
    if ring_rva is not None and vmpb_rva is not None and base:
        p = base + vmpb_rva + ring_rva
        try:
            hdr = (ctypes.c_uint64 * 2).from_address(p)
            cnt = hdr[1]
            hlog('    ring hdr[0]=0x%X count=%d' % (hdr[0], cnt))
            n = min(cnt, 16)
            ent = (ctypes.c_uint64 * (n * 2)).from_address(p + 16)
            seq = ['pc=0x%X/op=0x%X' % (ent[2 * i], ent[2 * i + 1]) for i in range(n)]
            hlog('    ring tail: ' + ' '.join(seq))
        except Exception as e:
            hlog('    ring read failed: %r' % (e,))
  except Exception as e:
    try:
        hlog('VEH handler failed: %r' % (e,))
    except Exception:
        pass
  return 0  # EXCEPTION_CONTINUE_SEARCH


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dir', required=True)
    ap.add_argument('--module', required=True)
    ap.add_argument('--module-name', default='example.cp313-win_amd64.pyd')
    ap.add_argument('--expr', required=True)
    ap.add_argument('--vmpb-rva', type=lambda s: int(s, 0), default=None)
    ap.add_argument('--ring-rva', type=lambda s: int(s, 0), default=None)
    ap.add_argument('--probe-rva', type=lambda s: int(s, 0), default=None)
    ap.add_argument('--probe2-rva', type=lambda s: int(s, 0), default=None)
    a = ap.parse_args()
    LOG['fd'] = os.open('build/veh_ring.log', os.O_CREAT | os.O_WRONLY | os.O_TRUNC)
    CFG['vmpb_rva'] = a.vmpb_rva
    CFG['ring_rva'] = a.ring_rva
    CFG['probe_rva'] = a.probe_rva
    CFG['probe2_rva'] = a.probe2_rva
    CFG['module_name'] = a.module_name
    proto = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.POINTER(EXCEPTION_POINTERS))
    global HANDLER
    HANDLER = proto(handler)  # 必须留引用：临时对象会被回收，回调就变成野指针
    h = ctypes.windll.kernel32.AddVectoredExceptionHandler(1, HANDLER)
    hlog('VEH registered handle=0x%X' % (h or 0))
    sys.path.insert(0, a.dir)
    __import__(a.module)
    k32 = ctypes.windll.kernel32
    k32.GetModuleHandleW.restype = ctypes.c_void_p
    mb0 = k32.GetModuleHandleW(a.module_name)
    if mb0 and CFG.get('probe_rva') is not None:
        v0 = ctypes.c_uint64.from_address(mb0 + CFG['probe_rva']).value
        hlog('    probe BEFORE call = 0x%X (module base 0x%X)' % (v0, mb0))
        if CFG.get('probe2_rva') is not None:
            hlog('    probe2 BEFORE call = 0x%X' % ctypes.c_uint64.from_address(mb0 + CFG['probe2_rva']).value)
    mod = sys.modules[a.module]
    print('loaded %s' % getattr(mod, '__file__', '?'), flush=True)
    print('call ->', eval(a.expr, {a.module: mod}), flush=True)
    print('no exception', flush=True)


if __name__ == '__main__':
    main()