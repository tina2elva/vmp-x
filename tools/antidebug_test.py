import argparse, ctypes, sys

class PBI(ctypes.Structure):
    _fields_ = [("Reserved1", ctypes.c_void_p), ("PebBaseAddress", ctypes.c_void_p),
                ("Reserved2", ctypes.c_void_p * 2), ("UniqueProcessId", ctypes.c_void_p),
                ("Reserved3", ctypes.c_void_p)]

ap = argparse.ArgumentParser()
ap.add_argument('--dir', required=True)
ap.add_argument('--module', default='example')
ap.add_argument('--expr', required=True)
ap.add_argument('--set-flag', action='store_true', help='把 PEB.BeingDebugged 置 1（模拟被调试）')
a = ap.parse_args()

pbi = PBI()
nt = ctypes.windll.ntdll
st = nt.NtQueryInformationProcess(ctypes.c_void_p(-1), 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None)
peb = pbi.PebBaseAddress
print('NtQueryInformationProcess status=0x%X peb=0x%X' % (st & 0xFFFFFFFF, peb or 0))
print('BeingDebugged (before) =', ctypes.c_ubyte.from_address(peb + 2).value)
if a.set_flag:
    written = ctypes.c_size_t(0)
    buf = ctypes.c_ubyte(1)
    ok = ctypes.windll.kernel32.WriteProcessMemory(ctypes.c_void_p(-1), ctypes.c_void_p(peb + 2), ctypes.byref(buf), 1, ctypes.byref(written))
    print('set BeingDebugged=1 ->', bool(ok), 'written', written.value)
    print('BeingDebugged (after) =', ctypes.c_ubyte.from_address(peb + 2).value)

sys.path.insert(0, a.dir)
__import__(a.module)
mod = sys.modules[a.module]
print('import ok:', getattr(mod, '__file__', '?'))
print('call ->', eval(a.expr, {a.module: mod}))
print('RESULT: protected call returned normally')
