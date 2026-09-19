#!/usr/bin/env python3
"""init_probe.py - init 类崩溃的跨进程观测。

用法:
  python tools/init_probe.py run   <pyddir> <manifest.json> <report.json> <out.log>
  python tools/init_probe.py watch <pid>  <manifest.json> <report.json> <out.log>

run 模式：先把 pyd 加载起来（DllMain 登记 payload），然后在工作线程 import（这一步会崩）。
watch 模式：对目标进程用 ReadProcessMemory 持续读 payload 里的诊断全局 —— 目标崩得太快，
           进程内采样抓不到，只有跨进程读才不丢窗口。"""
import ctypes, ctypes.wintypes as wt, json, os, sys, threading, time

PROC = ctypes.windll.kernel32

def rvas(man, rep):
    sec = rep['sectionRVA']; sym = man['symbols']
    ks = [k for k in ('vm_last_pc','vm_last_call','vm_last_call_rcx','vm_call_ring_n','vm_call_ring') if k in sym]
    return {k: sec + sym[k] for k in ks}

def module_base_of(pid, name):
    TH32CS_SNAPMODULE = 0x8; TH32CS_SNAPMODULE32 = 0x10
    class ME(ctypes.Structure):
        _fields_ = [('dwSize', wt.DWORD), ('th32ModuleID', wt.DWORD), ('th32ProcessID', wt.DWORD),
                    ('GlblcntUsage', wt.DWORD), ('ProccntUsage', wt.DWORD), ('modBaseAddr', ctypes.c_void_p),
                    ('modBaseSize', wt.DWORD), ('hModule', wt.HMODULE), ('szModule', ctypes.c_char * 256),
                    ('szExePath', ctypes.c_char * 260)]
    snap = PROC.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == -1: return None
    me = ME(); me.dwSize = ctypes.sizeof(ME); base = None
    ok = PROC.Module32First(snap, ctypes.byref(me))
    while ok:
        if me.szModule.decode(errors='replace').lower() == name.lower():
            base = me.modBaseAddr; break
        ok = PROC.Module32Next(snap, ctypes.byref(me))
    PROC.CloseHandle(snap)
    return base

def modules_of(pid):
    TH32CS_SNAPMODULE = 0x8; TH32CS_SNAPMODULE32 = 0x10
    class ME(ctypes.Structure):
        _fields_ = [('dwSize', wt.DWORD), ('th32ModuleID', wt.DWORD), ('th32ProcessID', wt.DWORD),
                    ('GlblcntUsage', wt.DWORD), ('ProccntUsage', wt.DWORD), ('modBaseAddr', ctypes.c_void_p),
                    ('modBaseSize', wt.DWORD), ('hModule', wt.HMODULE), ('szModule', ctypes.c_char * 256),
                    ('szExePath', ctypes.c_char * 260)]
    snap = PROC.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == -1: return []
    me = ME(); me.dwSize = ctypes.sizeof(ME); out = []
    ok = PROC.Module32First(snap, ctypes.byref(me))
    while ok:
        out.append((me.szModule.decode(errors='replace'), me.modBaseAddr, me.modBaseSize))
        ok = PROC.Module32Next(snap, ctypes.byref(me))
    PROC.CloseHandle(snap)
    return out

def watch(pid, offs, out):
    PROCESS_QUERY_INFORMATION = 0x0400; PROCESS_VM_READ = 0x0010
    h = PROC.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        open(out,'w').write('OpenProcess failed' + chr(10)); return
    f = open(out, 'w', buffering=1)
    f.write('rva: ' + json.dumps(offs) + chr(10)); f.flush()
    buf = ctypes.c_uint64(); n = 0; base = None
    while n < 2000000:
        n += 1
        if base is None:
            base = module_base_of(pid, 'example.cp313-win_amd64.pyd')
            if base:
                for nm, mb, ms in modules_of(pid):
                    f.write('mod %s base=0x%X size=0x%X' % (nm, mb or 0, ms) + chr(10))
                got0 = ctypes.c_size_t()
                iat = []
                for i in range(96):
                    q = ctypes.c_uint64()
                    if PROC.ReadProcessMemory(h, ctypes.c_void_p(base + 0x8300 + 8*i), ctypes.byref(q), 8, ctypes.byref(got0)):
                        if q.value: iat.append('0x%X:0x%X' % (0x8300 + 8*i, q.value))
                f.write('iat ' + ' '.join(iat) + chr(10))
                f.flush()
        if base:
            vals = {}
            for k, o in offs.items():
                got = ctypes.c_size_t()
                if PROC.ReadProcessMemory(h, ctypes.c_void_p(base + o), ctypes.byref(buf), 8, ctypes.byref(got)):
                    if k == 'vm_call_ring':
                        raw = (ctypes.c_uint64 * 16)()
                        if PROC.ReadProcessMemory(h, ctypes.c_void_p(base + o), ctypes.byref(raw), 128, ctypes.byref(got)):
                            vals['ring'] = [hex(raw[i]) for i in range(16)]
                        else:
                            vals['ring'] = []
                    else:
                        vals[k] = hex(buf.value)
            if vals: f.write(json.dumps({'t': n, 'base': hex(base), 'v': vals}) + chr(10))
        else:
            time.sleep(0.0005)
    f.write('watch ended samples=%d' % n + chr(10))

def run(d, man, rep, out, ready=None, go=None):
    offs = rvas(man, rep)
    f = open(out, 'w', buffering=1); f.write('rva: ' + json.dumps(offs) + chr(10)); f.flush()
    try:
        ctypes.WinDLL(os.path.join(d, 'example.cp313-win_amd64.pyd')); f.write('module loaded' + chr(10))
    except Exception as e:
        f.write('WinDLL failed: %r' % (e,) + chr(10))
    # 握手：写 ready 文件并等 go 文件，让观测进程有时间找到我们的模块基址
    if ready:
        open(ready, 'w').write('ready')
    if go:
        while not os.path.exists(go):
            time.sleep(0.002)
    f.write('go' + chr(10))

    def worker():
        try:
            sys.path.insert(0, d); import example  # noqa
        except BaseException as e:
            f.write('import raised: %r' % (e,) + chr(10))
    t = threading.Thread(target=worker, daemon=True); t.start()
    while t.is_alive(): time.sleep(0.01)
    f.write('done' + chr(10))

def main():
    mode = sys.argv[1]
    man = json.load(open(sys.argv[3] if mode == 'run' else sys.argv[3]))
    rep = json.load(open(sys.argv[4] if mode == 'run' else sys.argv[4]))
    if mode == 'run':
        run(sys.argv[2], man, rep, sys.argv[5],
            sys.argv[6] if len(sys.argv) > 6 else None,
            sys.argv[7] if len(sys.argv) > 7 else None)
    else:
        offs = rvas(man, rep)
        watch(int(sys.argv[2]), offs, sys.argv[5])

main()