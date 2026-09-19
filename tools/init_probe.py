#!/usr/bin/env python3
"""init_probe.py - 观测线程取崩溃现场：主线程死循环采样 blob 里的诊断全局（无缓冲直写文件），
工作线程去 import 目标 pyd。这样即使进程随后崩在宿主库里，最后几次采样也已经落盘。"""
import ctypes, json, os, sys, threading

def main():
    d = sys.argv[1]         # 放着 example.cp313-win_amd64.pyd 的目录
    man = json.load(open(sys.argv[2]))
    rep = json.load(open(sys.argv[3]))
    out = sys.argv[4]
    sec = rep['sectionRVA']
    sym = man['symbols']
    want = [k for k in ('vm_last_pc','vm_last_call','vm_call_ring_n','vm_call_ring') if k in sym]
    offs = {k: sec + sym[k] for k in want}
    f = open(out, 'w', buffering=1)
    f.write('rva: ' + json.dumps(offs) + chr(10)); f.flush()
    def worker():
        try:
            sys.path.insert(0, d)
            import example  # noqa
        except BaseException as e:
            f.write('import raised: %r' % (e,) + chr(10))
    # 先把模块**加载**起来（DllMain 会登记 payload），这样 GetModuleHandleW 立刻有值、采样能从第一刻开始；
    # 真正的 PyInit（会崩的那步）留给工作线程去 import。
    try:
        ctypes.WinDLL(os.path.join(d, 'example.cp313-win_amd64.pyd'))
        f.write('module loaded' + chr(10)); f.flush()
    except Exception as e:
        f.write('WinDLL failed: %r' % (e,) + chr(10)); f.flush()
    t = threading.Thread(target=worker, daemon=True)
    t.start()
    base = None
    n = 0
    while t.is_alive() and n < 400000:
        n += 1
        if base is None:
            h = ctypes.windll.kernel32.GetModuleHandleW('example.cp313-win_amd64.pyd')
            if h: base = h
        if base:
            try:
                v = {k: ctypes.c_uint64.from_address(base + offs[k]).value for k in want if k != 'vm_call_ring'}
                ring = [ctypes.c_uint64.from_address(base + offs['vm_call_ring'] + 8*i).value for i in range(16)] if 'vm_call_ring' in offs else []
                f.write(json.dumps({'t': n, 'v': {k: hex(x) for k, x in v.items()}, 'ring': [hex(x) for x in ring]}) + chr(10))
            except Exception:
                pass
    f.write('ended alive=%s samples=%d' % (t.is_alive(), n) + chr(10))
    f.flush()

main()