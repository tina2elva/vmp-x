#!/usr/bin/env python3
"""coverage_pyd.py - 用一个真实 Cython 扩展复测"保护后可保护函数的行为是否与原生一致"。

用法: python tools/coverage_pyd.py --wheel-dir D:\\taiji\\pytest --module example --python <python.exe>

默认保护除 __pyx_pymod_create 之外的 10 个候选函数（它属于"被外部调用者调用"那一类，见 docs/STATUS.md 第 489 节），
逐个 -func 打包，然后对比保护版与原生版的输出；任何不一致都会以非零码退出。"""
import argparse, os, shutil, subprocess, sys, tempfile

DEFAULT_FUNCS = [
    '__pyx_pw_7example_1n', '__pyx_pf_7example_n',
    '__pyx_pw_7example_3fibonacci', '__pyx_pf_7example_2fibonacci',
    '__pyx_pw_7example_5greet',
    '__pyx_pw_7example_7current_time_str', '__pyx_pf_7example_6current_time_str',
    '__pyx_pw_7example_9add_dly', '__pyx_pf_7example_8add_dly',
    '__pyx_bisect_code_objects',
]
KNOWN_BAD = ['__pyx_pymod_create']  # 见 STATUS 489：外部调用者这一类还没解决

EXPR = ('import example, numpy as np; '
        'print("fib", example.fibonacci(10), example.fibonacci(15)); '
        'print("n", example.n().shape); print("greet", example.greet("vmp")); '
        'print("time", len(example.current_time_str())); '
        'print("add_dly", float(example.add_dly(np.ones((4,2)),[1,2]).sum()))')

def run(pyd, python, module):
    d = tempfile.mkdtemp(prefix='covpyd_')
    # 必须按模块名落盘（Python 认的是 <module>.pyd / <module>.<abi>.pyd），否则 import 找不到
    shutil.copy(pyd, os.path.join(d, module + '.pyd'))
    code = 'import sys; sys.path.insert(0, r"%s"); %s' % (d, EXPR)
    try:
        p = subprocess.run([python, '-u', '-c', code], capture_output=True, timeout=300)
        return p.returncode, (p.stdout + p.stderr).decode('utf-8', 'replace').strip()
    finally:
        shutil.rmtree(d, ignore_errors=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--wheel-dir', required=True, help='放着 example.cp313-win_amd64.pyd 与 example.map 的目录')
    ap.add_argument('--module', default='example')
    ap.add_argument('--python', default='python')
    ap.add_argument('--vmpack', default='build/vmpack.exe' if os.name == 'nt' else 'build/vmpack')
    ap.add_argument('--blob', default='build/vm_interp_rel.bin')
    ap.add_argument('--manifest', default='build/vm_interp_rel.json')
    ap.add_argument('--func', action='append', default=[], help='覆盖默认函数列表')
    a = ap.parse_args()
    funcs = a.func or DEFAULT_FUNCS
    pyd = os.path.join(a.wheel_dir, '%s.cp313-win_amd64.pyd' % a.module)
    mp = os.path.join(a.wheel_dir, '%s.map' % a.module)
    for f in (pyd, mp, a.vmpack, a.blob, a.manifest):
        if not os.path.exists(f):
            print('[!] 缺少 %s' % f); return 2
    rc0, native = run(pyd, a.python, a.module)
    print('原生 rc=%s' % rc0)
    print(native)
    out = 'build/coverage_protected.pyd'
    args = [a.vmpack, '-exe', pyd, '-map', mp, '-blob', a.blob, '-manifest', a.manifest, '-out', out]
    for f in funcs: args += ['-func', f]
    r = subprocess.run(args, capture_output=True)
    if r.returncode != 0:
        print('[!] 打包失败:'); print((r.stdout + r.stderr).decode('utf-8', 'replace')[-500:]); return 1
    rc1, prot = run(out, a.python, a.module)
    print('--- 保护 %d 个函数 ---' % len(funcs))
    print('rc=%s' % rc1)
    print(prot)
    ok = (rc0 == 0 and rc1 == 0 and native == prot)
    print()
    print('覆盖率判定: %s（保护 %d 个：%s）' % ('一致' if ok else '不一致', len(funcs), ', '.join(funcs)))
    print('已知未解决: %s' % ', '.join(KNOWN_BAD))
    return 0 if ok else 1

if __name__ == '__main__':
    sys.exit(main())