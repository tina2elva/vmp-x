#!/usr/bin/env python3
"""pack.py - one-command packing wrapper for vmp-x (Windows PE / Linux ELF).

Why Python and not .ps1: PowerShell 5.1 mangles repeated array params and reads .ps1 as ANSI;
argparse has none of those pitfalls.

Examples:
  python tools/pack.py -i app.exe -m app.map --list
  python tools/pack.py -i app.exe -m app.map -f main -f check_key -o app.packed.exe
  python tools/pack.py -i app.exe -m app.map --all --max 10
  python tools/pack.py -i app.exe -f check_key,sum_to -o app.packed.exe   (gcc target: no map needed)

Notes:
  * keep the original binary; input/output sizes and the injection report are printed;
  * functions the lifter cannot translate are refused loudly (never silently mis-lifted);
  * default blob is the RELEASE build (no diagnostics, randomized section names).
"""
import argparse, os, re, shutil, subprocess, sys

JUNK_RE = re.compile(r'^[0-9a-fA-F]{4,}[A-Za-z]?$')   # map artifacts like 00006cd0H
MAP_RE = re.compile(r'^\s+0001:([0-9a-fA-F]{8})\s+(\S+)')
COFF_RE = re.compile(r'\(sec\s+1\).*\(ty\s+20\).*0x([0-9a-fA-F]+)\s+(\S+)\s*$')

def sh(args):
    p = subprocess.run(args, capture_output=True, text=True, errors='replace')
    return p.returncode, (p.stdout or '') + (p.stderr or '')

def find_exe(name):
    for c in (os.path.join('build', name + '.exe'), os.path.join('build', name)):
        if os.path.exists(c): return c
    return None

def ensure_tools():
    pairs = [('vmpack', './cmd/vmpack'), ('vmpbuild', './cmd/vmpbuild'), ('coverage', './cmd/coverage')]
    for name, pkg in pairs:
        if find_exe(name) is None:
            print('[build] go build -o build/%s %s' % (name, pkg))
            rc, out = sh(['go', 'build', '-o', os.path.join('build', name + '.exe'), pkg])
            if rc != 0: sys.exit('[!] go build failed:' + chr(10) + out)
    return {n: find_exe(n) for n, _ in pairs}

def ensure_blob(blob, manifest, stub_src, release):
    if os.path.exists(blob) and os.path.exists(manifest): return
    args = [find_exe('vmpbuild'), '-src', stub_src, '-out', blob, '-manifest', manifest, '-entry', 'vm_entry']
    if release: args.append('-release')
    print('[blob] building %s%s' % (blob, '' if release else ' (non-release)'))
    rc, out = sh(args)
    if rc != 0: sys.exit('[!] vmpbuild failed:' + chr(10) + out)

def candidate_names(inp, mapfile):
    names = []
    if mapfile and os.path.exists(mapfile):
        for line in open(mapfile, errors='replace'):
            m = MAP_RE.match(line)
            if m and not JUNK_RE.match(m.group(2)): names.append(m.group(2))
        return names
    objdump = shutil.which('objdump') or r'C:\msys64\ucrt64\bin\objdump.exe'
    if os.path.exists(objdump):
        rc, out = sh([objdump, '-t', inp])
        for line in out.splitlines():
            m = COFF_RE.search(line)
            if m and not JUNK_RE.match(m.group(2)): names.append(m.group(2))
    return names

def pack(inp, out, funcs, blob, manifest, mapfile, report, no_encrypt, tools):
    d = os.path.dirname(out)
    if d: os.makedirs(d, exist_ok=True)
    args = [tools['vmpack'], '-exe', inp, '-blob', blob, '-manifest', manifest, '-out', out]
    if mapfile: args += ['-map', mapfile]
    if report: args += ['-report', report]
    for f in funcs: args += ['-func', f]
    if no_encrypt: args.append('-no-encrypt')
    return sh(args)

def main():
    ap = argparse.ArgumentParser(description='vmp-x packing wrapper')
    ap.add_argument('-i', '--input', required=True, help='input PE/ELF')
    ap.add_argument('-o', '--out', default='', help='output file (default <input>.vmp)')
    ap.add_argument('-m', '--map', default='', help='MSVC .map (needed when the binary has no COFF symbols)')
    ap.add_argument('-f', '--func', action='append', default=[], help='function name(s); repeatable or comma separated')
    ap.add_argument('-r', '--report', default='', help='injection report JSON')
    ap.add_argument('--list', action='store_true', help='only list candidate function names')
    ap.add_argument('--all', action='store_true', help='probe candidates one by one, keep the ones that lift')
    ap.add_argument('--all-any', action='store_true', help='with --all: also try names starting with _ or ? (CRT/internal)')
    ap.add_argument('--max', type=int, default=12, help='with --all: keep at most N functions')
    ap.add_argument('--probe-limit', type=int, default=40, help='with --all: probe at most N candidates')
    ap.add_argument('--blob', default=os.path.join('build', 'vm_interp_rel.bin'))
    ap.add_argument('--manifest', default=os.path.join('build', 'vm_interp_rel.json'))
    ap.add_argument('--stub-src', default='stub/win/x64')
    ap.add_argument('--no-encrypt', action='store_true', help='debug only')
    ap.add_argument('--non-release', action='store_true', help='build blob without -release (keeps diagnostics)')
    ap.add_argument('-v', '--verbose', action='store_true')
    a = ap.parse_args()

    if not os.path.exists('go.mod'):
        sys.exit('[!] run this from the repository root (go.mod not found in %s)' % os.getcwd())
    if not os.path.exists(a.input):
        sys.exit('[!] input not found: %s' % a.input)

    tools = ensure_tools()
    ensure_blob(a.blob, a.manifest, a.stub_src, not a.non_release)
    in_size = os.path.getsize(a.input)
    print('[in  ] %s  %d bytes' % (a.input, in_size))
    print('[blob] %s' % a.blob)

    if a.list:
        names = candidate_names(a.input, a.map)
        print('candidate functions: %d (first 40)' % len(names))
        for n in names[:40]: print('   ' + n)
        print('tip: -f <name> (repeatable) to pick, or --all to probe automatically.')
        return 0

    funcs = []
    for item in a.func:
        funcs += [x for x in item.split(',') if x]

    if funcs:
        chosen = funcs
    elif a.all:
        cand = candidate_names(a.input, a.map)
        if not cand: sys.exit('[!] no candidate names (MSVC needs -m; gcc targets need COFF symbols)')
        # 默认跳过 CRT/内部符号（以下划线开头、或 C++ 修饰名），否则 --all 会先挑到 _DllMainCRTStartup 这类
        if not a.all_any:
            cand = [n for n in cand if not n.startswith('_') and not n.startswith('?')]
            if not cand: sys.exit('[!] only CRT/internal names found; use --all-any to include them')
        print('[all ] candidates=%d probe-limit=%d max=%d' % (len(cand), a.probe_limit, a.max))
        chosen = []
        probed = 0
        for n in cand:
            if len(chosen) >= a.max or probed >= a.probe_limit: break
            probed += 1
            rc, out = pack(a.input, os.path.join('build', '_probe.out'), [n], a.blob, a.manifest, a.map, '', a.no_encrypt, tools)
            if rc == 0:
                chosen.append(n); print('   [ok  ] ' + n)
            else:
                print('   [skip] ' + n)
        if not chosen: sys.exit('[!] nothing survived probing')
    else:
        print('usage: -f <name> (repeatable) or --all; use --list to see candidates.'); return 2

    out = a.out or (a.input + '.vmp')
    report = a.report or os.path.join('build', 'pack_report.json')
    rc, txt = pack(a.input, out, chosen, a.blob, a.manifest, a.map, report, a.no_encrypt, tools)
    if rc != 0:
        print(txt)
        sys.exit('[!] packing failed (see reason above); refused functions cannot be translated')

    print('')
    print('==== result ====')
    print('protected functions: %d -> %s' % (len(chosen), ', '.join(chosen)))
    print('input %d bytes  ->  output %d bytes  (%s)' % (in_size, os.path.getsize(out), out))
    if os.path.exists(report): print('injection report: %s' % report)
    if a.verbose: print(txt)
    print('reminder: keep the original; tools/analyze_packed.py can run adversarial checks on the output.')
    return 0

if __name__ == '__main__':
    sys.exit(main())