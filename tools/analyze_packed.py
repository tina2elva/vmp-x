#!/usr/bin/env python3
"""analyze_packed.py - adversarial re-analysis of a packed artifact (numbers, not prose).

    python tools/analyze_packed.py <packed> [--orig <original>] [--report <json>]
                                   [--module example] [--python <python.exe>] [--expr "..."]

Checks (all output ASCII so it is readable in any console/CI):
  1. section table + Shannon entropy per section
  2. marker scan: fixed magic VMPK, ring magic VMRING01 (both byte orders), diagnostic symbol names
  3. trampoline scan: E9 rel32 whose target lands in one of our new sections (real patches),
     plus the raw count of E9 bytes that leave .text (mostly false positives)
  4. .pdata: does a protected RVA still have a RUNTIME_FUNCTION (i.e. a signpost left behind)?
  5. rollback attempt: restore the overwritten bytes from the original and see if it still runs
"""
import argparse
import hashlib
import json
import math
import os
import struct
import subprocess
import sys
import tempfile


def parse_pe(d):
    pe = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    optsz = struct.unpack_from('<H', d, pe + 20)[0]
    magic = struct.unpack_from('<H', d, pe + 24)[0]
    opt = pe + 24
    dd = opt + (112 if magic == 0x20b else 96)
    imgbase = struct.unpack_from('<Q', d, opt + 24)[0]
    secoff = opt + optsz
    secs = []
    for i in range(nsec):
        o = secoff + i * 40
        name = d[o:o + 8].rstrip(b'\x00').decode('latin1')
        vsz, va, rsz, roff = struct.unpack_from('<IIII', d, o + 8)
        chars = struct.unpack_from('<I', d, o + 36)[0]
        secs.append(dict(name=name, va=va, vsz=vsz, rsz=rsz, roff=roff, chars=chars))
    dirs = [struct.unpack_from('<II', d, dd + 8 * i) for i in range(16)]
    return dict(pe=pe, opt=opt, dd=dd, imgbase=imgbase, secs=secs, dirs=dirs)


def entropy(b):
    if not b:
        return 0.0
    cnt = [0] * 256
    for x in b:
        cnt[x] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in cnt if c)


def rva2off(pe, rva):
    for s in pe['secs']:
        if s['va'] <= rva < s['va'] + max(s['vsz'], s['rsz']):
            return s['roff'] + (rva - s['va'])
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('packed')
    ap.add_argument('--orig')
    ap.add_argument('--report')
    ap.add_argument('--module', default=None, help='python module name (from the .pyd base name)')
    ap.add_argument('--python', default=sys.executable)
    ap.add_argument('--expr', default="print('ok')")
    ap.add_argument('--label', default='')
    a = ap.parse_args()

    rep_early = None
    if a.report and os.path.exists(a.report):
        rep_early = json.load(open(a.report))
    sec_names = (rep_early or {}).get('sectionNames') or []

    d = open(a.packed, 'rb').read()
    pe = parse_pe(d)
    print('== %s ==' % (a.label or os.path.basename(a.packed)))
    print('size=%d sha256=%s' % (len(d), hashlib.sha256(d).hexdigest()[:16]))

    print('[1] sections / entropy')
    for s in pe['secs']:
        body = d[s['roff']:s['roff'] + s['rsz']]
        print('    %-8s VA=0x%05X vsz=0x%05X raw=0x%05X flags=0x%08X H=%.3f' %
              (s['name'], s['va'], s['vsz'], s['rsz'], s['chars'], entropy(body)))

    print('[2] marker scan')
    for k, v in (('fixed magic VMPK', b'VMPK'), ('ring VMRING01 (fwd)', b'VMRING01'),
                 ('ring VMRING01 (rev)', b'10GNIRMV'), ('symbol vm_diag', b'vm_diag'),
                 ('symbol vm_ring_hdr', b'vm_ring_hdr')):
        print('    %-22s %s' % (k, 'PRESENT' if v in d else '-'))

    print('[3] trampoline scan (E9 rel32)')
    text = next((s for s in pe['secs'] if s['name'] == '.text'), None)
    ours = [s for s in pe['secs'] if s['name'] in sec_names] if sec_names else [s for s in pe['secs'] if s['name'].startswith('.vmp')]
    real, raw = [], 0
    if text:
        blob = d[text['roff']:text['roff'] + text['rsz']]
        lo, hi = text['va'], text['va'] + text['vsz']
        for i in range(len(blob) - 5):
            if blob[i] != 0xE9:
                continue
            tgt = text['va'] + i + 5 + struct.unpack_from('<i', blob, i + 1)[0]
            if not (lo <= tgt < hi):
                raw += 1
                if any(s['va'] <= tgt < s['va'] + s['vsz'] for s in ours):
                    real.append((text['va'] + i, tgt))
    print('    patches into our sections: %d%s' % (len(real), '' if not real else
          ' -> ' + ', '.join('0x%X->0x%X' % h for h in real[:8])))
    print('    raw E9 leaving .text (incl. false positives): %d' % raw)

    print('[4] .pdata signpost check')
    prot = []
    if a.report and os.path.exists(a.report):
        prot = [p['funcRVA'] for p in json.load(open(a.report)).get('placements', [])]
    exc_rva, exc_sz = pe['dirs'][3]
    found = []
    if exc_rva and exc_sz:
        base = rva2off(pe, exc_rva)
        for i in range(exc_sz // 12):
            beg, end, uw = struct.unpack_from('<III', d, base + i * 12)
            if beg in prot:
                found.append(beg)
    print('    protected %s -> remaining unwind records: %d %s' %
          (['0x%X' % x for x in prot], len(found), '' if not found else str([hex(f) for f in found])))

    print('[5] printable strings in our sections')
    import re as _re
    strings = []
    for s in ours:
        body = d[s['roff']:s['roff'] + s['rsz']]
        for m in _re.finditer(rb'[ -~]{6,}', body):
            wr = m.group().decode('ascii')
            strings.append(wr)
    interesting = [x for x in strings if not x.startswith('    ')]
    print('    runs>=6: %d (in our sections); sample: %s' %
          (len(strings), '; '.join(interesting[:8])[:160] if interesting else '-'))

    print('[6] crypto constant signatures')
    canon = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]  # ChaCha sigma
    hits = [hex(w) for w in canon if struct.pack('<I', w) in d]
    print('    ChaCha sigma words present: %s' % (hits if hits else 'NONE'))
    print('    Poly1305 mask 0x3ffffff : %s' %
          ('PRESENT' if struct.pack('<I', 0x3FFFFFF) in d else 'NONE'))

    print('[7] rollback attempt (restore overwritten bytes, then run)')
    if not (a.orig and prot):
        print('    skipped (need --orig and --report)')
    else:
        o = open(a.orig, 'rb').read()
        d2 = bytearray(d)
        for rva in prot:
            src = rva2off(pe, rva)
            if src is None:
                continue
            d2[src:src + 5] = o[src:src + 5]
        tmp = tempfile.mkdtemp(prefix='vmpk_rollback_')
        mod = a.module or os.path.basename(a.packed).split('.')[0]
        if a.packed.endswith('.pyd'):
            path = os.path.join(tmp, mod + '.cp313-win_amd64.pyd')
            code = "import sys; sys.path.insert(0, r'%s'); import %s; %s" % (tmp, mod, a.expr)
        else:
            path = os.path.join(tmp, os.path.basename(a.packed))
            code = None
        open(path, 'wb').write(bytes(d2))
        if code is None:
            print('    skipped (not a .pyd)')
        else:
            try:
                r = subprocess.run([a.python, '-c', code], capture_output=True, timeout=60)
                out = (r.stdout + r.stderr).decode('utf-8', 'replace').strip().splitlines()
                verdict = 'STILL RUNS (bypass succeeds)' if r.returncode == 0 else 'refused/crashed'
                last = (out[-1] if out else '').encode('ascii', 'replace').decode('ascii')
                print('    %s  exit=%d  %s' % (verdict, r.returncode, last[:100]))
            except subprocess.TimeoutExpired:
                print('    TIMEOUT (likely hung)')
    print()


    print('[8] bytecode tamper (flip one ciphertext byte, then run)')
    rep = None
    if a.report and os.path.exists(a.report):
        rep = json.load(open(a.report))
    pls = (rep or {}).get('placements') or []
    if not (pls and a.packed.endswith('.pyd')):
        print('    skipped (need --report with placements and a .pyd)')
    else:
        desc_off = rva2off(pe, pls[0]['descRVA'])
        code_rva = struct.unpack_from('<I', d, desc_off + 8)[0]
        code_off = desc_off + code_rva
        d3 = bytearray(d)
        d3[code_off + 8] ^= 0xFF
        r3 = run_packed(a, d3, 'vmpk_bctamper_')
        print('    %s' % r3)
    print()

    print('[9] entry-patch tamper (flip one patch byte, then run)')
    if not (real and a.packed.endswith('.pyd')):
        print('    skipped (need a patched entry and a .pyd)')
    else:
        src = rva2off(pe, real[0][0])
        d4 = bytearray(d)
        d4[src] ^= 0xFF
        r4 = run_packed(a, d4, 'vmpk_patchtamper_')
        print('    %s' % r4)
    print()

    print('[10] interpreter/stub code tamper (flip one .vmp code byte, then run)')
    vmp = next((s for s in pe['secs'] if s['name'] in sec_names), None) if sec_names else next((s for s in pe['secs'] if s['name'] == '.vmp'), None)
    if not (vmp and a.packed.endswith('.pyd')):
        print('    skipped (need a .vmp section and a .pyd)')
    else:
        d5 = bytearray(d)
        off5 = vmp['roff'] + 0x1000          # 段内偏一点，确保落在代码里
        d5[off5] ^= 0xFF
        r5 = run_packed(a, d5, 'vmpk_codetamper_')
        print('    %s' % r5)
    print()

    print('[11] section names (must not be a fixed .vmp* signature)')
    if sec_names:
        print('    our sections: %s' % ', '.join(sec_names))
        bad = [n for n in sec_names if n.startswith('.vmp')]
        print('    fixed .vmp* names: %s' % (bad if bad else 'none'))
    else:
        print('    (no sectionNames in report; pass --report)')
    print()


def run_packed(a, data, prefix):
    """把改动后的产物写成 pyd 跑一次，返回判定字符串。"""
    tmp = tempfile.mkdtemp(prefix=prefix)
    mod = a.module or os.path.basename(a.packed).split('.')[0]
    path = os.path.join(tmp, mod + '.cp313-win_amd64.pyd')
    open(path, 'wb').write(bytes(data))
    code = "import sys; sys.path.insert(0, r'%s'); import %s; %s" % (tmp, mod, a.expr)
    try:
        r = subprocess.run([a.python, '-c', code], capture_output=True, timeout=60)
    except subprocess.TimeoutExpired:
        return 'TIMEOUT (likely hung)'
    out = (r.stdout + r.stderr).decode('utf-8', 'replace').strip().splitlines()
    last = (out[-1] if out else '').encode('ascii', 'replace').decode('ascii')
    if r.returncode != 0:
        return 'refused/crashed  exit=%d  %s' % (r.returncode, last[:90])
    return 'runs but wrong?  exit=0  %s' % last[:90]


    print('[11] section names (must not be a fixed .vmp* signature)')
    if sec_names:
        print('    our sections: %s' % ', '.join(sec_names))
        bad = [n for n in sec_names if n.startswith('.vmp')]
        print('    fixed .vmp* names: %s' % (bad if bad else 'none'))
    else:
        print('    (no sectionNames in report; pass --report)')
    print()


if __name__ == '__main__':
    main()