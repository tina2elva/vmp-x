#!/usr/bin/env python3
"""antidebug_flag_test.py -- start a protected exe with PEB.BeingDebugged=1 and compare output.

This drives the anti-debug chain WITHOUT a real debugger (the debug-API route proved flaky in
this environment): start the target CREATE_SUSPENDED, set PEB.BeingDebugged (that is exactly what
a debugger does to every debuggee), resume, compare the output against a normal run.

With the production rule ">= 2 signals" a single flag must change NOTHING (that is the
calibration: no single point can flip the verdict). With the threshold forced to 1 the output
must change (verdict -> silent deferral -> wrong results, no crash).

Output is ASCII only. Usage:
  python tools/antidebug_flag_test.py --exe build/tb.exe --args "bench check_key 4"
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import os
import re
import sys

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
nt = ctypes.WinDLL("ntdll")
CREATE_SUSPENDED = 0x00000004
STARTF_USESTDHANDLES = 0x00000100
INFINITE = 0xFFFFFFFF


class PBI(ctypes.Structure):
    _fields_ = [("Reserved1", ctypes.c_void_p), ("PebBaseAddress", ctypes.c_void_p),
                ("Reserved2", ctypes.c_void_p * 2), ("UniqueProcessId", ctypes.c_void_p),
                ("Reserved3", ctypes.c_void_p)]


class STARTUPINFOA(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("lpReserved", wt.LPSTR), ("lpDesktop", wt.LPSTR), ("lpTitle", wt.LPSTR),
                ("dwX", wt.DWORD), ("dwY", wt.DWORD), ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD),
                ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD), ("dwFillAttribute", wt.DWORD),
                ("dwFlags", wt.DWORD), ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE),
                ("hStdError", wt.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE),
                ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD)]


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wt.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", wt.BOOL)]


def peb_of(pid):
    h = k32.OpenProcess(0x0400, False, pid)  # PROCESS_QUERY_INFORMATION
    pbi = PBI()
    nt.NtQueryInformationProcess(ctypes.c_void_p(h), 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None)
    k32.CloseHandle(h)
    return pbi.PebBaseAddress


def run(exe, args, set_flag):
    out = os.path.abspath("build/_adbg_out.txt")
    if os.path.exists(out):
        os.unlink(out)
    sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), None, True)
    k32.CreateFileA.restype = wt.HANDLE
    k32.CreateFileA.argtypes = [wt.LPCSTR, wt.DWORD, wt.DWORD, ctypes.POINTER(SECURITY_ATTRIBUTES),
                                wt.DWORD, wt.DWORD, wt.HANDLE]
    fh = k32.CreateFileA(out.encode(), 0x40000000, 0x00000001, ctypes.byref(sa), 2, 0x80, None)
    si = STARTUPINFOA()
    si.cb = ctypes.sizeof(si)
    si.dwFlags = STARTF_USESTDHANDLES
    si.hStdOutput = fh
    si.hStdError = fh
    pi = PROCESS_INFORMATION()
    cmd = ('"%s" %s' % (os.path.abspath(exe), args)).encode()
    if not k32.CreateProcessA(None, cmd, None, None, True, CREATE_SUSPENDED, None, None,
                              ctypes.byref(si), ctypes.byref(pi)):
        print("[!] CreateProcess failed: %d" % ctypes.get_last_error())
        return "", None
    k32.CloseHandle(fh)
    if set_flag:
        peb = peb_of(pi.dwProcessId)
        written = ctypes.c_size_t(0)
        one = ctypes.c_ubyte(1)
        ok = k32.WriteProcessMemory(pi.hProcess, ctypes.c_void_p(peb + 2), ctypes.byref(one), 1,
                                    ctypes.byref(written))
        got = ctypes.c_ubyte.from_address(0)
        read = ctypes.c_size_t(0)
        buf = ctypes.c_ubyte(0)
        k32.ReadProcessMemory(pi.hProcess, ctypes.c_void_p(peb + 2), ctypes.byref(buf), 1, ctypes.byref(read))
        print("[*] BeingDebugged: write ok=%s read back=%d" % (bool(ok), buf.value))
    k32.ResumeThread(pi.hThread)
    k32.WaitForSingleObject(pi.hProcess, INFINITE)
    c = wt.DWORD(0)
    k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(c))
    k32.CloseHandle(pi.hProcess)
    k32.CloseHandle(pi.hThread)
    text = open(out, "r", errors="replace").read()
    return text, c.value


# Lines whose content is a wall-clock measurement -- NOT an invariant of the program.
# Found the hard way (task C2): this case printed one "flake" where the ONLY difference between the
# plain and the flagged run was "ticks=0" vs "ticks=1". The target's bench line is
# "acc=%llu ticks=%lld iters=%llu" (testdata/target.c) and ticks is clock() difference in ms;
# four iterations of this loop round to 0 almost always, but once in a while the clock ticks over
# mid-run and the field becomes 1. Comparing it byte-for-byte turns an ordinary scheduling hiccup
# into "a single BeingDebugged signal already changed the result" -- a false accusation against the
# product. Measured on the real artifact: 8/8 plain runs said ticks=0, the flagged run that made
# this case red said ticks=1 (acc=782 in both, i.e. the deferral never fired).
#
# Refill is the opposite case and stays strict: "acc=%llu" is the deterministic answer, and a
# silent deferral changes it (verified: with the threshold forced to 1 the flagged run answers
# acc=185 instead of 782). So the fix is to drop measurement-only fields, not to loosen the check.
NONDET_KEYS = ("ticks=",)


def stable_lines(text):
    """Drop the measurement-only FIELDS (not whole lines!); keep the deterministic output.

    Dropping the whole line would turn this calibration into a check that can never fail: with the
    threshold forced to 1 the flagged run prints acc=185 -- but the same line also carries ticks=,
    so "skip the whole line" leaves both sides empty and the case reports OK (observed once while
    developing this very fix, which is exactly why it is spelled out here).
    """
    out = []
    for line in text.strip().splitlines():
        line = line.strip()
        for tok in NONDET_KEYS:
            line = re.sub(r"\s*" + re.escape(tok) + r"\S*", "", line)
        out.append(line.strip())
    return [x for x in out if x]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--args", default="bench check_key 4")
    ap.add_argument("--expect-unchanged", action="store_true",
                    help="production rule (>=2 signals): a single flag must change NOTHING")
    ap.add_argument("--strict", action="store_true",
                    help="compare the raw output including measurement-only fields (diagnostic)")
    a = ap.parse_args()
    plain, pc = run(a.exe, a.args, False)
    flagged, fc = run(a.exe, a.args, True)
    print("[*] plain   : rc=%s out=%r" % (pc, plain.strip()[:70]))
    print("[*] flagged : rc=%s out=%r" % (fc, flagged.strip()[:70]))
    if a.strict:
        same = plain.strip() == flagged.strip()
    else:
        same = stable_lines(plain) == stable_lines(flagged)
    if not same:
        # make the difference itself part of the record (the old script showed only the verdict)
        print("[*] comparison: plain=%r" % (stable_lines(plain),))
        print("[*]             flagged=%r" % (stable_lines(flagged),))
        print("[*] note: 'ticks=' fields are excluded -- they are wall-clock, not program output")
    if a.expect_unchanged:
        if same:
            print("[OK  ] one signal does not flip the verdict (as designed)")
            return 0
        print("[FAIL] a single BeingDebugged signal already changed the result")
        return 1
    if not same:
        print("[OK  ] verdict reached -> silent deferral changed the result (no crash: rc=%s)" % fc)
        return 0
    print("[FAIL] flagged run behaved exactly like the plain run")
    return 1


if __name__ == "__main__":
    sys.exit(main())
