/* e2e32.c - tiny 32-bit (i686/PE32) end-to-end subject for tools/e2e_32bit.ps1.
 *
 * Why a separate file from testdata/target.c: target.c is a printf/argv driven CLI, so it
 * has to be compared by parsing stdout. For the 32-bit path we want the cheapest possible
 * oracle: each function RETURNS a small distinct value and natively `main` hands it straight
 * back as the process exit code. Pack a function, run the packed exe with that selector,
 * compare the exit code with the unpacked exe - no output parsing, no native calls from
 * inside the guest (the guest never calls printf here).
 *
 * Keep every expected value in 0..255 and never 0 or 1: the exit code is what we read.
 * Compile with -O0: the point of the locals/loop cases is to force real stack traffic
 * ([ebp-N] STORE/LOAD), which is exactly the shape that exposed the i686 thunk bug
 * where 32-bit stores left the upper half of each u64 ctx register slot as stack garbage.
 */
#include <string.h>

/* no locals at all: push/mov/pop/ret only */
int e32_const(void) { return 100; }

/* two locals, one multiply: STORE/LOAD through [ebp-4]/[ebp-8] */
int e32_local(void) { int a = 7; int b = 5; return a * b; }   /* 35 */

/* loop with a stack-resident counter */
int e32_loop(void) { int i; int s = 0; for (i = 1; i <= 10; i++) s += i; return s; }  /* 55 */

/* cdecl multi-argument: the guest must read the caller frame through the simulated stack */
int e32_args(int a, int b, int c) { return a * 100 + b * 10 + c; }   /* 123 */

/* many locals: a longer bytecode (the class that used to run off the end) */
int e32_big(void) {
    int v0 = 1, v1 = 2, v2 = 3, v3 = 4, v4 = 5, v5 = 6, v6 = 7, v7 = 8;
    return v0 + v1 + v2 + v3 + v4 + v5 + v6 + v7;   /* 36 */
}

/* Address probes (not pass/fail cases by themselves; used to locate the guest frame).
 * e32_arga returns the absolute address the guest computes for its own arg1 ([ebp+8]);
 * native and packed differ by exactly "how far the simulated frame is from the real one".
 * e32_argm returns the address of a GLOBAL, which is the same in both runs and therefore
 * gives an absolute reference point to compare against. */
int g_marker32 = 0x5A;
int *g_markerp;   /* main stores &m (a local in main) here, so the callee can compare */
int e32_arga(int a) { return (int)(unsigned)&a; }
int e32_argm(void) { return (int)(unsigned)&g_marker32; }
/* &a (guest-computed arg address) minus a REAL caller-stack local address kept in a global.
 * Both are stack addresses inside one run, so the value is comparable native vs packed,
 * unlike absolute addresses (the native exe gets ASLR, the packed one is fixed at 0x400000). */
int e32_dist(int a) { return (int)((unsigned)&a - (unsigned)g_markerp); }

/* pure shift: isolates the shift-class ALU_RI path (suspected after STATUS #478, where
 * a*100+b*10+c failed while a*b passed - b*10 compiles to shift/add sequences). */
/* same shift, but on a CONSTANT LOCAL: no argument is read at all, so a wrong result
 * here isolates the shift semantics itself from anything about caller-frame reads. */
int e32_shl_imm(void) { int v = 1; return v << 3; }                  /* 8 */
int e32_shr_imm(void) { unsigned v = 0x100; return (int)(v >> 4); }  /* 16 */
int e32_shl(int a) { return a << 3; }                                /* 8 */
int e32_shr(unsigned a) { return (int)(a >> 4); }                    /* 0x10 */

/* floating point: exercises the blob FP path. cdecl passes doubles on the stack,
 * so this also covers 8-byte stack arguments (a shape the integer cases miss). */
int e32_dbl(void) { double v = 1.5 + 2.5; return (int)v; }          /* 4 */
int e32_dblarg(double a, double b) { return (int)(a * b); }         /* 1.5 * 2.0 = 3 */

/* nested call: the guest calls another (native) function and uses its result */
int e32_helper(int x) { return x + 1; }
int e32_call(void) { return e32_helper(41); }   /* 42 */

int main(int argc, char **argv) {
    int m = 5;
    g_markerp = &m;
    const char *w = (argc > 1) ? argv[1] : "e32_const";
    if (!strcmp(w, "e32_const")) return e32_const();
    if (!strcmp(w, "e32_local")) return e32_local();
    if (!strcmp(w, "e32_loop"))  return e32_loop();
    if (!strcmp(w, "e32_args"))  return e32_args(1, 2, 3);
    if (!strcmp(w, "e32_big"))   return e32_big();
    if (!strcmp(w, "e32_call"))  return e32_call();
    if (!strcmp(w, "e32_dist")) return e32_dist(0x11111111);
    if (!strcmp(w, "e32_arga")) return e32_arga(0x11111111);
    if (!strcmp(w, "e32_argm")) return e32_argm();
    if (!strcmp(w, "e32_shl_imm")) return e32_shl_imm();
    if (!strcmp(w, "e32_shr_imm")) return e32_shr_imm();
    if (!strcmp(w, "e32_shl"))   return e32_shl(1);
    if (!strcmp(w, "e32_shr"))   return e32_shr(0x100);
    if (!strcmp(w, "e32_dbl"))   return e32_dbl();
    if (!strcmp(w, "e32_dblarg")) return e32_dblarg(1.5, 2.0);
    return 250;   /* unknown selector: loud, and out of the expected range */
}
