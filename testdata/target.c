/* target.c - 差分测试与基准测试用目标程序
 *
 * 用法:
 *   target.exe <check_key|sum_to> <arg>        输出一行十进制结果
 *   target.exe bench <check_key|sum_to> <iters> 输出 acc/耗时（clock ticks）
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <windows.h>

__attribute__((noinline)) uint64_t check_key(uint64_t x) {
    return ((x * 7) + 42) ^ 0xFFu;
}

static volatile unsigned long long g_seed = 0;

__attribute__((noinline)) int sum_to(int n); /* 前置声明：下面要用到 */

/* ---- 覆盖用：内存寻址与宽度 ---- */
static long g_arr[8] = {1, 2, 3, 4, 5, 6, 7, 8};
static int8_t g_bytes[16] = {-1, 2, -3, 4, -5, 6, -7, 8, -9, 10, -11, 12, -13, 14, -15, 16};

/* 数组下标（index*scale 寻址）+ 8 位符号扩展 + 全局变量读写 */
__attribute__((noinline)) long mem_ops(int i) {
    int k = i & 7;
    g_arr[k] = g_arr[k] + 100;
    int8_t b = g_bytes[i & 15];
    uint8_t ub = (uint8_t)g_bytes[(i + 1) & 15];
    return g_arr[(k + 1) & 7] + (long)b * 3 + (long)ub;
}

/* 调用一个“不被保护”的本地函数：覆盖 OP_CALLN（原生调用） */
__attribute__((noinline)) static long local_square(long x) { return x * x + 1; }

__attribute__((noinline)) long calls_helper(long x) {
    long a = local_square(x);
    return a + local_square(x + 1);
}

/* ---- SIMD 诊断用变体：分别隔离"读进 XMM / 从 XMM 写出 / 两者都做 / 只碰槽位" ----
 * 这些函数用内联汇编精确控制指令，用来定位 SIMD 路径上的访问违例。 */
static unsigned char g_sbuf[64];

#define ASM_LINE(a, b) __asm__ __volatile__(a "\n\t" b)

__attribute__((noinline)) long simd_slot(long x) { /* 只写 XMM10 槽位，再读回来 */
    unsigned long long a = 0;
    __asm__ __volatile__("movq %1, %%xmm10\n\tmovq %%xmm10, %0"
                         : "=r"(a) : "r"((unsigned long long)x) : "xmm10");
    return (long)a;
}

__attribute__((noinline)) long simd_r(long x) { /* 内存 → XMM → 通用寄存器 */
    (void)x;
    unsigned long long a = 0;
    __asm__ __volatile__("movdqu (%1), %%xmm0\n\tmovq %%xmm0, %0"
                         : "=r"(a) : "r"(g_sbuf) : "xmm0", "memory");
    return (long)a;
}

__attribute__((noinline)) long simd_w(long x) { /* 通用寄存器 → XMM → 内存 */
    __asm__ __volatile__("movq %1, %%xmm0\n\tmovups %%xmm0, (%0)"
                         :: "r"(g_sbuf), "r"((unsigned long long)x) : "xmm0", "memory");
    return (long)(g_sbuf[0] ^ g_sbuf[8]);
}

__attribute__((noinline)) long simd_rw(long x) { /* 内存 → XMM → 内存（= 真实 memcpy 形态） */
    (void)x;
    __asm__ __volatile__("movdqu (%1), %%xmm0\n\tmovups %%xmm0, (%0)"
                         :: "r"(g_sbuf + 16), "r"(g_sbuf) : "xmm0", "memory");
    return (long)(g_sbuf[16] ^ g_sbuf[24]);
}

/* 16 字节搬运：gcc 对 16 字节 memcpy 会用 SSE 的 movdqa/movups（覆盖 SIMD 位搬运）。
 * 单独抽成一个 noinline 函数，既保证 gcc 真的发出 SSE 指令，又便于单独保护它。 */
static unsigned char g_buf[64];

__attribute__((noinline)) void copy16(void *d, const void *s) {
    __builtin_memcpy(d, s, 16);
}

__attribute__((noinline)) long vec_copy(long x) {
    unsigned long long v[2];
    v[0] = (unsigned long long)x;
    v[1] = (unsigned long long)x * 3u + 1u;
    copy16(g_buf, v);         /* 16 字节对齐搬移 */
    copy16(g_buf + 5, g_buf); /* 未对齐搬移 */
    return (long)(g_buf[0] ^ g_buf[7] ^ g_buf[15] ^ g_buf[20]);
}

/* 128 位整数运算：gcc 会用 add/adc 与 sub/sbb（覆盖带进位/借位的 ADC/SBB） */
static unsigned long long g_hi, g_lo;

__attribute__((noinline)) long add128(unsigned long long ah, unsigned long long al,
                                      unsigned long long bh, unsigned long long bl) {
    unsigned __int128 a = ((unsigned __int128)ah << 64) | (unsigned __int128)al;
    unsigned __int128 b = ((unsigned __int128)bh << 64) | (unsigned __int128)bl;
    unsigned __int128 s = a + b;
    g_lo = (unsigned long long)s;
    g_hi = (unsigned long long)(s >> 64);
    return (long)(unsigned long long)(g_lo ^ g_hi);
}

__attribute__((noinline)) long sub128(unsigned long long ah, unsigned long long al,
                                      unsigned long long bh, unsigned long long bl) {
    unsigned __int128 a = ((unsigned __int128)ah << 64) | (unsigned __int128)al;
    unsigned __int128 b = ((unsigned __int128)bh << 64) | (unsigned __int128)bl;
    unsigned __int128 d = a - b;
    g_lo = (unsigned long long)d;
    g_hi = (unsigned long long)(d >> 64);
    return (long)(unsigned long long)(g_lo ^ g_hi);
}

__attribute__((noinline)) long mul128(unsigned long long ah, unsigned long long al,
                                      unsigned long long bh, unsigned long long bl) {
    unsigned __int128 a = ((unsigned __int128)ah << 64) | (unsigned __int128)al;
    unsigned __int128 b = ((unsigned __int128)bh << 64) | (unsigned __int128)bl;
    unsigned __int128 p = a * b;
    g_lo = (unsigned long long)p;
    g_hi = (unsigned long long)(p >> 64);
    return (long)(unsigned long long)(g_lo ^ g_hi);
}

/* 诊断用：把 128 位乘法的各个部分拆成独立函数（不用 switch —— 带 switch 的函数会撞上
 * "跳转表默认分支落在函数外" 的限制，见 STATUS）。 */
#define MULD_PARAMS unsigned long long ah, unsigned long long al, unsigned long long bh, unsigned long long bl
#define MULD_VARS                                                                    \
    unsigned __int128 a = ((unsigned __int128)ah << 64) | (unsigned __int128)al;     \
    unsigned __int128 b = ((unsigned __int128)bh << 64) | (unsigned __int128)bl;

__attribute__((noinline)) long m_lo(MULD_PARAMS) { MULD_VARS return (long)(unsigned long long)(a * b); }
__attribute__((noinline)) long m_hi(MULD_PARAMS) { MULD_VARS return (long)(unsigned long long)((a * b) >> 64); }
__attribute__((noinline)) long m_allo(MULD_PARAMS) { return (long)(unsigned long long)(al * bl); }
__attribute__((noinline)) long m_allohi(MULD_PARAMS) { return (long)(unsigned long long)(((unsigned __int128)al * bl) >> 64); }
__attribute__((noinline)) long m_mix(MULD_PARAMS) {
    MULD_VARS
    unsigned __int128 t = (a * b) + ((unsigned __int128)ah << 64);
    return (long)(unsigned long long)t;
}
__attribute__((noinline)) long m_mixhi(MULD_PARAMS) {
    MULD_VARS
    unsigned __int128 t = (a * b) + ((unsigned __int128)ah << 64);
    return (long)(unsigned long long)(t >> 64);
}

/* 16 字节按位异或：gcc 会用 pxor（覆盖非清零形式的按位 SIMD） */
typedef unsigned char v16u __attribute__((vector_size(16)));

__attribute__((noinline)) long vec_bitwise(long x) {
    v16u a, b, c;
    unsigned long long *pa = (unsigned long long *)(void *)&a;
    unsigned long long *pb = (unsigned long long *)(void *)&b;
    pa[0] = (unsigned long long)x;
    pa[1] = (unsigned long long)x * 3u + 1u;
    pb[0] = (unsigned long long)x >> 1;
    pb[1] = (unsigned long long)x * 7u + 5u;
    __asm__ __volatile__("" ::: "memory");
    c = a ^ b;
    __asm__ __volatile__("" ::: "memory");
    unsigned long long *pc = (unsigned long long *)(void *)&c;
    return (long)(pc[0] ^ pc[1]);
}

/* 诊断变体：只做 pxor 并取低 8 字节（不经 MOVHLPS），用于二分定位 */
__attribute__((noinline)) long vb_xor_only(long x) {
    v16u a, b, c;
    unsigned long long *pa = (unsigned long long *)(void *)&a;
    unsigned long long *pb = (unsigned long long *)(void *)&b;
    pa[0] = (unsigned long long)x;
    pa[1] = (unsigned long long)x * 3u + 1u;
    pb[0] = (unsigned long long)x >> 1;
    pb[1] = (unsigned long long)x * 7u + 5u;
    __asm__ __volatile__("" ::: "memory");
    c = a ^ b;
    __asm__ __volatile__("" ::: "memory");
    unsigned long long *pc = (unsigned long long *)(void *)&c;
    return (long)pc[0];
}

/* 位扫描：gcc 在无 BMI 时会用 bsf/bsr（覆盖 BSF/BSR） */
__attribute__((noinline)) long bit_scan(long x) {
    unsigned long long v = (unsigned long long)x;
    if (v == 0) return -1;
    return (long)((unsigned long long)__builtin_ctzll(v) + (unsigned long long)__builtin_clzll(v) * 1000u);
}

/* 向量拼装：gcc 常用 punpcklqdq 把两个 64 位标量合成一个 XMM */
typedef unsigned long long v2u __attribute__((vector_size(16)));

__attribute__((noinline)) long vec_pair(long a, long b) {
    v2u v = {(unsigned long long)a, (unsigned long long)b};
    __asm__ __volatile__("" ::: "memory");
    unsigned long long r[2];
    *(v2u *)(void *)r = v;
    __asm__ __volatile__("" ::: "memory");
    return (long)(r[0] ^ r[1]);
}

/* 打包（向量）加法：gcc 会用 paddd（覆盖打包 SIMD 算术） */
typedef unsigned int v4u __attribute__((vector_size(16)));

__attribute__((noinline)) long vec_add(long x) {
    v4u a = {(unsigned)x, (unsigned)x * 3u, (unsigned)x + 7u, (unsigned)x ^ 0x55u};
    v4u b = {(unsigned)x >> 1, (unsigned)x * 7u, (unsigned)x + 1u, (unsigned)x ^ 0xAAu};
    __asm__ __volatile__("" ::: "memory");
    v4u c = a + b;
    __asm__ __volatile__("" ::: "memory");
    unsigned r[4];
    *(v4u *)(void *)r = c;
    return (long)(r[0] ^ r[1] ^ r[2] ^ r[3]);
}

/* double 的位往返（不做浮点运算）：看 gcc 是否用 movsd/movapd（覆盖标量搬移） */
__attribute__((noinline)) long dbl_roundtrip(long x) {
    /* 通过指针搬 double（不做任何浮点运算）：参数是整数指针，ABI 不涉及 XMM */
    double buf[4];
    buf[0] = (double)(long)(x & 0xFF);
    buf[1] = (double)(long)((x >> 8) & 0xFF);
    __asm__ __volatile__("" ::: "memory");
    double c0 = buf[0];
    double c1 = buf[1];
    __asm__ __volatile__("" ::: "memory");
    buf[2] = c0;
    buf[3] = c1;
    __asm__ __volatile__("" ::: "memory");
    unsigned long long r0, r1;
    __builtin_memcpy(&r0, &buf[2], 8);
    __builtin_memcpy(&r1, &buf[3], 8);
    return (long)(r0 ^ r1);
}

/* 原子操作：gcc 会用 lock xadd / lock cmpxchg / xchg（覆盖原子读改写） */
static volatile unsigned long long g_atom;
static volatile unsigned long long g_bump;

__attribute__((noinline)) long atom_ops(long x) {
    unsigned long long v = (unsigned long long)x | 1ull;
    unsigned long long old = __atomic_fetch_add(&g_atom, v, __ATOMIC_SEQ_CST);
    unsigned long long prev = __sync_val_compare_and_swap(&g_atom, old + v, v * 2ull);
    unsigned long long sw = __sync_lock_test_and_set(&g_atom, v * 3ull);
    return (long)(old ^ prev ^ sw ^ g_atom);
}

/* 被保护的原子自增：多线程并发调用时必须一次不丢（真机验证原子性） */
__attribute__((noinline)) long atom_bump(long x) {
    __atomic_fetch_add(&g_bump, 1ull, __ATOMIC_SEQ_CST);
    return x;
}

/* 有符号 128 位乘法：gcc 会用单操作数 imul（覆盖单操作数 IMUL） */
__attribute__((noinline)) long smul128(long ah, long al, long bh, long bl) {
    __int128 a = ((__int128)ah << 64) | (unsigned long long)al;
    __int128 b = ((__int128)bh << 64) | (unsigned long long)bl;
    __int128 p = a * b;
    g_lo = (unsigned long long)p;
    g_hi = (unsigned long long)(p >> 64);
    return (long)(unsigned long long)(g_lo ^ g_hi);
}

/* 浮点标量（全程在内部做，进出都是整数，避免触碰只支持整数的调用约定） */
__attribute__((noinline)) long fp_mix(long x) {
    double a = (double)(long)(x & 0xFFFF);          /* cvtsi2sd */
    double b = (double)(long)((x >> 16) & 0xFFFF);  /* cvtsi2sd */
    double c = a * b + a / (b + 1.0);               /* mulsd / divsd / addsd */
    double d = c - (double)(long)(x & 7);           /* subsd / cvtsi2sd */
    long bigger = (d > a) ? 1 : 0;                  /* ucomisd + setcc */
    long r;
    __builtin_memcpy(&r, &d, 8);                    /* movq */
    return (r ^ (long)d) + bigger;                  /* cvttsd2si */
}

/* 冷块用例：switch 的默认分支被 gcc 放到很远的地方（函数主体范围之外）。
 * 之前这种函数直接拒绝；现在靠"冷块孤岛"支持。 */
__attribute__((noinline)) long disp128(int sel, unsigned long long v) {
    unsigned long long ah = v, al = v * 3u + 1u, bh = v >> 1, bl = v * 7u + 5u;
    unsigned __int128 a = ((unsigned __int128)ah << 64) | (unsigned __int128)al;
    unsigned __int128 b = ((unsigned __int128)bh << 64) | (unsigned __int128)bl;
    unsigned __int128 p = a * b;
    switch (sel & 7) {
    case 0: return (long)(unsigned long long)p;
    case 1: return (long)(unsigned long long)(p >> 64);
    case 2: return (long)(unsigned long long)(al ^ bl);
    case 3: return (long)(unsigned long long)(ah + bh);
    case 4: return (long)(unsigned long long)(al * bl);
    case 5: return (long)(unsigned long long)((a >> 64) ^ (b >> 64));
    case 6: return (long)(unsigned long long)(p ^ a);
    default: return (long)(unsigned long long)(p + b);
    }
}

/* switch：覆盖跳转表（间接 JMP）——gcc 生成的是"分裂形态"（lea 表基址 + movsxd + add + jmp *reg） */
__attribute__((noinline)) long dispatch(int op, long x) {
    switch (op & 7) {
    case 0: return x + 1;
    case 1: return x * 3;
    case 2: return x ^ 0x55;
    case 3: return x - 7;
    case 4: return x << 2;
    case 5: return x >> 1;
    case 6: return x + 100;
    default: return -x;
    }
}

/* 通过函数指针调用：覆盖间接 CALL（CALLR）——虚调用/回调的真实形态 */
__attribute__((noinline)) long square_helper(long x) { return x * x + 3; }

__attribute__((noinline)) long via_ptr(long (*f)(long), long x) {
    long a = f(x);
    return a + 1;
}

/* 调用一个“被保护”的函数：覆盖 VM -> thunk -> VM 的嵌套 */
__attribute__((noinline)) long calls_protected(long x) {
    return (long)check_key((uint64_t)x) + (long)sum_to((int)(x & 0xFF));
}

/* 带栈帧的函数：volatile 局部强制占用栈槽（eff < 0），
 * 第 5 个参数 e 位于调用方栈帧（eff >= 0）——两者都依赖 FRAME_SKEW 修正正确。 */
/* 针对性压测：framed 内部有 movdqu（会碰共享 XMM 寄存器堆），多线程密集调用最容易放大共享状态竞争。 */
__attribute__((noinline)) long framed(long a, long b, long c, long d, long e);
static volatile LONG g_framed_bad = 0;
static DWORD WINAPI framed_mt_worker(LPVOID p) {
    long seed = (long)(long long)p;
    for (int i = 0; i < 300000; i++) {
        long x = seed + (i & 0xFF);
        long want = x + (x + 1) + (x + 2) + (x + 3) + (x + 4);
        long got = framed(x, x + 1, x + 2, x + 3, x + 4);
        if (got != want) {
            InterlockedIncrement(&g_framed_bad);
            if (g_framed_bad > 5) return 0;
        }
    }
    return 0;
}

__attribute__((noinline)) long framed(long a, long b, long c, long d, long e) {
    volatile long acc = a + b;
    acc += c + d;
    return acc + e;
}

__attribute__((noinline)) int sum_to(int n) {
    int s = 0;
    for (int i = 1; i <= n; i++) s += i;
    return s;
}

/* ---- 并发用例：验证解释器里的共享状态（明文解密缓存）在多线程下是否安全 ----
 * 4 个线程各自大量调用被保护函数，各算一个累加和；任何一次拿到错误的字节码都会让结果不同。
 * 原生与被保护两侧必须打印完全相同的向量。 */
typedef struct {
    long long acc;
    unsigned long long seed;
} mt_arg;

static DWORD WINAPI mt_worker(LPVOID p) {
    mt_arg *a = (mt_arg *)p;
    unsigned long long acc = a->seed;
    /* 刻意调用**多于缓存槽位数**（默认 4）的不同被保护函数：
     * 这样多个线程会同时走"找一个槽放新明文"的路径——正是共享状态最容易出问题的地方。 */
    for (int i = 0; i < 20000; i++) {
        acc = acc * 31u + check_key((unsigned long long)(i & 0xFFFF));
        acc = acc * 31u + (unsigned long long)sum_to((i & 0xFF) + 1);
        acc = acc * 31u + (unsigned long long)via_ptr(square_helper, (long)(i & 0xFFF));
        acc = acc * 31u + (unsigned long long)framed((long)i, (long)i + 1, (long)i + 2, (long)i + 3, (long)i + 4);
        acc = acc * 31u + (unsigned long long)calls_helper((long)(i & 0xFF));
        acc = acc * 31u + (unsigned long long)calls_protected((long)(i & 0xFF));
        atom_bump((long)i); /* 每次迭代一次原子自增：4 线程 × 20000 = 80000 */
    }
    a->acc = (long long)acc;
    return 0;
}

/* 崩溃自证：CI 上 mt 偶发崩溃时，注解里只有"protected 为空"，看不到崩在哪。
 * 这里装一个顶层异常过滤器，把异常码、故障地址、所属模块和模块内偏移打到 stderr ---
 * E2E 的失败诊断会抓 stderr，于是 CI 注解里就能带上崩溃地址，便于映射回 blob 符号。 */
/* VEH 版本：SetUnhandledExceptionFilter 对某些线程内/收尾期的访问违例不会触发（CI 实测 err 为空），
 * 而向量化异常处理器更早、范围更广。只打印一次，然后 CONTINUE_SEARCH，不改变原有退出行为。 */
static volatile LONG g_crash_reported = 0;
static void vmp_crash_line(EXCEPTION_POINTERS *ep) {
    void *addr = (void *)ep->ExceptionRecord->ExceptionAddress;
    HMODULE mod = NULL;
    fprintf(stderr, "CRASH code=0x%08lX addr=%p", (unsigned long)ep->ExceptionRecord->ExceptionCode, addr);
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)addr, &mod) && mod) {
        fprintf(stderr, " module=%p rva=0x%llX", (void *)mod,
                (unsigned long long)((unsigned char *)addr - (unsigned char *)mod));
    }
    /* 访问违例时 ExceptionInformation[1] 就是**出错的数据地址** —— 这比任何反汇编偏移都直接。 */
    if (ep->ExceptionRecord->ExceptionCode == 0xC0000005 && ep->ExceptionRecord->NumberParameters >= 2) {
        fprintf(stderr, " fault=%p op=%s",
                (void *)ep->ExceptionRecord->ExceptionInformation[1],
                ep->ExceptionRecord->ExceptionInformation[0] ? "write" : "read");
    }
    fprintf(stderr, "\n");
    /* 再把 GPR 打出来：偶发崩溃往往只差一个寄存器的值就能定性（尤其/疑似缓存/原子路径）。 */
    if (ep->ContextRecord) {
        CONTEXT *c = ep->ContextRecord;
        fprintf(stderr, "  rax=%p rbx=%p rcx=%p rdx=%p rsi=%p rdi=%p rbp=%p rsp=%p\n",
                (void *)c->Rax, (void *)c->Rbx, (void *)c->Rcx, (void *)c->Rdx,
                (void *)c->Rsi, (void *)c->Rdi, (void *)c->Rbp, (void *)c->Rsp);
        fprintf(stderr, "  r8=%p r9=%p r10=%p r11=%p r12=%p r13=%p r14=%p r15=%p\n",
                (void *)c->R8, (void *)c->R9, (void *)c->R10, (void *)c->R11,
                (void *)c->R12, (void *)c->R13, (void *)c->R14, (void *)c->R15);
    }
    fflush(stderr);
}
static LONG WINAPI vmp_veh(EXCEPTION_POINTERS *ep) {
    if (InterlockedExchange(&g_crash_reported, 1) == 0) {
        vmp_crash_line(ep);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG WINAPI vmp_crash_filter(EXCEPTION_POINTERS *ep) {
    if (InterlockedExchange(&g_crash_reported, 1) == 0) {
        vmp_crash_line(ep);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

int main(int argc, char **argv) {
    AddVectoredExceptionHandler(1, vmp_veh);   /* 更早、更广：CI 上那个 AV 只有它能抓到 */
    SetUnhandledExceptionFilter(vmp_crash_filter);
    if (argc >= 2 && strcmp(argv[1], "framed_mt") == 0) {
        enum { NT = 8 };
        HANDLE th[NT];
        for (int i = 0; i < NT; i++) th[i] = CreateThread(NULL, 0, framed_mt_worker, (LPVOID)(long long)(i + 1), 0, NULL);
        for (int i = 0; i < NT; i++) { WaitForSingleObject(th[i], INFINITE); CloseHandle(th[i]); }
        printf("framed_mt bad=%ld\n", (long)g_framed_bad);
        return g_framed_bad ? 1 : 0;
    }
    if (argc >= 2 && strcmp(argv[1], "crash_test") == 0) { /* 自检用：故意解引用空指针 */
        volatile int *nullp = (volatile int *)0;
        *nullp = 1;
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "mt") == 0) {
        enum { NT = 4 };
        HANDLE th[NT];
        mt_arg args[NT];
        for (int i = 0; i < NT; i++) {
            args[i].seed = (unsigned long long)(i + 1);
            args[i].acc = 0;
            th[i] = CreateThread(NULL, 0, mt_worker, &args[i], 0, NULL);
            if (!th[i]) { fprintf(stderr, "CreateThread failed\n"); return 2; }
        }
        for (int i = 0; i < NT; i++) {
            WaitForSingleObject(th[i], INFINITE);
            CloseHandle(th[i]);
        }
        for (int i = 0; i < NT; i++) printf("%lld\n", args[i].acc);
        printf("bump=%llu\n", g_bump);
        return 0;
    }
    if (argc < 3) {
        fprintf(stderr, "usage: target.exe <check_key|sum_to> <arg> | bench <noname> <iters>\n");
        return 2;
    }
    if (strcmp(argv[1], "bench") == 0) {
        if (argc < 4) return 2;
        unsigned long long iters = strtoull(argv[3], NULL, 0);
        unsigned long long acc = 0;
        /* volatile seed：阻止编译器把循环强度削减/闭式求值，保证两侧都在真调用 */
        g_seed = (unsigned long long)(argc > 4 ? strtoull(argv[4], NULL, 0) : 1);
        clock_t t0 = clock();
        if (strcmp(argv[2], "check_key") == 0) {
            for (unsigned long long i = 0; i < iters; i++) acc += check_key(i + g_seed);
        } else {
            /* 固定小参数：避免 VM 侧每次调用都跑 65535 次循环，导致基准不可测 */
            for (unsigned long long i = 0; i < iters; i++) acc += (unsigned long long)sum_to((int)(100 + (g_seed & 1)));
        }
        clock_t t1 = clock();
        printf("acc=%llu ticks=%lld iters=%llu\n", acc, (long long)(t1 - t0), iters);
        return 0;
    }

    uint64_t x = strtoull(argv[2], NULL, 0);
    if (strcmp(argv[1], "framed") == 0) {
        long a = (long)x;
        printf("%ld\n", framed(a, a + 1, a + 2, a + 3, a + 4));
        return 0;
    }
    if (strcmp(argv[1], "mem_ops") == 0) {
        printf("%ld\n", mem_ops((int)x));
        return 0;
    }
    if (strcmp(argv[1], "simd_slot") == 0) {
        printf("%ld\n", simd_slot((long)x));
        return 0;
    }
    if (strcmp(argv[1], "simd_r") == 0) {
        printf("%ld\n", simd_r((long)x));
        return 0;
    }
    if (strcmp(argv[1], "simd_w") == 0) {
        printf("%ld\n", simd_w((long)x));
        return 0;
    }
    if (strcmp(argv[1], "simd_rw") == 0) {
        printf("%ld\n", simd_rw((long)x));
        return 0;
    }
    if (strcmp(argv[1], "vb_xor_only") == 0) {
        printf("%ld\n", vb_xor_only((long)x));
        return 0;
    }
    if (strcmp(argv[1], "dbl_roundtrip") == 0) {
        printf("%ld\n", dbl_roundtrip((long)x));
        return 0;
    }
    if (strcmp(argv[1], "fp_mix") == 0) {
        printf("%ld\n", fp_mix((long)x));
        return 0;
    }
    if (strcmp(argv[1], "smul128") == 0) {
        long v = (long)x;
        printf("%ld\n", smul128(v, v + 3, v - 7, v * 5 + 1));
        return 0;
    }
    if (strcmp(argv[1], "atom_ops") == 0) {
        printf("%ld\n", atom_ops((long)x));
        return 0;
    }
    if (strcmp(argv[1], "vec_add") == 0) {
        printf("%ld\n", vec_add((long)x));
        return 0;
    }
    if (strcmp(argv[1], "bit_scan") == 0) {
        printf("%ld\n", bit_scan((long)x));
        return 0;
    }
    if (strcmp(argv[1], "vec_pair") == 0) {
        printf("%ld\n", vec_pair((long)x, (long)(x * 3 + 1)));
        return 0;
    }
    if (strcmp(argv[1], "vec_bitwise") == 0) {
        printf("%ld\n", vec_bitwise((long)x));
        return 0;
    }
    if (strcmp(argv[1], "vec_copy") == 0) {
        printf("%ld\n", vec_copy((long)x));
        return 0;
    }
    if (strcmp(argv[1], "add128") == 0) {
        unsigned long long v = (unsigned long long)x;
        printf("%ld\n", add128(v, v * 3u, v >> 1, v * 7u + 1u));
        return 0;
    }
    if (argv[1][0] == 'm' && argv[1][1] == '_') {
        unsigned long long v = strtoull(argv[2], NULL, 0);
        unsigned long long ah = v, al = v * 3u + 1u, bh = v >> 1, bl = v * 7u + 5u;
        long (*f)(MULD_PARAMS) = 0;
        if (strcmp(argv[1], "m_lo") == 0) f = m_lo;
        else if (strcmp(argv[1], "m_hi") == 0) f = m_hi;
        else if (strcmp(argv[1], "m_allo") == 0) f = m_allo;
        else if (strcmp(argv[1], "m_allohi") == 0) f = m_allohi;
        else if (strcmp(argv[1], "m_mix") == 0) f = m_mix;
        else if (strcmp(argv[1], "m_mixhi") == 0) f = m_mixhi;
        if (!f) { fprintf(stderr, "unknown %s\n", argv[1]); return 2; }
        printf("%ld\n", f(ah, al, bh, bl));
        return 0;
    }
    if (strcmp(argv[1], "mul128") == 0) {
        unsigned long long v = (unsigned long long)x;
        printf("%ld\n", mul128(v, v * 3u + 1u, v >> 1, v * 7u + 5u));
        return 0;
    }
    if (strcmp(argv[1], "sub128") == 0) {
        unsigned long long v = (unsigned long long)x;
        printf("%ld\n", sub128(v, v * 3u, v >> 1, v * 7u + 1u));
        return 0;
    }
    if (strcmp(argv[1], "dispatch") == 0) {
        printf("%ld\n", dispatch((int)(x & 0xFFFF), (long)x));
        return 0;
    }
    if (strcmp(argv[1], "callptr") == 0) {
        /* 通过函数指针调用（间接 CALL）：把 square_helper 的地址传进去 */
        printf("%ld\n", via_ptr(square_helper, (long)x));
        return 0;
    }
    if (strcmp(argv[1], "calls_helper") == 0) {
        printf("%ld\n", calls_helper((long)x));
        return 0;
    }
    if (strcmp(argv[1], "calls_protected") == 0) {
        printf("%ld\n", calls_protected((long)x));
        return 0;
    }
    if (strcmp(argv[1], "check_key") == 0) {
        printf("%llu\n", (unsigned long long)check_key(x));
    } else {
        printf("%d\n", sum_to((int)x));
    }
    return 0;
}