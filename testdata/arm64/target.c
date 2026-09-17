/* target.c - Linux/arm64 端到端目标程序（freestanding，CI 里用 qemu 跑）
 *
 * 目的：让"ARM64 lifter + 打包器 + 宿主入口 + 解释器 + 客户机语义"整条链都进端到端，
 * 而不是只跑手写字节码。
 *
 * 设计约束（重要）：
 *   - **被保护的函数**（check_key / sum_to）刻意只用 lifter 支持的子集：
 *     整数加减/逻辑/移位/乘、加载存储、比较与条件分支；不用除法（udiv ✗）、
 *     不用 SIMD ✗、不用条件比较 CCMP ✗、不用复合条件、不用 switch。
 *     编译参数用 -O1 -fno-tree-vectorize，避免向量化把代码带出子集。
 *   - **不被保护的代码**（下面的 syscall 包装与 _start）随便用什么指令都行，
 *     它们不会进 VM。
 *   - 没有 libc：直接用 write/exit 系统调用把结果打到 stdout。
 */
typedef unsigned long u64;
typedef long i64;

static long syscall3(long n, long a, long b, long c) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}

static void put_u64(u64 v) {
    char buf[24];
    int i = 24;
    buf[--i] = '\n';
    do {
        buf[--i] = (char)('0' + (int)(v % 10));
        v /= 10;
    } while (v != 0);
    syscall3(64 /* write */, 1, (long)(buf + i), 24 - i);
}

/* ---- 被保护的函数：只用可 lift 的子集 ---- */

__attribute__((noinline)) u64 check_key(u64 x) {
    return ((x * 7) + 42) ^ 0xFFu;
}

__attribute__((noinline)) u64 sum_to(u64 n) {
    u64 s = 0;
    for (u64 i = 1; i <= n; i++) {
        s += i;
    }
    return s;
}

/* ---- 不保护的驱动代码 ---- */

void _start(void) {
    const u64 keys[6] = {0, 1, 10, 255, 12345, 1000000};
    for (int i = 0; i < 6; i++) {
        put_u64(check_key(keys[i]));
    }
    put_u64(sum_to(0));
    put_u64(sum_to(7));
    put_u64(sum_to(1000));
    syscall3(93 /* exit */, 0, 0, 0);
    for (;;) {
    }
}
