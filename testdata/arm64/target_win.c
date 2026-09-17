/* target_win.c - Windows/arm64 端到端目标（freestanding，不需要 Windows SDK）
 *
 * 与 testdata/arm64/target.c 的区别：那个是 Linux/ELF（用 svc 做 write/exit），
 * 这个只做计算，把结果**组合成一个退出码**返回 —— 于是不需要任何 import：
 * PE 的 loader 在 entry 返回后会把返回值当进程退出码，PowerShell 的 $LASTEXITCODE 能读到。
 * 这样在 Windows/arm64 上就能直接比对 native 与打包后的结果。
 *
 * 被保护的 check_key / sum_to 刻意只用 lifter 支持的子集（加减/乘/比较/条件分支）。 */
typedef unsigned long long u64;

__attribute__((noinline)) u64 check_key(u64 x) {
    return ((x * 7) + 42) ^ 0xFFu;
}

__attribute__((noinline)) u64 sum_to(u64 n) {
    u64 s = 0;
    /* 倒计数写法：语义与 for (i=1;i<=n;i++) 完全相同，但**不会**让 clang 去算循环次数。
     * clang -O1 对 `i <= n` 这种形式会做强度削减，生成 UMULH + EXTR 的倒数序列，
     * 而 lifter 的子集里没有 UMULH/EXTR（CI 就是这么报的）。 */
    while (n != 0) {
        s += n;
        n--;
    }
    return s;
}

int entry(void) {
    u64 a = check_key(10);   /* native 143 */
    u64 b = check_key(255);  /* native 2012 */
    u64 c = sum_to(7);       /* 28 */
    u64 d = sum_to(1000);    /* 500500 */
    /* 混合成一个 30 位以内的退出码：任何一项算错都会改变它（且避开 0xC0000000 以上的"异常"区间） */
    return (int)((a * 7919ull + b * 104729ull + c * 1299709ull + d * 15485863ull) & 0x3FFFFFFFull);
}