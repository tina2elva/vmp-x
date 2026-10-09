/* relr_kat.c - C 侧的 DT_RELR 解码**契约断言**（与 Go 侧 internal/load/elf 的单测同一组向量）。
 *
 * 为什么要有它：LLR 的槽位展开在**两侧各有一份实现** —— 打包端用 Go 解码决定"这些槽位能不能进
 * 加密范围"，运行期用 C（vm_interp.c 的 vm_relr_entry）把同一批槽位还原。两侧算法错开一格，
 * 产物就是"验签失败"或更糟的静默错值。同一组向量喂两侧，任何一侧改错都会当场红。
 *
 * 向量来自**真实产物**（Ubuntu binutils 2.46 链接的 PIE，readelf -rW 的输出）：
 *   条目 [0x3d78, 0x3, 0x80001] ⇒ 槽位 {0x3d78, 0x3d80, 0x4008}
 * 三处旧缺陷（bitmap 之后缺 base += 63*8、首个 bitmap 的 base 应为 addr+8、裸地址条目被丢掉）
 * 都会在这里红。
 *
 * usage: relr_kat      (exit 0 = 两侧对同一组向量的解一致)
 */
#include <stdio.h>

/* 与 test_harness.c 一样的接线：占位构建常量 + 真源码本体（vm_interp.c）。 */
#include "keyname_probe_key.h"
#include "vm_interp.c"

static int failures;

/* 按 (条目序列) → (槽位序列) 展开，并与期望逐项比较。
 * vm_relr_entry 每次返回该条目产生的槽位数，并推进 base。 */
static void expect_slots(const char *what, const u64 *ents, int nents,
                         const u64 *want, int nwant)
{
    u64 base = 0;
    u64 got[256];
    int n = 0;
    int i;
    for (i = 0; i < nents; i++) {
        u32 k = vm_relr_entry(ents[i], &base, got + n, (u32)(256 - n));
        if (n + (int)k > 256) { printf("  [FAIL] %s: slot overflow\n", what); failures++; return; }
        n += (int)k;
    }
    if (n != nwant) {
        printf("  [FAIL] %s: %d slot(s), want %d\n", what, n, nwant);
        failures++;
        return;
    }
    for (i = 0; i < nwant; i++) {
        if (got[i] != want[i]) {
            printf("  [FAIL] %s: slot[%d]=0x%llX, want 0x%llX\n", what, i,
                   (unsigned long long)got[i], (unsigned long long)want[i]);
            failures++;
            return;
        }
    }
    printf("  [ok]   %s (%d slot(s))\n", what, n);
}

int main(void)
{
    /* 1. 真实产物的金向量（与 Go 的 TestRelrGoldenVectorAgainstReadelf 同一组） */
    {
        const u64 ents[3] = { 0x3d78ull, 0x3ull, 0x80001ull };
        const u64 want[3] = { 0x3d78ull, 0x3d80ull, 0x4008ull };
        expect_slots("golden vector (readelf: 3 locations)", ents, 3, want, 3);
    }

    /* 2. 两个位图窗口：第二个必须从第一个窗口推进 63*8 之后开始（旧缺陷就在这一步） */
    {
        const u64 addr = 0x401000ull;
        const u64 d1 = ((1ull << 1) | (1ull << 3)) | 1ull;
        const u64 d2 = ((1ull << 1) | (1ull << 63)) | 1ull;
        const u64 base2 = addr + 8ull + 63ull * 8ull;
        const u64 ents[3] = { addr, d1, d2 };
        const u64 want[5] = {
            addr,                /* 地址条目本身 */
            addr + 8ull,         /* bit1 ⇒ base + 0 */
            addr + 8ull + 2ull * 8ull, /* bit3 ⇒ base + (3-1)*8 */
            base2,               /* 第二个窗口的 bit1 */
            base2 + (63ull - 1ull) * 8ull, /* 第二个窗口的 bit63 */
        };
        expect_slots("two bitmap windows", ents, 3, want, 5);
    }

    /* 3. 位图之后再来一条地址条目 ⇒ base 必须被**重置**（不是接着累加） */
    {
        const u64 ents[4] = { 0x1000ull, ((1ull << 1)) | 1ull, 0x2000ull, ((1ull << 63)) | 1ull };
        const u64 want[4] = {
            0x1000ull,
            0x1008ull,
            0x2000ull,
            /* 注意 +8：地址条目之后 base = addr + 8，所以 bit63 落在 addr+8+(63-1)*8 */
            0x2000ull + 8ull + (63ull - 1ull) * 8ull,
        };
        expect_slots("address entry resets base", ents, 4, want, 4);
    }

    /* 4. 只置标志位（bit0）的位图 ⇒ 一个槽位都不产生，但仍推进 63*8 */
    {
        const u64 ents[2] = { 0x3000ull, 1ull };
        const u64 want[1] = { 0x3000ull };
        expect_slots("empty bitmap advances the window", ents, 2, want, 1);
    }

    printf("\n%s: %d failure(s)\n", failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}
