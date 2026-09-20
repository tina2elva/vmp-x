/* kdf_blob_kat.c - blob 级 KDF KAT（门禁用工具，不编进 blob）。
 *
 * 为什么需要它：vmpbuild 的重定位解析曾经按**符号名字**查符号值，而 ld -r 合并多个目标文件后
 * 同一节会有多个同名节符号（实测 .rdata 值 0 与 .rdata 值 0x80），于是"本目标文件里不是
 * 第一份只读数据"的字符串被解析到节的**起点** —— vm_kdf_salt 里的 lea 指向 .rdata+0，
 * 而 "VMPXKDF" 实际在 .rdata+0x80，派生出的 salt 全错。
 * stub/win/x64/kdf_kat.c 编的是**单个源文件**（只有一份只读数据），永远发现不了这类
 * "blob 内布局"缺陷；只有把**编好的 blob** 载入可执行内存、调用它里面的函数才能钉住。
 *
 * 用法: kdf_blob_kat <blob.bin> <vm_kdf_salt 偏移> <vm_kdf_entry 偏移>
 * 期望值与 stub/win/x64/kdf_kat.c、internal/inject/kdf_test.go 三处必须一致。
 * 输出全 ASCII（Windows runner 的编码问题）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned int u32;

#ifdef _WIN32
#include <windows.h>
static void *alloc_exec(long n) {
    return VirtualAlloc(NULL, (SIZE_T)n, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}
#else
#include <sys/mman.h>
static void *alloc_exec(long n) {
    void *p = mmap(NULL, (size_t)n, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (p == MAP_FAILED) ? NULL : p;
}
#endif

static int hex2bytes(const char *hex, u8 *out, int n) {
    for (int i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (u8)v;
    }
    return 1;
}

static int fails = 0;

static void show(const char *what, const u8 *got, int n) {
    printf("  %s = ", what);
    for (int i = 0; i < n; i++) printf("%02x", got[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 4) {
        printf("usage: kdf_blob_kat <blob.bin> <vm_kdf_salt off> <vm_kdf_entry off>\n");
        return 2;
    }
    /* 全局 KDF 掩码只影响 vm_crypto.c 的 ChaCha；这里两个函数都用规范 sigma，与构建无关。 */
    (void)argc;
    u8 master[32];
    for (int i = 0; i < 32; i++) master[i] = (u8)(0x10 + i);

    FILE *f = fopen(argv[1], "rb");
    if (!f) { printf("[!] cannot open %s\n", argv[1]); return 2; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) { fclose(f); printf("[!] empty blob\n"); return 2; }
    /* 多留一页：blob 的 .bss 之后可能还有被引用到的零区 */
    void *buf = alloc_exec(n + 0x4000);
    if (!buf) { fclose(f); printf("[!] cannot allocate executable memory\n"); return 2; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); printf("[!] short read\n"); return 2; }
    fclose(f);

    unsigned long saltOff = strtoul(argv[2], NULL, 0);
    unsigned long entryOff = strtoul(argv[3], NULL, 0);

    typedef u32 (*saltfn)(u32, u32, u32);
    typedef void (*entryfn)(const u8 *, u32, u32, u8 *);
    saltfn kdf_salt = (saltfn)(void *)((u8 *)buf + saltOff);
    entryfn kdf_entry = (entryfn)(void *)((u8 *)buf + entryOff);

    static const struct { u32 a, b, c, want; } salts[] = {
        {0x1670u, 0x90u, 40u, 0xAB20EB8Bu},
        {0x16A0u, 0x90u, 40u, 0x905C9AFBu},
        {0x1700u, 0x90u, 40u, 0xA611C1C0u},
        {0x1730u, 0x90u, 40u, 0x5C03BD70u},
        {0x93000u, 0x90u, 40u, 0x04C8664Cu},
    };
    for (unsigned i = 0; i < sizeof(salts) / sizeof(salts[0]); i++) {
        u32 got = kdf_salt(salts[i].a, salts[i].b, salts[i].c);
        if (got != salts[i].want) {
            printf("[FAIL] vm_kdf_salt(0x%X,0x%X,%u) = 0x%08X, want 0x%08X\n",
                   salts[i].a, salts[i].b, salts[i].c, got, salts[i].want);
            fails++;
        }
    }

    static const struct { u32 rva, salt; const char *want; } keys[] = {
        {0x1670u, 0x11223344u, "03504d6e5b8919be8be4810bcfa62727fde35898e3050c9438777953a8a04fc1"},
        {0x16A0u, 0x11223344u, "4bbdfb88dc35a67a794a1b620eeeb4c4da95a0cf77461ae1983bffd93d8538ce"},
        {0x93000u, 0xAABBCCDDu, "1966610b4c9164cb8a8ddff7b28736395af1fd503ccb5947aa1c0e137d41e149"},
    };
    for (unsigned i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        u8 got[32], want[32];
        memset(got, 0, 32);
        if (!hex2bytes(keys[i].want, want, 32)) { printf("[!] bad KAT literal\n"); return 2; }
        kdf_entry(master, keys[i].rva, keys[i].salt, got);
        if (memcmp(got, want, 32) != 0) {
            printf("[FAIL] vm_kdf_entry(rva=0x%X, salt=0x%08X)\n", keys[i].rva, keys[i].salt);
            show("got ", got, 32);
            show("want", want, 32);
            fails++;
        }
    }

    if (fails) {
        printf("[FAIL] blob KDF KAT: %d case(s) wrong (relocation/layout bug in vmpbuild?)\n", fails);
        return 1;
    }
    printf("[OK  ] blob KDF KAT: vm_kdf_salt x5 + vm_kdf_entry x3 match\n");
    return 0;
}
