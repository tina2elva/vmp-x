/* flags_probe.c - 对拍工具：把 ARM64 标志位/条件码语义跑成批处理
 *
 * 用法: flags_probe batch <casesFile> <resultsFile>
 *   casesFile: u32 count; 每个用例 u32 kind, u32 width, u64 a, u64 b, u64 shiftLast, u32 cnt, u32 oldFlags
 *     kind: 0=ADD 1=SUB 2=LOGIC 3=MUL 4=SHIFT
 *   resultsFile: u32 count; 每个用例 u32 flags, u32 condbits(16 个条件的结果打包)
 */
#include <stdio.h>
#include <stdlib.h>

#include "guest_semantics_arm64.h"

typedef struct {
    unsigned int kind, width;
    unsigned long long a, b, shiftLast;
    unsigned int cnt, oldFlags;
} tcase;

static unsigned int run_case(const tcase *c) {
    unsigned long long r = 0;
    switch (c->kind) {
    case 0:
        r = (c->a + c->b) & arm64_mask_w(c->width);
        return arm64_flags_add(c->a, c->b, r, c->width);
    case 1:
        r = (c->a - c->b) & arm64_mask_w(c->width);
        return arm64_flags_sub(c->a, c->b, r, c->width);
    case 2:
        r = (c->a & c->b) & arm64_mask_w(c->width);
        return arm64_flags_logic(r, c->width);
    case 3:
        r = (c->a * c->b) & arm64_mask_w(c->width);
        return arm64_flags_mul(r, c->width);
    default:
        r = c->a & arm64_mask_w(c->width);
        return arm64_flags_shift(r, c->shiftLast, c->width, c->cnt, c->oldFlags);
    }
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: flags_probe batch <cases> <results>\n");
        return 2;
    }
    FILE *cf = fopen(argv[2], "rb");
    if (!cf) { fprintf(stderr, "[!] cannot open cases\n"); return 2; }
    FILE *rf = fopen(argv[3], "wb");
    if (!rf) { fprintf(stderr, "[!] cannot create results\n"); return 2; }

    unsigned int count = 0;
    if (fread(&count, 4, 1, cf) != 1) { fprintf(stderr, "[!] bad cases file\n"); return 2; }
    fwrite(&count, 4, 1, rf);
    for (unsigned int i = 0; i < count; i++) {
        tcase c;
        if (fread(&c, sizeof(c), 1, cf) != 1) { fprintf(stderr, "[!] short cases at %u\n", i); return 2; }
        unsigned int flags = run_case(&c);
        unsigned int condbits = 0;
        for (unsigned int k = 0; k < 16; k++) {
            if (arm64_cond_holds(k, flags)) condbits |= (1u << k);
        }
        fwrite(&flags, 4, 1, rf);
        fwrite(&condbits, 4, 1, rf);
    }
    fclose(cf);
    fclose(rf);
    printf("flags_probe: %u cases\n", count);
    return 0;
}
