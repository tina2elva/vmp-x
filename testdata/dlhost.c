/* 宿主：显式 LoadLibrary + GetProcAddress，方便对比原版与被保护版 DLL */
#include <stdio.h>
#include <windows.h>

typedef unsigned long long (*ck_t)(unsigned long long);
typedef int (*st_t)(int);
typedef long (*mx_t)(long, long);

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: dlhost <dll> <check_key|sum_to|mix> [args...]\n");
        return 2;
    }
    HMODULE h = LoadLibraryA(argv[1]);
    if (!h) {
        fprintf(stderr, "LoadLibrary(%s) failed: %lu\n", argv[1], GetLastError());
        return 3;
    }
    if (strcmp(argv[2], "check_key") == 0) {
        ck_t f = (ck_t)GetProcAddress(h, "dll_check_key");
        if (!f) { fprintf(stderr, "no dll_check_key\n"); return 4; }
        for (int i = 3; i < argc; i++) {
            unsigned long long v = _strtoui64(argv[i], NULL, 0);
            printf("%llu\n", f(v));
        }
    } else if (strcmp(argv[2], "sum_to") == 0) {
        st_t f = (st_t)GetProcAddress(h, "dll_sum_to");
        if (!f) { fprintf(stderr, "no dll_sum_to\n"); return 4; }
        for (int i = 3; i < argc; i++) {
            printf("%d\n", f(atoi(argv[i])));
        }
    } else {
        mx_t f = (mx_t)GetProcAddress(h, "dll_mix");
        if (!f) { fprintf(stderr, "no dll_mix\n"); return 4; }
        for (int i = 3; i + 1 < argc; i += 2) {
            printf("%ld\n", f(atol(argv[i]), atol(argv[i + 1])));
        }
    }
    FreeLibrary(h);
    return 0;
}
