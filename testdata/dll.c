/* 被保护的 DLL：函数入口被补丁成 thunk，宿主 exe 通过 LoadLibrary/GetProcAddress 调用。
 * 与 EXE 的区别只是"没有入口点"——注入流程完全一样。 */
#include <stdint.h>

__declspec(dllexport) unsigned long long dll_check_key(unsigned long long x) {
    unsigned long long h = 0x9E3779B97F4A7C15ull ^ x;
    for (int i = 0; i < 8; i++) {
        h ^= h << 13;
        h ^= h >> 7;
        h ^= h << 17;
        h = h * 0x100000001B3ull + (unsigned long long)i;
    }
    if ((x & 1) != 0) {
        h ^= 0xDEADBEEFCAFEBABEull;
    }
    return h % 1000000007ull;
}

__declspec(dllexport) int dll_sum_to(int n) {
    int s = 0;
    for (int i = 1; i <= n; i++) {
        s += i * 3 - 1;
    }
    return s;
}

__declspec(dllexport) long dll_mix(long a, long b) {
    long r = a * 31 + b;
    r ^= r >> 11;
    r += a - b;
    return r;
}
