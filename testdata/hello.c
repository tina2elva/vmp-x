#include <stdio.h>
#include <stdint.h>

__attribute__((noinline)) uint64_t check_key(uint64_t x) {
    return ((x * 7) + 42) ^ 0xFFu;
}

__attribute__((noinline)) int sum_to(int n) {
    int s = 0;
    for (int i = 1; i <= n; i++) s += i;
    return s;
}

int main(void) {
    printf("check_key(10)=%llu sum_to(100)=%d\n",
           (unsigned long long)check_key(10), sum_to(100));
    return 0;
}
