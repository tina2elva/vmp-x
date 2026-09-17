#include "guest_semantics_arm64.h"

u64 arm64_mask_w(u32 w) { return w >= 64 ? ~0ull : ((1ull << w) - 1ull); }

static u32 nz(u64 r, u32 w) {
    u32 f = 0;
    if ((r & arm64_mask_w(w)) == 0) f |= ARM64_FL_Z;
    if (r & (1ull << (w - 1))) f |= ARM64_FL_N;
    return f;
}

/* ADD/ADDS：C = 无符号进位，V = 有符号溢出 */
u32 arm64_flags_add(u64 a, u64 b, u64 r, u32 w) {
    u64 m = arm64_mask_w(w), sign = 1ull << (w - 1);
    u32 f = nz(r, w);
    u64 ua = a & m, ub = b & m;
    if (w >= 64) {
        if (r < ua) f |= ARM64_FL_C;
    } else if (ua + ub > m) {
        f |= ARM64_FL_C;
    }
    if ((~(a ^ b) & (a ^ r) & sign) != 0) f |= ARM64_FL_V;
    return f;
}

/* SUB/SUBS/CMP：C = **无借位**（a >= b），V = 有符号溢出 */
u32 arm64_flags_sub(u64 a, u64 b, u64 r, u32 w) {
    u64 m = arm64_mask_w(w), sign = 1ull << (w - 1);
    u32 f = nz(r, w);
    if ((a & m) >= (b & m)) f |= ARM64_FL_C;
    if (((a ^ b) & (a ^ r) & sign) != 0) f |= ARM64_FL_V;
    return f;
}

/* 逻辑运算（ANDS/BICS 等）：N/Z 来自结果，C=0，V=0 */
u32 arm64_flags_logic(u64 r, u32 w) { return nz(r, w); }

/* 乘法（MADD/MSUB 的旗标设置形式）：N/Z 来自低位结果，C=0，V=0 */
u32 arm64_flags_mul(u64 r, u32 w) { return nz(r, w); }

u32 arm64_flags_shift(u64 r, u64 last_bit_out, u32 w, u32 cnt, u32 old_flags) {
    u32 f = nz(r, w) | (old_flags & ARM64_FL_V); /* V 不变 */
    if (cnt == 0) {
        f |= old_flags & ARM64_FL_C; /* 不移位时 C 不变 */
    } else if (last_bit_out & 1ull) {
        f |= ARM64_FL_C;
    }
    return f;
}

int arm64_cond_holds(u32 cond, u32 f) {
    int n = (f & ARM64_FL_N) != 0;
    int z = (f & ARM64_FL_Z) != 0;
    int c = (f & ARM64_FL_C) != 0;
    int v = (f & ARM64_FL_V) != 0;
    switch (cond & 15u) {
    case 0:  return z;                 /* EQ */
    case 1:  return !z;                /* NE */
    case 2:  return c;                 /* CS / HS */
    case 3:  return !c;                /* CC / LO */
    case 4:  return n;                 /* MI */
    case 5:  return !n;                /* PL */
    case 6:  return v;                 /* VS */
    case 7:  return !v;                /* VC */
    case 8:  return c && !z;           /* HI */
    case 9:  return !c || z;           /* LS */
    case 10: return n == v;            /* GE */
    case 11: return n != v;            /* LT */
    case 12: return !z && (n == v);    /* GT */
    case 13: return z || (n != v);     /* LE */
    default: return 1;                 /* AL / NV */
    }
}
