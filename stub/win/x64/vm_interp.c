/* vm_interp.c - VM 解释器核心（Windows/x64；无 libc、无全局可写状态）
 *
 * 与 VMPacker 的关键差别：
 *  1. 标志位是真实 NZCV：ADD/SUB 计算 CF(进位/借位) 与 OF(有符号溢出)，
 *     逻辑运算按 x86 规则清 CF/OF，另附 PF。所以 Jcc/ADC/SBB 都能精确实现。
 *  2. 每条 ALU/内存指令都带 width：32 位运算零扩展到 64 位、8/16 位是局部写，
 *     标志位按对应宽度计算 —— 这是 x86-64 翻译绕不过去的语义。
 *  3. 解释器不假设宿主栈布局；RSP 相关偏移由 lifter 处理。
 */
#include "vm_types.h"
#include "vm_opcodes.h"
#include "vm_abi.h"
#include "vm_crypto.h"

/* 本 blob 的主密钥以宏形式由 cmd/vmpbuild 生成（VM_KEY_BYTES） */

/* ---- 编译期校验：vm_abi.h 里的偏移必须与 vm_ctx_t 的真实布局一致 ---- */
#define VM_STATIC_ASSERT(cond, name) typedef char vm_sa_##name[(cond) ? 1 : -1]
/* ctx 的字节偏移只在"18 槽位 x86-64 客户机"布局下有意义；
 * ARM64 客户机（35 槽位）由 -DVM_REG_COUNT 指定，此时只校验结构体自身一致。 */
#if VM_REG_COUNT == VM_REG_COUNT_X64
VM_STATIC_ASSERT(sizeof(vm_ctx_t) == VM_CTX_SIZE, ctx_size);
VM_STATIC_ASSERT(__builtin_offsetof(vm_ctx_t, regs[VRAX]) == VM_CTX_RAX, ctx_rax);
VM_STATIC_ASSERT(__builtin_offsetof(vm_ctx_t, regs[VRSP]) == VM_CTX_RSP, ctx_rsp);
VM_STATIC_ASSERT(__builtin_offsetof(vm_ctx_t, regs[VRBASE]) == VM_CTX_VBASE, ctx_vbase);
VM_STATIC_ASSERT(__builtin_offsetof(vm_ctx_t, regs[VRSCRATCH]) == VM_CTX_VSCRATCH, ctx_vscratch);
VM_STATIC_ASSERT(__builtin_offsetof(vm_ctx_t, flags) == VM_CTX_FLAGS, ctx_flags);
VM_STATIC_ASSERT(__builtin_offsetof(vm_ctx_t, pc) == VM_CTX_PC, ctx_pc);
VM_STATIC_ASSERT(__builtin_offsetof(vm_ctx_t, codeLen) == VM_CTX_CODELEN, ctx_codelen);
VM_STATIC_ASSERT(__builtin_offsetof(vm_ctx_t, code) == VM_CTX_CODE, ctx_code);
#endif
VM_STATIC_ASSERT((VM_FRAME_SIZE % 16) == 0, frame_align);
/* 这两个常量只存在于 x86-64 宿主的 vm_abi.h 里：aarch64 宿主的入口 stub 保存布局完全不同，
 * 所以这条断言只在 x86 宿主上成立（CI 的 linux-arm64 作业曾因此编译失败）。 */
#ifdef VM_SAVE_R15
VM_STATIC_ASSERT(VM_SAVE_R15 + 8 == VM_SAVE_RCX, saves_fit);
#endif
VM_STATIC_ASSERT(VM_SAVE_TOP <= VM_FRAME_SIZE - 8, save_top_fit);
VM_STATIC_ASSERT(sizeof(vm_desc_t) == VM_DESC_SIZE, desc_size);

/* 前向声明（blob 入口符号） */
int vm_run(vm_ctx_t *vm);
#ifndef VM_RELEASE
/* 调试探针：入口路径的阶段计数器（仅非 release；实现在文件后部） */
extern u64 vm_last_pc;
extern u64 vm_last_call; /* 最后一次本机调用的目标 */
extern u64 vm_last_call_rcx; /* 发起该调用时的 guest RCX（第一个参数） */
extern u64 vm_last_call_sp;  /* 发起该调用时的 guest RSP */
#endif
u32 vm_insn_size(u8 op);
u64 vm_selftest(void *ctxp);

static u32 rd32(const u8 *p) { return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24); }

/* 客户机栈槽宽度：x86-32 是 4 字节（push eax 压 4 字节、call 压 4 字节返回地址），
 * x86-64 / arm64 是 8 字节。这是 x86-32 与 x86-64 在**执行语义**上最主要的一处差别 ——
 * 其余（标志位、条件码、算术规则）两者一致，运算宽度由每条 IR 自己带。 */
#ifdef VM_GUEST_X86_32
#define VM_STACK_SLOT 4u
#else
#define VM_STACK_SLOT 8u
#endif

/* 寄存器字段的掩码：x86-64 客户机 18 个槽位（5 位足够），
 * ARM64 客户机 35 个槽位（必须是 8 位）。
 * 越界寄存器不会来自打包端：字节码经过 AEAD 认证，篡改会在执行前被拒。 */
#ifdef VM_GUEST_ARM64
#define VM_REG_MASK 0xFFu
#else
#define VM_REG_MASK 31u
#endif

static u64 width_mask(u32 w) { return w >= 64 ? ~0ull : ((1ull << w) - 1ull); }

/* 把低 w 位符号扩展到 64 位 */
static i64 sign_extend_w(u64 v, u32 w) {
    if (w >= 64) return (i64)v;
    u64 m = width_mask(w);
    u64 x = v & m;
    u64 sign = 1ull << (w - 1);
    return (i64)((x ^ sign) - sign);
}

static u32 parity_flag(u64 r) {
    u8 b = (u8)r;
    u32 ones = 0;
    for (int i = 0; i < 8; i++) ones += (b >> i) & 1u;
    return (ones & 1u) ? 0u : VM_FL_P; /* 偶数个 1 时 PF=1 */
}

/* ---------------- 标志位 ---------------- */

static u32 flags_add_w(u64 x, u64 y, u64 r, u32 w) {
    u64 m = width_mask(w), sign = 1ull << (w - 1);
    u32 f = 0;
    if ((r & m) == 0) f |= VM_FL_Z;
    if (r & sign) f |= VM_FL_N;
    if (w >= 64) {
        if (r < x) f |= VM_FL_C;
    } else if ((x + y) > m) {
        f |= VM_FL_C;
    }
    if (((~(x ^ y)) & (x ^ r)) & sign) f |= VM_FL_V;
    return f | parity_flag(r);
}

static u32 flags_sub_w(u64 x, u64 y, u64 r, u32 w) {
    u64 m = width_mask(w), sign = 1ull << (w - 1);
    u32 f = 0;
    if ((r & m) == 0) f |= VM_FL_Z;
    if (r & sign) f |= VM_FL_N;
    if (x < y) f |= VM_FL_C; /* 借位 */
    if (((x ^ y) & (x ^ r)) & sign) f |= VM_FL_V;
    return f | parity_flag(r);
}

/* ADC 的标志位：x + y + cin（进位出 = 含进位的无符号溢出） */
static u32 flags_adc_w(u64 x, u64 y, u32 cin, u64 r, u32 w) {
    u64 m = width_mask(w), sign = 1ull << (w - 1);
    u32 f = 0;
    if ((r & m) == 0) f |= VM_FL_Z;
    if (r & sign) f |= VM_FL_N;
    if (w >= 64) {
        u64 t = x + y;
        if (t < x || (cin && t == ~0ull)) f |= VM_FL_C;
    } else if (x + y + (u64)cin > m) {
        f |= VM_FL_C;
    }
    if ((~(x ^ y) & (x ^ r) & sign) != 0) f |= VM_FL_V;
    return f | parity_flag(r);
}

/* SBB 的标志位：x - y - cin */
static u32 flags_sbb_w(u64 x, u64 y, u32 cin, u64 r, u32 w) {
    u64 m = width_mask(w), sign = 1ull << (w - 1);
    u32 f = 0;
    if ((r & m) == 0) f |= VM_FL_Z;
    if (r & sign) f |= VM_FL_N;
    if (x < y || (cin && x == y)) f |= VM_FL_C;
    if (((x ^ y) & (x ^ r) & sign) != 0) f |= VM_FL_V;
    return f | parity_flag(r);
}

static u32 flags_logic_w(u64 r, u32 w) {
    u64 m = width_mask(w), sign = 1ull << (w - 1);
    u32 f = 0;
    if ((r & m) == 0) f |= VM_FL_Z;
    if (r & sign) f |= VM_FL_N;
    return f | parity_flag(r); /* 逻辑运算清 CF/OF */
}

/* 64x64 -> 128 的**可移植**实现：i686 没有 __int128（会直接编译不过）。
 *
 * 关键性质：二进制补码下，把操作数**按无符号重解释**后算出的 128 位乘积，
 * 与"有符号乘积"的**位模式完全一致** ⇒ 一个无符号版本就够两边用（有符号那边按需做符号修正）。
 * 算法：把两个 64 位操作数各拆成 32 位两半做小学生乘法；
 *   mid = (p00>>32) + 低32(p01) + 低32(p10) < 3*2^32 ⇒ 不会溢出。
 * 这也是本文件"除法早就不用 __int128"那条纪律的延续（见下面 K_DIVU/K_DIVS 的注释）。 */
static void vm_mul64_full(u64 a, u64 b, u64 *hi, u64 *lo) {
    u64 a0 = a & 0xFFFFFFFFu, a1 = a >> 32;
    u64 b0 = b & 0xFFFFFFFFu, b1 = b >> 32;
    u64 p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    u64 mid = (p00 >> 32) + (p01 & 0xFFFFFFFFu) + (p10 & 0xFFFFFFFFu);
    *lo = (mid << 32) | (p00 & 0xFFFFFFFFu);
    *hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
}
/* Portable 64/64 divide + remainder (only used on 32-bit hosts).
 * i686 has no native 64-bit division: plain `/` or `%` makes GCC emit calls to the
 * runtime helpers (__udivdi3 / __umoddi3 / __divdi3 / __moddi3); the blob is
 * freestanding, so the merge then fails with "undefined symbol __divdi3" - exactly
 * what blocked the 32-bit blob. Shift-subtract long division works on any host.
 * Guarded to 32-bit hosts on purpose: x64/arm64 keep the native division so that
 * their generated code stays byte-identical (which the x64 gates verify). */
#if defined(VM_HOST_X86_32)
static u64 vm_udivmod64(u64 n, u64 d, u64 *rem) {
    u64 q = 0, r = 0;
    int i;
    for (i = 63; i >= 0; i--) {
        r = (r << 1) | ((n >> i) & 1ull);
        if (r >= d) {
            r -= d;
            q |= (1ull << i);
        }
    }
    *rem = r;
    return q;
}
/* Signed version: C truncation semantics (quotient toward zero, remainder sign of n). */
static i64 vm_idivmod64(i64 n, i64 d, i64 *rem) {
    int negN = n < 0, negD = d < 0;
    u64 un = negN ? (u64)(-n) : (u64)n;
    u64 ud = negD ? (u64)(-d) : (u64)d;
    u64 ur = 0;
    u64 uq = vm_udivmod64(un, ud, &ur);
    *rem = negN ? -(i64)ur : (i64)ur;
    return negN != negD ? -(i64)uq : (i64)uq;
}
#endif

static u32 flags_mul_w(u64 x, u64 y, u64 r, u32 w) {
    i64 a = sign_extend_w(x, w), b = sign_extend_w(y, w);
    u64 phi = 0, plo = 0;
    vm_mul64_full((u64)a, (u64)b, &phi, &plo);
    /* 为什么这里还要修正：helper 算的是**无符号** 64x64->128，而我们要的是**有符号**乘积。
     * 两者的关系是（与下面 K_MULHIS 同一套式子）：
     *   有符号乘积 = 无符号乘积 − (a<0 ? b : 0) − (b<0 ? a : 0)
     * 只做"无符号重解释"是不够的：a=-1,b=1 时无符号乘积是 2^64−1，而有符号乘积是 −1。（
     * 这个坑真踩过：不加修正会让 IMUL 的 CF/OF **多置**，被 C/Go 对拍抓住。） */
    phi -= (a < 0 ? (u64)b : 0ull) + (b < 0 ? (u64)a : 0ull);
    i64 lo = sign_extend_w(r, w);
    u32 f = 0;
    if ((r & width_mask(w)) == 0) f |= VM_FL_Z;
    if (r & (1ull << (w - 1))) f |= VM_FL_N;
    /* 与原来等价的判据：乘积是否等于 lo 的**128 位符号扩展** */
    if (plo != (u64)lo || phi != (lo < 0 ? ~0ull : 0ull)) f |= (VM_FL_C | VM_FL_V);
    return f | parity_flag(r);
}

static u32 flags_shift_w(u64 x, u64 r, u32 w, u32 kind, u32 cnt) {
    u64 sign = 1ull << (w - 1);
    u32 f = 0;
    if ((r & width_mask(w)) == 0) f |= VM_FL_Z;
    if (r & sign) f |= VM_FL_N;
    if (kind == K_SHL) {
        if (x & (sign >> (cnt - 1))) f |= VM_FL_C;
        if (cnt == 1 && ((r ^ x) & sign)) f |= VM_FL_V;
    } else if (kind == K_SHR) {
        if (x & (1ull << (cnt - 1))) f |= VM_FL_C;
        if (cnt == 1 && (x & sign)) f |= VM_FL_V;
    } else { /* SAR */
        if (x & (1ull << (cnt - 1))) f |= VM_FL_C;
    }
    return f | parity_flag(r);
}

/* ---------------- 运算 ---------------- */

#ifdef VM_GUEST_ARM64
#include "../../arm64/guest_semantics_arm64.h"
#endif

static u64 alu_apply(vm_ctx_t *vm, u32 kind, u32 width, u64 a, u64 b) {
    u64 m = width_mask(width);
    u64 x = a & m, y = b & m, r = 0;
#ifdef VM_GUEST_ARM64
    /* ARM64 客户机：C 位是"无借位"、没有 PF、移位计数为 0 时 C 不变、V 永不变 */
    switch (kind) {
    case K_ADD: r = x + y; vm->flags = arm64_flags_add(x, y, r, width); break;
    case K_SUB: r = x - y; vm->flags = arm64_flags_sub(x, y, r, width); break;
    case K_AND: r = x & y; vm->flags = arm64_flags_logic(r, width); break;
    case K_OR:  r = x | y; vm->flags = arm64_flags_logic(r, width); break;
    case K_XOR: r = x ^ y; vm->flags = arm64_flags_logic(r, width); break;
    case K_MUL: r = (u64)(sign_extend_w(x, width) * sign_extend_w(y, width));
                vm->flags = arm64_flags_mul(r, width); break;
    case K_SHL: case K_SHR: case K_SAR: {
        u32 cnt = (u32)(y & (u64)(width - 1));
        if (cnt == 0) return a;
        u64 lastOut = (x >> (width - cnt)) & 1ull;
        if (kind == K_SHL) r = x << cnt;
        else if (kind == K_SHR) r = x >> cnt;
        else r = (u64)(sign_extend_w(x, width) >> cnt);
        vm->flags = arm64_flags_shift(r, lastOut, width, cnt, vm->flags);
        break;
    }
    case K_ROL: case K_ROR: {
        /* ARM64 的 ROR 不设标志；lifter 正常不会发出 ROL/ROR，这里保守处理 */
        u32 cnt = (u32)(y & (u64)(width - 1));
        if (cnt == 0) return a;
        if (kind == K_ROL) r = ((x << cnt) | (x >> ((width - cnt) & (width - 1)))) & m;
        else r = ((x >> cnt) | (x << ((width - cnt) & (width - 1)))) & m;
        break;
    }
    default: r = 0; break;
    }
    return r & m;
#endif
    switch (kind) {
    case K_ADD: r = x + y; vm->flags = flags_add_w(x, y, r, width); break;
    case K_SUB: r = x - y; vm->flags = flags_sub_w(x, y, r, width); break;
    case K_TZCNT: case K_LZCNT: { /* BMI1：源为 0 时结果是位宽，并置 CF/ZF；其它标志位保持 */
        u64 v = x & width_mask(width);
        if (v == 0) {
            vm->flags = (vm->flags & ~(VM_FL_Z | VM_FL_C)) | VM_FL_Z | VM_FL_C;
            return width;
        }
        vm->flags &= ~(VM_FL_Z | VM_FL_C);
        if (kind == K_TZCNT) {
            return (width >= 64) ? (u64)__builtin_ctzll(v) : (u64)__builtin_ctz((u32)v);
        }
        return (width >= 64) ? (u64)(63 - __builtin_clzll(v)) : (u64)(31 - __builtin_clz((u32)v));
    }
    case K_BSF: case K_BSR: { /* x86 BSF/BSR：下标结果；只有 ZF 被改写（源为 0 时 ZF=1、结果定为 0） */
        u64 v = x & width_mask(width);
        u64 idx = 0;
        if (v != 0) {
            if (kind == K_BSF) {
                idx = (width >= 64) ? (u64)__builtin_ctzll(v) : (u64)__builtin_ctz((u32)v);
            } else {
                idx = (width >= 64) ? (u64)(63 - __builtin_clzll(v)) : (u64)(31 - __builtin_clz((u32)v));
            }
            vm->flags &= ~VM_FL_Z;
        } else {
            vm->flags |= VM_FL_Z;
        }
        return idx & width_mask(width);
    }
    case K_BT: { /* x86 BT：把 a 的第 (b mod width) 位送进 CF，其它标志位**保持不变** */
        u32 bn = (u32)(y & (u64)(width - 1));
        u64 bit = (x >> bn) & 1ull;
        vm->flags = (vm->flags & ~VM_FL_C) | (bit ? VM_FL_C : 0);
        return 0; /* BT 不写目标寄存器；调用方写的是 VMSCR，无所谓 */
    }
    case K_MULHIS: { /* 单操作数 IMUL 的高半（有符号）；CF=OF 表示结果放不进低半（高半不是低半的符号扩展） */
        u64 m = width_mask(width);
        u64 lo, hi;
        if (width >= 64) {
            i64 a = (i64)x, b = (i64)y;
            /* 有符号高半 = 无符号高半 − (a<0 ? b : 0) − (b<0 ? a : 0) */
            u64 uh = 0;
            vm_mul64_full((u64)a, (u64)b, &uh, &lo);
            u64 uh2 = uh - (a < 0 ? (u64)b : 0ull) - (b < 0 ? (u64)a : 0ull);
            hi = uh2;
        } else {
            i64 p = (i64)sign_extend_w(x, width) * (i64)sign_extend_w(y, width);
            lo = (u64)p & m;
            hi = ((u64)p >> width) & m;
        }
        u64 want = ((i64)sign_extend_w(lo, width) < 0) ? m : 0ull;
        u32 f = 0;
        if (lo == 0) f |= VM_FL_Z;
        if (lo & (m ^ (m >> 1))) f |= VM_FL_N;
        if (hi != want) f |= VM_FL_C | VM_FL_V;
        vm->flags = f | parity_flag(lo);
        return lo;
    }
    case K_MULHI: { /* MUL 的高半：r = (x*y) >> width；CF=OF 表示"高半非零"（= x86 MUL 的进位/溢出语义） */
        u64 m = width_mask(width);
        u64 hi;
        if (width >= 64) {
            { u64 dummy = 0; vm_mul64_full(x, y, &hi, &dummy); }
        } else {
            hi = ((x & m) * (y & m)) >> width;
        }
        u32 nf = 0;
        if (hi != 0) nf |= VM_FL_C | VM_FL_V;
        vm->flags = nf | flags_logic_w(hi, width);
        return hi;
    }
    case K_ADC: { /* ADC：x + y + CF（CF 必须是**运算前**的值） */
        u32 cin = (vm->flags & VM_FL_C) ? 1u : 0u;
        r = x + y + (u64)cin;
        vm->flags = flags_adc_w(x, y, cin, r, width);
        break;
    }
    case K_SBB: { /* SBB：x - y - CF */
        u32 cin = (vm->flags & VM_FL_C) ? 1u : 0u;
        r = x - y - (u64)cin;
        vm->flags = flags_sbb_w(x, y, cin, r, width);
        break;
    }
    case K_AND: r = x & y; vm->flags = flags_logic_w(r, width); break;
    case K_OR:  r = x | y; vm->flags = flags_logic_w(r, width); break;
    case K_XOR: r = x ^ y; vm->flags = flags_logic_w(r, width); break;
    case K_MUL: r = (u64)(sign_extend_w(x, width) * sign_extend_w(y, width));
                vm->flags = flags_mul_w(x, y, r, width); break;
    case K_SHL: case K_SHR: case K_SAR: {
        u32 cnt = (u32)(y & (u64)(width - 1));
        if (cnt == 0) return a; /* x86: 计数为 0 时标志不变 */
        if (kind == K_SHL) r = x << cnt;
        else if (kind == K_SHR) r = x >> cnt;
        else r = (u64)(sign_extend_w(x, width) >> cnt);
        vm->flags = flags_shift_w(x, r, width, kind, cnt);
        break;
    }
    case K_ROL: {
        u32 cnt = (u32)(y & (u64)(width - 1));
        if (cnt == 0) return a;
        r = ((x << cnt) | (x >> ((width - cnt) & (width - 1)))) & m;
        vm->flags = flags_logic_w(r, width) | ((r & 1) ? VM_FL_C : 0);
        break;
    }
    case K_ROR: {
        u32 cnt = (u32)(y & (u64)(width - 1));
        if (cnt == 0) return a;
        r = ((x >> cnt) | (x << ((width - cnt) & (width - 1)))) & m;
        vm->flags = flags_logic_w(r, width) | ((r & (1ull << (width - 1))) ? VM_FL_C : 0);
        break;
    }
    default: r = 0; break;
    }
    return r & m;
}

static u64 alu_unary(vm_ctx_t *vm, u32 kind, u32 width, u64 a) {
    switch (kind) {
    case KU_NEG: return alu_apply(vm, K_SUB, width, 0, a);
    case KU_NOT: return (~a) & width_mask(width); /* 不影响标志 */
    case KU_INC: return alu_apply(vm, K_ADD, width, a, 1);
    default:     return alu_apply(vm, K_SUB, width, a, 1); /* KU_DEC */
    }
}

/* 寄存器写入：32 位零扩展，8/16 位局部写 */
static void write_reg(vm_ctx_t *vm, u32 r, u32 width, u64 val) {
#ifdef VM_GUEST_ARM64
    if (r == VRARM64_ZR) return; /* XZR/WZR：写被丢弃 */
#endif
    /* 索引来自字节码。注意 VM_REG_MASK 是 31，而 regs[] 只有 VM_REG_COUNT(17/18) 项 ——
     * 所以"掩码"并不能保证在界内：一旦字节码损坏或解码失步，写入就会越界。
     * 读越界只是拿到错值，写越界会踩坏上下文（第 35 轮那个 adst 就是这么崩到栈守护页的）。
     * 写是危险动作 ⇒ 这里一律先校验；越界就不写（宁可算错也不破坏宿主内存）。 */
    if (r >= (u32)VM_REG_COUNT) {
#ifndef VM_RELEASE
        __builtin_trap();   /* 同上：写侧看到越界索引也当场 trap，便于 CI 判定 */
#endif
        return;
    }
    if (width >= 64) { vm->regs[r] = val; return; }
    if (width == 32) { vm->regs[r] = val & 0xFFFFFFFFull; return; }
    u64 m = width_mask(width);
    vm->regs[r] = (vm->regs[r] & ~m) | (val & m);
}

/* 读寄存器：索引同样来自字节码。注意 VM_REG_MASK(31) **大于** regs[] 的项数(17/18)，
 * 所以 `& VM_REG_MASK` 并不保证在界内 —— 对被当作"内存基址/调用目标"来用的读，越界会放大成野地址。
 * 这里统一收口：越界一律读作 0（读错值不会破坏宿主内存，但会让地址立刻算错，问题暴露得更早）。
 * 写侧见 write_reg（第 36 轮已设防）。 */
static u64 vm_rdreg(vm_ctx_t *vm, u32 i) {
    i &= VM_REG_MASK;
    if (i >= (u32)(sizeof(vm->regs) / sizeof(vm->regs[0]))) {
#ifndef VM_RELEASE
        /* 非 release：看到越界索引就当场 trap（ud2）。
         * 这样 CI 上"偶发错值/野地址"若起源于一个坏索引，会变成一眼可辨的 0xC000001D，
         * 而不是含混的 0xC0000005 或纯错值 —— 这是这轮要的判定信号。 */
        __builtin_trap();
#endif
        return 0;   /* release：读作 0，让地址立刻算错而不是野跳 */
    }
    return vm->regs[i];
}

static int cond_holds(vm_ctx_t *vm, u32 cond) {
#ifdef VM_GUEST_ARM64
    return arm64_cond_holds(cond & 15u, vm->flags);
#else
    u32 f = vm->flags;
    int z = (f & VM_FL_Z) != 0, n = (f & VM_FL_N) != 0;
    int c = (f & VM_FL_C) != 0, v = (f & VM_FL_V) != 0, p = (f & VM_FL_P) != 0;
    switch (cond & 15u) {
    case CC_O:  return v;
    case CC_NO: return !v;
    case CC_B:  return c;
    case CC_AE: return !c;
    case CC_E:  return z;
    case CC_NE: return !z;
    case CC_BE: return c || z;
    case CC_A:  return !c && !z;
    case CC_S:  return n;
    case CC_NS: return !n;
    case CC_P:  return p;
    case CC_NP: return !p;
    case CC_L:  return n != v;
    case CC_GE: return n == v;
    case CC_LE: return z || (n != v);
    default:    return !z && (n == v); /* CC_G */
    }
#endif
}

/* ---------------- 主循环 ---------------- */

/* 字节码长度上限：**打包端**读 vm_bc_slot_size 做硬校验（超限的字节码在打包期就被拒绝，
 * 而不是在运行期静默算错、把错误码当函数返回值交回客户机）。
 *
 * 这里曾经有一整套"验签后把明文缓存在 .bss 里"的机制（缓存槽 + 自旋锁 + 引用计数，
 * 理由是逐次 AEAD 会把小函数从 ~30ns 拉到 ~345ns）。改成流式取指（见 vm_bcs_t）之后
 * **不再需要任何明文缓冲**：只验签（Poly1305 认证的是**密文**），取指时按块取 ChaCha20
 * 密钥流、逐字节异或还原。顺带消掉三类老问题：跨线程共享同一份明文、槽位耗尽、
 * 以及"整份明文常驻内存可被 dump"（现在有专门的门禁盯着这条，见 tools/gates.ps1）。 */
#ifndef VM_BC_SLOT_SIZE
#define VM_BC_SLOT_SIZE 16384 /* 只是长度上限：真实函数出现过 7313B（add_dly）与 4971B（pymod_exec） */
#endif
/* 打包端要按这个值做校验：const 会落到 .rdata（可读、且不会被写），打包时从 blob 字节里读出真实值。 */
const u64 vm_bc_slot_size = VM_BC_SLOT_SIZE;

/* 前向声明：外层 vm_run 要调用它。
 * rsp_start 是进入时的模拟 RSP。诊断用：客户机压栈超过"自己栈下界"（rsp_start - VM_MARGIN）
 * 就会踩坏宿主栈帧（在 Go 的 goroutine 栈上尤其致命），与其让它把控制流搞坏、再表现为"跳进 .bss"，
 * 不如当场返回一个可辨认的错误码。
 * 用"位移"而不是"直接比较下界"：后者在宿主把 regs[VRSP] 配成 0 的场合（单元测试的 harness）
 * 会因为无符号回绕而误报。 */
/* ---- 调 native 目标的 ABI 蹦床（Win64）----
 * 直接 fn(rcx,rdx,r8,r9,...) 只传寄存器参数，native 被调者读自己的**栈参数**时（第 5 个及以后，
 * 位于 [rsp+0x28..]）会读到宿主 C 栈上 —— 实测 caller5(x){ return five(1,2,3,4,x); } 得到 1 而不是 42，
 * 客户 demo /Od 下把 score 当第 5 个参数转发给 native 的 Math::FormatReport 也因此在算错。
 *
 * 修法：切到 guest 栈、压一个「回到蹦床」的返回地址，再 call —— 这样被调者入口 rsp = guest_rsp-8，
 * 它读 [rsp+0x28] 正好是 guest 写在 [guest_rsp+0x20] 的那格。返回后用 rbx（被调者必须保存）恢复宿主 rsp。
 * 只对 Windows x64 启用：Linux/SysV 与 arm64 的调用约定不同（前 6/8 个参数都在寄存器里），留作后续。 */
/* vm_xmm 的定义在后面（.bss）；两个平台的蹦床都要用它做 FP 参数装载/返回值回流。 */
extern u8 vm_xmm[256];
/* 蹦床参数块。字段全是 u64 ⇒ 两种宿主下偏移相同（fn=0 gsp=8 a0=16 a1=24 a2=32 a3=40 xmm=48）。 */
typedef struct { u64 fn, gsp, a0, a1, a2, a3, xmm; } vm_calln_t;

#if defined(VM_BLOB_USES_WIN64) && defined(__x86_64__) && !defined(VM_BLOB_TARGET_LINUX)

/* 注意：这一段是 **x64 专属**（naked 汇编按 Win64 约定搬参数）。32 位宿主的 cdecl 蹦床
 * 属于目标项 ④，尚未实现 —— 见 STATUS #439 的"未做项"。 */
__attribute__((naked, used)) static u64 vm_calln_x64(vm_calln_t *p) {
    /* 注意：Windows x64 的第一个整型参数在 **RCX**（不是 SysV 的 RDI）。
     * 一开始照 SysV 读 %rdi，拿到的是野指针 → 切栈时 0xC0000005。
     * a0 要进 RCX，所以先把参数块指针搬到 rbp，最后一步才写 RCX。
     * 返回地址由 call 自己压 —— 千万别先 sub rsp,8 再手写一个：那样被调者入口 rsp 会少 8，
     * 它读第 5 个参数就会差一格（实测得到 0）。 */
    __asm__ volatile(
        "pushq %rbx\n\t"
        "pushq %rbp\n\t"
        "movq %rsp, %rbx\n\t"
        "movq %rcx, %rbp\n\t"
        /* FP 参数方向：把 guest 的 xmm0-xmm3 装进真实寄存器（Win64 前四个浮点参数）。
         * 不做这一步，被保护函数调用**带 double 参数的 native 函数**时对方拿到的是垃圾。 */
        "movq 48(%rbp), %r11\n\t"
        "movups 0(%r11), %xmm0\n\t"
        "movups 16(%r11), %xmm1\n\t"
        "movups 32(%r11), %xmm2\n\t"
        "movups 48(%r11), %xmm3\n\t"
        "movq 8(%rbp), %rsp\n\t"

        "movq 16(%rbp), %rax\n\t"
        "movq 24(%rbp), %rdx\n\t"
        "movq 32(%rbp), %r8\n\t"
        "movq 40(%rbp), %r9\n\t"
        "movq 0(%rbp), %r10\n\t"
        "movq %rax, %rcx\n\t"
        "callq *%r10\n\t"
        "1:\n\t"
        /* FP 返回方向：把真实 xmm0-xmm5 写回 guest 的 XMM 堆。
         * 返回值在 xmm0 —— 少了这一步，"转发壳"（call 完直接 ret）交出去的是旧值，
         * 实测客户 demo 的 ?DemoMean@@YANPEBNH@Z 在 /Od 下因此得到 0.000。 */
        "movq 48(%rbp), %r11\n\t"
        "movups %xmm0, 0(%r11)\n\t"
        "movups %xmm1, 16(%r11)\n\t"
        "movups %xmm2, 32(%r11)\n\t"
        "movups %xmm3, 48(%r11)\n\t"
        "movups %xmm4, 64(%r11)\n\t"
        "movups %xmm5, 80(%r11)\n\t"
        "movq %rbx, %rsp\n\t"
        "popq %rbp\n\t"
        "popq %rbx\n\t"
        "ret\n\t");
}

static u64 vm_call_native(vm_ctx_t *vm, u64 addr) {
    vm_calln_t c;
    c.fn = addr;
    c.gsp = vm->regs[VRSP];
    c.a0 = vm->regs[VRCX];
    c.a1 = vm->regs[VRDX];
    c.a2 = vm->regs[VR8];
    c.a3 = vm->regs[VR9];
    c.xmm = (u64)(void *)vm_xmm; /* guest 的 XMM 堆：call 前装 FP 参数、call 后回流返回值 */
    return vm_calln_x64(&c);
}
#elif defined(VM_BLOB_USES_WIN64) && defined(VM_HOST_X86_32) && !defined(VM_BLOB_TARGET_LINUX)
/* ---- 32 位 Windows 宿主：cdecl 蹦床 ----
 *
 * 与 x64 版本最大的不同：**参数不用搬**。cdecl 的参数本来就在客户机栈上（lifted 代码
 * 自己 push 的），而我们的"客户机栈"就是真实内存里的那段栈 —— 直接切过去 call 即可，
 * 被调者看到的 [esp+4..] 正好是客户机压的那些参数。这也正是"无 xmm 传参"的原因。
 *
 * 仍然要做 XMM0 的回流：cdecl 下 double 返回值在 XMM0 里（SSE2 约定）。
 *
 * 进入时（naked + cdecl）：[esp] = 返回地址，[esp+4] = p。 */
__attribute__((naked, used)) static u64 vm_calln_x86(vm_calln_t *p) {
    __asm__ volatile(
        "pushl %ebx\n\t"
        "pushl %ebp\n\t"
        "pushl %esi\n\t"
        "pushl %edi\n\t"
        "movl 20(%esp), %ebp\n\t" /* p：入口 [esp+4]，四次 push 之后是 [esp+20] */
        "movl %esp, %ebx\n\t"     /* 宿主 esp 锚点（ebx 是 callee-saved ⇒ call 后仍有效） */
        "movl 8(%ebp), %esp\n\t"   /* 切到客户机栈 */
        "call *0(%ebp)\n\t"
        "movl 48(%ebp), %ecx\n\t" /* 客户机 XMM 堆 */
        "movups %xmm0, 0(%ecx)\n\t"
        "movl %ebx, %esp\n\t"
        "popl %edi\n\t"
        "popl %esi\n\t"
        "popl %ebp\n\t"
        "popl %ebx\n\t"
        "ret\n\t");
}

static u64 vm_call_native(vm_ctx_t *vm, u64 addr) {
    vm_calln_t c;
    c.fn = addr;
    c.gsp = vm->regs[VRSP];
    /* cdecl 下 a0..a3 用不到（参数在客户机栈上）；保留字段只为与 x64 共用布局。 */
    c.a0 = vm->regs[VRCX];
    c.a1 = vm->regs[VRDX];
    c.a2 = vm->regs[VR8];
    c.a3 = vm->regs[VR9];
    c.xmm = (u64)(void *)vm_xmm;
    return vm_calln_x86(&c);
}
#else
static u64 vm_call_native(vm_ctx_t *vm, u64 addr) {
    typedef u64 (*fn_t)(u64, u64, u64, u64, u64, u64, u64, u64);
    fn_t fn = (fn_t)addr;
    return fn(vm->regs[VRCX], vm->regs[VRDX], vm->regs[VR8], vm->regs[VR9],
              vm->regs[VR10], vm->regs[VR11], vm->regs[VR12], vm->regs[VR13]);
}
#endif
static int vm_run_inner(vm_ctx_t *vm, u64 rsp_start);
static void vm_keep_verify_ref(vm_ctx_t *vm);

/* 这里曾经有一份"兜底缓冲池"，更早还有一整套明文缓存槽（含自旋锁与引用计数）。
 * 两者都随流式取指一起消失了：现在每次调用只在前向的 64 字节密钥流缓存上工作，
 * 既没有跨线程共享的明文，也没有"槽位耗尽"这条失败路径。 */

/* XMM 寄存器堆：x86-64 里 XMM0-15 是**调用者保存**（volatile），
 * 所以被保护函数不需要从宿主那里复制进来/送回去——只要有一块私有内存当寄存器堆即可。
 * 放在 blob 的 .bss 里（注入器已经为 .bss 准备了可写区间），偏移由 vmpbuild 通过符号表导出，
 * 交给 lifter 用作 "VMBASE + RVA" 形式的寻址基址。
 * 刻意排在解密缓存**之后**：.bss 起始处与缓存同一页，排后面更不容易被别的写入影响。 */
u8 vm_xmm[256]; /* 16 × 16 字节；非 static 是为了让符号表里能看到它 */

/* SIMD 按位运算要临时借一个通用寄存器（ALU 需要两个寄存器）时的**保存槽**。
 * 注意：不能用 push/pop 借——那会改动模拟 RSP，进而让同一条指令里后面
 * 那些 [rsp+disp] 形式的内存操作数算错（实测表现为『结果 = 原生*4+1』这种怪值）。 */
/* [0] = 借用的通用寄存器保存位；[8..24) = 16 字节构建缓冲（洗牌/字节移位用）。
 * 非 static，同上：需要出现在符号表里。 */
u64 vm_tmp[3];

/* 现场记录（诊断用）：最近 16 条 (pc, op) + 一个 magic，放在 .bss 里。
 * 目的：Linux 上"跳进 payload 的 .bss"这类跑飞，寄存器/栈记账都已排除，
 * 需要一个"跑飞前执行了什么"的现场。进程崩溃后进程内不便打印，
 * 但 core dump 里包含 payload 的这些页 —— 用 magic 一搜就能把这段读出来。 */
/* 注意：**不要给这两个数组初始化器** —— 有初始化器就会落进 .data，
 * 而注入段里只有 .bss 那一截被映射成可写（.data 在 RX 区）→ 解释器一写就 SIGSEGV。
 * 这不是假设：第一版带初始化器时本机 E2E 立刻从 146/146 掉成 protected 全空。
 * 所以 magic 在记录时再写。 */
#ifndef VM_RELEASE
u64 vm_ring_hdr[2]; /* [0]=magic, [1]=已记录条数（.bss） */
/* 客户机入口/出口的关键状态（诊断用，非 static 以便进 manifest 符号表）：
 * arm64 宿主上被保护函数返回值恒定，需要确认"参数有没有到达客户机、客户机最后算出了什么"。 */
u64 vm_diag[16]; /* [0..7] 见下；[8..10] = 解密后字节码前 24 字节（诊断用） */
u64 vm_ring[16][2]; /* {pc, op}（.bss） */
#endif /* !VM_RELEASE */

/* ---------------- 主循环入口 ---------------- */

/* ---- (g) 反调试 ----
 * 直接读 PEB，不依赖任何导入（blob 是 freestanding，没有导入表）：
 *   x64 上 gs:[0x60] 就是 PEB；PEB+0x02 = BeingDebugged。
 * 命中就 __builtin_trap()（非法指令，进程立即死）—— 是拒绝执行，不是悄悄继续。
 * vm_peb_seen 只用于自证这段代码确实跑过（volatile 防止被优化掉）。 */
/* 仅 Windows 宿主 + x86-64：这段内联汇编是 x86-64 的，编到 aarch64 目标会编译失败
 * （CI 的 windows-arm64-blob 就是因此红的）。arm64 上反调试暂时置空。 */
volatile u64 vm_peb_seen;
#ifndef VM_RELEASE
/* 诊断：模拟栈指针在"第一条指令"与"最后一条指令"时的值 —— 用来判断是否发生 SP 漂移。 */
u64 vm_first_sp;
u64 vm_last_sp;
/* 追踪"谁写了 guest 寄存器 1"：每检测到 reg1 变化就记下**执行它的那条指令的 pc** 与写后的值。
 * 为什么单开一条环：add_dly 的崩溃链路里 reg1 是个坏指针，而通用写入者表只覆盖最近一步，
 * 回溯不到最初把它写坏的那条指令。 */
u64 vm_r1_pcs[64];
u64 vm_r1_vals[64];
u32 vm_r1_i;
u64 vm_r1_prev;
u64 vm_r1_prev_pc;
/* 追踪最近的 STORE：pc / 目标地址 / 写入值。用来回答"那个栈槽是谁写的"。 */
u64 vm_st_pcs[16];
u64 vm_st_addrs[16];
u64 vm_st_vals[16];
u32 vm_st_i;
/* 诊断：每次 CALLN 前后各快照 guest 栈顶 32 个 qword，记录第一处变化。
 * 用来回答"那个栈槽是不是被原生调用改的"。 */
u64 vm_call_snap[32];
u64 vm_call_diff_off;
u64 vm_call_diff_before;
u64 vm_call_diff_after;
u64 vm_call_diffs;
/* 最近 8 次 CALLN/CALLR 的 (目标, 调用后的 RAX) —— 用来看"某次间接调用到底返回了什么"。 */
u64 vm_call_ring[16]; /* 8 组 (target, rax) */
u64 vm_last_call_args[4]; /* 最近一次 CALLN/CALLR 的四个入参（RCX/RDX/R8/R9）—— 调用**前**记录 */
u32 vm_call_ring_n;
#endif

/* 解释器的**私有客户机栈**：
 * 原来 guest SP = host_sp - VM_MARGIN，靠"留出 margin"避免 VM 里发起的原生调用（Cython/numpy）
 * 把帧压到 guest 自己的栈上。实测 add_dly：一次 CALLN 就改掉了 guest 栈顶 32 个 qword 里的 31 个，
 * 随后 guest 从栈槽里读出的就是原生调用留下的脏值 → 拿它当指针 → 崩。
 * 现在把客户机栈放到这块**私有缓冲**里：原生调用走宿主栈，两者再也不会互相踩。
 * 放在 C 里而不是汇编里，四个平台都不用改入口桩。 */
/* ---- (g) 解释器/桩代码段自哈希 ----
 * vmpbuild 在合并完成后把三个值写进下面三个全局（都在 .bss，位于被哈希区间之外）：
 *   vm_code_off  = vm_entry 相对 blob 起点的偏移
 *   vm_self_len  = 被哈希区间长度（blob 起点到 .bss 起点）
 *   vm_self_hash = 该区间的 FNV-1a
 * 运行时重算比对：把解释器补丁成 dumper、或改掉校验逻辑，都会在这里被拒。
 * 为什么要 vm_code_off：C 侧只能拿到 &vm_entry（汇编符号），拿不到节区起点。 */
u64 vm_code_off;
u64 vm_self_len;
u32 vm_self_hash;
/* ---- 每条目密钥派生（KDF） ----
 * 实现见 vm_kdf.c（标准 ChaCha20 块；与 Go 侧 internal/inject/kdf.go 逐字节一致）：
 *   K_e = ChaCha20_block(key = master(32B), counter = 0, nonce = le32(rva) || le32(salt) || 0^8)[0..32)
 *   salt = FNV1a32("VMPXKDF\0" || le32(selfRVA) || le32(codeRVA) || le32(codeLen))
 * 描述符格式不变：salt 的三个输入本来就在描述符里（selfRVA / reserved1=funcRVA / codeLen），
 * 所以两侧都能独立算出来，不需要额外的 salt 字段。 */
void vm_kdf_entry(const u8 master[32], u32 rva, u32 salt, u8 out[32]);
u32 vm_kdf_salt(u32 selfRVA, u32 codeRVA, u32 codeLen);
/* 入口补丁的带密钥 MAC（实现在 vm_kdf.c；打包端 internal/inject/patchmac.go 同式）。 */
u32 vm_patch_mac(const u8 master[32], u32 salt, u32 selfRVA, u32 funcRVA, u32 codeLen,
                 const u8 *patch, u32 len);

/* (3) 描述符里 6 个标量字段（偏移 8..32：codeRVA/codeLen/encLen/flags/reserved1/reserved2）
 * 在打包时与一段掩码异或了 —— 目的是让静态读者无法直接读出"哪个函数被虚拟化、它的原始 RVA、
 * 字节码长度、哪些节被整体加密"。掩码 = vm_kdf_entry(master, VM_FIELD_MASK_DESC, VM_FIELD_MASK_SALT)
 * （域常量由 internal/inject/fields.go 经构建头发过来，两侧同一来源）。 */
typedef struct {
    u32 codeRVA, codeLen, encLen, flags, reserved1, reserved2;
} vm_dfields_t;

static u32 vm_xor32(const u8 *p, const u8 *m) {
    return (u32)(p[0] ^ m[0]) | ((u32)(p[1] ^ m[1]) << 8) |
           ((u32)(p[2] ^ m[2]) << 16) | ((u32)(p[3] ^ m[3]) << 24);
}

static void vm_desc_fields(const vm_desc_t *d, const u8 master[32], vm_dfields_t *o) {
    const u8 *p = (const u8 *)d + 8;
    u8 m[32];
    vm_kdf_entry(master, VM_FIELD_MASK_DESC, VM_FIELD_MASK_SALT, m);
    o->codeRVA = vm_xor32(p + 0, m + 0);
    o->codeLen = vm_xor32(p + 4, m + 4);
    o->encLen = vm_xor32(p + 8, m + 8);
    o->flags = vm_xor32(p + 12, m + 12);
    o->reserved1 = vm_xor32(p + 16, m + 16);
    o->reserved2 = vm_xor32(p + 20, m + 20);
}

/* 描述符 → 本条目的派生密钥（打包端 internal/inject 用同一算式，否则全量 trap）。
 * 只吃**已解掩码**的字段，所以调用方必须先 vm_desc_fields()。 */
static void vm_desc_key(const vm_desc_t *d, const vm_dfields_t *f, const u8 master[32], u8 out[32]) {
    vm_kdf_entry(master, f->reserved1, vm_kdf_salt(d->selfRVA, f->reserved1, f->codeLen), out);
}

/* ---- (1b) 主密钥来源：外置取钥 + 密钥校验值（KCV） ----
 * 兼容模式（默认）：blob 里就带主密钥（VM_KEY_BYTES），行为与 1b 之前完全一致。
 * 外置模式（vmpbuild -key-external）：blob 里只有**随机占位密钥**，真主密钥运行期从外部取；
 * 取不到、或与 KCV 不符 ⇒ 硬门：以专用退出码 0xC0DE0007 结束、不输出任何内容。
 * 所有需要主密钥的地方（字节码/镜像解密、加载期校验表、vm_crypto 的 sigma 掩码）都走
 * vm_master()，于是"第一次解密之前就把错密钥挡掉"是结构性保证。
 *
 * 取钥路径刻意**不调用 kernel32 的取环境/文件 API**：kernel32 里这批 API 在部分 Windows
 * 版本上是**转发导出**（导出项不是代码，而是指向 "KERNELBASE.xxx" 字符串的 RVA），要拿真地址
 * 必须先正确识别转发器 —— 这条路在 CI 的 runner 上就踩崩过（0xC0000005，见 STATUS #385）。
 * 改走两条完全绕开它的路：
 *   1) 密钥从 **PEB 的环境块**直接读（纯内存读，零 API 调用）；
 *   2) 硬门用 **ntdll!NtTerminateProcess**（ntdll 的导出从不转发）。
 * 密钥形式：环境变量 VMPX_KEY = 64 个十六进制字符（32 字节原始密钥）。 */
#ifdef VM_KEY_EXTERNAL

#if !(defined(VM_BLOB_USES_WIN64) && (defined(__x86_64__) || defined(VM_HOST_X86_32)))
#error "VM_KEY_EXTERNAL 目前只有 Windows/x64 的取钥实现（vmpbuild 会先拦住别的目标）"
#endif

static u8 vm_master_buf[32];
static u32 vm_master_ok; /* .bss：0 = 还没取，1 = 已取且 KCV 通过 */

/* 这两个符号在本文件靠后的 Windows 段里定义 */
static u64 vm_peb_base(void);
static u64 vm_find_module(const char *name);
static void *vm_get_proc(u64 mod, const char *fn);

/* 硬门：走 ntdll!NtTerminateProcess(-1, code) —— ntdll 的导出不转发，地址一定有效；
 * 万一取不到就 ud2（0xC000001D）。默认 code = 7 ⇒ 退出码 0xC0DE0007、无任何输出。 */
static void vm_key_reject_code(u32 code) {
    typedef long (*termfn_t)(void *, u32);
    termfn_t tp = (termfn_t)vm_get_proc(vm_find_module("ntdll.dll"), "NtTerminateProcess");
    if (tp) tp((void *)(long long)-1, 0xC0DE0000u | code);
    __builtin_trap();
}
static void vm_key_reject(void) { vm_key_reject_code(7u); }

/* PEB -> ProcessParameters(+0x20) -> Environment(+0x80)：UTF-16 块 "NAME=VALUE\0...\0\0"。 */
static const u16 *vm_env_block(void) {
    u64 peb = vm_peb_base();
    if (!peb) return 0;
    const u8 *pp = *(const u8 *const *)(peb + 0x20);
    if (!pp) return 0;
    return *(const u16 *const *)(pp + 0x80);
}

/* 在环境块里按名字取右值（名字是 ASCII，大小写不敏感）。 */
static const u16 *vm_env_get(const char *name) {
    const u16 *p = vm_env_block();
    if (!p) return 0;
    for (u32 n = 0; n < 8192; n++) {
        if (!*p) {
            if (!p[1]) return 0; /* 双 NUL = 环境块结束 */
            p++;
            continue;
        }
        const u16 *q = p;
        const char *a = name;
        int same = 1;
        while (*a) {
            u16 c = *q++;
            if (c >= 'a' && c <= 'z') c = (u16)(c - 32);
            char b = *a++;
            if (b >= 'a' && b <= 'z') b = (char)(b - 32);
            if (c > 127 || (char)c != b) { same = 0; break; }
        }
        if (same && *q == '=') return q + 1;
        while (*p) p++;
        p++;
    }
    return 0;
}

static u32 vm_hexval(u16 c) {
    if (c >= '0' && c <= '9') return (u32)(c - '0');
    if (c >= 'a' && c <= 'f') return (u32)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (u32)(c - 'A' + 10);
    return 0xFFFFFFFFu;
}

/* ---- 密钥来源①：外部**文件**（部署默认形态；将来换成硬件狗时换的就是这一个函数） ----
 * 路径 = <产物全路径>.vmpkey（PEB -> ProcessParameters -> ImagePathName 拼出来，不调 API），
 * 环境变量 VMPX_KEY_FILE 可覆盖。文件内容接受两种写法：32 字节原始密钥，或 64 位 hex 文本
 * （vmpbuild -key-out 写的就是后者）。
 *
 * 为什么开文件用 **ntdll 的 NtCreateFile/NtReadFile/NtClose** 而不是 kernel32 的
 * CreateFileA/ReadFile：kernel32 里那批 API 在部分 Windows 版本上是**转发导出**（导出项指向
 * "KERNELBASE.xxx" 字符串），要么正确解转发、要么就崩/拿不到真地址 —— 这条在 CI 上踩过
 * （见 STATUS #385）。ntdll 的导出从不转发，所以这里零风险。 */
typedef struct { u16 Length, MaximumLength; u16 *Buffer; } vm_ustr_t;
typedef struct {
    u32 Length, Pad;
    void *RootDirectory;
    vm_ustr_t *ObjectName;
    u32 Attributes, Pad2;
    void *SecurityDescriptor;
    void *SecurityQualityOfService;
} vm_objattr_t;
typedef struct { void *Status; u64 Information; } vm_iosb_t;

static u16 vm_key_path_buf[360]; /* .bss：别在帧上放这么大一块 */

static const u16 *vm_key_path(void) {
    u16 *b = vm_key_path_buf;
    u32 n = 0;
    const u16 *ov = vm_env_get("VMPX_KEY_FILE");
    if (ov && *ov) {
        if (ov[0] != '\\' && ov[0] != '/') {
            b[n++] = '\\'; b[n++] = '?'; b[n++] = '?'; b[n++] = '\\'; /* 原生 API 要 "\??\" 前缀 */
        }
        for (u32 i = 0; ov[i] && n < 344; i++) b[n++] = ov[i];
        b[n] = 0;
        return b;
    }
    u64 peb = vm_peb_base();
    if (!peb) return 0;
    const u8 *pp = *(const u8 *const *)(peb + 0x20);
    if (!pp) return 0;
    const vm_ustr_t *ip = (const vm_ustr_t *)(pp + 0x60); /* ImagePathName */
    if (!ip || !ip->Buffer || ip->Length < 2) return 0;
    u32 chars = (u32)(ip->Length / 2);
    if (chars > 330) chars = 330;
    b[n++] = '\\'; b[n++] = '?'; b[n++] = '?'; b[n++] = '\\';
    for (u32 i = 0; i < chars; i++) b[n++] = ip->Buffer[i];
    const char *suf = ".vmpkey";
    for (u32 i = 0; i < 7; i++) b[n++] = (u16)(u8)suf[i];
    b[n] = 0;
    return b;
}

static int vm_key_read_nt(const u16 *path, u8 *out, u32 cap, u32 *got) {
    typedef long (*create_t)(void **, u32, vm_objattr_t *, vm_iosb_t *, void *, u32, u32, u32, u32, void *, u32);
    typedef long (*read_t)(void *, void *, void *, void *, vm_iosb_t *, void *, u32, void *, void *);
    typedef long (*close_t)(void *);
    u64 nt = vm_find_module("ntdll.dll");
    create_t ncf = (create_t)vm_get_proc(nt, "NtCreateFile");
    read_t nrf = (read_t)vm_get_proc(nt, "NtReadFile");
    close_t ncl = (close_t)vm_get_proc(nt, "NtClose");
    if (!ncf || !nrf || !ncl) return 0;
    vm_ustr_t name;
    u32 chars = 0;
    while (path[chars]) chars++;
    name.Length = (u16)(chars * 2);
    name.MaximumLength = (u16)(chars * 2 + 2);
    name.Buffer = (u16 *)path;
    vm_objattr_t oa;
    oa.Length = (u32)sizeof(oa); oa.Pad = 0; oa.RootDirectory = 0; oa.ObjectName = &name;
    oa.Attributes = 0x40u; /* OBJ_CASE_INSENSITIVE */
    oa.Pad2 = 0; oa.SecurityDescriptor = 0; oa.SecurityQualityOfService = 0;
    vm_iosb_t iosb;
    iosb.Status = 0; iosb.Information = 0;
    void *h = 0;
    long st = ncf(&h, 0x00120089u /* FILE_GENERIC_READ */, &oa, &iosb, 0, 0x80u /* FILE_ATTRIBUTE_NORMAL */,
                  1u /* FILE_SHARE_READ */, 1u /* FILE_OPEN */, 0x40u | 0x20u, 0, 0);
    if (st < 0 || !h) return 0;
    long rs = nrf(h, 0, 0, 0, &iosb, out, cap, 0, 0);
    ncl(h);
    if (rs < 0) return 0;
    *got = (u32)iosb.Information;
    return 1;
}

/* 文件内容 -> 主密钥：32 字节原始，或 64 位 hex 文本（允许尾随空白）。 */
static int vm_key_parse(const u8 *buf, u32 got) {
    if (got == 32) {
        for (u32 i = 0; i < 32; i++) vm_master_buf[i] = buf[i];
        return 1;
    }
    u8 hex[64];
    u32 n = 0;
    for (u32 i = 0; i < got; i++) {
        u8 c = buf[i];
        if (c == ' ' || c == '\r' || c == '\n' || c == '\t') continue;
        if (n >= 64) return 0;
        hex[n++] = c;
    }
    if (n != 64) return 0;
    for (u32 i = 0; i < 32; i++) {
        u32 hi = vm_hexval(hex[2 * i]), lo = vm_hexval(hex[2 * i + 1]);
        if (hi > 15 || lo > 15) return 0;
        vm_master_buf[i] = (u8)((hi << 4) | lo);
    }
    return 1;
}

/* ---- 运行期强制（授权门禁）----
 * 产物里烘的是「签发者公钥 + vendorID/productID 的 4 字节哈希」；运行期读 <产物>.vmplic.bin，
 * 用 CNG（bcrypt.dll）验 ECDSA P-256 签名，再比对哈希与到期时间；不通过就走同一个硬门 0xC0DE0007。
 * 这里**没有自带任何密码学实现**：哈希与验签都交给 Windows CNG（Ed25519 换 ECDSA 就是为了这个）。
 * 注意：门禁只在 **外置密钥模式**（-key-external，推荐的产品形态）下编入。 */
typedef struct __attribute__((aligned(8))) {
    u32 kind;          /* 0 = 不校验（默认，向后兼容）；1 = 校验 <产物>.vmplic.bin */
    u32 vendorHash;    /* SHA-256(vendorID)[0:4]，由 vmpack 烘进来 */
    u32 productHash;   /* SHA-256(productID)[0:4] */
    u8 issuerPub[64];  /* ECDSA P-256 签发者公钥 X||Y */
} vm_license_meta_t;

__attribute__((section(".data"), used))
volatile vm_license_meta_t vm_license_meta = {0, 0, 0, {0}};

/* 门禁失败：对外**统一**是 0xC0DE0007（契约）；"卡在哪一步"记进 vm_license_fail_stage
 * （.bss，非 static，会出现在 manifest 符号表里，便于现场排查）。 */
u32 vm_license_fail_stage;
#define VM_LIC_FAIL(stage) do { vm_license_fail_stage = (stage); vm_key_reject(); } while (0)

/* 把 "<产物全路径><suffix>" 拼成原生 API 要的 "\??\..."（UTF-16）。与 key 不同：不受环境变量覆盖。 */
static const u16 *vm_exe_path_suffix(const char *suffix, u16 *out, u32 cap) {
    u64 peb = vm_peb_base();
    if (!peb) return 0;
    const u8 *pp = *(const u8 *const *)(peb + 0x20);
    if (!pp) return 0;
    const vm_ustr_t *ip = (const vm_ustr_t *)(pp + 0x60);
    if (!ip || !ip->Buffer || ip->Length < 2) return 0;
    u32 n = 0, chars = (u32)(ip->Length / 2);
    out[n++] = '\\'; out[n++] = '?'; out[n++] = '?'; out[n++] = '\\';
    for (u32 i = 0; i < chars && n < cap - 24; i++) out[n++] = ip->Buffer[i];
    for (u32 i = 0; suffix[i] && n < cap - 1; i++) out[n++] = (u16)(u8)suffix[i];
    out[n] = 0;
    return out;
}

/* 当前 UTC Unix 秒（FILETIME 100ns since 1601）。取不到返回 0（0 表示"时间不可用"）。 */
static i64 vm_now_unix(void) {
    typedef void (*gstft_t)(void *);
    gstft_t f = (gstft_t)vm_get_proc(vm_find_module("KERNEL32.DLL"), "GetSystemTimeAsFileTime");
    if (!f) return 0;
    u64 ft = 0;
    f(&ft);
#if defined(VM_HOST_X86_32)
    {   /* 32 位宿主没有原生 64 位除法：走可移植助手，避免拉进 __udivdi3 */
        u64 rem = 0;
        return (i64)vm_udivmod64(ft, 10000000ull, &rem) - 11644473600LL;
    }
#else
    return (i64)(ft / 10000000ull) - 11644473600LL;
#endif
}

/* bcrypt.dll 是**按需加载**的：在简单进程里 PEB 模块表里根本没有它（实测 0x31）。
 * 用 ntdll!LdrLoadDll 自己加载 —— ntdll 永远在，且它的导出从不转发。 */
static u64 vm_load_lib(const u16 *name) {
    u64 nt = vm_find_module("ntdll.dll");
    if (!nt) return 0;
    typedef long (*ldr_t)(u32 *, void *, vm_ustr_t *, void **);
    ldr_t ldr = (ldr_t)vm_get_proc(nt, "LdrLoadDll");
    if (!ldr) return 0;
    vm_ustr_t us;
    u32 len = 0;
    while (name[len]) len++;
    us.Length = (u16)(len * 2);
    us.MaximumLength = (u16)(len * 2 + 2);
    us.Buffer = (u16 *)name;
    void *h = 0;
    if (ldr(0, 0, &us, &h) < 0) return 0;
    return (u64)h;
}

/* CNG：SHA-256 + ECDSA P-256 验签（全部通过 vm_get_proc 取，不引入导入表）。 */
static int vm_license_verify(const u8 *msg, u32 msgLen, const u8 *sig64, const u8 *pub64) {
    u64 bc = vm_find_module("bcrypt.dll");
    if (!bc) {
        static const u16 bcName[] = {'b','c','r','y','p','t','.','d','l','l',0};
        bc = vm_load_lib(bcName);
    }
    if (!bc) { VM_LIC_FAIL(0x31u); return 0; }
    typedef long (*open_t)(void **, const u16 *, const u16 *, u32);
    typedef long (*imp_t)(void *, void *, const u16 *, void **, u8 *, u32, u32);
    typedef long (*hash_t)(void *, void *, u8 *, u32, u8 *, u32, u32);
    typedef long (*hdata_t)(void *, u8 *, u32, u32);
    typedef long (*hfin_t)(void *, u8 *, u32, u32);
    typedef long (*ver_t)(void *, void *, u8 *, u32, u8 *, u32, u32);
    open_t bOpen = (open_t)vm_get_proc(bc, "BCryptOpenAlgorithmProvider");
    imp_t bImport = (imp_t)vm_get_proc(bc, "BCryptImportKeyPair");
    hash_t bHash = (hash_t)vm_get_proc(bc, "BCryptCreateHash");
    hdata_t bData = (hdata_t)vm_get_proc(bc, "BCryptHashData");
    hfin_t bFin = (hfin_t)vm_get_proc(bc, "BCryptFinishHash");
    ver_t bVerify = (ver_t)vm_get_proc(bc, "BCryptVerifySignature");
    if (!bOpen) { VM_LIC_FAIL(0x32u); return 0; }
    if (!bImport) { VM_LIC_FAIL(0x33u); return 0; }
    if (!bHash) { VM_LIC_FAIL(0x34u); return 0; }
    if (!bData) { VM_LIC_FAIL(0x35u); return 0; }
    if (!bFin) { VM_LIC_FAIL(0x36u); return 0; }
    if (!bVerify) { VM_LIC_FAIL(0x37u); return 0; }
    static const u16 algSha[] = {'S','H','A','2','5','6',0};
    static const u16 algEcc[] = {'E','C','D','S','A','_','P','2','5','6',0};
    static const u16 blobEcc[] = {'E','C','C','P','U','B','L','I','C','B','L','O','B',0};
    void *hSha = 0, *hEcc = 0, *hHash = 0, *hKey = 0;
    if (bOpen(&hSha, algSha, 0, 0) < 0) { VM_LIC_FAIL(0x38u); return 0; }
    u8 digest[32];
    int ok = 0;
    if (bHash(hSha, &hHash, 0, 0, 0, 0, 0) < 0) { VM_LIC_FAIL(0x39u); return 0; }
    if (bData(hHash, (u8 *)msg, msgLen, 0) < 0) { VM_LIC_FAIL(0x3Au); return 0; }
    if (bFin(hHash, digest, 32, 0) < 0) { VM_LIC_FAIL(0x3Bu); return 0; }
    if (bOpen(&hEcc, algEcc, 0, 0) < 0) { VM_LIC_FAIL(0x3Cu); return 0; }
    {
        /* BCRYPT_ECCKEY_BLOB: { dwMagic, cbKey, X[cbKey], Y[cbKey] } */
        u8 keyBlob[8 + 64];
        *(u32 *)(keyBlob + 0) = 0x31534345u; /* BCRYPT_ECDSA_PUBLIC_P256_MAGIC ('ECS1') */
        *(u32 *)(keyBlob + 4) = 32u;
        for (u32 i = 0; i < 64; i++) keyBlob[8 + i] = pub64[i];
        if (bImport(hEcc, 0, blobEcc, &hKey, keyBlob, (u32)sizeof(keyBlob), 0) < 0) { VM_LIC_FAIL(0x3Du); return 0; }
        if (bVerify(hKey, 0, digest, 32, (u8 *)sig64, 64, 0) < 0) { VM_LIC_FAIL(0x3Eu); return 0; }
        ok = 1;
    }
    return ok;
}

/* ---- 主密钥来源元数据（由 vmpack 烘进产物；默认全零 = 不启用）----
 * kind: 0 = 文件/环境变量（默认）  2 = Sentinel 真狗  3 = 假狗文件（测试用）
 * 放在 .data：它在自哈希区间 [0,bssOff) 内，静态改 kind 会被 vm_selfcheck() 拒绝。
 * licFeature：vm_license_meta.kind==2 时"问狗要授权"用的 feature id。 */
typedef struct __attribute__((aligned(8))) {
    u32 kind, feature, fileID, offset, length, reserved;
    char vendorCode[64];
    char dllName[64];
    char fakePath[128];
    u32 licFeature;
} vm_key_src_t;

__attribute__((section(".data"), used))
volatile vm_key_src_t vm_key_src = {0, 0, 0, 0, 0, 0, {0}, {0}, {0}, 0};

u32 vm_sentinel_fail_stage;

/* ---- 授权判定（blob 侧"问狗"）----
 * kind==2：用 HASP 的标准做法 —— hasp_login 到**该产品对应的 feature**；
 * 狗上没有这个 feature、或它已过期，login 就失败 ⇒ 直接拒绝（不需要多一个 API，也不用解析结构体）。
 * kind==3（假狗文件）：文件布局 [0..31]=主密钥，随后 u32 count，再 count × (u32 feature, i64 notAfter) ——
 * 让没有真狗也能把这条正例测通；性质与 kind=2 一致：库里没有就拒绝。 */
static int vm_license_from_fakefile(void) {
    u16 wpath[300];
    u32 n = 0;
    const char *p = (const char *)vm_key_src.fakePath;
    while (p[n] && n < 280) { wpath[n] = (u16)(u8)p[n]; n++; }
    wpath[n] = 0;
    static u8 buf[1024];
    u32 got = 0;
    if (!vm_key_read_nt(wpath, buf, (u32)sizeof(buf), &got)) { VM_LIC_FAIL(0x31u); return 0; }
    if (got < 36) { VM_LIC_FAIL(0x32u); return 0; }
    u32 count = *(const u32 *)(buf + 32);
    if (count > 64 || got < 36 + count * 12) { VM_LIC_FAIL(0x33u); return 0; }
    i64 now = vm_now_unix();
    for (u32 i = 0; i < count; i++) {
        const u8 *e = buf + 36 + (u64)i * 12;
        u32 feat = *(const u32 *)(e + 0);
        i64 notAfter = *(const i64 *)(e + 4);
        if (feat != vm_key_src.licFeature) continue;
        if (notAfter == 0) return 1;
        if (now == 0) continue;
        if (now <= notAfter) return 1;
        VM_LIC_FAIL(0x34u);
        return 0;
    }
    VM_LIC_FAIL(0x35u);
    return 0;
}

static int vm_license_from_dongle(void) {
    if (vm_key_src.kind == 3) return vm_license_from_fakefile();
    const char *dll = vm_key_src.dllName[0] ? (const char *)vm_key_src.dllName : "hasp_windows.dll";
    u64 h = vm_find_module(dll);
    if (!h) {
        static u16 wname[64];
        u32 n = 0;
        while (dll[n] && n < 63) { wname[n] = (u16)(u8)dll[n]; n++; }
        wname[n] = 0;
        h = vm_load_lib(wname);
    }
    if (!h) { VM_LIC_FAIL(0x36u); return 0; }
    typedef i32 (*login_t)(u32, const char *, u32 *);
    typedef i32 (*logout_t)(u32);
    login_t pLogin = (login_t)vm_get_proc(h, "hasp_login");
    logout_t pLogout = (logout_t)vm_get_proc(h, "hasp_logout");
    if (!pLogin || !pLogout) { VM_LIC_FAIL(0x37u); return 0; }
    u32 handle = 0;
    if (pLogin(vm_key_src.licFeature, (const char *)vm_key_src.vendorCode, &handle) != 0) { VM_LIC_FAIL(0x38u); return 0; }
    pLogout(handle);
    return 1;
}

/* 门禁：1 = 放行（未启用也算放行）；0 = 拒绝。 */
static int vm_license_check(void) {
    if (vm_license_meta.kind == 0) return 1;
    /* (2) 授权来自加密狗：问狗（kind=2 真狗 / kind=3 假狗文件），不走文件授权那条路 */
    if (vm_license_meta.kind == 2) return vm_license_from_dongle();
    u16 path[360];
    if (!vm_exe_path_suffix(".vmplic.bin", path, 360)) { VM_LIC_FAIL(0x21u); return 0; }
    static u8 lic[2048];
    u32 got = 0;
    if (!vm_key_read_nt(path, lic, (u32)sizeof(lic), &got)) { VM_LIC_FAIL(0x22u); return 0; }
    /* hdr: magic(4) version(4) vendorHash(4) count(4) reserved(8) = 24；条目 16 字节；末尾 64 字节签名 */
    if (got < 24 + 64) { VM_LIC_FAIL(0x23u); return 0; }
    if (*(const u32 *)(lic + 0) != 0x564C5043u) { VM_LIC_FAIL(0x24u); return 0; }
    if (*(const u32 *)(lic + 4) != 1u) { VM_LIC_FAIL(0x25u); return 0; }
    if (*(const u32 *)(lic + 8) != vm_license_meta.vendorHash) { VM_LIC_FAIL(0x26u); return 0; }
    u32 count = *(const u32 *)(lic + 12);
    if (got != 24 + count * 16 + 64) { VM_LIC_FAIL(0x27u); return 0; }
    u64 signedLen = 24 + (u64)count * 16;
    if (!vm_license_verify(lic, (u32)signedLen, lic + signedLen, (const u8 *)vm_license_meta.issuerPub)) { VM_LIC_FAIL(0x28u); return 0; }
    i64 now = vm_now_unix();
    int found = 0;
    for (u32 i = 0; i < count; i++) {
        const u8 *e = lic + 24 + (u64)i * 16;
        u32 ph = *(const u32 *)(e + 0);
        i64 notAfter = *(const i64 *)(e + 8);
        if (ph != vm_license_meta.productHash) continue;
        if (notAfter == 0) { found = 1; break; }          /* 永久 */
        if (now == 0) continue;                            /* 时间取不到 -> 不认"限期授权" */
        if (now <= notAfter) { found = 1; break; }
        VM_LIC_FAIL(0x2Au);                         /* 该产品已过期 */
        return 0;
    }
    if (!found) { VM_LIC_FAIL(0x29u); return 0; }
    return 1;
}

/* ---- Sentinel 后端（可选）---- 删掉这一段 + 不烘 kind 就回到"文件/环境变量取钥"。
 * 设计要点：① 动态加载 hasp*.dll（**无导入表**，没狗也能启动）；② 路由由烘进产物的 kind 决定；
 *           ③ kind>=2 时**严格模式**：只用狗，失败即硬门 —— 不回退文件/环境变量（堵降级攻击）。
 * kind: 2 = Sentinel 真狗（hasp_login/hasp_read）  3 = 假狗文件（测试用，路径需 \??\... 形式）
 * vm_key_src 放在 .data：它在自哈希区间 [0,bssOff) 内，静态改 kind 会让 vm_selfcheck() 直接拒绝。 */
/* 主密钥来源元数据与 vm_sentinel_fail_stage 已上移到授权代码之前（那里也要用）。 */

static int vm_key_from_sentinel(void) {
    if (vm_key_src.kind == 3) {
        u16 wpath[300];
        u32 n = 0;
        const char *p = (const char *)vm_key_src.fakePath;
        while (p[n] && n < 280) { wpath[n] = (u16)(u8)p[n]; n++; }
        wpath[n] = 0;
        u8 buf[32];
        u32 got = 0;
        if (!vm_key_read_nt(wpath, buf, 32u, &got) || got < 32) { vm_sentinel_fail_stage = 1; return 0; }
        { u32 i; for (i = 0; i < 32; i++) vm_master_buf[i] = buf[i]; }
        return 1;
    }
    if (vm_key_src.kind == 2) {
        const char *dll = vm_key_src.dllName[0] ? (const char *)vm_key_src.dllName : "hasp_windows.dll";
        u64 h = vm_find_module(dll);
        if (!h) {
            static u16 wname[64];
            u32 n = 0;
            while (dll[n] && n < 63) { wname[n] = (u16)(u8)dll[n]; n++; }
            wname[n] = 0;
            h = vm_load_lib(wname);
        }
        if (!h) { vm_sentinel_fail_stage = 2; return 0; }
        typedef i32 (*login_t)(u32, const char *, u32 *);
        typedef i32 (*logout_t)(u32);
        typedef i32 (*hread_t)(u32, u32, u32, u32, void *);
        login_t pLogin = (login_t)vm_get_proc(h, "hasp_login");
        logout_t pLogout = (logout_t)vm_get_proc(h, "hasp_logout");
        hread_t pRead = (hread_t)vm_get_proc(h, "hasp_read");
        if (!pLogin || !pLogout || !pRead) { vm_sentinel_fail_stage = 3; return 0; }
        u32 handle = 0;
        if (pLogin(vm_key_src.feature, (const char *)vm_key_src.vendorCode, &handle) != 0) { vm_sentinel_fail_stage = 4; return 0; }
        u8 buf[32];
        i32 st = pRead(handle, vm_key_src.fileID, vm_key_src.offset, 32u, buf);
        pLogout(handle);
        if (st != 0) { vm_sentinel_fail_stage = 5; return 0; }
        { u32 i; for (i = 0; i < 32; i++) vm_master_buf[i] = buf[i]; }
        return 1;
    }
    vm_sentinel_fail_stage = 15;
    return 0;
}

static int vm_key_from_file(void) {
    const u16 *path = vm_key_path();
    if (!path || !*path) return 0;
    u8 buf[128];
    u32 got = 0;
    if (!vm_key_read_nt(path, buf, (u32)sizeof(buf), &got)) return 0;
    return vm_key_parse(buf, got);
}

/* VMPX_KEY = 64 个十六进制字符 -> 32 字节主密钥。 */
static int vm_key_from_env(void) {
    const u16 *v = vm_env_get("VMPX_KEY");
    if (!v) return 0;
    for (u32 i = 0; i < 32; i++) {
        u32 hi = vm_hexval(v[2 * i]), lo = vm_hexval(v[2 * i + 1]);
        if (hi > 15 || lo > 15) return 0;
        vm_master_buf[i] = (u8)((hi << 4) | lo);
    }
    return 1;
}

const u8 *vm_master(void) {
    if (vm_master_ok) return vm_master_buf;
    /* 取钥顺序：① 外部文件（部署默认：与产物同目录的 <产物名>.vmpkey）
     *           ② 环境变量 VMPX_KEY（64 位 hex，方便临时/CI 用）
     * 两者都拿不到、或与 KCV 不符 -> 硬门 0xC0DE0007。将来上硬件狗时，
     * 换掉的只是 ①（同一个函数接缝：把 vm_key_from_file 换成向狗询问即可）。 */
    /* 取钥路由由烘进产物的 kind 决定（vmpack 写 vm_key_src）：kind>=2 = **严格模式，只用狗**，
     * 失败即硬门、不回退文件/环境变量；kind=0 时是今天的默认行为（文件 -> 环境变量），逐字节不变。 */
    if (vm_key_src.kind >= 2) {
        /* 对外统一 0xC0DE0007（契约）；卡在哪一步记在 vm_sentinel_fail_stage 里备查 */
        if (!vm_key_from_sentinel()) vm_key_reject();
    } else if (!vm_key_from_file() && !vm_key_from_env()) {
        vm_key_reject();
    }
    {   /* KCV 自检：在任何解密之前判定"手里这把主密钥对不对" */
        static const u8 want[VM_KEY_CHECK_LEN] = VM_KEY_CHECK_BYTES;
        u8 kcv[32];
        vm_kdf_entry(vm_master_buf, VM_KEY_CHECK_RVA, VM_KEY_CHECK_SALT, kcv);
        for (u32 i = 0; i < (u32)VM_KEY_CHECK_LEN; i++) {
            if (kcv[i] != want[i]) vm_key_reject();
        }
    }
    /* 注意：授权校验**不能**放在这里 —— vm_master() 也会被 TLS 回调路径调用，
     * 而在 TLS 回调里调 LdrLoadDll/bcrypt 是非法的（loader lock 被持有，实测 ud2 崩）。
     * 所以门禁放在入口蹦床 vm_verify_table()：那里是"入口点"，loader lock 已释放，
     * 而且仍在 main 之前 —— 体感同样是"没授权就跑不起来"。 */
    vm_master_ok = 1;
    return vm_master_buf;
}

#else
/* 兼容模式：blob 里就带主密钥 */
const u8 *vm_master(void) {
    static const u8 k[32] = VM_KEY_BYTES;
    return k;
}
#endif

/* ---- 流式取指：字节码在内存里始终是密文 ----
 * ks 缓存的是 ChaCha20 **密钥流**（不是明文）。解释器取指只向前走，所以单块缓存就够：
 * 跨块时重取一次（一块 64 字节，约合 8-16 条指令），回跳自然落到新块。 */
typedef struct {
    const u8 *ct;     /* 密文基址（就在镜像里） */
    const u8 *key;    /* 32 字节**条目**密钥（指向 keybuf：KDF 现推，不再是主密钥） */
    u8  keybuf[32];   /* 派生密钥的存储（栈上的 vm_bcs_t 自带一份，嵌套调用互不干扰） */
    const u8 *nonce;  /* 12 字节 nonce（指向描述符） */
    u32 ks_block;     /* 当前密钥流块号；0xFFFFFFFF = 未装载 */
    u8  ks[64];
    int enc;          /* 0 = 未加密（调试/单测路径），直接读 ct */
} vm_bcs_t;

static inline u8 vmb_byte(vm_bcs_t *s, u32 off) {
    if (!s->enc) return s->ct[off];
    u32 blk = off >> 6;
    if (blk != s->ks_block) {
        vm_chacha20_keystream(s->key, blk + 1u, s->nonce, s->ks); /* AEAD 数据流从 counter=1 开始 */
        s->ks_block = blk;
    }
    return (u8)(s->ct[off] ^ s->ks[off & 63u]);
}

static inline u32 vmb_rd32(vm_bcs_t *s, u32 off) {
    return (u32)vmb_byte(s, off) | ((u32)vmb_byte(s, off + 1) << 8) |
           ((u32)vmb_byte(s, off + 2) << 16) | ((u32)vmb_byte(s, off + 3) << 24);
}

static inline u64 vmb_rd64(vm_bcs_t *s, u32 off) {
    return (u64)vmb_rd32(s, off) | ((u64)vmb_rd32(s, off + 4) << 32);
}

static inline void vm_bcs_init(vm_bcs_t *s, const vm_ctx_t *vm) {
    const vm_desc_t *d = (const vm_desc_t *)vm->desc;
    s->ks_block = 0xFFFFFFFFu;
    s->key = 0;
    s->nonce = 0;
    vm_dfields_t f;
    if (d) {
        const u8 *master = vm_master(); /* 1b：外置模式下这里会先取钥+校验，不通就硬门退出 */
        vm_desc_fields(d, master, &f);  /* (3)：先解掩码，后面一律用 f.* */
    }
    if (d && (f.flags & VM_DESC_FLAG_ENC)) {
        const u8 *master = vm_master();
        s->enc = 1;
        s->ct = (const u8 *)d + f.codeRVA;
        vm_desc_key(d, &f, master, s->keybuf); /* 每条目一把：与 vm_run 的验签/解密用同一把 */
        s->key = s->keybuf;
        s->nonce = d->nonce;
    } else {
        s->enc = 0;
        s->ct = vm->code;
    }
}


/* vm_entry 由各平台的 vm_entry_asm.S 定义。两个要点：
 * 1) 必须声明成**函数**：数组形式会让 gcc 生成 .refptr 绝对指针节（被合并器拒绝）；
 * 2) 必须标 **hidden**：PIE 默认下 gcc 认为它可被外部抢占，于是走 GOT（linux/amd64 上报的
 *    R_X86_64_REX_GOTPCRELX=0x2A 就是这个），hidden 之后才回到 PC 相对引用。 */
extern void vm_entry(void) __attribute__((visibility("hidden")));
/* 基址重定位表的 blob 偏移（0 = 没有表），由 vmpbuild 烘焙；非 static 以便出现在符号表里。
 * 自校验必须与加载期补丁用**同一套规则**：站点内的字节按 0 参与哈希。 */
u32 vm_reloc_tab_off;
static void vm_selfcheck(void) {
    const u8 *base = (const u8 *)&vm_entry - (u32)vm_code_off;
    u32 h = 2166136261u;
    u64 i;
    if (!vm_self_len) return; /* 还没被烘焙（比如本地直接编 blob 跑测试） */
    for (i = 0; i < vm_self_len; i++) {
        u32 b = (u32)base[i];
        if (vm_reloc_tab_off) {
            const u32 *tab = (const u32 *)(base + vm_reloc_tab_off);
            u32 n = tab[0], k;
            for (k = 0; k < n; k++) {
                u32 site = tab[1 + k];
                if (i >= site && i < site + 4u) {
                    b = 0; /* 基址相关站点：加载期会被加 base，所以哈希按 0 算 */
                    break;
                }
            }
        }
        h ^= b;
        h *= 16777619u;
    }
    if (h != vm_self_hash) __builtin_trap();
}

/* ---- (4) 反调试：多路径判定 + 失败**静默延后** ----
 * 改造前只看 PEB.BeingDebugged（一条 cmp 就能 patch 掉），而且命中就 __builtin_trap()
 * —— "跳转点即指纹"：攻击者崩在哪里就知道校验在哪里。现在改成多路径 + 静默延后：
 *   ① PEB.BeingDebugged（每次调用都查，最便宜）
 *   ② ntdll!NtQueryInformationProcess(ProcessDebugPort / ProcessDebugObjectHandle)（进程级）
 *   ③ ntdll!NtGetContextThread(NtCurrentThread, CONTEXT_DEBUG_REGISTERS)：硬件断点会在
 *      Dr0..Dr3 / Dr7 留痕。（**不看 Dr6**：它复位时本来就不是 0，看了必误报。）
 *   ④ 时间差：一次性、极保守的 rdtsc 检查（阈值很松，只贡献 1 个信号）
 * ②③④ 只探一次（进程级/一次性状态），① 每次都查。
 * 判据：**累计 >= 2 个信号**才定性 —— 单点误判不动手；真实调试器会同时踩中 ① 与 ②
 * （Windows 调试 API 必然设置这两者），所以并不会漏。
 * 定性后**不 trap**：置延后计数器，接下来 VM_DBG_DEFER_CALLS 次 vm_run 直接返回错误结果，
 * 攻击者看到的是"偶尔算错"，而不是一个可以一眼定位的崩点。
 *
 * 关于第 ④ 条（时间差）的**降级记录**：它最初参与定性（bit3），但实测**两次误报** ——
 * 忙机器/虚拟化环境下一次 64 次迭代的空转能被调度顶到远超阈值，只要另一条路径（例如
 * BeingDebugged）也命中，就会把正常程序判成被调试（e2e 因此偶发红）。现在它只累加
 * vm_dbg_timing_hits 供诊断，**不再贡献判定位**；真正的调试器由 ①②③ 确定性路径抓。 */
#define VM_DBG_DEFER_CALLS 3
u32 vm_dbg_defer;        /* .bss；非 Windows 也定义（vm_run 里统一判断） */
u32 vm_dbg_timing_hits;  /* 时间差路径命中次数：**只作参考**，不参与定性（见下） */

/* 这两个符号定义在本文件靠后的 Windows 段里。**必须在 VM_KEY_EXTERNAL 之外也声明**：
 * 兼容模式（baked）下反调试同样要用它们（上一版把声明放在外置分支里 -> baked 编不过 ->
 * blob 构建失败，而我只 grep 'blob:' 没看出来，于是打包用的还是旧 blob）。 */
/* 注意条件是"**Windows 目标**"而不是只看内部 ABI：mingw 编 Linux 目标时 VM_BLOB_USES_WIN64
 * 同样成立（那是宿主 ABI），但 Windows 目标那段代码不参与编译，符号是未定义的 ——
 * 上一版就是这么把 linux blob 编成"非自包含"的（CI 报：引用了未定义符号 "vm_find_module"）。 */
#if defined(VM_BLOB_USES_WIN64) && (defined(__x86_64__) || defined(VM_HOST_X86_32)) && !defined(VM_BLOB_TARGET_LINUX)
static u64 vm_find_module(const char *name);
static void *vm_get_proc(u64 mod, const char *fn);
#endif

#if defined(VM_BLOB_USES_WIN64) && (defined(__x86_64__) || defined(VM_HOST_X86_32)) && !defined(VM_BLOB_TARGET_LINUX)
/* 信号按**路径**记位，而不是计数：同一个路径被两个调用点各查一次（入口蹦床的 vm_verify_table
 * 与 vm_run）不该算两个信号 —— 那会把"≥2 条不同路径"退化成"同一条路径查了两次"。 */
static u32 vm_dbg_mask;       /* bit0=①BeingDebugged bit1=②调试端口/对象 bit2=③DR bit3=④时间差 */
static u32 vm_dbg_probe_mask;
static u32 vm_dbg_verdict;
static u32 vm_dbg_probed;

static int vm_debugger_present(void) {
    const u8 *peb;
#if defined(VM_HOST_X86_32)
    /* 32 位 Windows：PEB 指针在 fs:[0x30]（x64 才在 gs:[0x60]）。地址也是 32 位。 */
    {
        u32 peb32 = 0;
        __asm__ volatile("movl %%fs:0x30, %0" : "=r"(peb32));
        peb = (const u8 *)(u64)peb32;
    }
#else
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
#endif
    vm_peb_seen = (u64)peb;
    if (!peb) return 0;
    return *(const u8 *)(peb + 0x02) ? 1 : 0;
}

static u64 vm_rdtsc(void) {
    u32 lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((u64)hi << 32) | lo;
}

static u32 vm_antidebug_probe(void) {
    u32 hits = 0;
    u64 nt = vm_find_module("ntdll.dll");

    /* ② 调试端口 / 调试对象句柄（进程级；真实调试器必然把它们置上） */
    typedef long (*qip_t)(void *, u32, void *, u32, void *);
    qip_t qip = (qip_t)vm_get_proc(nt, "NtQueryInformationProcess");
    if (qip) {
        u64 out = 0;
        if (qip((void *)(long long)-1, 7u /* ProcessDebugPort */, &out, 8, 0) >= 0 && out) hits |= 1u;
        out = 0;
        if (qip((void *)(long long)-1, 30u /* ProcessDebugObjectHandle */, &out, 8, 0) >= 0 && out) hits |= 2u;
    }

    /* ③ 硬件断点寄存器的影子（Dr0..Dr3 / Dr7） */
    typedef long (*gct_t)(void *, void *);
    gct_t gct = (gct_t)vm_get_proc(nt, "NtGetContextThread");
    if (gct) {
        static u8 ctx[1232]; /* CONTEXT 全尺寸：API 会把整块写满 */
        for (u32 i = 0; i < sizeof(ctx); i++) ctx[i] = 0;
        *(u32 *)(ctx + 0x30) = 0x00100010u; /* CONTEXT_AMD64 | CONTEXT_DEBUG_REGISTERS */
        if (gct((void *)(long long)-2 /* NtCurrentThread */, ctx) >= 0) {
            u64 dr0 = *(const u64 *)(ctx + 0x48), dr1 = *(const u64 *)(ctx + 0x50);
            u64 dr2 = *(const u64 *)(ctx + 0x58), dr3 = *(const u64 *)(ctx + 0x60);
            u64 dr7 = *(const u64 *)(ctx + 0x70);
            if (dr0 || dr1 || dr2 || dr3 || dr7) hits |= 4u;
        }
    }

    /* ④ 时间差：**只记录、不定性**。
     * 阈值为什么定这么高（1e9 cycles ≈ 0.3s）：实测在忙的机器上，一次 64 次迭代的空转也能被
     * 调度/页错误顶到 >3ms —— 那样这条路径就成了**误报源**，只要另一条路径（例如 BeingDebugged）
     * 也命中，就会把正常程序判成被调试（本机与 CI 都出现过一次，e2e 因此变成偶发红）。
     * 而单步调试会让 64 次迭代里**每一步**都按毫秒甚至秒计，取最小值仍然远超 1e9，所以不会漏。 */
    u64 best = ~(u64)0;
    for (u32 k = 0; k < 4; k++) {
        u64 t0 = vm_rdtsc();
        volatile u64 acc = 0;
        for (u32 i = 0; i < 64; i++) acc += (u64)i;
        u64 t1 = vm_rdtsc();
        if (k && (t1 - t0) < best) best = t1 - t0; /* 第 0 次当热身丢弃 */
    }
    if (best != ~(u64)0 && best > 1000000000ull) vm_dbg_timing_hits++;
    return hits;
}

static void vm_antidebug(void) {
    if (vm_debugger_present()) vm_dbg_mask |= 1u;
    if (!vm_dbg_probed) {
        vm_dbg_probed = 1;
        vm_dbg_probe_mask = vm_antidebug_probe() << 1; /* ②③④ 各占一位（bit1..bit3） */
    }
    vm_dbg_mask |= vm_dbg_probe_mask;
    /* ≥2 条**不同**路径命中才定性：单点误判不动手；真实调试器必然同时踩中 ① 与 ②。 */
    if (!vm_dbg_verdict && (vm_dbg_mask & (vm_dbg_mask - 1)) != 0) {
        vm_dbg_verdict = 1;
        vm_dbg_defer = VM_DBG_DEFER_CALLS; /* 静默延后：不 trap */
    }
}
#else
static void vm_antidebug(void) { }
#endif

int vm_run(vm_ctx_t *vm) {
    vm_antidebug();
    /* (4) 反调试定性后走**静默延后**：接下来几次直接给错结果，不给一个可定位的崩点。 */
    if (vm_dbg_defer) {
        vm_dbg_defer--;
        return 3;
    }
    vm_selfcheck();
    /* 第 49 轮这里曾放一条"客户机 RSP 应 16 字节对齐"的 int3 断言。第 55 轮查明它是**错误前提**：
     * 客户机 RSP 该不该对齐是我们自己的约定，不是 ABI 要求；而 thunk 的 call 让 vm_entry 从 rsp%16==0
     * 进入，减 FRAME_SIZE/8/MARGIN 后客户机 RSP 自然落在 %16==8 —— 这是原设计的正常值。
     * 断言 + 第 50 轮那条对齐掩码是一对：掩码让 RSP 变成 %16==0 才"骗过"断言，却把与调用方帧的定长
     * 关系挪了 8 字节，于是 E2E 的 framed（第 5 参数在调用方帧里）全错。两者一并撤除。 */
    /* 先把客户机栈要用的页"踩"一遍，逼宿主把它们提交出来。
     * Windows 的线程栈是"保留一大段、只提交头几页 + 一个守护页"，自动增长只在**碰到守护页**时发生；
     * 而客户机栈起点在宿主 rsp 下方 MARGIN(16KB) 处 —— 客户机第一次往里 push 时，可能一次性跨过守护页，
     * 于是得到一个"写野地址"式的访问违例（实测出错地址正好在 rsp 下方约 16KB，且是写、RVA 每次不同、
     * 在"新线程 + 首次调用"时最容易出现）。这里按页写一个 0 把这几十页提交掉。
     * 只踩**客户机栈顶以下**的区域：它此刻还没被任何代码用过，写它是安全的（往上是 stub 的帧，不能碰）。 */
    /* 逐页向下"踩"到客户机栈要用的范围。
     * 关键点（第 28 轮的写法错在这里）：**必须从当前栈指针附近开始、每次只跨一页** ——
     * 这样每一步踩到的都是"当前的守护页"，内核会正常按页增长；
     * 而一次性跨 16KB 会**跳过**中间所有页直落守护页，内核来不及增长就直接 AV
     * （CI 现场正是如此：出错页 protect=0x104=PAGE_GUARD，地址≈rsp-16KB=客户机栈起点）。 */
    {
        u8 *cur = (u8 *)(u64)(&vm);                       /* 当前帧附近，一定已提交 */
        u8 *end = (u8 *)(u64)vm->regs[VRSP] - (u64)(VM_MARGIN + 0x1000u);
        u32 steps = 0;
        while (cur > end && steps++ < 256u) {
            cur -= 0x1000u;
            *(volatile u8 *)cur = 0;                     /* 触碰 => 让内核按页提交 */
        }
    }
    /* 注：曾试过把客户机栈搬到私有缓冲（彻底避免原生调用压栈）。功能上 add_dly 立刻就好了，
     * 但它会破坏"客户机栈与宿主栈保持固定 skew"这条前提 —— E2E 的 framed 用例（第 5 个参数在
     * 调用方栈帧里，靠 FRAME_SKEW 修正）立刻全红。所以正解是**放大 margin**（skew 与 stub 一起变，自洽），
     * 而不是把栈挪走。 */
#ifndef VM_RELEASE
    vm_last_pc = 0xAA000001u; /* 已进入 vm_run */
#endif
    /* 加密支持：先查明文缓存；未命中则验签+解密到缓存槽（全忙则解到帧内缓冲）。
     * 验签失败返回 3，绝不执行未经验证的字节码。 */
    if (vm->desc) {
        const vm_desc_t *d = (const vm_desc_t *)vm->desc;
        const u8 *master = vm_master(); /* 1b：取钥 + KCV 校验（不通即 0xC0DE0007） */
        vm_dfields_t f;
        vm_desc_fields(d, master, &f); /* (3)：描述符标量字段先解掩码 */
#ifndef VM_RELEASE
        vm_last_pc = 0xAA000002u; /* 拿到描述符 */
#endif
        if (f.flags & VM_DESC_FLAG_ENC) {
            /* (c) 防回填完整性校验：入口补丁的字节 + 构建密钥做 FNV-1a，与描述符里的值比对。
             * 静态分析报告里那条绕过 —— 按函数尾声把被覆盖的 5 字节推回来 —— 会撞在这里。
             * 地址全部相对描述符算（base = d - selfRVA），因此与 ASLR 无关。 */
            /* 默认**关闭**运行期比对：ELF 路径上打包端写的期望值与镜像里的入口字节对不上
             * （离线复算：patch = e9 7b f1 12 00 的 FNV 是 0x2F8BCF94，而描述符里写的是 0xC15C90E3），
             * 一旦比对就会 trap，把 ELF/arm64 载荷全部拒绝执行 —— CI 自第 3 轮起一直红就是这个原因。
             * 需要它时用 -DVM_INVM_PATCHCHECK 显式打开；补丁字节的真正防线是加载期的入口蹦床
             * （vm_verify_table，PE 上已验证能拒绝回填）。 */
#ifdef VM_INVM_PATCHCHECK
            {
                u32 plen = (f.flags >> 8) & 0xFFu;
                if (plen) {
                    /* 补丁位置用「相对描述符的偏移」(reserved2) 定位：
                     * 之前用 d - selfRVA + reserved1，在 PE 上成立，但 ELF 的 selfRVA 语义不同，
                     * 于是校验必然失败、载荷被拒绝执行（CI 自第 3 轮起一直红就是这个原因）。 */
                    const u8 *pb = (const u8 *)d + (i32)f.reserved2;
                    /* 同一个 vm_patch_mac（打包端 PatchMAC 同式），不是无盐 FNV：
                     * key = KDFEntry(master, funcRVA, salt ^ 0x9E3779B9)（与加解密密钥域分离），
                     * msg = patch || le32(selfRVA) || le32(funcRVA) || le32(codeLen)。 */
                    u32 got = vm_patch_mac(master, vm_kdf_salt(d->selfRVA, f.reserved1, f.codeLen),
                                           d->selfRVA, f.reserved1, f.codeLen, pb, plen);
                    u32 want = (u32)rd32((const u8 *)d + 60);
                    if (got != want) {
                        __builtin_trap(); /* 被篡改：直接崩，不给"还原后继续跑"的机会 */
                    }
                }
            }
#endif /* VM_INVM_PATCHCHECK */
            if (f.encLen < f.codeLen) return 2;
#ifndef VM_RELEASE
            vm_last_pc = 0xAA000005u; /* 补丁校验通过 */
#endif
            /* 流式取指：**不解密到任何缓冲**。
             * Poly1305 认证的是**密文**，所以完整性可以在不解密的前提下校验；
             * 字节码在执行期始终以密文留在镜像里，取指时按块取 ChaCha20 密钥流逐字节还原，
             * 明文只以"寄存器里的一个字节"存在 —— 内存里不再有整份明文。 */
            u8 key[32];
            vm_desc_key(d, &f, master, key); /* 本条目的派生密钥（打包端 KDFEntry 同式现推） */
            const u8 *ct = (const u8 *)d + f.codeRVA;
            u8 aad[8];
            aad[0] = (u8)(d->selfRVA); aad[1] = (u8)(d->selfRVA >> 8);
            aad[2] = (u8)(d->selfRVA >> 16); aad[3] = (u8)(d->selfRVA >> 24);
            aad[4] = (u8)(f.reserved1); aad[5] = (u8)(f.reserved1 >> 8);
            aad[6] = (u8)(f.reserved1 >> 16); aad[7] = (u8)(f.reserved1 >> 24);
            if (!vm_aead_verify_aad(key, d->nonce, aad, 8, ct, f.encLen, d->tag)) {
                return 3; /* 验签失败：绝不执行未经验证的字节码 */
            }
            vm->code = (u8 *)ct;   /* 注意：这里存的是**密文**基址，取指经 vmb_byte 还原 */
            vm->codeLen = f.codeLen;
        }
    }
#ifndef VM_RELEASE
    vm_last_pc = 0xAA000004u; /* 解密完成，进入解释循环前 */
#endif
    vm_keep_verify_ref(vm);
    u64 rsp_start = vm->regs[VRSP]; /* 诊断用：客户机栈起点，见 vm_run_inner 注释 */
    /* 【已回退，勿再照抄】曾在这里按 frame = rsp_start + 8 + VM_MARGIN 做 XMM 双向同步，
     * 实测**毫无效果**（retconst/dblarg/dbladd/noarg 的错值与同步前完全一样），
     * 说明该地址公式在实际运行时并不成立（或读到的是已被改写的 RSP）。下次先在运行期把
     * 两个候选地址的内容 dump 出来定位，再动手。诊断结论见 STATUS #408。 */
    /* XMM 边界同步（入口）：蹦床把宿主 xmm0-xmm5 存进了它自己的帧，而解释器全程用 blob 里的
     * vm_xmm 当寄存器堆 —— 两者不是同一块内存，不同步就会：double 参数读不到、返回值送不出去。
     * 帧基址 = 模拟 RSP + 8 + VM_MARGIN（vm_abi.h「模拟栈位置」）；槽位偏移必须用宏 ——
     * 第一版硬编码成 304，而真实值是 VM_SAVE_XMM0(320/336，按平台)，于是同步写进了填充区、毫无效果。 */
#if defined(VM_BLOB_USES_WIN64) && !defined(VM_GUEST_ARM64)
    /* 只在 Windows blob + x86-64 客户机下同步：
     * - vm->frame 由 **Windows 入口 asm** 写入（Linux 入口还没写 ⇒ 那里读到的是相邻垃圾，
     *   实测会让 ELF e2e 全部 fault，所以这里按平台排除）；
     * - 测试 harness 直接调 vm_run、frame 为 0 ⇒ 天然跳过；
     * - arm64 客户机的帧布局不同（XMM 槽位在别处），同样排除。 */
    if (vm->frame) {
        u8 *xframe = (u8 *)(u64)vm->frame;
        int xi;
        for (xi = 0; xi < 6; xi++) {
            int b;
            for (b = 0; b < 16; b++) vm_xmm[xi * 16 + b] = xframe[VM_SAVE_XMM0 + xi * 16 + b];
        }
    }
#endif
#ifndef VM_RELEASE /* release 构建不带任何诊断状态：少一份明文、少一族特征 */
    vm_diag[0] = vm->regs[0];          /* 入口 X0（客户机参数） */
    vm_diag[1] = rsp_start;            /* 入口模拟 SP */
    vm_diag[2] = (u64)(unsigned long long)vm->code; /* **密文**字节码指针（Windows 的 unsigned long 是 32 位，会截断） */
    vm_diag[3] = vm->codeLen;
    if (vm->code) {
        for (int i = 0; i < 8; i++) { /* 前 64 字节（现在是**密文**，只用于对拍/定位，不再是明文） */
            u64 w = 0;
            for (int j = 0; j < 8; j++) w |= (u64)vm->code[i * 8 + j] << (8 * j);
            vm_diag[8 + i] = w;
        }
    }
#endif /* !VM_RELEASE */
    int rc = vm_run_inner(vm, rsp_start);
    /* XMM 边界同步（出口）：把 guest 算出来的 xmm0-xmm5 写回蹦床帧的保存槽，
     * 这样出口 asm 恢复 xmm0 时交还给调用方的就是**被保护函数的返回值**（xmm0 承载 FP 返回值）。 */
#if defined(VM_BLOB_USES_WIN64) && !defined(VM_GUEST_ARM64)
    if (vm->frame) {
        u8 *xframe = (u8 *)(u64)vm->frame;
        int xi;
        for (xi = 0; xi < 6; xi++) {
            int b;
            for (b = 0; b < 16; b++) xframe[VM_SAVE_XMM0 + xi * 16 + b] = vm_xmm[xi * 16 + b];
        }
    }
#endif
#ifndef VM_RELEASE
    vm_diag[4] = vm->regs[0];          /* 出口 X0（返回值） */
    vm_diag[5] = vm->regs[VRSP];
    vm_diag[6] = vm->pc;
    vm_diag[7] = (u64)(u32)rc;
#endif /* !VM_RELEASE */
#ifndef VM_RELEASE
    /* 明文缓存已移除（流式取指）：12..14 保留为 0，老观测脚本仍可读 */
    vm_diag[12] = 0;
    vm_diag[13] = 0;
    vm_diag[14] = 0;
    vm_diag[15] = vm_call_ring_n;
#endif
    return rc;
}

/* 内层解释循环：所有 return 都从这里出去；取指由 vm_bcs_t 流式还原（无明文缓冲） */
/* 浮点标量运算：**单独成函数**。
 * 为什么不让它留在那个巨大的 switch 里：实测只要把浮点代码写在 vm_run_inner 内部，
 * gcc -O2 就会把整个函数编译错（连根本不执行浮点的函数结果都是错的）；
 * 分出来之后 -O2 下恢复正常（这就是"加了浮点代码、别的函数全错"的真正原因）。 */
/* noinline：-O2 下如果它被内联回 vm_run_inner，整个解释器会被编译错（实测）。
 * 独立成函数 + 禁止内联之后，-O2 恢复正常。 */
/* 浮点标量运算：独立成函数并禁止内联（详见 STATUS 第 71/72 轮）。 */
__attribute__((noinline)) static u32 vm_fp_step(vm_ctx_t *vm, vm_bcs_t *s, u32 pc) {


            /* 浮点标量运算：解释器本身就是原生代码，直接用它自己的 FPU 最准。
             * 操作数是**相对 VMBASE 的偏移**（Disp=目标、Imm=第一操作数、Imm2=第二操作数，0 表示不用）。
             * 运算不额外改标志位，除了 UCOMISD/COMISD 按 SDM 的表设置 ZF/PF/CF。 */
            u32 fk = vmb_byte(s, pc + 1), fw = vmb_byte(s, pc + 2);
            u32 fdst = vmb_rd32(s, pc + 3), fa = vmb_rd32(s, pc + 7), fb = vmb_rd32(s, pc + 11);
            u8 *fbase = (u8 *)(vm->regs[VRBASE]);
            void *pa = (void *)(fbase + fa);
            void *pb = fb ? (void *)(fbase + fb) : 0;
            void *pdst = (void *)(fbase + fdst);
            if (fw == 32) {
                float a = *(float *)pa;
                float b = pb ? *(float *)pb : 0.0f;
                switch (fk) {
                case KF_ADD: *(float *)pdst = a + b; break;
                case KF_SUB: *(float *)pdst = a - b; break;
                case KF_MUL: *(float *)pdst = a * b; break;
                case KF_DIV: *(float *)pdst = a / b; break;
                case KF_MIN: *(float *)pdst = a < b ? a : b; break;
                case KF_MAX: *(float *)pdst = a > b ? a : b; break;
#if defined(__x86_64__) || defined(_M_X64)
                case KF_SQRT: { float sr; __asm__ __volatile__("sqrtss %1, %0" : "=x"(sr) : "x"(a)); *(float *)pdst = sr; break; }
#else
                /* 非 x86 宿主：sqrtss 是 x86 助记符，汇编不过去（CI 的 linux-arm64 作业实测就卡在这）。
                 * 而且这条路径在 arm64 客户机上根本不会被发射（KF_SQRT 只由 x64 lifter 产生），
                 * 所以这里保持"传值不计算"即可，不引入 aarch64 内联汇编。 */
                case KF_SQRT: *(float *)pdst = a; break;
#endif
                case KF_CVTSI2F: { u64 iv = 0; u32 k; for (k = 0; k < 8; k++) iv |= (u64)((const u8 *)pa)[k] << (8 * k); *(float *)pdst = (float)(i64)iv; break; }
                case KF_CVTTF2SI: *(i64 *)pdst = (i64)a; break; /* 结果写成整数，调用方再搬进寄存器 */
                case KF_UCOMI: {
                    u32 nf = 0;
                    if (!(a == a) || !(b == b)) nf = VM_FL_Z | VM_FL_P | VM_FL_C;
                    else if (a < b) nf = VM_FL_C;
                    else if (a == b) nf = VM_FL_Z;
                    vm->flags = (vm->flags & ~(VM_FL_Z | VM_FL_P | VM_FL_C | VM_FL_N | VM_FL_V)) | nf;
                    break;
                }
                }
            } else {
                double a = *(double *)pa;
                double b = pb ? *(double *)pb : 0.0;
                switch (fk) {
                case KF_ADD: *(double *)pdst = a + b; break;
                case KF_SUB: *(double *)pdst = a - b; break;
                case KF_MUL: *(double *)pdst = a * b; break;
                case KF_DIV: *(double *)pdst = a / b; break;
                case KF_MIN: *(double *)pdst = a < b ? a : b; break;
                case KF_MAX: *(double *)pdst = a > b ? a : b; break;
                case KF_CVTDQ2PD: {
                    /* CVTDQ2PD dst, src：把 src 低 64 位里的两个 int32 各自转成 double，
                     * 写满目标的 128 位（两条 lane）。源是 XMM 或内存，lifter 已经把它摆到 pa。 */
                    const int *si = (const int *)pa;
                    double *dd = (double *)pdst;
                    dd[0] = (double)si[0];
                    dd[1] = (double)si[1];
                    break;
                }
#if defined(__x86_64__) || defined(_M_X64)
                case KF_SQRT: { double sr; __asm__ __volatile__("sqrtsd %1, %0" : "=x"(sr) : "x"(a)); *(double *)pdst = sr; break; }
#else
                case KF_SQRT: *(double *)pdst = a; break;
#endif
                case KF_CVTSI2F: { u64 iv = 0; u32 k; for (k = 0; k < 8; k++) iv |= (u64)((const u8 *)pa)[k] << (8 * k); *(double *)pdst = (double)(i64)iv; break; }
                case KF_CVTTF2SI: {
                    /* x86 的 CVTTSD2SI：超出范围给 0x8000000000000000（不定值），且不抛异常 */
                    i64 r;
                    if (a != a || a >= 9223372036854775808.0 || a < -9223372036854775808.0) {
                        r = (i64)0x8000000000000000LL;
                    } else {
                        r = (i64)a;
                    }
                    { u64 uv = (u64)r; u32 k; for (k = 0; k < 8; k++) ((u8 *)pdst)[k] = (u8)(uv >> (8 * k)); }
                    break;
                }
                case KF_UCOMI: {
                    u32 nf = 0;
                    if (!(a == a) || !(b == b)) nf = VM_FL_Z | VM_FL_P | VM_FL_C;
                    else if (a < b) nf = VM_FL_C;
                    else if (a == b) nf = VM_FL_Z;
                    vm->flags = (vm->flags & ~(VM_FL_Z | VM_FL_P | VM_FL_C | VM_FL_N | VM_FL_V)) | nf;
                    break;
                }
                }
            }
    return pc + 15;
}

/* 一次调用的指令预算（诊断用）：超了就以 96 返回。
 * 为什么需要：arm64 上带循环的 sum_to 在探针里"永不返回"，我们需要它快速返回、
 * 并把环形缓冲（最近执行的 pc/op）留下来，才能看出是哪条分支没让 pc 前进。 */
#ifndef VM_RELEASE
#define VM_STEP_BUDGET 20000000u
#endif

/* 调试探针（仅非 release）：最后执行的 pc | op<<32。
 * 不写描述符：描述符所在节是 RX 映射，写它会直接访问违例；
 * 用全局的地址 = 模块基址 + sectionRVA + (符号偏移 - bssOff)，三个量都由打包器自己给出。 */
#ifndef VM_RELEASE
u64 vm_last_pc;
u64 vm_last_call;
u64 vm_last_call_rcx;
u64 vm_last_call_sp;
#endif

static int vm_run_inner(vm_ctx_t *vm, u64 rsp_start) {
    u32 steps = 0;
    (void)steps;
    vm_bcs_t bcs;
    vm_bcs_init(&bcs, vm);
    for (;;) {
#ifndef VM_RELEASE
        if (++steps > VM_STEP_BUDGET) return 96;
#endif
        /* 诊断用（见 vm_run_inner 的注释）：客户机压栈越过给它的栈下界时当场返回 99。
         * 这样 Linux 上那个"跳进 .bss"就能被区分成"客户机踩穿了自己的栈"或"另有原因"。 */
#ifndef VM_GUEST_ARM64
        /* 只对 x86-64 客户机生效：ARM64 客户机的 SP 用法与 VM_MARGIN（宿主侧常量）不是一个口径，
         * 直接套用会让 arm64 客户机差分误报（CI 上确实被它抓到过一次）。 */
        if (rsp_start - vm->regs[VRSP] > (u64)VM_MARGIN) {
            return 99; /* 压栈越过给它的栈下界 */
        }
        if (vm->regs[VRSP] > rsp_start) {
            return 97; /* 弹出过多：SP 高过进入值（返回地址会取错，进而跳到任意地址） */
        }
#endif
        if (vm->pc >= vm->codeLen) return 1;
        u32 pc = vm->pc;
        u8 op = vmb_byte(&bcs, pc);
#ifndef VM_RELEASE
        vm_last_pc = (u64)pc | ((u64)op << 32);
        if (!vm_first_sp) vm_first_sp = vm->regs[VRSP];
        vm_last_sp = vm->regs[VRSP];
        if (vm->regs[1] != vm_r1_prev) {
            /* 变化是在本步检出的，真正写它的指令是**上一条** */
            vm_r1_pcs[vm_r1_i & 63u] = vm_r1_prev_pc;
            vm_r1_vals[vm_r1_i & 63u] = vm->regs[1];
            vm_r1_i++;
            vm_r1_prev = vm->regs[1];
        }
        vm_r1_prev_pc = pc;
#endif
#ifndef VM_RELEASE
        /* 现场记录（见 vm_ring_hdr 的注释）：只记环形缓冲，不影响语义 */
        {
            u32 k = (u32)(vm_ring_hdr[1] & 15);
            vm_ring[k][0] = pc;
            vm_ring[k][1] = op;
            vm_ring_hdr[0] = 0x564D52494E473031ULL; /* "VMRING01"：运行时写，避免落进 .data */
            vm_ring_hdr[1]++;
        }
#endif /* !VM_RELEASE */

        switch (op) {
        case OP_HALT: return 1;
        case OP_NOP:  vm->pc = pc + 1; break;
        case OP_RET:  return 0;

        case OP_MOV_RR: {
            u32 width = vmb_byte(&bcs, pc + 1);
            write_reg(vm, vmb_byte(&bcs, pc + 2) & VM_REG_MASK, width, vm->regs[vmb_byte(&bcs, pc + 3) & VM_REG_MASK]);
            vm->pc = pc + 4;
            break;
        }
        case OP_MOV_RI: {
            u32 width = vmb_byte(&bcs, pc + 1);
            write_reg(vm, vmb_byte(&bcs, pc + 2) & VM_REG_MASK, width, vmb_rd64(&bcs, pc + 3));
            vm->pc = pc + 11;
            break;
        }
        case OP_MOV_RI32: {
            vm->regs[vmb_byte(&bcs, pc + 1) & VM_REG_MASK] = (u64)vmb_rd32(&bcs, pc + 2); /* 32 位 mov 零扩展 */
            vm->pc = pc + 6;
            break;
        }
        case OP_LEA: {
            u32 width = vmb_byte(&bcs, pc + 1), dst = vmb_byte(&bcs, pc + 2) & VM_REG_MASK, base = vmb_byte(&bcs, pc + 3), idx = vmb_byte(&bcs, pc + 4);
            u64 scale = vmb_byte(&bcs, pc + 5);
            i64 disp = (i64)(i32)vmb_rd32(&bcs, pc + 6);
            u64 addr = (u64)disp;
            if (base != VM_NO_REG) addr += vm_rdreg(vm, base);
            if (idx != VM_NO_REG) addr += vm_rdreg(vm, idx) * scale;
            write_reg(vm, dst, width, addr);
            vm->pc = pc + 10;
            break;
        }
        case OP_ALU_RR: {
            u32 kind = vmb_byte(&bcs, pc + 1), width = vmb_byte(&bcs, pc + 2), dst = vmb_byte(&bcs, pc + 3) & VM_REG_MASK;
            u32 keep = kind & VM_ALU_KEEP_FLAGS;
            kind &= (u32)~VM_ALU_KEEP_FLAGS;
            u64 a = vm->regs[vmb_byte(&bcs, pc + 4) & VM_REG_MASK], b = vm->regs[vmb_byte(&bcs, pc + 5) & VM_REG_MASK];
            u32 saved = vm->flags;
            write_reg(vm, dst, width, alu_apply(vm, kind, width, a, b));
            if (keep) vm->flags = saved;
            vm->pc = pc + 6;
            break;
        }
        case OP_ALU_RI: {
            u32 kind = vmb_byte(&bcs, pc + 1), width = vmb_byte(&bcs, pc + 2), dst = vmb_byte(&bcs, pc + 3) & VM_REG_MASK;
            u32 keep = kind & VM_ALU_KEEP_FLAGS;
            kind &= (u32)~VM_ALU_KEEP_FLAGS;
            u64 a = vm->regs[vmb_byte(&bcs, pc + 4) & VM_REG_MASK];
            u32 raw = vmb_rd32(&bcs, pc + 5);
            /* x86: ADD/SUB/MUL 的 imm32 符号扩展；AND/OR/XOR 的 imm32 零扩展。
             * 注意：判断前要屏蔽 keep-flags 位，否则负立即数会被零扩展成 +2^32。 */
            u32 kc = kind & (u32)~VM_ALU_KEEP_FLAGS;
            u64 b = (kc == K_ADD || kc == K_SUB || kc == K_MUL || kc == K_ADC || kc == K_SBB) ? (u64)(i64)(i32)raw : (u64)raw;
            u32 saved = vm->flags;
            write_reg(vm, dst, width, alu_apply(vm, kind, width, a, b));
            if (keep) vm->flags = saved;
            vm->pc = pc + 9;
            break;
        }
        case OP_ALU_U: {
            u32 kind = vmb_byte(&bcs, pc + 1), width = vmb_byte(&bcs, pc + 2), dst = vmb_byte(&bcs, pc + 3) & VM_REG_MASK;
            u32 keep = kind & VM_ALU_KEEP_FLAGS;
            kind &= (u32)~VM_ALU_KEEP_FLAGS;
            u64 a = vm->regs[vmb_byte(&bcs, pc + 4) & VM_REG_MASK];
            u32 saved = vm->flags;
            if (kind == K_DIVU || kind == K_DIVS) {
                /* x86 单操作数 DIV/IDIV（复用 OP_ALU_U 编码：a = 除数、dst 不用）。
                 * 被除数是隐含的：8 位用 AH:AL（= RAX 低 16 位），16/32/64 位用 DX:AX 族；
                 * 商→AX 族、余→DX 族。标志位按 x86 规定未定义，这里不动。
                 * 除零 / 商放不下 —— **绝不静默算错**：直接 trap（等同于原生未处理 #DE：进程死掉）。 */
                u64 q = 0, r = 0;
                /* 注意：blob 是 freestanding 的，**不能用 __int128 的除法**（会拉进 __divti3，
                 * 而 stub 不是自包含的 —— 实测门禁直接报"引用了未定义符号 __divti3"）。
                 * 所以 8/16/32 位用 u64/i64 运算（2w 位被除数在 w<=32 时放得进 64 位），
                 * 64 位直接交给硬件指令（语义与 #DE 行为都完全一致）。 */
                if (width == 8) {
                    u32 dividend = (u32)(vm->regs[VRAX] & 0xFFFFu); /* AH:AL */
                    if (kind == K_DIVU) {
                        u32 dv = (u32)(a & 0xFFu);
                        if (dv == 0) __builtin_trap();
                        q = dividend / dv;
                        r = dividend % dv;
                        if (q > 0xFFu) __builtin_trap();
                    } else {
                        int dvd = (int)(short)(unsigned short)dividend;
                        int dvs = (int)(signed char)(unsigned char)a;
                        int qq;
                        if (dvs == 0) __builtin_trap();
                        qq = dvd / dvs;
                        if (qq < -128 || qq > 127) __builtin_trap();
                        q = (u64)(unsigned char)(signed char)qq;
                        r = (u64)(unsigned char)(signed char)(dvd % dvs);
                    }
                    write_reg(vm, VRAX, 16, (u64)(((r & 0xFFu) << 8) | (q & 0xFFu))); /* AH=余、AL=商 */
                } else if (width == 16 || width == 32) {
                    u64 mask = width_mask(width);
                    u64 dxv = vm->regs[VRDX] & mask, axv = vm->regs[VRAX] & mask;
                    if (kind == K_DIVU) {
                        u64 dv = a & mask, n = (dxv << width) | axv;
                        if (dv == 0) __builtin_trap();
#if defined(VM_HOST_X86_32)
                        q = vm_udivmod64(n, dv, &r);
#else
                        q = n / dv;
                        r = n % dv;
#endif
                        if (q > mask) __builtin_trap();
                    } else {
                        i64 dvs = sign_extend_w(a & mask, width);
                        i64 n, qq, lo, hi;
                        if (dvs == 0) __builtin_trap();
                        n = (i64)(((u64)sign_extend_w(dxv, width) << width) | axv);
#if defined(VM_HOST_X86_32)
                        {   /* 32 位宿主：有符号 64 位除余也走可移植助手 */
                            i64 rr = 0;
                            qq = vm_idivmod64(n, dvs, &rr);
                            r = (u64)rr & mask;
                        }
#else
                        qq = n / dvs;
#endif
                        lo = -((i64)1 << (width - 1));
                        hi = ((i64)1 << (width - 1)) - 1;
                        if (qq < lo || qq > hi) __builtin_trap();
                        q = (u64)qq & mask;
#if !defined(VM_HOST_X86_32)
                        r = (u64)(n % dvs) & mask;
#endif
                    }
                    if (width == 16) {
                        write_reg(vm, VRAX, 16, q & 0xFFFFu);
                        write_reg(vm, VRDX, 16, r & 0xFFFFu);
                    } else {
                        write_reg(vm, VRAX, 32, q & 0xFFFFFFFFu);
                        write_reg(vm, VRDX, 32, r & 0xFFFFFFFFu);
                    }
                } else {
                    
/* 64 位：手写 128/64 长除法。
                     * 为什么不用 inline asm：同一个 vm_interp.c 也会被 clang 交叉编译成 arm64 blob，
                     * 那里既没有 divq、clang 也不接受 "+a"/"+d" 约束（CI 实测报 invalid output constraint）。
                     * 也不用 __int128 的除法：freestanding blob 里会拉进 __divti3（门禁直接报未定义符号）。 */
                    u64 dxv = vm->regs[VRDX], axv = vm->regs[VRAX], dv = a;
                    u32 negn = 0, negd = 0;
                    u64 qq = 0, rem = 0;
                    int bi;
                    if (kind == K_DIVS) {
                        if (dxv >> 63) { /* 取 |被除数|（128 位取反加一） */
                            axv = ~axv + 1ull;
                            dxv = ~dxv + (axv == 0 ? 1ull : 0ull);
                            negn = 1;
                        }
                        if (dv >> 63) {
                            dv = ~dv + 1ull;
                            negd = 1;
                        }
                    }
                    if (dv == 0) __builtin_trap();
                    if (dxv >= dv) __builtin_trap(); /* 商放不下 64 位 ⇒ #DE */
                    rem = dxv;
                    for (bi = 63; bi >= 0; bi--) {
                        u64 carry = rem >> 63;
                        rem = (rem << 1) | ((axv >> (u32)bi) & 1ull);
                        if (carry || rem >= dv) {
                            rem -= dv;
                            qq |= (1ull << (u32)bi);
                        }
                    }
                    if (kind == K_DIVS) {
                        /* 向零截断：商为负 ⟺ 两操作数异号；余数随被除数的符号。 */
                        if (negn != negd) {
                            if (qq > 0x8000000000000000ull) __builtin_trap();
                            qq = ~qq + 1ull;
                        } else if (qq > 0x7FFFFFFFFFFFFFFFull) {
                            __builtin_trap();
                        }
                        if (negn) rem = ~rem + 1ull;
                    }
                    write_reg(vm, VRAX, 64, qq);
                    write_reg(vm, VRDX, 64, rem);
                }
                vm->pc = pc + 5;
                break;
            }
            write_reg(vm, dst, width, alu_unary(vm, kind, width, a));
            if (keep) vm->flags = saved;
            vm->pc = pc + 5;
            break;
        }
        case OP_CMP_RR: {
            u32 kind = vmb_byte(&bcs, pc + 1), width = vmb_byte(&bcs, pc + 2);
            u64 a = vm->regs[vmb_byte(&bcs, pc + 3) & VM_REG_MASK], b = vm->regs[vmb_byte(&bcs, pc + 4) & VM_REG_MASK];
            u64 m = width_mask(width);
            u64 x = a & m, y = b & m;
            /* 走 alu_apply：这样 ARM64 客户机的 C 位语义（无借位）也生效 */
            if (kind == KC_TEST) {
                (void)alu_apply(vm, K_AND, width, x, y);
            } else {
                (void)alu_apply(vm, K_SUB, width, x, y);
            }
            vm->pc = pc + 5;
            break;
        }
        case OP_CMP_RI: {
            u32 kind = vmb_byte(&bcs, pc + 1), width = vmb_byte(&bcs, pc + 2);
            u64 a = vm->regs[vmb_byte(&bcs, pc + 3) & VM_REG_MASK];
            u32 raw = vmb_rd32(&bcs, pc + 4);
            u64 b = (kind == KC_TEST) ? (u64)raw : (u64)(i64)(i32)raw;
            u64 m = width_mask(width);
            u64 x = a & m, y = b & m;
            if (kind == KC_TEST) {
                (void)alu_apply(vm, K_AND, width, x, y);
            } else {
                (void)alu_apply(vm, K_SUB, width, x, y);
            }
            vm->pc = pc + 8;
            break;
        }
        case OP_EXT: {
            u32 kind = vmb_byte(&bcs, pc + 1), srcw = vmb_byte(&bcs, pc + 2), dst = vmb_byte(&bcs, pc + 3) & VM_REG_MASK;
            u64 v = vm->regs[vmb_byte(&bcs, pc + 4) & VM_REG_MASK];
            vm->regs[dst] = kind ? (u64)sign_extend_w(v, srcw) : (v & width_mask(srcw));
            vm->pc = pc + 5;
            break;
        }
        case OP_LOAD: {
            u32 kind = vmb_byte(&bcs, pc + 1), width = vmb_byte(&bcs, pc + 2), dst = vmb_byte(&bcs, pc + 3) & VM_REG_MASK, base = vmb_byte(&bcs, pc + 4) & VM_REG_MASK;
            u32 idx = vmb_byte(&bcs, pc + 5), scale = vmb_byte(&bcs, pc + 6);
            i64 disp = (i64)(i32)vmb_rd32(&bcs, pc + 7);
            u64 addr = vm_rdreg(vm, base) + (u64)disp;
            if (idx != VM_NO_REG)
                addr += vm_rdreg(vm, idx) * (u64)scale;
            u64 v = 0;
            switch (width) {
            case 8:  v = *(volatile u8 *)addr; break;
            case 16: v = *(volatile u16 *)addr; break;
            case 32: v = *(volatile u32 *)addr; break;
            default: v = *(volatile u64 *)addr; break;
            }
            vm->regs[dst] = kind ? (u64)sign_extend_w(v, width) : (v & width_mask(width));
            vm->pc = pc + 11;
            break;
        }
        case OP_STORE: {
            u32 width = vmb_byte(&bcs, pc + 1), base = vmb_byte(&bcs, pc + 2) & VM_REG_MASK;
            u32 idx = vmb_byte(&bcs, pc + 3), scale = vmb_byte(&bcs, pc + 4);
            i64 disp = (i64)(i32)vmb_rd32(&bcs, pc + 5);
            u32 src = vmb_byte(&bcs, pc + 9) & VM_REG_MASK;
            u64 addr = vm_rdreg(vm, base) + (u64)disp;
            if (idx != VM_NO_REG)
                addr += vm_rdreg(vm, idx) * (u64)scale;
            u64 v = vm->regs[src];
#ifndef VM_RELEASE
            vm_st_pcs[vm_st_i & 15u] = pc;
            vm_st_addrs[vm_st_i & 15u] = addr;
            vm_st_vals[vm_st_i & 15u] = v;
            vm_st_i++;
#endif
            switch (width) {
            case 8:  *(volatile u8 *)addr = (u8)v; break;
            case 16: *(volatile u16 *)addr = (u16)v; break;
            case 32: *(volatile u32 *)addr = (u32)v; break;
            default: *(volatile u64 *)addr = v; break;
            }
            vm->pc = pc + 10;
            break;
        }

        case OP_ATOMIC: {
            /* 原子读改写：真用宿主硬件的原子指令（__atomic_* 在 x86-64 上就是 lock 前缀指令），
             * 所以多线程语义与原生一致——不是"假装原子"。
             * 布局：[op][kind][width][dst][src][base][idx][scale][disp32] */
            u32 ak = vmb_byte(&bcs, pc + 1);
            u32 keep = ak & VM_ALU_KEEP_FLAGS;
            ak &= (u32)~VM_ALU_KEEP_FLAGS;
            u32 aw = vmb_byte(&bcs, pc + 2), adst = vmb_byte(&bcs, pc + 3), asrc = vmb_byte(&bcs, pc + 4) & VM_REG_MASK; /* adst 不掩码：要能表示 VM_NO_REG */
            u32 abase = vmb_byte(&bcs, pc + 5) & VM_REG_MASK, aidx = vmb_byte(&bcs, pc + 6), ascale = vmb_byte(&bcs, pc + 7);
            i64 adisp = (i64)(i32)vmb_rd32(&bcs, pc + 8);
            u64 addr = vm_rdreg(vm, abase) + (u64)adisp;
            if (aidx != VM_NO_REG)
                addr += vm_rdreg(vm, aidx) * (u64)ascale;
            u32 saved = vm->flags;
            u64 sv = vm->regs[asrc] & width_mask(aw);
            u64 old = 0;
            /* 注意：**不能**先无条件 exchange 一把来"取旧值"——
             * 对 ADD/AND/… 这类读改写来说那会多写一次内存，CMPXCHG 更是会被提前破坏
             * （实测就是这个原因导致数值与原生不一致）。下面按 kind 选用对应的原子内建，
             * 它们既完成读改写、又把旧值返回给我们。 */
            u32 am = width_mask(aw);
            if (ak == KA_XCHG || ak == KA_CMPXCHG) {
                if (ak == KA_XCHG) {
                    switch (aw) {
                    case 8:  old = (u64)__atomic_exchange_n((volatile u8 *)addr, (u8)sv, __ATOMIC_SEQ_CST); break;
                    case 16: old = (u64)__atomic_exchange_n((volatile u16 *)addr, (u16)sv, __ATOMIC_SEQ_CST); break;
                    case 32: old = (u64)__atomic_exchange_n((volatile u32 *)addr, (u32)sv, __ATOMIC_SEQ_CST); break;
                    default: old = __atomic_exchange_n((volatile u64 *)addr, sv, __ATOMIC_SEQ_CST); break;
                    }
                } else {
                    /* CMPXCHG：与 RAX 比较；相等则写回并置 ZF，否则把内存值读进 RAX 并清 ZF */
                    u64 expect = vm->regs[VRAX] & am;
                    u8 ok = 0;
                    switch (aw) {
                    case 8:  { u8 e = (u8)expect;  ok = __atomic_compare_exchange_n((volatile u8 *)addr, &e, (u8)sv, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);  expect = e; break; }
                    case 16: { u16 e = (u16)expect; ok = __atomic_compare_exchange_n((volatile u16 *)addr, &e, (u16)sv, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); expect = e; break; }
                    case 32: { u32 e = (u32)expect; ok = __atomic_compare_exchange_n((volatile u32 *)addr, &e, (u32)sv, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); expect = e; break; }
                    default: { u64 e = expect;        ok = __atomic_compare_exchange_n((volatile u64 *)addr, &e, sv, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);       expect = e; break; }
                    }
                    if (ok) {
                        vm->flags = (vm->flags & ~VM_FL_Z) | VM_FL_Z;
                    } else {
                        vm->flags &= ~VM_FL_Z;
                        vm->regs[VRAX] = expect & am;
                    }
                }
                if (adst != VM_NO_REG) {
                /* 目的寄存器索引必须落在 ctx 的 regs[] 之内。adst 来自字节码、**未经掩码**
                 * （因为 0xFF 要表示"不写寄存器"）；一旦字节码损坏或 PC 失步，这里就是越界写。
                 * CI 上那些"写、地址≈rsp-16KB、protect=0x104(守护页)"的偶发崩溃正是这条：
                 * 反汇编里就是 `mov %rsi,(%r15,%rax,8)`（r15=ctx，rax=adst）。
                 * 越界即响亮失败（98 = 未知/非法操作），绝不越界写。 */
                if (adst >= (u32)(sizeof(vm->regs) / sizeof(vm->regs[0]))) return 98;
                vm->regs[adst] = old & am;
            }
            } else {
                /* 读改写：用对应的 fetch_* 内建（原子完成，并返回旧值） */
                switch (aw) {
                case 8:
                    switch (ak) {
                    case KA_ADD: case KA_INC: old = (u64)__atomic_fetch_add((volatile u8 *)addr, (ak == KA_ADD ? (u8)sv : 1u), __ATOMIC_SEQ_CST); break;
                    case KA_SUB: case KA_DEC: old = (u64)__atomic_fetch_sub((volatile u8 *)addr, (ak == KA_SUB ? (u8)sv : 1u), __ATOMIC_SEQ_CST); break;
                    case KA_AND: old = (u64)__atomic_fetch_and((volatile u8 *)addr, (u8)sv, __ATOMIC_SEQ_CST); break;
                    case KA_OR:  old = (u64)__atomic_fetch_or((volatile u8 *)addr, (u8)sv, __ATOMIC_SEQ_CST); break;
                    case KA_XOR: old = (u64)__atomic_fetch_xor((volatile u8 *)addr, (u8)sv, __ATOMIC_SEQ_CST); break;
                    }
                    break;
                case 16:
                    switch (ak) {
                    case KA_ADD: case KA_INC: old = (u64)__atomic_fetch_add((volatile u16 *)addr, (ak == KA_ADD ? (u16)sv : 1u), __ATOMIC_SEQ_CST); break;
                    case KA_SUB: case KA_DEC: old = (u64)__atomic_fetch_sub((volatile u16 *)addr, (ak == KA_SUB ? (u16)sv : 1u), __ATOMIC_SEQ_CST); break;
                    case KA_AND: old = (u64)__atomic_fetch_and((volatile u16 *)addr, (u16)sv, __ATOMIC_SEQ_CST); break;
                    case KA_OR:  old = (u64)__atomic_fetch_or((volatile u16 *)addr, (u16)sv, __ATOMIC_SEQ_CST); break;
                    case KA_XOR: old = (u64)__atomic_fetch_xor((volatile u16 *)addr, (u16)sv, __ATOMIC_SEQ_CST); break;
                    }
                    break;
                case 32:
                    switch (ak) {
                    case KA_ADD: case KA_INC: old = (u64)__atomic_fetch_add((volatile u32 *)addr, (ak == KA_ADD ? (u32)sv : 1u), __ATOMIC_SEQ_CST); break;
                    case KA_SUB: case KA_DEC: old = (u64)__atomic_fetch_sub((volatile u32 *)addr, (ak == KA_SUB ? (u32)sv : 1u), __ATOMIC_SEQ_CST); break;
                    case KA_AND: old = (u64)__atomic_fetch_and((volatile u32 *)addr, (u32)sv, __ATOMIC_SEQ_CST); break;
                    case KA_OR:  old = (u64)__atomic_fetch_or((volatile u32 *)addr, (u32)sv, __ATOMIC_SEQ_CST); break;
                    case KA_XOR: old = (u64)__atomic_fetch_xor((volatile u32 *)addr, (u32)sv, __ATOMIC_SEQ_CST); break;
                    }
                    break;
                default:
                    switch (ak) {
                    case KA_ADD: case KA_INC: old = __atomic_fetch_add((volatile u64 *)addr, (ak == KA_ADD ? sv : 1u), __ATOMIC_SEQ_CST); break;
                    case KA_SUB: case KA_DEC: old = __atomic_fetch_sub((volatile u64 *)addr, (ak == KA_SUB ? sv : 1u), __ATOMIC_SEQ_CST); break;
                    case KA_AND: old = __atomic_fetch_and((volatile u64 *)addr, sv, __ATOMIC_SEQ_CST); break;
                    case KA_OR:  old = __atomic_fetch_or((volatile u64 *)addr, sv, __ATOMIC_SEQ_CST); break;
                    case KA_XOR: old = __atomic_fetch_xor((volatile u64 *)addr, sv, __ATOMIC_SEQ_CST); break;
                    }
                    break;
                }
                /* 标志位按"运算结果"算（x86 的 LOCK ALU 语义） */
                {
                    u64 a = old & am, b = sv & am, res = old & am;
                    switch (ak) {
                    case KA_ADD: res = a + b; vm->flags = flags_add_w(a, b, res, aw); break;
                    case KA_SUB: res = a - b; vm->flags = flags_sub_w(a, b, res, aw); break;
                    case KA_AND: res = a & b; vm->flags = flags_logic_w(res, aw); break;
                    case KA_OR:  res = a | b; vm->flags = flags_logic_w(res, aw); break;
                    case KA_XOR: res = a ^ b; vm->flags = flags_logic_w(res, aw); break;
                    case KA_INC: res = a + 1; vm->flags = flags_add_w(a, 1, res, aw); break;
                    case KA_DEC: res = a - 1; vm->flags = flags_sub_w(a, 1, res, aw); break;
                    default: break;
                    }
                }
                if (adst != VM_NO_REG) {
                /* 目的寄存器索引必须落在 ctx 的 regs[] 之内。adst 来自字节码、**未经掩码**
                 * （因为 0xFF 要表示"不写寄存器"）；一旦字节码损坏或 PC 失步，这里就是越界写。
                 * CI 上那些"写、地址≈rsp-16KB、protect=0x104(守护页)"的偶发崩溃正是这条：
                 * 反汇编里就是 `mov %rsi,(%r15,%rax,8)`（r15=ctx，rax=adst）。
                 * 越界即响亮失败（98 = 未知/非法操作），绝不越界写。 */
                if (adst >= (u32)(sizeof(vm->regs) / sizeof(vm->regs[0]))) return 98;
                vm->regs[adst] = old & am;
            }
            }
            if (keep) vm->flags = saved;
            vm->pc = pc + 12;
            break;
        }


        case OP_FP: { vm->pc = vm_fp_step(vm, &bcs, pc); break; }
        case OP_PUSH_R: {
            u32 r = vmb_byte(&bcs, pc + 1) & VM_REG_MASK;
            u64 sp = vm->regs[VRSP] - VM_STACK_SLOT;
            /* 按**槽宽**读写：32 位槽只动 4 字节，否则会覆盖槽下方的内存（静默踩内存）。 */
            if (VM_STACK_SLOT == 4u) *(volatile u32 *)sp = (u32)vm->regs[r];
            else                    *(volatile u64 *)sp = vm->regs[r];
            vm->regs[VRSP] = sp;
            vm->pc = pc + 2;
            break;
        }
        case OP_PUSH_I: {
            u64 sp = vm->regs[VRSP] - VM_STACK_SLOT;
            if (VM_STACK_SLOT == 4u) *(volatile u32 *)sp = (u32)(i32)vmb_rd32(&bcs, pc + 1);
            else                    *(volatile u64 *)sp = (u64)(i64)(i32)vmb_rd32(&bcs, pc + 1);
            vm->regs[VRSP] = sp;
            vm->pc = pc + 5;
            break;
        }
        case OP_POP_R: {
            u32 r = vmb_byte(&bcs, pc + 1) & VM_REG_MASK;
            u64 sp = vm->regs[VRSP];
            vm->regs[r] = (VM_STACK_SLOT == 4u) ? (u64)(*(volatile u32 *)sp) : (*(volatile u64 *)sp);
            vm->regs[VRSP] = sp + VM_STACK_SLOT;
            vm->pc = pc + 2;
            break;
        }
        case OP_JCC: {
            u32 cond = vmb_byte(&bcs, pc + 1);
            if (cond_holds(vm, cond)) vm->pc = vmb_rd32(&bcs, pc + 2);
            else vm->pc = pc + 6;
            break;
        }
        case OP_JBZ:
        case OP_JBNZ: {
            u32 r = vmb_byte(&bcs, pc + 1) & VM_REG_MASK;
            u32 target = vmb_rd32(&bcs, pc + 2);
            int isZero = (vm->regs[r] == 0);
            int take = (vmb_byte(&bcs, pc) == OP_JBZ) ? isZero : !isZero;
            vm->pc = take ? target : pc + 6;
            break;
        }
        case OP_JMP:
            vm->pc = vmb_rd32(&bcs, pc + 1);
            break;
        case OP_CALLN: {
            /* 字节码里存的是 RVA：真实地址 = 模块基址 + RVA */
            u64 addr = vm->regs[VRBASE] + vmb_rd64(&bcs, pc + 1);
#ifndef VM_RELEASE
            vm_last_call = addr; /* 探针：最后一次 CALLN 的目标 */
            vm_last_call_rcx = vm->regs[VRCX];
            vm_last_call_sp = vm->regs[VRSP];
            vm_last_call_args[0] = vm->regs[VRCX];
            vm_last_call_args[1] = vm->regs[VRDX];
            vm_last_call_args[2] = vm->regs[VR8];
            vm_last_call_args[3] = vm->regs[VR9];
            /* 同时放进 vm_diag[8..11]（这个数组早已在 manifest 里、且被历史探针验证可读） */
            vm_diag[8] = vm_last_call_args[0];
            vm_diag[9] = vm_last_call_args[1];
            vm_diag[10] = vm_last_call_args[2];
            vm_diag[11] = vm_last_call_args[3];
#endif
#ifndef VM_RELEASE
            {   /* 调用前后快照 guest 栈顶 32 个 qword，记录第一处变化 */
                u64 sp = vm->regs[VRSP] + (u64)VM_MARGIN; /* 调用前后 guest SP 是同一个值；这里只取地址基准 */
                u32 k;
                sp = vm->regs[VRSP];
                for (k = 0; k < 32u; k++) vm_call_snap[k] = ((const u64 *)(void *)sp)[k];
                vm->regs[VRAX] = vm_call_native(vm, addr);
                for (k = 0; k < 32u; k++) {
                    u64 now = ((const u64 *)(void *)sp)[k];
                    if (now != vm_call_snap[k]) {
                        if (vm_call_diffs == 0u) {
                            vm_call_diff_off = (u64)k * 8u;
                            vm_call_diff_before = vm_call_snap[k];
                            vm_call_diff_after = now;
                        }
                        vm_call_diffs++;
                    }
                }
                /* 注意：非 release 走的是这一条分支，所以**这里也必须记 ring** ——
                 * 否则最后几次 CALLN 不会出现在调用环里（第 60 轮就因为缺了它们，
                 * 看到的"最后一次调用"与 vm_last_call 对不上）。 */
                vm_call_ring[(vm_call_ring_n & 7u) * 2u] = addr;
                vm_call_ring[(vm_call_ring_n & 7u) * 2u + 1u] = vm->regs[VRAX];
                vm_call_ring_n++;
                vm->pc = pc + 9;
                break;
            }
#endif
            vm->regs[VRAX] = vm_call_native(vm, addr);
#ifndef VM_RELEASE
            vm_call_ring[(vm_call_ring_n & 7u) * 2u] = addr;
            vm_call_ring[(vm_call_ring_n & 7u) * 2u + 1u] = vm->regs[VRAX];
            vm_call_ring_n++;
#endif
            vm->pc = pc + 9;
            break;
        }
        case OP_CALLR: {
            /* 间接调用（虚调用/函数指针）：寄存器里是**客户机地址**（模块基址 + RVA），
             * 与 CALLN 的区别只是目标来自运行时。调用约定仍是宿主的（blob 由哪个工具链编译就是哪个）。
             * 空指针明确失败，而不是跳到 0。 */
            u64 addr = vm_rdreg(vm, vmb_byte(&bcs, pc + 1)); /* 调用目标：越界读作 0 ⇒ 立刻走下面的空指针分支，不会野跳 */
#ifndef VM_RELEASE
            vm_last_call = addr | 0x8000000000000000ull; /* 高位标记：来自 CALLR */
            vm_last_call_args[0] = vm->regs[VRCX];
            vm_last_call_args[1] = vm->regs[VRDX];
            vm_last_call_args[2] = vm->regs[VR8];
            vm_last_call_args[3] = vm->regs[VR9];
            /* 同时放进 vm_diag[8..11]（这个数组早已在 manifest 里、且被历史探针验证可读） */
            vm_diag[8] = vm_last_call_args[0];
            vm_diag[9] = vm_last_call_args[1];
            vm_diag[10] = vm_last_call_args[2];
            vm_diag[11] = vm_last_call_args[3];
#endif
            if (addr == 0) return 1;
            vm->regs[VRAX] = vm_call_native(vm, addr);
#ifndef VM_RELEASE
            vm_call_ring[(vm_call_ring_n & 7u) * 2u] = addr | 0x8000000000000000ull;
            vm_call_ring[(vm_call_ring_n & 7u) * 2u + 1u] = vm->regs[VRAX];
            vm_call_ring_n++;
#endif
            vm->pc = pc + 2;
            break;
        }
        default:
            return 98; /* 未知操作码：失败而不是猜（用 98 与 OP_HALT 的正常返回 1 区分开，便于 CI 判读） */
        }
    }
}

/* 指令长度表（Go/C 两侧共用同一份规格；M2 起由 vmpbuild 生成） */
u32 vm_insn_size(u8 op) {
    switch (op) {
    case OP_HALT: case OP_NOP: case OP_RET: return 1;
    case OP_MOV_RR: return 4;
    case OP_MOV_RI: return 11;
    case OP_MOV_RI32: return 6;
    case OP_LEA: return 10;
    case OP_ALU_RR: return 6;
    case OP_ALU_RI: return 9;
    case OP_ALU_U: return 5;
    case OP_CMP_RR: return 5;
    case OP_CMP_RI: return 8;
    case OP_EXT: return 5;
    case OP_LOAD: return 11;
    case OP_STORE: return 10;
    case OP_ATOMIC: return 12;
    case OP_FP: return 15;
    case OP_PUSH_R: return 2;
    case OP_PUSH_I: return 5;
    case OP_POP_R: return 2;
    case OP_JCC: return 6;
    case OP_JMP: return 5;
    case OP_JBZ: case OP_JBNZ: return 6;
    case OP_CALLN: return 9;
    case OP_CALLR: return 2;
    default: return 0;
    }
}

/* 自检入口：验证 blob 抽取后的重定位修补（会走 vm_insn_size 的 .rdata 表） */
u64 vm_selftest(void *ctxp) {
    vm_ctx_t *vm = (vm_ctx_t *)ctxp;
    int rc = vm_run(vm);
    u64 h = 0;
    for (u32 op = 0; op <= 0x7F; op++) {
        h = h * 131u + (u64)vm_insn_size((u8)op);
    }
    return h * 2u + (u64)rc;
}

/* ---- (c) 加载期完整性校验 ----
 * 由 internal/inject 放进 payload 的入口蹦床调用。
 * 表格式：u32 count；随后每项 { i32 delta; u32 len; u32 check; u32 selfRVA; u32 funcRVA; u32 codeLen }，
 * delta 相对表首。check 是**带密钥 MAC**（与描述符 pad 用同一算式，见 internal/inject/patchmac.go）：
 *   key = KDFEntry(master, funcRVA, salt ^ 0x9E3779B9)，msg = patch || selfRVA || funcRVA || codeLen，
 *   check = le32(Poly1305(key,msg)[0:4])。改造前是**无盐** FNV-1a（key 只取主密钥前 8 字节）——
 * 那种校验攻击者可以自己重算，等于没有完整性。"
 *
 * 为什么必须在**加载期**做：回填（把被覆盖的几字节补回原生代码）之后，被保护函数
 * 根本不再进入 VM —— 放在解释器里的校验永远不会执行。只有加载期的检查能拦住它。 */
void vm_verify_table(const u32 *t) {
    u32 n, i;
    const u8 *base = (const u8 *)t;
    const u8 *master = vm_master(); /* 1b：取钥 + KCV 校验（不通即 0xC0DE0007） */
#ifdef VM_KEY_EXTERNAL
    /* (2) 运行期强制：在这里（入口蹦床 = 入口点、main 之前）做授权校验。
     * 放在 vm_master() 里是错的：那条路径也被 TLS 回调走到，不能在回调里加载 DLL/调 CNG。
     * 只在外置密钥模式下编入（vmpack 也拒绝给非外置 blob 传 -license-*，所以不存在"静默无门禁"）。 */
    if (!vm_license_check()) vm_key_reject();
#endif
    if (!t) return;
    u8 m[32];
    vm_kdf_entry(master, VM_FIELD_MASK_VERIFY, VM_FIELD_MASK_SALT, m);
    n = t[0];
    for (i = 0; i < n; i++) {
        /* (3)：每条 24 字节（delta/len/check/selfRVA/funcRVA/codeLen）整体加了掩码 ——
         * 只蒙 funcRVA 而留着 delta 是自欺欺人（delta 就等于 funcRVA - 表首 RVA）。 */
        const u8 *e = (const u8 *)(t + 1 + i * 6);
        u32 delta = vm_xor32(e + 0, m + 0);
        u32 len = vm_xor32(e + 4, m + 4);
        u32 want = vm_xor32(e + 8, m + 8);
        u32 selfRVA = vm_xor32(e + 12, m + 12);
        u32 funcRVA = vm_xor32(e + 16, m + 16);
        u32 codeLen = vm_xor32(e + 20, m + 20);
        if (!len) continue; /* 没写校验值的条目（例如未接 KDF 的单测载荷）直接跳过 */
        const u8 *p = base + (i32)delta;
        u32 got = vm_patch_mac(master, vm_kdf_salt(selfRVA, funcRVA, codeLen), selfRVA, funcRVA, codeLen, p, len);
        if (got != want) __builtin_trap();
    }
}

/* 钉住 vm_verify_table 的符号：release 构建里它在 blob 内部没有别的引用，内置合并器会
 * 丢掉未被引用的全局符号，manifest 里就查不到偏移（入口蹦床会白做）。这里用永不成立
 * 条件里的直接调用（rel32、位置无关 —— 函数指针常量会生成绝对重定位，被合并器拒绝）。 */
static void vm_keep_verify_ref(vm_ctx_t *vm) {
    if (vm->codeLen == 0xFFFFFFFEu) {
        vm_verify_table((const u32 *)0);
    }
    /* 同理：打包端要读 vm_bc_slot_size 做字节码长度硬校验，release 构建里也不能被优化掉。
     * （上一轮就吃了这个亏：release blob 里没这个符号 → 校验被静默跳过。） */
    if (vm->codeLen == 0xFFFFFFFDu) {
        if (vm_bc_slot_size == 0) {
            __builtin_trap();
        }
    }
}


/* ---- (h) 原镜像整体加密：入口自解密 ----
 *
 * 打包端把目标 .text 的**文件字节**原地加密（ChaCha20-Poly1305；AAD = rva||size，
 * nonce = rva||size||构建 salt，两者都由本函数按同样的规则算出来），并把"要解密的节表"
 * 放进 payload。本函数由入口蹦床**最先**调用：
 *   ① 验签（Poly1305 认证的是密文，不需要明文）；
 *   ② VirtualProtect 成可写；
 *   ③ 原地解密；
 *   ④ 恢复成原来的保护（代码段 PAGE_EXECUTE_READ，只读数据 PAGE_READONLY）。
 * 之后蹦床跳到原始入口点（或先跳到补丁校验蹦床），程序照常启动。
 *
 * 两个前置条件（打包端保证，这里 fail-fast 复检）：
 *   1) 镜像必须落在**首选基址**上 —— 打包端清掉 DYNAMIC_BASE，加载器因此不做重定位
 *      （若基址被占，Windows 会强制重定位；那时密文已被改写，必须拒绝执行而不是跑飞）；
 *   2) 目标不能有 TLS 回调 —— TLS 回调在入口点之前运行，那时 .text 还是密文。
 *
 * 表布局（与 cmd/vmpack 的 imgTable 字节级一致）：
 *   [0]  u64 imageBase
 *   [8]  u32 salt
 *   [12] u32 count
 *   [16] u32 selfRVA（表自身的 RVA；用它 + 表地址反推镜像基址）
 *   [20] u32 reserved
 *   [24] count x { u32 rva; u32 size; u32 flags; u32 pad; u8 tag[16] }
 *        flags: bit0 = 解密后恢复成可执行，bit1 = 解密后恢复成可写（打包端 inject.ImgSection）
 */
/* 幂等标志：TLS 回调最先解密一次，入口蹦床随后还会调一次（加载器的调用顺序是
 * TLS 回调 -> 入口点）。放在 .bss（不能有初始化器，否则落进只读的 .data 段）。 */
static u32 vm_img_done;

#if defined(VM_BLOB_TARGET_LINUX) && defined(__aarch64__)
/* ---- Linux/aarch64：与 x86-64 那条同构（只验签 + 原地解密），差别只在 syscall 约定：
 * 号放 x8、参数 x0..x2、svc #0；mprotect = 226、write = 64。基址同样用「表地址 - selfRVA」反推。 ---- */
u64 vm_img_diag[4];

static long vm_syscall3_a64(long n, long a, long b, long c) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}

static void vm_dbg_trace(const char *tag, long v) {
    char buf[96];
    u32 n = 0;
    while (tag[n] && n < 60) {
        buf[n] = tag[n];
        n++;
    }
    char tmp[24];
    u32 m = 0;
    int neg = v < 0;
    unsigned long u = neg ? (unsigned long)(-v) : (unsigned long)v;
    if (u == 0) tmp[m++] = '0';
    while (u != 0) {
        tmp[m++] = (char)('0' + (u % 10));
        u /= 10;
    }
    if (neg) buf[n++] = '-';
    while (m != 0) buf[n++] = tmp[--m];
    buf[n++] = 10;
    vm_syscall3_a64(64 /* SYS_write */, 2 /* stderr */, (long)buf, (long)n);
}

int vm_unpack_image(const void *tblp) {
    if (vm_img_done) return 0;
    const u8 *t = (const u8 *)tblp;
    u64 wantBase = *(const u64 *)(t + 0);
    u32 salt = *(const u32 *)(t + 8);
    /* (3)：表头的 count/selfRVA/保留 加了掩码 —— 静态读者不再能直接从表里读出"哪些节被
     * 整体加密、加密表在哪"。掩码与 Go 侧 inject.FieldMask 同式。 */
    const u8 *master = vm_master(); /* 1b：取钥 + KCV 校验（不通即 0xC0DE0007） */
    u8 mi[32];
    vm_kdf_entry(master, VM_FIELD_MASK_IMAGE, VM_FIELD_MASK_SALT, mi);
    u32 count = vm_xor32(t + 12, mi + 0);
    u32 selfRVA = vm_xor32(t + 16, mi + 4);
    if (!selfRVA) return -1;
    u64 base = (u64)(const void *)t - (u64)selfRVA;
    vm_img_diag[0] = 0;
    vm_img_diag[1] = base;
    vm_img_diag[2] = wantBase;
    vm_img_diag[3]++;
    if (*(const u32 *)base != 0x464C457Fu) { vm_img_diag[0] = 1; vm_dbg_trace("VMPELF badmagic base=", (long)base); return -1; }
    if (wantBase && base != wantBase) { vm_img_diag[0] = 2; vm_dbg_trace("VMPELF basemismatch base=", (long)base); return -2; }
    for (u32 i = 0; i < count; i++) {
        const u8 *e = t + 24 + (u64)i * 32;
        u32 rva = vm_xor32(e + 0, mi + 12);
        u32 size = vm_xor32(e + 4, mi + 16);
        u32 flags = vm_xor32(e + 8, mi + 20);
        const u8 *tag = e + 16;
        u8 *dst = (u8 *)(base + rva);
        u8 key[32];
        vm_kdf_entry(master, rva, salt, key); /* 每节一把派生密钥（打包端 encryptImageSections 同式现推） */
        u8 nonce[12];
        *(u32 *)(nonce + 0) = rva;
        *(u32 *)(nonce + 4) = size;
        *(u32 *)(nonce + 8) = salt;
        u8 aad[8];
        *(u32 *)(aad + 0) = rva;
        *(u32 *)(aad + 4) = size;
        if (!vm_aead_verify_aad(key, nonce, aad, 8, dst, size, tag)) {
            vm_img_diag[0] = 4;
            vm_dbg_trace("VMPELF verifyfail rva=", (long)rva);
            return -4;
        }
        u64 page = 0x1000;
        u64 pstart = (u64)dst & ~(page - 1);
        u64 pend = ((u64)dst + size + page - 1) & ~(page - 1);
        /* 临时放开写权限即可：**只读数据节不需要 X**。一律要 RWX 是多余的，
         * 且在 aarch64（qemu）上实测会让打包后的目标 SIGSEGV。 */
        u32 tmpProt = 1u | 2u | ((flags & 1u) ? 4u : 0u);
        long mr = vm_syscall3_a64(226 /* SYS_mprotect */, (long)pstart, (long)(pend - pstart), (long)tmpProt);
        if (mr != 0) {
            vm_img_diag[0] = 5;
            vm_dbg_trace("VMPELF mprotectfail rva=", (long)rva);
            vm_dbg_trace("VMPELF mprotect errno=", -mr);
            return -5;
        }
        vm_chacha20_xor(key, 1, nonce, dst, dst, size);
        long prot = (flags & 1u) ? (1 | 4) : 1;
        if (flags & 2u) prot |= 2;
        vm_syscall3_a64(226, (long)pstart, (long)(pend - pstart), prot);
    }
    vm_img_done = 1;
    vm_img_diag[0] = 0;
    return 0;
}
#elif defined(VM_BLOB_TARGET_LINUX) && defined(__x86_64__)
/* ---- Linux/amd64：同样"只验签 + 原地解密"，但改页保护走 mprotect(2) 系统调用（无 libc），
 * 基址用"表地址 - selfRVA"反推（和 Windows 侧同一套表格式）。 ---- */
u64 vm_img_diag[4];

static long vm_syscall3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}

/* 诊断：CI 上（真 Linux）跑挂时，唯一能看到现场的通道就是 stderr。
 * 只在**失败路径**打印：什么都没打印 = 桩根本没跑（或跑之前就死了），本身就是信息。 */
static void vm_dbg_trace(const char *tag, long v) {
    char buf[96];
    u32 n = 0;
    while (tag[n] && n < 60) {
        buf[n] = tag[n];
        n++;
    }
    char tmp[24];
    u32 m = 0;
    int neg = v < 0;
    unsigned long u = neg ? (unsigned long)(-v) : (unsigned long)v;
    if (u == 0) tmp[m++] = '0';
    while (u != 0) {
        tmp[m++] = (char)('0' + (u % 10));
        u /= 10;
    }
    if (neg) buf[n++] = '-';
    while (m != 0) buf[n++] = tmp[--m];
    buf[n++] = 10;
    vm_syscall3(1 /* SYS_write */, 2 /* stderr */, (long)buf, (long)n);
}

int vm_unpack_image(const void *tblp) {
    if (vm_img_done) return 0;
    const u8 *t = (const u8 *)tblp;
    u64 wantBase = *(const u64 *)(t + 0);
    u32 salt = *(const u32 *)(t + 8);
    /* (3)：表头的 count/selfRVA/保留 加了掩码 —— 静态读者不再能直接从表里读出"哪些节被
     * 整体加密、加密表在哪"。掩码与 Go 侧 inject.FieldMask 同式。 */
    const u8 *master = vm_master(); /* 1b：取钥 + KCV 校验（不通即 0xC0DE0007） */
    u8 mi[32];
    vm_kdf_entry(master, VM_FIELD_MASK_IMAGE, VM_FIELD_MASK_SALT, mi);
    u32 count = vm_xor32(t + 12, mi + 0);
    u32 selfRVA = vm_xor32(t + 16, mi + 4);
    if (!selfRVA) return -1;
    u64 base = (u64)(const void *)t - (u64)selfRVA;
    vm_img_diag[0] = 0;
    vm_img_diag[1] = base;
    vm_img_diag[2] = wantBase;
    vm_img_diag[3]++;
    if (*(const u32 *)base != 0x464C457Fu) { vm_img_diag[0] = 1; vm_dbg_trace("VMPELF badmagic base=", (long)base); return -1; }
    if (wantBase && base != wantBase) { vm_img_diag[0] = 2; vm_dbg_trace("VMPELF basemismatch base=", (long)base); vm_dbg_trace("VMPELF want=", (long)wantBase); return -2; }
    for (u32 i = 0; i < count; i++) {
        const u8 *e = t + 24 + (u64)i * 32;
        u32 rva = vm_xor32(e + 0, mi + 12);
        u32 size = vm_xor32(e + 4, mi + 16);
        u32 flags = vm_xor32(e + 8, mi + 20);
        const u8 *tag = e + 16;
        u8 *dst = (u8 *)(base + rva);
        u8 key[32];
        vm_kdf_entry(master, rva, salt, key); /* 每节一把派生密钥（打包端 encryptImageSections 同式现推） */
        u8 nonce[12];
        *(u32 *)(nonce + 0) = rva;
        *(u32 *)(nonce + 4) = size;
        *(u32 *)(nonce + 8) = salt;
        u8 aad[8];
        *(u32 *)(aad + 0) = rva;
        *(u32 *)(aad + 4) = size;
        if (!vm_aead_verify_aad(key, nonce, aad, 8, dst, size, tag)) { vm_img_diag[0] = 4; vm_dbg_trace("VMPELF verifyfail rva=", (long)rva); vm_dbg_trace("VMPELF verifyfail size=", (long)size); return -4; }
        /* mprotect 按页：整页放宽再解，解完恢复（代码段 RWX 只是这一瞬间） */
        u64 page = 0x1000;
        u64 pstart = (u64)dst & ~(page - 1);
        u64 pend = ((u64)dst + size + page - 1) & ~(page - 1);
        /* 同 aarch64：只读数据节临时只要 R|W，不要 X。 */
        u32 tmpProt = 1u | 2u | ((flags & 1u) ? 4u : 0u);
        long mr = vm_syscall3(10 /* SYS_mprotect */, (long)pstart, (long)(pend - pstart), (long)tmpProt);
        if (mr != 0) {
            vm_img_diag[0] = 5;
            vm_dbg_trace("VMPELF mprotectfail rva=", (long)rva);
            vm_dbg_trace("VMPELF mprotect errno=", -mr);
            vm_dbg_trace("VMPELF mprotect len=", (long)(pend - pstart));
            return -5;
        }
        vm_chacha20_xor(key, 1, nonce, dst, dst, size);
        long prot = (flags & 1u) ? (1 | 4) : 1;
        if (flags & 2u) prot |= 2;
        vm_syscall3(10, (long)pstart, (long)(pend - pstart), prot);
    }
    vm_img_done = 1;
    vm_img_diag[0] = 0;
    return 0;
}
#elif defined(VM_BLOB_USES_WIN64) && (defined(__x86_64__) || defined(__aarch64__) || defined(VM_HOST_X86_32))
/* Windows 上取模块列表的入口：x86-64 走 gs:[0x60]，arm64 走 TEB(x18)+0x60（都是 PEB）。
 * Ldr 链表偏移、导出表解析两边完全一致，所以共用这一整段；只有取 PEB 这一行分架构。 */
static u64 vm_peb_base(void) {
#if defined(__aarch64__)
    u64 teb;
    __asm__ volatile("mov %0, x18" : "=r"(teb));
    if (!teb) return 0;
    return *(const u64 *)(teb + 0x60);
#elif defined(VM_HOST_X86_32)
    /* 32 位 Windows：PEB 指针在 fs:[0x30]。 */
    u32 p32;
    __asm__ volatile("movl %%fs:0x30, %0" : "=r"(p32));
    return (u64)p32;
#else
    u64 p;
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(p));
    return p;
#endif
}

/* ASCII 大小写不敏感比较（blob 没有 libc） */
static int vm_name_eq(const char *a, const char *b) {
    for (;;) {
        char x = *a++, y = *b++;
        if (x >= 'a' && x <= 'z') x = (char)(x - 32);
        if (y >= 'a' && y <= 'z') y = (char)(y - 32);
        if (x != y) return 0;
        if (!x) return 1;
    }
}

/* PEB / PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY 的布局**按宿主位宽不同**：
 *   x64 : Ldr@0x18、InMemoryOrderModuleList@Ldr+0x20、节点回链@entry+0x10、
 *         DllBase@+0x30、BaseDllName.Length@+0x58、Buffer@+0x60（指针 8 字节）；
 *   i386: Ldr@0x0C、InMemoryOrderModuleList@Ldr+0x14、节点回链@entry+0x08、
 *         DllBase@+0x18、Length@+0x2C、Buffer@+0x30（指针 4 字节）。
 * 踩坑留档：不区分就会在 i386 上读错字段、顺着垃圾指针走 —— 实测崩在
 * `mov 0x20(%esi),%eax`（blob 偏移 0x72E），av_addr=0x11F。 */
#if defined(VM_HOST_X86_32)
#define VM_PEB_LDR_OFF      0x0Cu
#define VM_LDR_HEAD_OFF     0x14u
#define VM_LINK_BACK_OFF    0x08u
#define VM_DLLBASE_OFF      0x18u
#define VM_NAMELEN_OFF      0x2Cu
#define VM_NAMEBUF_OFF      0x30u
#define vm_pread(p)         (*(const u32 *)(p))
#else
#define VM_PEB_LDR_OFF      0x18u
#define VM_LDR_HEAD_OFF     0x20u
#define VM_LINK_BACK_OFF    0x10u
#define VM_DLLBASE_OFF      0x30u
#define VM_NAMELEN_OFF      0x58u
#define VM_NAMEBUF_OFF      0x60u
#define vm_pread(p)         (*(const u64 *)(p))
#endif

/* 只走 PEB -> Ldr -> InMemoryOrderModuleList（偏移见上面的宏）。 */
static u64 vm_find_module(const char *name) {
    u64 peb = vm_peb_base();
    if (!peb) return 0;
    u64 ldr = vm_pread(peb + VM_PEB_LDR_OFF);
    if (!ldr) return 0;
    u64 head = ldr + VM_LDR_HEAD_OFF;
    u64 cur = vm_pread(head);
    for (int i = 0; i < 512 && cur && cur != head; i++) {
        u64 ent = cur - VM_LINK_BACK_OFF;
        u64 base = vm_pread(ent + VM_DLLBASE_OFF);
        u16 len = *(const u16 *)(ent + VM_NAMELEN_OFF);
        const u16 *buf = (const u16 *)(u64)vm_pread(ent + VM_NAMEBUF_OFF);
        char tmp[64];
        u32 n = len / 2;
        if (n > 63) n = 63;
        for (u32 k = 0; k < n && buf; k++) {
            u16 ch = buf[k];
            tmp[k] = (ch < 128) ? (char)ch : '?';
        }
        tmp[n] = 0;
        if (base && vm_name_eq(tmp, name)) return base;
        cur = vm_pread(cur);
    }
    return 0;
}

/* 从模块的导出表按名字取函数地址（PE32+：导出目录在可选头 +112）。
 *
 * 必须处理**转发导出（forwarder）**：kernel32 里有一大批 API 的导出项不是代码，而是
 * 指向字符串 "KERNELBASE.CreateFileA" 的 RVA（判据：该 RVA 落在导出目录范围之内）。
 * 旧实现把那个 RVA 直接当函数地址返回 —— 调过去就是跳进一段字符串，页属性是只读，
 * 于是 0xC0000005。这个缺陷在**本机看不出来**（本机 kernel32 恰好是真实桩），
 * 只在 CI 的 runner（kernel32 把这些转发给 kernelbase）上暴露；现有的镜像自解密只用到
 * VirtualProtect/ExitProcess，恰好两边都是真实导出，所以一直没被踩到。 */
/* rva 是否落在**可执行节**里：真实导出函数一定在可执行节，而转发器字符串在只读数据节。
 * 用它兜住"导出目录的 Size 不覆盖转发器字符串"的情况 —— 只按 [expRva,expRva+expSize)
 * 判转发器是标准做法，但那个 Size 各家链接器写法不一，实测就差在这里出过事。 */
static int vm_rva_is_exec(const u8 *p, const u8 *pe, u32 rva) {
    u32 nsec = *(const u16 *)(pe + 6);
    u32 optSize = *(const u16 *)(pe + 20);
    const u8 *sec = pe + 24 + optSize;
    for (u32 i = 0; i < nsec && i < 96; i++) {
        const u8 *s = sec + (u64)i * 40;
        u32 vsz = *(const u32 *)(s + 8);
        u32 va = *(const u32 *)(s + 12);
        u32 chars = *(const u32 *)(s + 36);
        if (rva >= va && rva < va + (vsz ? vsz : 1u)) return (chars & 0x20000000u) != 0;
    }
    return 0;
}

static void *vm_get_proc_d(u64 mod, const char *fn, int depth) {
    const u8 *p = (const u8 *)mod;
    if (!p || depth > 4 || *(const u16 *)p != 0x5A4D) return 0; /* "MZ" */
    u32 lfanew = *(const u32 *)(p + 0x3C);
    const u8 *pe = p + lfanew;
    if (*(const u32 *)pe != 0x00004550u) return 0;              /* "PE\0\0" */
    u32 expRva = *(const u32 *)(pe + 24 + 112);
    u32 expSize = *(const u32 *)(pe + 24 + 116);
    if (!expRva) return 0;
    const u8 *exp = p + expRva;
    u32 nFuncs = *(const u32 *)(exp + 20);
    u32 nNames = *(const u32 *)(exp + 24);
    const u32 *funcs = (const u32 *)(p + *(const u32 *)(exp + 28));
    const u32 *names = (const u32 *)(p + *(const u32 *)(exp + 32));
    const u16 *ords = (const u16 *)(p + *(const u32 *)(exp + 36));
    for (u32 i = 0; i < nNames; i++) {
        const char *nm = (const char *)(p + names[i]);
        if (vm_name_eq(nm, fn)) {
            u16 o = ords[i];
            if (o >= nFuncs) return 0;
            u32 rva = funcs[o];
            if ((expSize && rva >= expRva && rva < expRva + expSize) || !vm_rva_is_exec(p, pe, rva)) {
                const char *fwd = (const char *)(p + rva); /* "KERNELBASE.CreateFileA" */
                char dll[64];
                u32 k = 0;
                while (fwd[k] && fwd[k] != '.' && k < 56) { dll[k] = fwd[k]; k++; }
                if (fwd[k] != '.') return 0;
                dll[k] = 0;
                u64 tgt = vm_find_module(dll); /* PEB 里的模块名带扩展名，先补 ".DLL" 试一次 */
                if (!tgt) {
                    const char *ext = ".DLL";
                    u32 e = 0;
                    while (ext[e] && k + e < 60) { dll[k + e] = ext[e]; e++; }
                    dll[k + e] = 0;
                    tgt = vm_find_module(dll);
                }
                if (!tgt) return 0;
                return vm_get_proc_d(tgt, fwd + k + 1, depth + 1);
            }
            return (void *)(p + rva);
        }
    }
    return 0;
}

static void *vm_get_proc(u64 mod, const char *fn) { return vm_get_proc_d(mod, fn, 0); }

/* 返回 0 = 成功；负数是可辨认的失败码（会以"被保护程序莫名退出"的形式暴露，便于定位） */
/* 诊断：整体加密自解密的观测量（.bss；非 static 以便进 manifest 符号表）。
 * [0]=rc [1]=实际镜像基址 [2]=期望基址 [3]=被调用次数。加载失败后镜像会被卸载，
 * 所以失败路径额外用 ExitProcess(0xC0DE0000|code) 把 rc 带到退出码上（现场可辨）。 */
u64 vm_img_diag[4];

static void vm_img_fail(u32 code) {
    typedef void (*exitfn_t)(u32);
    exitfn_t ex = (exitfn_t)vm_get_proc(vm_find_module("KERNEL32.DLL"), "ExitProcess");
    if (ex) ex(0xC0DE0000u | code);
    __builtin_trap();
}

/* ---- (6) 加载器重定位 ↔ 解密 的顺序问题 ----
 * 保留重定位与 ASLR 之后，加载器会在**入口点之前**把 (实际基址 - 首选基址) 加进镜像里的
 * 绝对地址字段。可那些位置此刻还是**密文** —— 直接解密会得到垃圾（这正是当初拆掉重定位表的原因）。
 * 所以按 STATUS #381 的方案：对落在被解密节里的每个重定位项
 *     ① 先减回去（还原出"当初被加密的字节"）→ ② 验签 → ③ 解密 → ④ 再把 delta 加回来。
 * delta == 0（落在首选基址）时 ①④ 都是空操作。
 * 重定位目录本身不会落在被加密的节里（vmpack 的 loaderDirConflict 把 BASERELOC 算作冲突）。 */
static void vm_reloc_dir(const u8 *img, u32 *rvaOut, u32 *sizeOut) {
    *rvaOut = 0;
    *sizeOut = 0;
    const u8 *pe = img + *(const u32 *)(img + 0x3C);
    const u8 *opt = pe + 24;
    u32 rva = *(const u32 *)(opt + 112 + 5 * 8);
    u32 size = *(const u32 *)(opt + 112 + 5 * 8 + 4);
    if (!rva || size < 8) return;
    *rvaOut = rva;
    *sizeOut = size;
}

static void vm_reloc_apply(const u8 *img, long long delta, u64 lo, u64 hi) {
    u32 rva, size;
    vm_reloc_dir(img, &rva, &size);
    if (!rva) return;
    const u8 *p = img + rva;
    const u8 *end = p + size;
    while (p + 8 <= end) {
        u32 page = *(const u32 *)p;
        u32 blk = *(const u32 *)(p + 4);
        if (blk < 8 || p + blk > end) break;
        for (u32 o = 8; o + 2 <= blk; o += 2) {
            u16 v = *(const u16 *)(p + o);
            u32 type = (u32)(v >> 12), off = (u32)(v & 0xFFFu);
            if (!type) continue; /* ABSOLUTE：填充项 */
            u64 tgt = (u64)(img + page + off);
            if (tgt < lo || tgt + (type == 10 ? 8u : 4u) > hi) continue;
            if (type == 10) { /* IMAGE_REL_BASED_DIR64 */
                u64 *q = (u64 *)tgt;
                *q = (u64)((long long)*q + delta);
            } else if (type == 3) { /* IMAGE_REL_BASED_HIGHLOW（32 位镜像用） */
                u32 *q = (u32 *)tgt;
                *q = (u32)((long long)(int)*q + delta);
            }
        }
        p += blk;
    }
}

int vm_unpack_image(const void *tblp) {
    if (vm_img_done) return 0;
    const u8 *t = (const u8 *)tblp;
    u64 wantBase = *(const u64 *)(t + 0);
    u32 salt = *(const u32 *)(t + 8);
    /* (3)：表头的 count/selfRVA/保留 加了掩码（与 Go 侧 inject.FieldMask 同式）。 */
    const u8 *master = vm_master(); /* 1b：取钥 + KCV 校验（不通即 0xC0DE0007） */
    u8 mi[32];
    vm_kdf_entry(master, VM_FIELD_MASK_IMAGE, VM_FIELD_MASK_SALT, mi);
    u32 count = vm_xor32(t + 12, mi + 0);
    /* 基址不能用 PEB->ImageBaseAddress：那是**宿主 EXE** 的基址。DLL 在被加载时，
     * 那个字段指向宿主进程的主镜像，于是 base != wantBase 永远成立（实测直接 -2）。
     * 正确做法：表就在 payload 里，用"表的地址 - 表自身的 RVA"反推本镜像基址。 */
    u32 selfRVA = vm_xor32(t + 16, mi + 4);
    if (!selfRVA) return -1;
    u64 base = (u64)(const void *)t - (u64)selfRVA;
    vm_img_diag[0] = 0;
    vm_img_diag[1] = base;
    vm_img_diag[2] = wantBase;
    vm_img_diag[3]++;
    if (*(const u16 *)base != 0x5A4D) { vm_img_diag[0] = 1; vm_img_fail(1); return -1; } /* 反推出来的基址没有 MZ */
    /* (6)：以前是"实际基址 != 首选基址就拒绝执行"。现在保留重定位（ASLR 生效），
     * 基址不同是**正常**的：算出 delta，解密前后各做一次逆/正变换。只有"需要重定位却没有重定位表"
     * （被人为剥掉）才继续 fail-fast —— 那种情况下我们无法把加载器写进密文的增量还原出来。 */
    long long delta = wantBase ? (long long)(base - wantBase) : 0;
    if (delta != 0) {
        u32 rr, rs;
        vm_reloc_dir((const u8 *)base, &rr, &rs);
        if (!rr) { vm_img_diag[0] = 2; vm_img_fail(2); return -2; } /* 需要重定位但表没了 */
    }
    typedef int (*vpfn_t)(void *, u64, u32, u32 *);
    vpfn_t vp = (vpfn_t)vm_get_proc(vm_find_module("KERNEL32.DLL"), "VirtualProtect");
    if (!vp) { vm_img_diag[0] = 3; vm_img_fail(3); return -3; }
    for (u32 i = 0; i < count; i++) {
        const u8 *e = t + 24 + (u64)i * 32;   /* 表头 24 字节（imageBase/salt/count/selfRVA/保留） */
        u32 rva = vm_xor32(e + 0, mi + 12);
        u32 size = vm_xor32(e + 4, mi + 16);
        u32 flags = vm_xor32(e + 8, mi + 20);
        const u8 *tag = e + 16;
        u8 *dst = (u8 *)(base + rva);
        u8 key[32];
        vm_kdf_entry(master, rva, salt, key); /* 每节一把派生密钥（打包端 encryptImageSections 同式现推） */
        u8 nonce[12];
        *(u32 *)(nonce + 0) = rva;
        *(u32 *)(nonce + 4) = size;
        *(u32 *)(nonce + 8) = salt;
        u8 aad[8];
        *(u32 *)(aad + 0) = rva;
        *(u32 *)(aad + 4) = size;
        u32 old = 0;
        if (!vp(dst, size, (flags & 1u) ? 0x40u : 0x04u /* 执行节 RWX，数据节 RW */, &old)) { vm_img_diag[0] = 5; vm_img_fail(5); return -5; }
        /* ① 先把加载器写进密文的 delta 减回去 —— 否则下面的验签必然失败、解密出来的也是垃圾。
         * 必须在 VirtualProtect 之后做：加载器已经把这些页设成了最终保护属性。 */
        if (delta) vm_reloc_apply((const u8 *)base, -delta, (u64)dst, (u64)dst + size);
        if (!vm_aead_verify_aad(key, nonce, aad, 8, dst, size, tag)) { vm_img_diag[0] = 4; vm_img_fail(4); return -4; }
        vm_chacha20_xor(key, 1, nonce, dst, dst, size);
        /* ④ 解密之后再把 delta 加回来（等价于加载器对明文做的那次重定位）。 */
        if (delta) vm_reloc_apply((const u8 *)base, delta, (u64)dst, (u64)dst + size);
        /* flags: bit0 = 可执行，bit1 = 可写（与打包端 inject.ImgSection 的约定一致）
         * PAGE_READONLY=0x02 / PAGE_READWRITE=0x04 / PAGE_EXECUTE_READ=0x20 / PAGE_EXECUTE_READWRITE=0x40 */
        u32 prot;
        if (flags & 2u) {
            prot = (flags & 1u) ? 0x40u : 0x04u;
        } else {
            prot = (flags & 1u) ? 0x20u : 0x02u;
        }
        vp(dst, size, prot, &old);
    }
    vm_img_done = 1;
    vm_img_diag[0] = 0;
    return 0;
}
#else
int vm_unpack_image(const void *tblp) { (void)tblp; return -9; } /* 只做了 Linux x86-64/aarch64 与 Windows x86-64/arm64 */
#endif
