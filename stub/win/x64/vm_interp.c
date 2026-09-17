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
u32 vm_insn_size(u8 op);
u64 vm_selftest(void *ctxp);

static u32 rd32(const u8 *p) { return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24); }
static u64 rd64(const u8 *p) { return (u64)rd32(p) | ((u64)rd32(p + 4) << 32); }

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

static u32 flags_mul_w(u64 x, u64 y, u64 r, u32 w) {
    i64 a = sign_extend_w(x, w), b = sign_extend_w(y, w);
    __int128 p = (__int128)a * (__int128)b;
    i64 lo = sign_extend_w(r, w);
    u32 f = 0;
    if ((r & width_mask(w)) == 0) f |= VM_FL_Z;
    if (r & (1ull << (w - 1))) f |= VM_FL_N;
    if ((__int128)lo != p) f |= (VM_FL_C | VM_FL_V);
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
            unsigned __int128 p = (unsigned __int128)(u64)a * (unsigned __int128)(u64)(b);
            /* 有符号高半 = 无符号高半 − (a<0 ? b : 0) − (b<0 ? a : 0) */
            u64 uh = (u64)(p >> 64);
            u64 uh2 = uh - (a < 0 ? (u64)b : 0ull) - (b < 0 ? (u64)a : 0ull);
            lo = (u64)p;
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
            hi = (u64)(((unsigned __int128)x * (unsigned __int128)y) >> 64);
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
    if (width >= 64) { vm->regs[r] = val; return; }
    if (width == 32) { vm->regs[r] = val & 0xFFFFFFFFull; return; }
    u64 m = width_mask(width);
    vm->regs[r] = (vm->regs[r] & ~m) | (val & m);
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

/* ---------------- 明文解密缓存 ----------------
 * 逐次解密会让每次调用都付一次 AEAD（实测把小函数从 ~30ns 拉到 ~345ns）。
 * 因此把验签后的明文缓存在 blob 的 .bss 里：
 *   - 明文是只读的，同一函数的递归/嵌套调用可以安全共用；
 *   - 槽位有上限，只回收"当前没在跑"的槽（活跃计数为 0）；全忙时退回本次调用的帧内缓冲，
 *     绝不覆盖正在执行的明文；
 *   - 前提是注入段**可写**（PE 的 .vmp 加了 ScnMemWrite、ELF 的新 PT_LOAD 加了 PF_W）。
 */
#ifndef VM_BC_CACHE_SLOTS
#define VM_BC_CACHE_SLOTS 16 /* 每个槽 4KB（.bss 里 64KB）：并发线程 + 嵌套调用都够用 */
#endif

/* 并发保护：槽位分配与回收必须互斥，否则两个线程可能拿到同一个槽，
 * 或者回收掉另一个线程**正在执行**的明文（实测：4 线程 × 6 个被保护函数就会崩）。
 * 临界区很短（一次 AEAD + 几次数组写），所以用自旋锁；原子内建在 freestanding 下可用。 */
static u32 vm_bc_lock = 0;
static void vm_bc_enter(void) {
    while (__atomic_exchange_n(&vm_bc_lock, 1u, __ATOMIC_ACQUIRE) != 0u) {
        /* spin */
    }
}
static void vm_bc_leave(void) { __atomic_store_n(&vm_bc_lock, 0u, __ATOMIC_RELEASE); }

/* 前向声明：外层 vm_run 要调用它。
 * rsp_start 是进入时的模拟 RSP。诊断用：客户机压栈超过"自己栈下界"（rsp_start - VM_MARGIN）
 * 就会踩坏宿主栈帧（在 Go 的 goroutine 栈上尤其致命），与其让它把控制流搞坏、再表现为"跳进 .bss"，
 * 不如当场返回一个可辨认的错误码。
 * 用"位移"而不是"直接比较下界"：后者在宿主把 regs[VRSP] 配成 0 的场合（单元测试的 harness）
 * 会因为无符号回绕而误报。 */
static int vm_run_inner(vm_ctx_t *vm, u64 rsp_start);

static u8 vm_bc_cache[VM_BC_CACHE_SLOTS][VM_SCRATCH_SIZE];
static const void *vm_bc_key[VM_BC_CACHE_SLOTS];
static u32 vm_bc_inuse[VM_BC_CACHE_SLOTS];
static u32 vm_bc_tick[VM_BC_CACHE_SLOTS];
static u32 vm_bc_clock = 0;

/* 注意：这里曾经有一份"兜底缓冲池"（缓存槽全忙时用独占的一份）。
 * 二分实验证明它是错的：并发线程 + 嵌套调用会把它耗尽，于是返回错误码、客户机算出错值
 * （CI 的 mt 用例：4 线程 × 嵌套，200 次里错 24 次）。而缓存槽本身就会在并发调用间**共享**
 * 同一份明文（只读 + 引用计数），所以"池"本来就是多余概念 —— 直接给足缓存槽即可。 */

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

static int vm_bc_lookup(const void *desc) {
    for (int i = 0; i < VM_BC_CACHE_SLOTS; i++) {
        if (vm_bc_key[i] == desc) {
            vm_bc_tick[i] = ++vm_bc_clock;
            return i;
        }
    }
    return -1;
}

/* 找一个可以放新明文的槽：优先空槽，其次回收"没在跑"里最久未用的；全忙返回 -1 */
static int vm_bc_acquire(void) {
    int cand = -1;
    for (int i = 0; i < VM_BC_CACHE_SLOTS; i++) {
        if (vm_bc_key[i] == 0) {
            cand = i;
            break;
        }
    }
    if (cand < 0) {
        u32 best = 0xFFFFFFFFu;
        for (int i = 0; i < VM_BC_CACHE_SLOTS; i++) {
            if (vm_bc_inuse[i] == 0 && vm_bc_tick[i] < best) {
                best = vm_bc_tick[i];
                cand = i;
            }
        }
    }
    if (cand >= 0) {
        vm_bc_tick[cand] = ++vm_bc_clock;
    }
    return cand;
}


/* ---------------- 主循环入口 ---------------- */

int vm_run(vm_ctx_t *vm) {
    int slot = -1;
    /* 加密支持：先查明文缓存；未命中则验签+解密到缓存槽（全忙则解到帧内缓冲）。
     * 验签失败返回 3，绝不执行未经验证的字节码。 */
    if (vm->desc) {
        const vm_desc_t *d = (const vm_desc_t *)vm->desc;
        if (d->flags & VM_DESC_FLAG_ENC) {
            if (d->encLen < d->codeLen) return 2;
            u8 *dst = 0;
            vm_bc_enter();
            slot = vm_bc_lookup(vm->desc);
            if (slot >= 0) {
                vm_bc_inuse[slot]++;
                dst = vm_bc_cache[slot];
            } else {
                const u8 *ct = (const u8 *)d + d->codeRVA;
                u8 key[32] = VM_KEY_BYTES;
                /* AAD 绑定槽位：selfRVA || funcRVA（打包端用同样的字节密封） */
                u8 aad[8];
                aad[0] = (u8)(d->selfRVA); aad[1] = (u8)(d->selfRVA >> 8);
                aad[2] = (u8)(d->selfRVA >> 16); aad[3] = (u8)(d->selfRVA >> 24);
                aad[4] = (u8)(d->reserved1); aad[5] = (u8)(d->reserved1 >> 8);
                aad[6] = (u8)(d->reserved1 >> 16); aad[7] = (u8)(d->reserved1 >> 24);
                int c = vm_bc_acquire();
                if (c < 0 || (u32)d->codeLen > (u32)VM_SCRATCH_SIZE) {
                    /* 槽全忙（并发 + 嵌套超过槽数）：宁可直接失败，也不要用错的值继续跑 */
                    vm_bc_leave();
                    return 2;
                }
                dst = vm_bc_cache[c];
                if (!vm_aead_open_aad(key, d->nonce, aad, 8, ct, d->encLen, d->tag, dst)) {
                    vm_bc_leave();
                    return 3;
                }
                if (c >= 0) {
                    vm_bc_key[c] = vm->desc;
                    vm_bc_inuse[c]++;
                    slot = c;
                }
            }
            vm_bc_leave();
            vm->code = dst;
            vm->codeLen = d->codeLen;
        }
    }
    u64 rsp_start = vm->regs[VRSP]; /* 诊断用：客户机栈起点，见 vm_run_inner 注释 */
    int rc = vm_run_inner(vm, rsp_start);
    if (slot >= 0) {
        /* 原子递减：别的线程可能正在临界区里检查"这个槽有没有人在用" */
        __atomic_fetch_sub(&vm_bc_inuse[slot], 1u, __ATOMIC_RELEASE);
    }
    return rc;
}

/* 内层解释循环：所有 return 都从这里出去，缓存计数由外层统一收尾 */
/* 浮点标量运算：**单独成函数**。
 * 为什么不让它留在那个巨大的 switch 里：实测只要把浮点代码写在 vm_run_inner 内部，
 * gcc -O2 就会把整个函数编译错（连根本不执行浮点的函数结果都是错的）；
 * 分出来之后 -O2 下恢复正常（这就是"加了浮点代码、别的函数全错"的真正原因）。 */
/* noinline：-O2 下如果它被内联回 vm_run_inner，整个解释器会被编译错（实测）。
 * 独立成函数 + 禁止内联之后，-O2 恢复正常。 */
/* 浮点标量运算：独立成函数并禁止内联（详见 STATUS 第 71/72 轮）。 */
__attribute__((noinline)) static u32 vm_fp_step(vm_ctx_t *vm, const u8 *c, u32 pc) {


            /* 浮点标量运算：解释器本身就是原生代码，直接用它自己的 FPU 最准。
             * 操作数是**相对 VMBASE 的偏移**（Disp=目标、Imm=第一操作数、Imm2=第二操作数，0 表示不用）。
             * 运算不额外改标志位，除了 UCOMISD/COMISD 按 SDM 的表设置 ZF/PF/CF。 */
            u32 fk = c[pc + 1], fw = c[pc + 2];
            u32 fdst = rd32(&c[pc + 3]), fa = rd32(&c[pc + 7]), fb = rd32(&c[pc + 11]);
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



static int vm_run_inner(vm_ctx_t *vm, u64 rsp_start) {
    for (;;) {
        /* 诊断用（见 vm_run_inner 的注释）：客户机压栈越过给它的栈下界时当场返回 99。
         * 这样 Linux 上那个"跳进 .bss"就能被区分成"客户机踩穿了自己的栈"或"另有原因"。 */
        if (rsp_start - vm->regs[VRSP] > (u64)VM_MARGIN) {
            return 99;
        }
        if (vm->pc >= vm->codeLen) return 1;
        const u8 *c = vm->code;
        u32 pc = vm->pc;
        u8 op = c[pc];

        switch (op) {
        case OP_HALT: return 1;
        case OP_NOP:  vm->pc = pc + 1; break;
        case OP_RET:  return 0;

        case OP_MOV_RR: {
            u32 width = c[pc + 1];
            write_reg(vm, c[pc + 2] & VM_REG_MASK, width, vm->regs[c[pc + 3] & VM_REG_MASK]);
            vm->pc = pc + 4;
            break;
        }
        case OP_MOV_RI: {
            u32 width = c[pc + 1];
            write_reg(vm, c[pc + 2] & VM_REG_MASK, width, rd64(&c[pc + 3]));
            vm->pc = pc + 11;
            break;
        }
        case OP_MOV_RI32: {
            vm->regs[c[pc + 1] & VM_REG_MASK] = (u64)rd32(&c[pc + 2]); /* 32 位 mov 零扩展 */
            vm->pc = pc + 6;
            break;
        }
        case OP_LEA: {
            u32 width = c[pc + 1], dst = c[pc + 2] & VM_REG_MASK, base = c[pc + 3], idx = c[pc + 4];
            u64 scale = c[pc + 5];
            i64 disp = (i64)(i32)rd32(&c[pc + 6]);
            u64 addr = (u64)disp;
            if (base != VM_NO_REG) addr += vm->regs[base & VM_REG_MASK];
            if (idx != VM_NO_REG) addr += vm->regs[idx & VM_REG_MASK] * scale;
            write_reg(vm, dst, width, addr);
            vm->pc = pc + 10;
            break;
        }
        case OP_ALU_RR: {
            u32 kind = c[pc + 1], width = c[pc + 2], dst = c[pc + 3] & VM_REG_MASK;
            u32 keep = kind & VM_ALU_KEEP_FLAGS;
            kind &= (u32)~VM_ALU_KEEP_FLAGS;
            u64 a = vm->regs[c[pc + 4] & VM_REG_MASK], b = vm->regs[c[pc + 5] & VM_REG_MASK];
            u32 saved = vm->flags;
            write_reg(vm, dst, width, alu_apply(vm, kind, width, a, b));
            if (keep) vm->flags = saved;
            vm->pc = pc + 6;
            break;
        }
        case OP_ALU_RI: {
            u32 kind = c[pc + 1], width = c[pc + 2], dst = c[pc + 3] & VM_REG_MASK;
            u32 keep = kind & VM_ALU_KEEP_FLAGS;
            kind &= (u32)~VM_ALU_KEEP_FLAGS;
            u64 a = vm->regs[c[pc + 4] & VM_REG_MASK];
            u32 raw = rd32(&c[pc + 5]);
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
            u32 kind = c[pc + 1], width = c[pc + 2], dst = c[pc + 3] & VM_REG_MASK;
            u32 keep = kind & VM_ALU_KEEP_FLAGS;
            kind &= (u32)~VM_ALU_KEEP_FLAGS;
            u64 a = vm->regs[c[pc + 4] & VM_REG_MASK];
            u32 saved = vm->flags;
            write_reg(vm, dst, width, alu_unary(vm, kind, width, a));
            if (keep) vm->flags = saved;
            vm->pc = pc + 5;
            break;
        }
        case OP_CMP_RR: {
            u32 kind = c[pc + 1], width = c[pc + 2];
            u64 a = vm->regs[c[pc + 3] & VM_REG_MASK], b = vm->regs[c[pc + 4] & VM_REG_MASK];
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
            u32 kind = c[pc + 1], width = c[pc + 2];
            u64 a = vm->regs[c[pc + 3] & VM_REG_MASK];
            u32 raw = rd32(&c[pc + 4]);
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
            u32 kind = c[pc + 1], srcw = c[pc + 2], dst = c[pc + 3] & VM_REG_MASK;
            u64 v = vm->regs[c[pc + 4] & VM_REG_MASK];
            vm->regs[dst] = kind ? (u64)sign_extend_w(v, srcw) : (v & width_mask(srcw));
            vm->pc = pc + 5;
            break;
        }
        case OP_LOAD: {
            u32 kind = c[pc + 1], width = c[pc + 2], dst = c[pc + 3] & VM_REG_MASK, base = c[pc + 4] & VM_REG_MASK;
            u32 idx = c[pc + 5], scale = c[pc + 6];
            i64 disp = (i64)(i32)rd32(&c[pc + 7]);
            u64 addr = vm->regs[base] + (u64)disp;
            if (idx != VM_NO_REG)
                addr += vm->regs[idx & VM_REG_MASK] * (u64)scale;
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
            u32 width = c[pc + 1], base = c[pc + 2] & VM_REG_MASK;
            u32 idx = c[pc + 3], scale = c[pc + 4];
            i64 disp = (i64)(i32)rd32(&c[pc + 5]);
            u32 src = c[pc + 9] & VM_REG_MASK;
            u64 addr = vm->regs[base] + (u64)disp;
            if (idx != VM_NO_REG)
                addr += vm->regs[idx & VM_REG_MASK] * (u64)scale;
            u64 v = vm->regs[src];
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
            u32 ak = c[pc + 1];
            u32 keep = ak & VM_ALU_KEEP_FLAGS;
            ak &= (u32)~VM_ALU_KEEP_FLAGS;
            u32 aw = c[pc + 2], adst = c[pc + 3], asrc = c[pc + 4] & VM_REG_MASK; /* adst 不掩码：要能表示 VM_NO_REG */
            u32 abase = c[pc + 5] & VM_REG_MASK, aidx = c[pc + 6], ascale = c[pc + 7];
            i64 adisp = (i64)(i32)rd32(&c[pc + 8]);
            u64 addr = vm->regs[abase] + (u64)adisp;
            if (aidx != VM_NO_REG)
                addr += vm->regs[aidx & VM_REG_MASK] * (u64)ascale;
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
                if (adst != VM_NO_REG) vm->regs[adst] = old & am;
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
                if (adst != VM_NO_REG) vm->regs[adst] = old & am;
            }
            if (keep) vm->flags = saved;
            vm->pc = pc + 12;
            break;
        }


        case OP_FP: { vm->pc = vm_fp_step(vm, c, pc); break; }
        case OP_PUSH_R: {
            u32 r = c[pc + 1] & VM_REG_MASK;
            u64 sp = vm->regs[VRSP] - 8;
            *(volatile u64 *)sp = vm->regs[r];
            vm->regs[VRSP] = sp;
            vm->pc = pc + 2;
            break;
        }
        case OP_PUSH_I: {
            u64 sp = vm->regs[VRSP] - 8;
            *(volatile u64 *)sp = (u64)(i64)(i32)rd32(&c[pc + 1]);
            vm->regs[VRSP] = sp;
            vm->pc = pc + 5;
            break;
        }
        case OP_POP_R: {
            u32 r = c[pc + 1] & VM_REG_MASK;
            u64 sp = vm->regs[VRSP];
            vm->regs[r] = *(volatile u64 *)sp;
            vm->regs[VRSP] = sp + 8;
            vm->pc = pc + 2;
            break;
        }
        case OP_JCC: {
            u32 cond = c[pc + 1];
            if (cond_holds(vm, cond)) vm->pc = rd32(&c[pc + 2]);
            else vm->pc = pc + 6;
            break;
        }
        case OP_JBZ:
        case OP_JBNZ: {
            u32 r = c[pc + 1] & VM_REG_MASK;
            u32 target = rd32(&c[pc + 2]);
            int isZero = (vm->regs[r] == 0);
            int take = (c[pc] == OP_JBZ) ? isZero : !isZero;
            vm->pc = take ? target : pc + 6;
            break;
        }
        case OP_JMP:
            vm->pc = rd32(&c[pc + 1]);
            break;
        case OP_CALLN: {
            /* 字节码里存的是 RVA：真实地址 = 模块基址 + RVA */
            u64 addr = vm->regs[VRBASE] + rd64(&c[pc + 1]);
            typedef u64 (*fn_t)(u64, u64, u64, u64, u64, u64, u64, u64);
            fn_t fn = (fn_t)addr;
            vm->regs[VRAX] = fn(vm->regs[VRCX], vm->regs[VRDX], vm->regs[VR8], vm->regs[VR9],
                                vm->regs[VR10], vm->regs[VR11], vm->regs[VR12], vm->regs[VR13]);
            vm->pc = pc + 9;
            break;
        }
        case OP_CALLR: {
            /* 间接调用（虚调用/函数指针）：寄存器里是**客户机地址**（模块基址 + RVA），
             * 与 CALLN 的区别只是目标来自运行时。调用约定仍是宿主的（blob 由哪个工具链编译就是哪个）。
             * 空指针明确失败，而不是跳到 0。 */
            u64 addr = vm->regs[c[pc + 1] & VM_REG_MASK];
            if (addr == 0) return 1;
            typedef u64 (*fnr_t)(u64, u64, u64, u64, u64, u64, u64, u64);
            fnr_t fn = (fnr_t)addr;
            vm->regs[VRAX] = fn(vm->regs[VRCX], vm->regs[VRDX], vm->regs[VR8], vm->regs[VR9],
                                vm->regs[VR10], vm->regs[VR11], vm->regs[VR12], vm->regs[VR13]);
            vm->pc = pc + 2;
            break;
        }
        default:
            return 1; /* 未知操作码：失败而不是猜 */
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