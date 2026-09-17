/* test_harness.c - 解释器语义测试（宿主链接 libc，仅验证字节码语义）
 *
 * 覆盖 x86-64 翻译必须正确、而 VMPacker 会出错的语义：
 *  - 真实进位/借位/溢出标志
 *  - 32 位运算零扩展到 64 位、8 位运算是局部寄存器写
 *  - LEA 的 base+index*scale+disp
 *  - TEST 与 Jcc 的 N/V 组合、无符号/有符号比较
 */
#include <stdio.h>
#include <string.h>

#include "vm_types.h"
#include "vm_opcodes.h"

int vm_run(vm_ctx_t *vm);

static u8 buf[2048];
static u32 n;
static int failures;

static void e1(u8 v) { buf[n++] = v; }
static void e4(u32 v) { e1((u8)v); e1((u8)(v >> 8)); e1((u8)(v >> 16)); e1((u8)(v >> 24)); }
static void e8(u64 v) { for (int i = 0; i < 8; i++) e1((u8)(v >> (8 * i))); }

static void emit_mov_rr(u32 w, int dst, int src) { e1(OP_MOV_RR); e1((u8)w); e1((u8)dst); e1((u8)src); }
static void emit_mov_ri(u32 w, int dst, u64 v) { e1(OP_MOV_RI); e1((u8)w); e1((u8)dst); e8(v); }
static void emit_mov_ri32(int dst, u32 v) { e1(OP_MOV_RI32); e1((u8)dst); e4(v); }
static void emit_lea(u32 w, int dst, int base, int idx, u32 scale, i32 disp) {
    e1(OP_LEA); e1((u8)w); e1((u8)dst); e1((u8)base); e1((u8)idx); e1((u8)scale); e4((u32)disp);
}
static void emit_alu_rr(u32 kind, u32 w, int dst, int a, int b) {
    e1(OP_ALU_RR); e1((u8)kind); e1((u8)w); e1((u8)dst); e1((u8)a); e1((u8)b);
}
static void emit_alu_ri(u32 kind, u32 w, int dst, int a, u32 imm) {
    e1(OP_ALU_RI); e1((u8)kind); e1((u8)w); e1((u8)dst); e1((u8)a); e4(imm);
}
static void emit_cmp_rr(u32 kind, u32 w, int a, int b) {
    e1(OP_CMP_RR); e1((u8)kind); e1((u8)w); e1((u8)a); e1((u8)b);
}
static void emit_cmp_ri(u32 kind, u32 w, int a, u32 imm) {
    e1(OP_CMP_RI); e1((u8)kind); e1((u8)w); e1((u8)a); e4(imm);
}
static void emit_load(u32 kind, u32 w, int dst, int base, i32 disp) {
    e1(OP_LOAD); e1((u8)kind); e1((u8)w); e1((u8)dst); e1((u8)base); e4((u32)disp);
}
static void emit_store(u32 w, int base, i32 disp, int src) {
    e1(OP_STORE); e1((u8)w); e1((u8)base); e4((u32)disp); e1((u8)src);
}
static void emit_jcc(u32 cond, u32 target) { e1(OP_JCC); e1((u8)cond); e4(target); }
static void emit_ret(void) { e1(OP_RET); }
static u32 pc_here(void) { return n; }

#define CHECK(cond, msg)                                                           do {                                                                               if (cond) { printf("  [ok]   %s\n", msg); }                                    else { printf("  [FAIL] %s\n", msg); failures++; }                        } while (0)

static u8 emu_stack[8192];

static void reset(vm_ctx_t *vm) {
    memset(vm, 0, sizeof(*vm));
    n = 0;
    vm->code = buf;
    vm->regs[VRSP] = (u64)(emu_stack + sizeof(emu_stack));
}

int main(void) {
    vm_ctx_t vm;

    /* 1. check_key 的真实指令序列：
     *    lea rax,[rcx*8] ; sub rax,rcx ; add rax,0x2a ; xor al,0xff ; ret */
    printf("[1] check_key 真实序列 (LEA + 8 位局部写)\n");
    reset(&vm);
    emit_lea(64, VRAX, VM_NO_REG, VRCX, 8, 0);
    emit_alu_rr(K_SUB, 64, VRAX, VRAX, VRCX);
    emit_alu_ri(K_ADD, 64, VRAX, VRAX, 0x2a);
    emit_alu_ri(K_XOR, 8, VRAX, VRAX, 0xFF);
    emit_ret();
    vm.codeLen = n;
    vm.regs[VRCX] = 10;
    vm.regs[VRAX] = 0xDEADBEEF00000000ull; /* 前面的 64 位 LEA 会覆盖全寄存器 */
    CHECK(vm_run(&vm) == 0, "RET 正常结束");
    CHECK(vm.regs[VRAX] == 0x8Full, "check_key(10)=143（0x8F）");

    /* 2. 32 位 mov 零扩展到 64 位 */
    printf("[2] 32 位写零扩展\n");
    reset(&vm);
    emit_mov_rr(32, VR8, VRCX);
    emit_ret();
    vm.codeLen = n;
    vm.regs[VRCX] = 0xFFFFFFFF00000005ull;
    vm_run(&vm);
    CHECK(vm.regs[VR8] == 5, "mov r8d,ecx 得到 5（高位清零）");

    /* 3. 32 位 ADD 的进位：0xFFFFFFFF + 1 => 0，CF=1，且高 32 位清零 */
    printf("[3] 32 位 ADD 进位\n");
    reset(&vm);
    emit_mov_ri32(VRAX, 0xFFFFFFFFu);
    emit_alu_ri(K_ADD, 32, VRAX, VRAX, 1);
    emit_ret();
    vm.codeLen = n;
    vm_run(&vm);
    CHECK(vm.regs[VRAX] == 0, "结果为 0 且零扩展到 64 位");
    CHECK((vm.flags & VM_FL_C) != 0, "CF=1（32 位进位）");
    CHECK((vm.flags & VM_FL_Z) != 0, "ZF=1");
    CHECK((vm.flags & VM_FL_V) == 0, "OF=0");

    /* 4. 8 位运算只改低字节 */
    printf("[4] 8 位局部寄存器写\n");
    reset(&vm);
    emit_alu_ri(K_XOR, 8, VRAX, VRAX, 0xFF);
    emit_ret();
    vm.codeLen = n;
    vm.regs[VRAX] = 0x1122334455667788ull;
    vm_run(&vm);
    CHECK(vm.regs[VRAX] == 0x1122334455667777ull, "仅低字节取反");

    /* 5. LEA base+index*scale+disp（32 位结果零扩展） */
    printf("[5] LEA 寻址\n");
    reset(&vm);
    emit_lea(32, VRDX, VRDX, VRAX, 2, 1);
    emit_ret();
    vm.codeLen = n;
    vm.regs[VRDX] = 5;
    vm.regs[VRAX] = 0x100000003ull;
    vm_run(&vm);
    CHECK(vm.regs[VRDX] == 12, "lea edx,[rdx+rax*2+1] = 12（索引按低 32 位参与）");

    /* 6. TEST 与 Jcc：有符号/无符号条件 */
    printf("[6] TEST/CMP 与 Jcc\n");
    reset(&vm);
    {
        /* test ecx,ecx ; jle L_zero ; mov eax,0xBAD ; ret; L_zero: mov eax,0x600D ; ret */
        emit_cmp_rr(KC_TEST, 32, VRCX, VRCX);
        u32 jle_at = pc_here();
        emit_jcc(CC_LE, 0);
        emit_mov_ri(64, VRAX, 0xBAD);
        emit_ret();
        u32 lzero = pc_here();
        emit_mov_ri(64, VRAX, 0x600D);
        emit_ret();
        buf[jle_at + 2] = (u8)lzero; buf[jle_at + 3] = (u8)(lzero >> 8);
        buf[jle_at + 4] = (u8)(lzero >> 16); buf[jle_at + 5] = (u8)(lzero >> 24);
        vm.codeLen = n;
        vm.regs[VRCX] = 0;
        vm_run(&vm);
        CHECK(vm.regs[VRAX] == 0x600D, "test ecx,ecx 且 ecx=0 → ZF=1 → JLE 成立");
    }
    {
        /* cmp ecx,edx (1 vs -1)：有符号 1 > -1（JL 不成立），无符号 1 < 0xFFFFFFFF（JB 成立）
         * 这正是“CF/SF/OF 必须分开建模”的场景：
         *   cmp 1,0xFFFFFFFF → 结果 2，CF=1(借位)，SF=0，OF=0 */
        reset(&vm);
        emit_cmp_rr(KC_CMP, 32, VRCX, VRDX);
        u32 jl_at = pc_here();
        emit_jcc(CC_L, 0); /* JL 不应跳 */
        u32 jb_at = pc_here();
        emit_jcc(CC_B, 0); /* JB 应跳 */
        emit_mov_ri(64, VRAX, 0xBAD); /* 不应到达 */
        emit_ret();
        u32 l_jb = pc_here();
        emit_mov_ri(64, VRAX, 0x111);
        emit_ret();
        u32 l_bad = pc_here();
        emit_mov_ri(64, VRAX, 0x222);
        emit_ret();
        buf[jl_at + 2] = (u8)l_bad; buf[jl_at + 3] = (u8)(l_bad >> 8);
        buf[jl_at + 4] = (u8)(l_bad >> 16); buf[jl_at + 5] = (u8)(l_bad >> 24);
        buf[jb_at + 2] = (u8)l_jb; buf[jb_at + 3] = (u8)(l_jb >> 8);
        buf[jb_at + 4] = (u8)(l_jb >> 16); buf[jb_at + 5] = (u8)(l_jb >> 24);
        vm.codeLen = n;
        vm.regs[VRCX] = 1;
        vm.regs[VRDX] = 0xFFFFFFFFull; /* -1 */
        vm_run(&vm);
        CHECK(vm.regs[VRAX] == 0x111, "cmp 1,-1 → JL 不跳、JB 跳（有符号/无符号分离）");
        CHECK((vm.flags & VM_FL_C) != 0, "CF=1（无符号借位：1 < 0xFFFFFFFF）");
        CHECK((vm.flags & VM_FL_V) == 0, "OF=0");
        CHECK((vm.flags & VM_FL_N) == 0, "SF=0（结果为 2）");
    }

    /* 7. 移位与 CF */
    printf("[7] 移位与进位\n");
    reset(&vm);
    emit_mov_ri(64, VRAX, 0x8000000000000000ull);
    emit_alu_ri(K_SHL, 64, VRAX, VRAX, 1);
    emit_ret();
    vm.codeLen = n;
    vm_run(&vm);
    CHECK(vm.regs[VRAX] == 0, "shl 后为 0");
    CHECK((vm.flags & VM_FL_C) != 0, "CF=1（移出的最高位）");
    CHECK((vm.flags & VM_FL_Z) != 0, "ZF=1");

    /* 8. LOAD 符号扩展 */
    printf("[8] LOAD 符号扩展\n");
    reset(&vm);
    {
        u32 slot = 0xFFFFFFFFu;
        emit_mov_ri(64, VRCX, (u64)(unsigned long long)&slot);
        emit_load(1, 32, VRAX, VRCX, 0); /* 带符号扩展到 64 位 */
        emit_ret();
        vm.codeLen = n;
        vm_run(&vm);
        CHECK(vm.regs[VRAX] == 0xFFFFFFFFFFFFFFFFull, "32 位 -1 符号扩展为 64 位");
    }

    /* 9. STORE/LOAD 多种宽度 + CMP_RI */
    printf("[9] STORE/LOAD 宽度与 CMP_RI\n");
    reset(&vm);
    {
        u64 slot = 0;
        emit_mov_ri(64, VRCX, (u64)(unsigned long long)&slot);
        emit_mov_ri(64, VRAX, 0x123456789ABCDEF0ull);
        emit_store(16, VRCX, 0, VRAX);        /* 只写 2 字节 */
        emit_store(8, VRCX, 2, VRAX);         /* 再写 1 字节 */
        emit_load(0, 16, VRDX, VRCX, 0);
        emit_load(0, 8, VR8, VRCX, 2);
        emit_mov_ri(64, VRAX, 0);
        emit_cmp_ri(KC_CMP, 64, VRAX, 0);
        {
            u32 jz_at = pc_here();
            emit_jcc(CC_E, 0);
            emit_mov_ri(64, VRAX, 0xBAD);
            emit_ret();
            u32 l_ok = pc_here();
            emit_mov_ri(64, VRAX, 0x999);
            emit_ret();
            buf[jz_at + 2] = (u8)l_ok; buf[jz_at + 3] = (u8)(l_ok >> 8);
            buf[jz_at + 4] = (u8)(l_ok >> 16); buf[jz_at + 5] = (u8)(l_ok >> 24);
        }
        vm.codeLen = n;
        vm_run(&vm);
        CHECK(vm.regs[VRDX] == 0xDEF0ull, "16 位 STORE/LOAD 往返正确");
        CHECK(vm.regs[VR8] == 0xF0ull, "8 位 STORE 写入的是低字节 (0xF0)");
        CHECK(vm.regs[VRAX] == 0x999, "CMP_RI + JE 成立");
    }

    printf("\n%s: %d failure(s)\n", failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}
