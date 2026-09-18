# vmp-x 进度与证据日志

> 原则：**只记录被实际执行验证过的事实**。命令与输出都能复现；没跑过的一律标注为“未验证”。

## 当前阶段

M1（Windows/amd64 端到端 PoC）进行中。已完成：PE 结构手术、x86-64 解码、VM 解释器核心、blob 构建与任意地址执行验证。
未完成：x86-64 子集 lifter、asm 入口/跳板、真实函数端到端、性能基准。

## 已验证事实（附证据）

### 1. PE 结构手术（真实可执行文件，非合成样本）
- 目标：mingw 编译的真实 PE32+（19 个节，含 .pdata/.xdata/.reloc/.tls）。
- 操作：`peprobe testdata/hello.exe testdata/hello_vmp.exe 64` 追加 `.vmp` 节（RX）。
- 结果：节数 19→20，SizeOfImage 0x24000→0x25000，新节 VA=0x24000 / raw=0x21600；**改造后的 exe 在 Windows 上正常运行且输出与原始完全一致**：
  - 原始：`check_key(10)=143 sum_to(100)=5050`
  - 注入后：`check_key(10)=143 sum_to(100)=5050`
- 单元测试：`internal/load/pe` 覆盖解析、追加、无空间报错、连续两次追加、RVA→偏移、重解析一致性、PE32 拒绝。

### 2. x86-64 解码
- 使用 `golang.org/x/arch v0.20.0`（BSD-3，兼容 go1.24.5）。
- **发现并处理了 ENDBR64 陷阱**：`F3 0F 1E FA` 被 x86asm 解成 1 字节 `REP`，线性扫描会整体错位。
- `internal/decode/x64` 提供：ENDBR64/ENDBR32 特判、PCRelTarget 计算、前缀/未知操作码 fail-fast、`DecodeRange` 强制“消费字节数 == 代码长度”。
- 单元测试 11 条已知编码 + CET + PCRel + 错位失败路径全部通过。

### 3. VM 解释器核心（真实 NZCV 标志）
- `stub/win/x64/vm_interp.c`：无 libc、无全局可写状态；ADD/SUB 计算真实 CF（进位/借位）与 OF（有符号溢出），逻辑运算按 x86 清 CF/OF。
- 语义测试 7 组全部通过（`build/vmtest.exe`）：
  - check_key 字节码：`check_key(10)==143`
  - `0xFFFFFFFFFFFFFFFF + 1` → 结果 0，**ZF=1、CF=1（真进位）、OF=0** ← VMPacker 在此处必然出错
  - `0 - 1` → 全 1，CF=1（借位）、SF=1
  - 有符号溢出：`0x7FFF...+1` → OF=1，JL 不跳转（N==OF 组合正确）
  - 循环 `sum(1..100)==5050`
  - LOAD64/STORE64 读写一致
  - PUSH/POP 取回原值且 RSP 平衡

### 4. blob 构建器（COFF 重定位自解析）
- `cmd/vmpbuild`：stage 源码到 ASCII 临时目录 → 无 libc 编译 → 用 `debug/pe` 读 COFF 符号表与**节重定位**（不解析 objdump 文本）→ 拼接 `.text/.rdata/.data` → 自行重算节内 REL32 → 输出 blob + manifest。
- 构建结果：**2080 字节 blob**（.text 0x7C0 + .rdata 0x60），**2 个重定位全部内部解析**，manifest 含入口偏移/符号表/SHA256。
- 安全性质：出现绝对重定位或引用 blob 外符号会**直接构建失败**（保证可注入性）。

### 5. blob 在任意地址执行（注入可行性硬证据）
- `stub/win/x64/blob_probe.c`：VirtualAlloc(RWX) → memcpy blob → 调用 `blob + entryOff`，与链接进进程的参考实现在同输入下比对。
- 两次运行加载地址不同（`0x1F6E18A0000` / `0x19390420000`），结果与参考实现完全一致：
  - `check_key(10)=143`、`check_key(12345)=86342`
  - 校验和（内部遍历 `vm_insn_size`，会走 .rdata 表）完全一致 → 证明**重定位修补正确**。

### 6. 构建环境约束
- msys2 工具链不支持非 ASCII 路径（`D:\\其它\\...` 下 gcc 报 `can't create ... No such file or directory`）→ 项目根目录为 `D:\\vmp-x`，且 vmpbuild 一律 stage 到 ASCII 临时目录。
- 本机无 clang/zig/qemu，WSL 未安装发行版 → 除 Windows/amd64 外只能靠 CI 验证。

## 下一步（M1 剩余）

1. `internal/ir` + `internal/lift/x64`：x86-64 子集 lift（整数 ALU/内存/控制流/Jcc），并输出“不支持指令清单”（fail-fast）。
2. `internal/codegen`：IR → VM 字节码；含 RSP 相关偏移的 FRAME_SKEW 修正。
3. `stub/win/x64/vm_entry.asm/c`：入口封装（保存 callee-saved 到自有区域、设置 emulated RSP、调用 vm_run、恢复并 ret）。
4. `internal/inject/pe`：thunk（`lea r11,[rip+desc]` + `jmp vm_entry`）+ 函数入口 5 字节补丁 + 描述符表。
5. 端到端差分测试（原生 vs VM，多输入）+ 性能基准。
6. 之后：Linux/ELF、arm64、CI 矩阵。

## 第二轮进展：lifter / codegen / 差分测试（本轮全部实测）

### 7. VM ISA 重写为「宽度感知」并保持真实标志语义
- 起因：真实 x86-64 代码需要 32 位零扩展、8 位局部寄存器写、LEA 的 base+index*scale。
- `vm_interp.c` 改为通用 ALU（kind+width）+ 真实 NZCV **外加 PF**，Jcc 16 个条件全部按真实语义实现。
- 语义测试 9 组全过（`build/vmtest.exe`），含：
  - `add eax,1` 到 0xFFFFFFFF → 结果 0、CF=1、ZF=1 且高 32 位清零；
  - `xor al,0xff` 只改低字节（高 56 位保持）；
  - `lea edx,[rdx+rax*2+1]` = 12（32 位寻址按低 32 位参与并零扩展）；
  - `cmp 1,-1` → JL 不跳、JB 跳（有符号与无符号条件严格分离），CF=1/SF=0/OF=0；
  - SHL 的 CF 为移出位；32 位 LOAD 符号扩展；8/16 位 STORE 宽度正确。
- 纠正了两处**测试期望写错**（不是解释器错）：LEA 会覆盖全寄存器；`store8` 写的是低字节 0xF0。

### 8. x86-64 → IR lifter（真实机器码验证）
- `internal/ir`（线性三地址 IR，显式 width/kind）+ `internal/lift/x64`。
- 寄存器映射自校验测试（AH/CH/DH/BH 明确拒绝）；不支持指令一律 fail-fast 并给出偏移与原文。
- 对真实函数机器码的单元测试：
  - `check_key`（RVA 0x1450，18 字节）→ 5 条 IR，与手写期望逐字段一致；
  - `sum_to`（RVA 0x1470，69 字节，两个基本块 + 中间 nop 填充）→ 23 条 IR，分支目标全部解析。
- 过程中修掉一个**真实解码陷阱**：x86asm 把 12 字节 nop 与 11 字节 nop 区分正确，但手抄字节数错误会让后续全部错位——因此边界/偏移都靠解码器算，不靠人眼。

### 9. 字节码生成 + 差分测试（本轮最关键证据）
- `internal/vm/codegen.go`：两遍生成（先算偏移再落字节），分支/跳转目标由 IR 下标解析为字节码偏移。
- `cmd/lift`：从 PE 符号定位函数（自动识别符号值是 VA/RVA/节内偏移三种形式）、去尾部填充、要求以 RET 结尾，输出 `.vmb`。
- `stub/win/x64/blob_probe.c`（改名 runbc）：把 blob 加载到任意地址执行指定字节码。
- `tools/difftest.ps1`：**同一函数、同一输入，原生执行 vs VM 解释执行** 逐项比对。
- 结果：**13/13 全部一致**（`differential test: 13 passed, 0 failed`）
  - check_key(0/1/10/12345/255/1000000) → 213/206/143/86342/2012/6999829
  - sum_to(0/1/2/10/100/1000/9999) → 0/1/3/55/5050/500500/49995000
- 规模：check_key 18B x86 → 35B 字节码；sum_to 69B → 138B。

### 10. 当前命令级验证入口
```
pwsh -File tools/difftest.ps1      # 差分测试（原生 vs VM）
go test ./...                      # 解码器/PE/IR/lifter 单测
build\vmtest.exe                   # 解释器语义测试
build\vmpbuild.exe -src stub\win\x64 -out ... -entry vm_run   # blob 构建 + 重定位自解析
```

## 第三轮进展：真实注入闭环 + 端到端 + 基准（M1 达成）

### 11. vm_entry 汇编入口与 ABI（含一个实测发现的严重坑）
- 新增 `stub/win/x64/vm_abi.h`（单一事实来源：ctx 偏移、帧布局、描述符、thunk、FRAME_SKEW），
  `vm_interp.c` 用**编译期断言**校验它与 `vm_ctx_t` 真实布局一致；`cmd/vmpbuild` 解析它并写入 manifest 供 Go 侧使用。
- `vm_entry_asm.S`：建立自有帧 → 保存寄存器 → 从真实寄存器填 ctx → 设置模拟 RSP（在 vm_run 栈帧下方 8KB 处）→ `call vm_run` → 还原寄存器 → `ret`。
  真实 RSP 始终由入口掌控，模拟代码即使算错 RSP 也不会破坏宿主栈。
- **实测发现的坑（关键）**：GCC 会依据它对**原函数**寄存器用法的分析，
  把循环计数器放在 volatile 寄存器（RDX）里跨调用使用（IPA 优化，不是 ABI 保证）。
  我们替换了函数体后，解释器顺手清掉 RDX，导致调用方循环失控——
  单次调用完全正常，一旦进入循环就“卡死”（`bench check_key 1000` 挂起，而 `check_key 10` 正常）。
  修复：入口**额外保存/还原全部 volatile 寄存器（GPR + XMM0-5）**，即“破坏的寄存器不多于原函数”。
  修复后 `bench check_key 200000` 由挂起变为 7ms。
  （M2 可改为按函数生成“原函数破坏集”掩码，只保存必要的那几个，省掉部分开销。）

### 12. PE 注入与 vmpack 闭环
- `internal/inject`：payload = [解释器 blob][每个函数的描述符(16B)+thunk(12B)][字节码]，
  全部跨引用都是 PC-relative 或“相对描述符自身”的偏移 → 整块放到任意 RVA 都不需要重定位表。
  函数入口改写为 `E9 rel32`（jmp thunk），并校验节 RVA 与预估一致。
- `cmd/vmpack`：定位函数 → lift → codegen → 注入 → 输出被保护 PE + JSON 报告。
  解释器 blob 通过 `-blob/-manifest` 从磁盘读取（**不用 go:embed**，避免 VMPacker 那种“干净 clone 无法构建”的问题）。

### 13. 端到端差分测试（`tools/e2e.ps1`）
- 同时保护 `check_key` 与 `sum_to`，原生 vs 被保护二进制逐项比对：**14/14 全部一致**。
  - check_key(0/1/10/255/12345/1000000/4294967295) → 213/206/143/2012/86342/6999829/30064771292
  - sum_to(0/1/2/10/100/1000/9999) → 0/1/3/55/5050/500500/49995000
- 注入布局实例：`.vmp` RVA=0x24000，`vm_entry` RVA=0x25340；
  check_key desc=0x255E0 thunk=0x255F0 code=0x25620 patch=`E9 9B 41 02 00`；
  sum_to desc=0x255FC thunk=0x2560C code=0x25650。

### 14. 性能基准（真实数字，非估算）
| 函数 | 原生 | 被保护（VM） | 开销 |
|---|---|---|---|
| check_key（5 条指令的叶子函数） | 0.5–0.7 ns/次 | 20 ns/次 | **29–40x** |
| sum_to(100)（含循环） | 12–13 ns/次 | 900–950 ns/次 | **69–79x** |
- 这就是“无 JIT、纯 fetch-decode-execute”解释器的合理量级；M2 的 threaded dispatch + 预解码缓存是主要优化方向。
- 说明：bench 用 volatile seed 防止编译器闭式求值；否则原生侧会被优化成常数时间，基准不可信。

### 15. 环境坑（记录，避免重复踩）
- Windows PowerShell 解析**无 BOM 且含非 ASCII 字符**的 .ps1 时会出错（多字节字符吞掉行尾）。
  因此 `tools/*.ps1` 一律保持 ASCII-only。
- 刚生成的 exe 偶发被实时防护短暂锁定 → e2e 用 “重定向到文件 + Wait-Process 超时” 的方式运行子进程。

## 第四轮进展：栈帧函数支持（FRAME_SKEW 落地）+ 平台路线图/CI

### 16. FRAME_SKEW 实现：从"只能保护叶子函数"到"能保护带栈帧的函数"
- lifter 新增栈跟踪（`trackRegs`）：
  `push/pop`、`add/sub rsp,imm`、`lea rsp,[rsp+d]`、`mov rbp,rsp`、`lea rbp,[rsp+d]`；
  其它写 RSP/RBP 的方式 → 标记"不可跟踪"，后续栈访问**报错而不是算错**。
- 修正规则：`eff = disp + spDelta`（相对进入时 RSP）；
  **`eff >= 0` 的访问补 `FRAME_SKEW`**（调用方返回地址/栈上传参/调用方局部），
  `eff < 0`（函数自己的帧）留在私有区域即可。
- 安全阀：把 `eff >= 0` 的栈地址取到别的寄存器（无法跟踪其后续使用）→ **直接拒绝**。
- 单测：函数自身帧不修正、调用方栈帧按 FRAME_SKEW 修正、未启用时不修正、栈地址逃逸被拒。
  `cmd/lift` 也会从 manifest 读取 FRAME_SKEW（否则它产出的字节码对带栈帧函数会静默错误）。

### 17. 端到端验证（新增 framed 函数，`tools/e2e.ps1`）
- 新增目标函数（同时覆盖两类访问）：
  ```c
  long framed(long a,long b,long c,long d,long e){ volatile long acc=a+b; acc+=c+d; return acc+e; }
  ```
  反汇编确认：`mov %ecx,0xc(%rsp)`（eff=-0xc，自己帧）与
  `add 0x40(%rsp),%eax`（进入时 eff=+0x28，**调用方栈上的第 5 个参数**）。
- 结果：**19/19 全部一致**（check_key 7 组 + sum_to 7 组 + framed 5 组）。
  framed 的 5 组：0/1/7/1000/123456 → 10/15/45/5010/617290。
- 基准（同一轮）：check_key 原生 0.4ns vs 保护后 40ns（~100x，含噪声）；
  sum_to 12.5ns vs 800ns（~64x）。之前几轮测得 check_key 约 20–40ns/次、sum_to 约 800–950ns/次。

### 18. 平台路线图与 CI 矩阵
- `cmd/vmpack` 现在**先识别容器格式**：ELF → 明确提示"Linux/ELF 注入尚未实现"（附路线图）；
  非 PE/ELF → 明确报错；PE 非 x86-64 → 明确报错。不再依赖 PE 解析器的含糊错误。
- `.github/workflows/ci.yml`：
  windows/amd64 跑**完整端到端**（差分 + 基准）；
  linux/amd64、linux/arm64 跑 Go 交叉构建 + 单测 + 解释器 C 的 freestanding 编译
  （用来抓 Linux/Windows 的 C 差异）；windows/arm64 只做交叉构建。
  非 Windows 的完整端到端所需的 ELF packer / SysV 入口 / arm64 后端，
  在 workflow 里以 TODO 形式显式标出（而不是暗示"已支持"）。
- 已实测：`GOOS/GOARCH` 四种组合 `go build ./...` 全部通过。

## 第五轮进展：Linux/amd64（ELF）注入路径 + 更强的自校验

### 19. ELF 加载/注入（Linux/amd64）
- `internal/load/elf`：ELF64 头/程序头解析、VA↔offset 映射、`AddLoadSegmentFromNote`
  （复用 PT_NOTE 槽位改写成指向 payload 的 **PT_LOAD(RX)**，payload 页对齐追加到文件尾）。
- `internal/inject/payload.go`：把 payload 组装（blob+描述符+thunk+字节码）抽成与容器无关的一份实现，
  PE 与 ELF 共用（避免两套实现漂移）；`inject.go`(PE) 与 `elf.go`(ELF) 只负责“放哪里、怎么打补丁”。
- `internal/scan/elf.go`：ELF 符号定位。**Go 生成的 ELF 符号带 Size**，边界比 PE 更可靠。
- `cmd/vmpack` 现在按格式分派：PE 走原路径，ELF 走新路径；非 PE/ELF 或非 x86-64 明确报错。
- 实测（真实 Linux ELF：用 `GOOS=linux GOARCH=amd64 go build` 生成 2.2MB 静态可执行文件）：
  ```
  [*] 目标: ELF64 x86-64 exec, entry=0x46F1C0, imageBase=0x400000, phnum=6
      main.checkKey: RVA=0x91AA0 native=19B -> 5 IR -> 40B bytecode
      main.sumTo:    RVA=0x91AC0 native=28B -> 10 IR -> 58B bytecode
  [*] 新 PT_LOAD: RVA=0x183000 size=0x1690 | vm_entry RVA=0x184340
      main.checkKey desc=0x1845E0 thunk=0x1845F0 code=0x184620 patch=[E9 4B 2B 0F 00]
      main.sumTo    desc=0x1845FC thunk=0x18460C code=0x184650 patch=[E9 47 2B 0F 00]
  ```
  注入后 `elfprobe` 复查：PT_NOTE 已消失、新增 `PH[1] LOAD flags=PF_X+PF_R va=0x583000 filesz=0x1690 align=0x1000`。

### 20. 结构化验证（不依赖 Linux 执行环境）
- `internal/load/elf/elf_test.go`：注入后用 **Go 标准库 `debug/elf`（独立解析器）** 复查产物：
  4 个 PT_LOAD、新段 R+X 且页对齐、payload 经 VA 映射逐字节读回一致、原有段数据未被动过。
- `internal/inject/elf_test.go`：从磁盘重新解析产物，逐字节核对
  **入口补丁(E9→thunk) → thunk(lea→描述符, jmp→vm_entry) → 描述符(magic/selfRVA/codeRVA/codeLen) → 字节码内容**，
  并用自家反汇编器确认字节码可完整解码且以 RET 结尾。全部通过。
- `internal/vm/disasm_test.go`：**Go 侧 opTable 与 C 侧 `vm_insn_size` + `vm_opcodes.h` 数值交叉校验，
  21 条指令的值与长度全部一致**（这类“双份手写表”漂移正是 VMPacker 那类项目的事故源）。
- Windows 回归：完整 E2E 仍然 **19/19 通过**（PE 路径重构后无回归）。

### 21. 仍缺的一块（Linux 运行时）
Linux/amd64 目前只差两件事就能在 CI 上真跑：
1. `stub/linux/amd64/vm_entry_asm.S`（System V ABI：参数 RDI/RSI/RDX/RCX/R8/R9，
   volatile 集合与 Win64 不同，callee-saved 为 RBX/RBP/R12-R15，XMM 全 volatile）；
2. `cmd/vmpbuild` 的 ELF 目标文件重定位解析（COFF 那条路径已实现，ELF 需对称补上）。
之后 `tools/e2e.sh` 即可在 ubuntu runner（原生执行）上做与 Windows 同样的差分测试。
本轮已尝试在 MSYS2 里装 Zig 作为 Linux 交叉编译器（用于构建 stub），但依赖树下载时间超出本轮预算，任务仍在后台跑。

## 第七轮进展：覆盖扩展找出并修掉 3 个真 bug（差分 32/32）

这轮加了 3 个"更真实"的目标函数，**每个都立刻暴露了一个此前没测到的缺陷**——
这正是"单次调用能跑通"给不了的信心。

### 22. 新增覆盖与修掉的缺陷
| 新增目标函数 | 覆盖点 | 暴露的问题 | 修复 |
|---|---|---|---|
| `mem_ops` | RIP-relative 全局变量、**index\*scale 寻址**、MOVSX/MOVZX 宽度、8/32 位混用 | ① VM 的 LOAD/STORE **没有 index/scale 字段**，lifter 算出来的索引被静默丢弃 → `g_arr[k]` 退化成 `g_arr[0]`；② 承接 ①，codegen 把 `Index==0`（**RAX 是合法索引**）当成"无索引" | ① OP_LOAD 扩到 11B、OP_STORE 扩到 10B，带 index/scale，C 与 Go 两侧同步（交叉校验测试覆盖）；② 用 `NoReg(0xFF)` 作"无索引"哨兵 |
| `calls_helper` | `OP_CALLN` 原生调用 | 解释器把字节码里的 **RVA 当绝对地址**调用 → 直接崩溃（protected 输出为空） | `addr = VMBASE + rva` |
| `calls_protected` | **嵌套**：被保护函数调用被保护函数（VM→thunk→VM） | 依赖上一个修复；修好后一次通过，说明"净零调用 + 全 volatile 保存"的入口模型对嵌套是成立的 | — |

另外还修了一个**符号基准约定**问题：mingw 的 COFF 符号值是"节内偏移"而非 RVA/VA
（例：真实 RVA 0x24F0 的符号其 Value 是 0x14F0），此前用取值区间猜约定，导致
`framed`/`mem_ops` 的函数边界被截断。现在改为**逐个约定试一遍，用"能否解码成整段且以 RET 结束"来定夺**，
全不成立就报错——不猜。

### 23. 端到端结果（`tools/e2e.ps1`）
- **32/32 全部一致**：check_key(7) + sum_to(7) + framed(5) + mem_ops(5) + calls_helper(4) + calls_protected(4)。
- 基准：check_key 原生 0.35ns → 保护后 20ns（~57x）；sum_to 11ns → 700ns（~64x）。
- 工程门：`gofmt`/`go vet` 干净；6 个测试包全绿；**Go/C 指令表交叉校验 21 条仍一致**（LOAD/STORE 新长度已同步）。

### 24. 教训（值得写进任何二进制重写项目）
- "0 是合法值"陷阱：寄存器 0 就是 RAX，用 0 当哨兵会静默算错地址。
- "字段悄悄丢掉"最危险：IR 里有 index/scale，VM 指令没有 → 编译期不报错、单次调用也可能对（i==0 时）——
  必须让 IR 与目标 ISA 的能力**显式对齐**，或者直接拒绝。
- 覆盖扩展的性价比极高：3 个新函数 = 3 个真 bug，全部在 15 分钟内定位（因为差分测试直接给出 native vs VM 的数字）。

## 第八轮进展：VM 语义对拍 —— Go 参考实现 vs C 解释器，8519 例零不一致

### 25. 第三份实现（Go 参考解释器）+ 结构化对拍
- `internal/vm/ref.go`：按 ISA 规格**独立实现**的 Go 参考解释器（寄存器/标志/内存全状态）。
  内存用稀疏 map 建模并限制在窗口内，因此对拍过程不会因为野指针而崩。
- `stub/win/x64/blob_probe.c` 新增 **batch 模式**：一个进程内跑成百上千个用例
  （用例文件 = count + 每个用例的 codeLen/18 个初始寄存器/字节码；结果文件 = rc/flags/18 寄存器/256 字节内存窗口），
  C 侧把内存窗口固定在 0x10000000，Go 侧用同一地址模拟 → 可以逐字节比对。
- `internal/vm/conformance_test.go` 生成对拍用例：
  二元 ALU(11 种 kind × 4 种宽度 × 抽样边界值) + 一元 ALU + **CMP/TEST 与全部 16 个条件码**
  + MOV 各宽度（含 8/16 位局部写、32 位零扩展）+ 扩展(zx/sx) + LEA(base+index*scale+disp)
  + LOAD/STORE 各宽度与符号扩展写回内存窗口。
- **结果：8519 个用例，寄存器/标志/内存 0 处不一致。**（失败时会直接报出"go=… c=…"的差异点）

### 26. 本轮额外发现
- 用例生成器自身写错了一次 STORE 的编码（漏了 src 字节），Go 参考实现直接 panic 而不是静默算错 ——
  这正好说明"第二份实现"的价值：错误无处可藏。
- 记录一个待加固点：C 解释器对寄存器下标用 `& 31` 掩码，而 `regs[18]` 只有 18 项；
  合法字节码（我们自己生成）永远不会到 18+，但畸形字节码会越界写。
  M2 的"构建期随机映射 + 字节码完整性校验"会顺带覆盖这一类防御。

## 第九轮进展：R11 隐患（实测复现 → 设计修正）+ Linux 入口 stub

### 27. 发现并证明了一个"静默破坏调用方寄存器"的隐患
上一轮修的是"入口没保存 volatile 寄存器"；这一轮发现**入口之前还有一步会破坏寄存器**：
thunk 原来用 `lea r11,[rip+desc] ; jmp vm_entry` 传递描述符——**R11 在进入 vm_entry 之前就被改写了**，
而入口保存/还原的是"被改写后的 R11"，调用方原本的值已经丢了。

用实测证明了这不是理论问题：让 GCC 看到被调函数体（IPA 生效）并制造多个跨调用活跃值，
它会把活跃值放进 volatile 寄存器，**R11 确实出现在跨调用活跃列表里**：
```
 8a: add %r11,%rdi      ; 用 r11
 8d: xor %r8,%r9
 90: mov %r8,%r11       ; 写 r11
 9c: call callee        ; ← 调用；r11 的值在调用后（下一轮迭代 8a）才被读
```
即：如果被调方是"被保护函数"，原来的 thunk 就会把它悄悄改掉，**结果错但不会崩**。

**修正设计**：thunk 改成 5 字节的 `call vm_entry`（E8 rel32），入口**先填完 ctx**，
再从栈上反推描述符（thunk 用 call 压入的返回地址在 `[rsp+FRAME]`，等于 thunk+5，
描述符固定在 thunk 之前 16 字节 → 描述符 = 返回地址 - 21）。
这样进入时**不破坏任何 guest 可见寄存器**，而且 thunk 从 12 字节缩到 5 字节。
配套改动：帧大小对齐（thunk 用 call 后入口 RSP ≡ 0，帧必须是 16 的倍数）、
`VM_FRAME_SKEW_EXTRA` 抽成显式常量并由 vmpbuild 解析（避免 Go/C 两处公式漂移）、
Windows 入口补上此前**缺失的 32 字节 shadow space**（Win64 要求，原先 callee 可能把参数溢出到我们的 ctx 上）。

### 28. Linux/amd64（System V）入口 stub
- `stub/linux/amd64/vm_abi.h`：SysV 的保存集合（callee-saved RBX/RBP/R12-R15；
  volatile RCX/RDX/RSI/RDI/R8-R11 + **XMM0-XMM15 全部**），帧 560 字节。
- `stub/linux/amd64/vm_entry_asm.S`：客户机与宿主同为 x86-64 SysV，寄存器 1:1 填 ctx；
  因为 blob 仍由 mingw 编译（内部是 Win64 约定），调用 vm_run 时按 Win64 传参（RCX + 32B shadow）。
- `BLOB.sources` 机制改成"相对 stub/ 根目录列文件 + `-include` 平台 vm_abi.h"：
  **同一个 vm_interp.c 用两份 ABI 头编译**，不复制实现。
- 产出：`build/vm_interp_linux.bin`（5792 字节，3 个重定位全部内部解析，FRAME_SKEW=8768），
  并用它把真实 Linux ELF 打包完成（新 PT_LOAD RVA=0x183000）。
- 反汇编核对入口骨架：`sub $0x228,%rsp` / `mov %rcx,0xe0(%rsp)` / `movups %xmm15,0x210(%rsp)` /
  `sub $0x20,%rsp ; lea 0x20(%rsp),%rcx ; call` / `ret` 全部符合预期。

### 29. 本轮验证结果
- 端到端差分：**32/32 通过**（含 framed/mem_ops/calls_helper/calls_protected）。
- 入口单元测试（Windows）：**PASS**，其中新增断言"**r11 在 thunk+入口 全程未被破坏**"。
- VM 语义对拍：**8519 例 0 不一致**（Go 参考实现 vs C 解释器，改动后重跑）。
- 工程门：gofmt/vet 干净，6 个测试包全绿。

### 30. 教训
"入口保存了 volatile 寄存器"并不等于"调用方的值没丢"——**入口之前还有 trampoline**。
这类"替换实现的副作用面"必须按调用链从内到外逐段检查：
thunk → 入口 → 解释器 → 被调用的原生函数，每一段都可能多破坏一个寄存器。

## 第十轮进展：Linux/amd64 产物在本机被真正执行验证 + CI 跑通 Linux 端到端

### 31. 关键认识：客户机是 x86-64，所以 Linux 产物可以在本机"执行验证"
被保护 ELF 的注入段里是**位置无关的 x86-64 机器码**（解释器 blob + 描述符 + thunk + 字节码），
与宿主内核无关。于是可以：把 payload 按 ELF 里的**原始 VA** 映射成可执行内存，
再用客户机的调用约定调用 thunk —— 这就验证了
**payload 字节 + 描述符 + thunk + System V 入口 + 字节码** 整条链。
剩下唯一不可在本机验证的，只有"Linux 加载器映射该段并把控制权交给被补丁的函数入口"。

具体做法（`tools/verify_linux_payload.ps1` + `cmd/extractpayload` + `stub/linux/amd64/payload_probe.c`）：
- Windows 的保留粒度是 64KB，直接按 VA 申请会落到向下取整的地址上（VMBASE 就会错）；
  改成"申请 [VA & ~0xFFFF] 区间再补偿偏移"，payload 精确落在 0x585000；
- 客户机（Go 编译的 Linux 程序）把第一个参数放在 **RAX**（Go 内部 ABI，不是 C 的 RDI）——
  入口 1:1 复制宿主寄存器，所以两种 ABI 都不需要特殊处理；
- 执行结果：`checkKey(10/0/1/255/12345/1000000) = 143/213/206/2012/86342/6999829` **全部与源码公式一致**。

### 32. blob 的调用约定改为自动判定（去掉一个 CI 上的坑）
同一份 System V 入口，在不同环境下要按不同约定调用 `vm_run`：
mingw 编译的 blob 内部是 Win64（RCX + shadow），本机 Linux gcc 编译的是 SysV（RDI）。
现在 `vmpbuild` 自己跑 `cc -dumpmachine`，发现是 mingw 就定义 `VM_BLOB_USES_WIN64`，
入口用 `#ifdef` 选对应调用方式——**不需要人工传标志，也不会因为忘记传而错**。

### 33. CI 矩阵开始真正跑 Linux 端到端
- `tools/e2e.sh`（Linux 原生）：构建 stub → 打包真实 Linux ELF → **原生 vs 被保护逐项比对**（14 组）。
- `.github/workflows/ci.yml`：linux/amd64 作业安装 mingw 交叉编译器后执行 `bash tools/e2e.sh`；
  windows 作业在原有 E2E 之外，额外跑 `tools/verify_linux_payload.ps1`（本机执行 Linux 产物 payload）。
- 诚实标注：`vmpbuild` 目前解析的是 **COFF** 目标文件，所以 Linux 上仍用 mingw 交叉编译器产出 blob；
  要用宿主 gcc 直接编译，需要给 vmpbuild 补一个 **ELF 可重定位目标**的解析器（`e2e.sh` 里已写明）。

### 34. 本轮验证结果
- Windows/amd64 端到端：**32/32**；`go test ./...` 6 个包全绿。
- Linux/amd64 payload 执行验证：**6/6 与源码公式一致**（`tools/verify_linux_payload.ps1` 退出码 0）。
- VM 语义对拍：8519 例 0 不一致（保持）。

## 第十一轮进展：目标文件读取归一化 —— COFF 与 ELF 共用一条 blob 组装路径

### 35. 归一化目标文件层
- `cmd/vmpbuild/objfile.go`：把 **COFF（Windows 工具链）** 与 **ELF 可重定位目标（Linux 工具链）**
  读成同一套模型（节 / 符号 / 重定位），重定位归一到三类：
  `PCRel32`（COFF REL32 家族 / ELF PC32、PLT32）、`Absolute32`、`Absolute64`。
- `cmd/vmpbuild/blob.go`：blob 组装与 PC-relative 重算只写一份，两种格式共用。
  绝对重定位、未定义符号、越界引用一律**明确失败**（"stub 必须位置无关"是硬要求）。
- 踩到并修掉一个坑：ELF 的保留节索引（SHN_ABS 等 ≥ SHN_LORESERVE）不是真实节，
  早期把它们当节索引用 → 越界 panic；现在归为"未定义符号"，走明确的拒绝路径。

### 36. 验证（本机能做的都做了）
- **COFF 路径回归**：新实现产出的 blob 与旧实现**逐字节相同**（5632 字节），
  说明归一化没有改变任何行为；Windows 端到端仍 **32/32**。
- **ELF 路径**：用 `objcopy -O elf64-x86-64` 把 COFF 目标转成 ELF 目标做了实测——
  节能/符号/重定位都能正确解析（`.rela.text` 里 3 条 `R_X86_64_PC32` 与 COFF 侧一一对应）；
  该转换产物引用了绝对符号，被明确拒绝（`引用了未定义符号 "fake" — 该 stub 不是自包含的`），
  这正是期望行为。
- **诚实标注**：本机没有 Linux C 编译器，无法造出"忠实的 ELF 目标"，
  因此 ELF 路径的**成功分支只能在 CI 上验证**。`tools/e2e.sh` 已改为**优先用宿主 gcc**（ELF 目标），
  失败时才回退到 mingw，并在日志里打印实际用了哪个——CI 一跑就能看到结论。

### 37. 本轮验证结果
- Windows/amd64 端到端：**32/32**；`go test ./...` 6 个包全绿。
- Linux/amd64 payload 执行验证：**6/6 与源码公式一致**。
- blob 归一化前后**逐字节一致**（5632 字节）。

## 第十二轮进展：ARM64 后端第一步 —— 解码层（与参考解码器对拍 5.8 万条零不一致）

### 38. arm64 解码层（`internal/decode/arm64`）
沿用 x86-64 侧的原则：**解码不是难点，lifter 才是**，所以复用经过验证的参考解码器
（`golang.org/x/arch/arm64/arm64asm`），本层只做参考实现不保证的三件事：

1. **严格输入检查**：A64 定长 4 字节；长度不足、未分配编码一律报错，绝不返回"大概是什么"；
2. **编码分类 `Class`**：参考解码器给的是**别名**（MOV/CMP/CMN/TST…），别名会把底层编码
   （MOVZ/MOVN/MOVK、ORR-imm、ADDS…）藏起来，而 lifter 必须知道真实语义。分类完全基于原始
   编码字、按 ARM ARM 的 A64 编码树判定；
3. **字段提取**：寄存器号、立即数、条件码、分支目标（`Reg/Imm/PCRelTarget/IsBranch`）。

分类覆盖：AddSub(imm/shifted/extended)、Logical(imm/shifted)、MoveWide、Bitfield、CondSelect、
DataProc2、B/BL、B.cond、CBZ/CBNZ、TBZ/TBNZ、BR/BLR/RET、ADR/ADRP、LoadStore、LoadStorePair、
LoadLiteral；另加两类**显式不 lift**的空间：`ClassFPVec`（SIMD/FP）与 `ClassMisc`。
未覆盖的编码 → `ClassUnknown`，lifter 据此拒绝翻译。

### 39. 验证：和参考解码器做差分对拍
`TestClassifyMatchesReference` 采样 20 万个编码字（一半纯随机，一半围绕 28 个常见前缀扰动），
凡是参考解码器认得出来的，就要求我的分类与参考助记符**自洽**（含"FP 寄存器 ⇒ 必须是 FPVec"、
别名对应多个允许类等规则）：

```
分类与参考一致性: 校验 58499 条，跳过（参考不认识/未覆盖）141501 条，不一致 0 条
```

另有锚点测试（RET/NOP/STP/LDP/MOVZ/LDR/STR/B/BL/B.cond/ADD/SUB/BLR 的助记符、类与文本逐一比对）、
严格性测试（截断、未分配编码、长度非 4 倍数）、分支目标测试、DecodeRange 测试。

**过程记录**：这个差分测试一开始报出 2378 条不一致，直方图直接把缺口列出来，分三步收敛到 0：
① 缺 `LoadLiteral`（LDR 字面量）与 `FPVec` 两类；② LDP/STP 的 SIMD 形式要按 bit26 分流；
③ 测试自身的"FP 判断"要用参数**类型**而不是名字首字母（"HI"/"HS" 这类条件名会被误判）。

### 40. 本轮验证结果
- 新增解码包：**7 个测试包全绿**（`go test ./...`）；`gofmt`/`go vet` 干净。
- Windows/amd64 端到端：**32/32**；Linux payload 执行验证：**6/6 一致**。
- 顺手清掉了 vmpbuild 里归一化后遗留的旧实现（死代码 ~3.2KB，用新写的 `cmd/trim` 删的——
  PowerShell 做文件手术在本环境里会静默失败，Go 工具则可靠）。

## 第十三轮进展：ARM64 客户机语义（标志位/条件码）落地并完成对拍与锚点验证

### 41. 设计定稿（写入 DESIGN.md §8c）
- 客户机寄存器上下文：同一个 `vm_ctx_t`，槽位数由**客户机 ISA** 构建期决定
  （x86-64：16 GPR + VBASE + VSCRATCH；ARM64：X0-X30 + SP + VBASE + VSCRATCH + **ZR**）。
  ZR 由 codegen 保证**不生成写操作**（emit 期检查），避免"零点被写脏"的静默错误。
- flags 仍是同一个 32 位字段，含义按客户机解释；**ARM64 的 C 与 x86 相反**
  （C=1 = 无借位），移位类指令的 C/V 规则也不同（ARM64：移位量 0 时 C 不变、V 永远不变）。
- 调用模型：ARM64 的 `BL` 把返回地址写进 X30，同时沿用"净零栈"调用模型；
  入口 stub 保守地保存/还原宿主 X0-X30 与 V0-V31（x86-64 侧已因 IPA 优化踩过一次 RDX/R11）。
- v1 明确不支持：SIMD/FP 运算、原子/独占、系统指令、PAC、SVE（一律 fail-fast）。

### 42. 语义模块 + 两重验证
- C 实现（进 blob）：`stub/arm64/guest_semantics_arm64.c`
  （ADD/SUB/逻辑/乘法/移位的标志位、16 个条件码）；
- Go 参考实现：`internal/guest/arm64/semantics.go`；
- **差分对拍**：`flags_probe.exe` 批处理 + Go 参考，覆盖 32/64 位、边界值与随机值、
  移位量 0..w-1、旧标志位的各种组合：
  ```
  ARM64 语义对拍: 13000 个用例全部一致（flags + 全部 16 个条件码）
  ```
- **手算锚点**（从 ARM ARM 伪码直接推，防止两份实现同时犯同一个概念错误）：
  含 `SUB 1-2 (C=0 借位)`、`ADD max+1 (C=1,Z=1)`、`ADD 0x7FFF…+1 (N=1,V=1)`、
  `移位量 0 → C 不变`、`移位保留 V`、以及 Z/C/N/V 各组合下的条件码真值集合。
- **过程记录（值得保留）**：锚点第一次跑就报了 7 条不符——**全是我自己的期望写错了**，
  不是实现错：
  ① `SUB 0x8000000000000000-1` 我漏了 C=1（无借位）；② 32 位 `ADD 0xFFFFFFF0+0x20`
  掩码后结果是 0x10（非 0），我错写了 Z=1；③ `FlagsShift(1,1,…)` 我漏了 C=1；
  ④ 条件码锚点里我把 `Z=1` 的 CS/CC、把 `C=1,Z=0` 的 LS/NE 写反了。
  这说明"独立锚点"确实在强制我把精度提上来——对拍测不出"两份实现犯同一个概念错"，
  锚点可以。

### 43. 本轮验证结果
- `go test ./...`：**8 个包全绿**（新增 `internal/guest/arm64`）。
- `gofmt -l` / `go vet` 干净；Windows/amd64 端到端 **32/32**；Linux payload 执行验证 6/6。

## 第十四轮：为 ARM64 lifter 铺路的两块地基（已落地并验证）+ 一次诚实的"未完成"

### 44. 已落地并验证
**(a) Go 参考 VM 支持"客户机选择"**（`internal/vm/ref.go`）
- 新增 `Guest` 字段（`GuestX86` / `GuestARM64`）与 35 槽位寄存器数组；
- ADD/SUB/逻辑/乘法/移位与**条件码**都按客户机分派：x86-64 走原来的实现，
  ARM64 直接调用第十三轮的 `internal/guest/arm64` 语义模块；
- 回归证据：**x86-64 的 8519 例对拍与全部单测保持通过**（改动没有影响既有语义）。

**(b) ALU 的 "keep flags" 位**（C + Go 参考 + `vm_opcodes.h`）
- kind 字节的 bit7 = `VM_ALU_KEEP_FLAGS`：执行运算但**不修改标志位**；
- 动机是真实的 ISA 冲突：**ARM64 的 ADD/SUB/... 不带 S 时不设置标志位，而 x86 的同类指令一定设置**。
  同一个 opcode 靠这一位区分，x86-64 侧现有字节码该位恒为 0，因此**完全向后兼容**；
- 证据：blob 重新构建（5728 字节）、`go test ./...` 8 个包全绿、Windows E2E **32/32**。

**(c) 解码层/IR 的小补齐**：`dec.Insn.Cond()`（A64 条件码就是标准 4 位值）、
IR 新增 ARM64 条件码常量（值即 A64 编码）。

### 45. 未完成，且**不假装完成**
- **ARM64 lifter 骨架**：已写出 ALU（立即数/移位寄存器）、逻辑、移动立即数、分支、
  ADR/ADRP、BL（含把返回地址写进 X30）等分支的处理框架，但还缺内存访问、位域、
  BIC/ORN 取反形式、间接跳转（VM 没有间接跳转指令 → 明确不支持），
  且**没有配套测试**。已移到 `docs/drafts/arm64_lift_draft.go.txt`，
  不让未完成的代码留在构建里。
- **位掩码立即数解码（DecodeBitMasks）**：写了实现 + 与参考解码器的差分测试，
  **没有通过**——首轮 3719/5291 不一致；修掉"NOT(imms) 必须取 6 位"这个错后仍有
  546/2557 不一致（例如 `AND W0, W27, #0x44444444` 我算成 0xFFFFFFFF）。
  说明我对 ARM64 这个算法的转写还没到位。已连同测试移到 `docs/drafts/`，
  差分测试保留着——下一轮参考伪码把它做对，或改为**只接受参考解码器认可的形式**。
  **结论：这部分我暂时不会声称"支持逻辑立即数"。**

### 46. 本轮的工程副作用（值得记）
本环境里 **PowerShell 做文件手术会静默失败**（这轮又踩了两次：替换、删除都没生效），
因此写了两个 Go 小工具并留在仓库：`cmd/trim`（删两个标记之间的内容）、
`cmd/splice`（用文件内容替换两个标记之间的内容）——这类操作从此走 Go，可靠。

### 47. 本轮验证结果
- `go test ./...`：8 个包全绿；`gofmt -l` / `go vet` 干净。
- Windows/amd64 端到端：**32/32**（含 keep-flags 改动后的 blob）。
- Linux payload 执行验证：6/6 一致。

## 第十五轮：位掩码立即数解码**做对了**（对拍 2422 例零不一致）+ lifter 落地但差分未对齐

### 48. 把上一轮没做成的做对了
`DecodeBitMasks` 上一轮 546/2557 不一致，这轮定位到**两个**错误并修好：
1. `NOT(imms)` 必须取 **6 位**（N 只提供第 7 位；32 位形式下 N=0 但高位仍然有效）；
2. **`levels = Ones(len)`，随 `len` 变化**——这是主要错误。例：`AND W0, W27, #0x44444444`
   的 len=2 → levels=3、esize=4，S=0、R=2 → `ror(Ones(1),2,4)=0b0100` → 重复得 0x44444444。

结果：
```
位掩码立即数解码与参考一致: 校验 2422 条，跳过 57420 条（其中架构保留编码 158 条），不一致 0 条
```
（那 158 条是"S 全 1"的保留编码——**架构规定 UNDEFINED**、参考解码器偏宽松仍会打印；
我的实现按架构拒绝，因此不计入比对。这一点写在测试注释里。）

### 49. ARM64 lifter 落地（`internal/lift/arm64/lift.go`）
覆盖 ADD/SUB（立即数/移位寄存器，含 S 与**不带 S 时保留标志位**）、AND/ORR/EOR（立即数/移位寄存器）、
MOV/MOVZ/MOVN/MOVK、LSL/LSR/ASR 立即数、CMP/CMN/TST 别名、CBZ/CBNZ、TBZ/TBNZ、B/B.cond、
BL（含把返回地址写进 X30）、RET、ADR/ADRP（→ `LEA dst,[VBASE+rva]`）。
明确拒绝并记录原因：带扩展的加减、BIC/ORN/EON/MVN、UBFM/SBFM/BFM 位域形式、BR/BLR（VM 无间接跳转指令）。

### 50. **未对齐**：lift 的字节码 vs 直接按 ARM ARM 求值（诚实记录）
写了差分测试（`lift → 在 Go 参考 VM 里跑` vs `直接语义`，随机指令序列 4000 组）：
**校验 69 组、不一致 1323 组**——远未通过。
已定位一类**确定的原因**：Go 参考 VM 是为 x86-64 写的，寄存器下标被 5 位掩码截断，
而 ARM64 的 VBASE/VMSCR/ZR 在槽位 **32/33/34** → 掩码把它们别名到 X0-X3
（调试中看到 `ORR` 把 R1 写坏：SCR=33 → 33&31=1）。
我尝试去掉掩码后**重跑结果完全没变**，而 PowerShell 侧的报告自相矛盾
（`&31` 计数 0、`VMRegCount` 计数 0，但文件内容明显仍在使用掩码）——
本环境对"我的源码改动是否生效"存在我尚未搞清的问题，**我不在此下结论**。

因此：差分测试与调试测试退回草稿（`docs/drafts/arm64_lift_diff_test_draft.go.txt` 等），
`lift.go` 留在树里但加了醒目的"尚未验证"头注释，`go test ./...` 保持全绿。

### 51. 本轮验证结果
- `go test ./...`：**9 个包全绿**；`gofmt -l` / `go vet` 干净。
- Windows/amd64 端到端：**32/32**；Linux payload 执行验证 6/6。
- 位掩码立即数：**2422 例 0 不一致**（本轮新增的可信结论）。

## 第十六轮：ARM64 lifter **差分对齐**（单条 30522 例 + 序列 3973 组，零不一致）

### 52. 上一轮"未对齐"的根因：Go 参考 VM 的 5 位寄存器掩码——已修
`internal/vm/ref.go` 里 27 处 `& 31`（x86-64 时代留下的防御性掩码）会把 ARM64 的
VBASE/VMSCR/ZR（槽位 **32/33/34**）别名到 X0-X3——调试中看到 `ORR` 把 R1 写坏
（SCR=33 → 33&31=1）。全部去掉后：**不一致从 1323/1379 降到 13/1379**。
（顺带查明上一轮"改了没效果"的原因：**PowerShell 会把空字符串参数丢掉**，
导致 `replace` 工具只收到 3 个参数而打出 usage；工具已改成 `new` 可省略。）

### 53. 剩下 13 例的根因：逻辑指令的"是否设置标志位"判错了位
逻辑立即数/寄存器类里，**S 语义由 `opc` 编码（bit30:29）决定，不是 bit29**：
`00=AND, 01=ORR, 10=EOR, 11=ANDS`——只有 `11`（ANDS/BICS/TST）设置标志位。
我（lifter 与参考实现**两边都**）错用了 `bit29`，于是普通 `ORR`/`MOV #imm` 会误设标志位。
修正为 `((raw >> 29) & 3) == 3` 后：

```
ARM64 lift 差分：校验 3973 组（每组 6 条），不一致 0 组；
    跳过：解码失败 14378、参考不支持 0、lifter 拒绝 1649
单条扫描：校验 30522 条，不一致 0 条
```

（跳过原因分类统计了：解码失败多数是我随机生成器造出的非法编码；lifter 拒绝是设计内的
fail-fast——扩展加减、取反形式、位域、间接跳转。）

### 54. 这一轮验证了什么、没验证什么
- **已验证（语义差分）**：ADD/SUB（立即数/移位寄存器，含 S 与 keep-flags）、
  AND/ORR/EOR（立即数/移位寄存器）、MOV/MOVZ/MOVN/MOVK、LSL/LSR/ASR、CMP/CMN/TST。
  两条独立路径——"lift 成字节码后在 Go 参考 VM（ARM64 客户机语义）里跑" 与
  "按 ARM ARM 直接求值"——在寄存器与标志位上完全一致。
- **仅结构化验证**：CBZ/CBNZ、TBZ/TBNZ、B/B.cond、BL、RET、ADR/ADRP
  （断言 IR 形状、分支目标合法、条件码是 ARM64 编码；没有端到端语义验证）。
- **明确拒绝**：BR/BLR 间接跳转、扩展加减、取反形式、UBFM/SBFM/BFM 位域。

### 55. 本轮验证结果
- `go test ./...`：**9 个包全绿**（含 ARM64 lift 的 4 个测试）；
  `gofmt -l` / `go vet` 干净。
- Windows/amd64 端到端：**32/32**；Linux payload 执行验证 6/6。

## 第十七轮：ARM64 控制流语义验证通过（6577 个程序零不一致）+ VM ISA 扩到 23 条

### 56. 发现并修掉一个**真实的标志位破坏缺陷**：CBZ/TBZ 用 CMP+JCC 是错的
上一轮的控制流只做了结构验证。本轮写"带 PC 的参考执行器"做程序级对拍，立刻暴露两个问题：
1. **CBZ/CBNZ/TBZ/TBNZ 不修改 NZCV**（ARM64 语义），而我原来用 `CMP + JCC` 实现 → 会破坏客户机标志位；
2. 分支目标用的是**解码指令下标**，但一条解码指令可能展开成多条 IR 指令（TBZ→4 条），
   而 codegen 需要的是 **IR 下标** → 分支落到了错误位置（表现为 VM 里死循环）。

修法：
- **新增两条 VM 指令** `OP_JBZ`/`OP_JBNZ`（`[op][reg][target32]`，按寄存器是否为零分支，**完全不碰标志位**）→
  放在 `OP_JMP` 之后（0x62/0x63），VM ISA 从 21 条扩到 **23 条**；
  同步改了 C 解释器、Go codegen、Go 参考 VM、反汇编器，以及 Go/C 长度交叉校验（现在校验 **23 条**）；
- lifter 先记录每条解码指令展开后的 **IR 起点**，全部 lift 完再统一换算分支目标；
- W 形式的 CBZ 只比较低 32 位 → 先 `EXT`（零扩展，不碰标志位）再 JBZ。

### 57. 控制流差分结果
参考执行器按 ARM64 语义逐步执行（含 CBZ/TBZ 的"不改标志位"语义），与"lift → 在 Go 参考 VM 里跑"对比
寄存器与标志位：

```
ARM64 控制流差分：校验 6577 组，不一致 0 组；
    跳过：解码失败 11801、参考不支持 0、lifter 拒绝 1622、超过步数 0
```

覆盖：前向 `B` / `B.cond`（14 个条件）/ `CBZ`/`CBNZ` / `TBZ`/`TBNZ` + 数据类指令混合。

### 58. 仍未验证的部分（写清楚）
- **循环（后向分支）**：生成器只发前向分支以保证终止，因此**未覆盖**；
- `BL`/`RET`：仅结构验证（跨函数调用需要真实目标）；
- **内存访问（LDR/STR/LDP/STP）**：ARM64 侧**尚未实现** lift（含栈偏移分析）。

### 59. 本轮验证结果
- `go test ./...`：**9 个包全绿**；`gofmt -l` / `go vet` 干净。
- Go/C 指令长度表：**23 条一致**。
- Windows/amd64 端到端：**32/32**（blob 重建为 5792 字节，新指令未影响既有路径）。
- Linux payload 执行验证：6/6 一致。
- 工具教训：**含引号的字符串不要经 PowerShell 传给工具做原地替换**（这轮因此把
  `struct_test.go` 改坏过一次）——这类改动一律"整文件重写 + `cmd/writefile` 安装"。

## 第十八轮：ARM64 访存 lift 实现 + 差分测试**尚未通过**（如实记录）

### 60. 实现（`internal/lift/arm64/mem.go`，编译通过、fail-fast）
- **LDR/STR**：无符号偏移、未缩放（LDUR/STUR）、前/后索引、寄存器偏移（仅 LSL 形式）；
- **有符号加载** LDRSB/LDRSH/LDRSW：`Load(零扩展) + Ext(符号扩展)` 两步；
- **LDP/STP**：偏移/前索引/后索引，32/64 位；no-allocate（STNP/LDNP）明确拒绝；
- **LDR (literal)**：翻译成 `Load [VBASE + rva]`；
- **SP 处理**：基址 31 在内存操作里是 SP（不是 ZR）；`spAdjust` 按 x86-64 同一规则加
  `FrameSkew`——`eff = disp + spDelta >= 0`（访问调用方栈帧）才加，自有帧不加；
  前/后索引的写回**显式发射**（VM 的 LOAD/STORE 不改基址），并同步更新 spDelta；
- **寻址解析直接读原始编码字**：参考解码器把 imm 字段设为私有（读不到），
  这一层反而是自包含的（编码速查写在文件头注释里）。

### 61. 差分测试**没有通过**（诚实说明）
写了独立的参考执行器（自带内存模型、独立解析寻址、与 VM 共用同一段内存窗口），
比较寄存器/标志位/整个窗口的内存。当前结果：

```
VM 执行失败 rc=1 err=参考实现拒绝越界写: 0x6CD7C2BA (w=8)
```

即 VM 侧的内存访问落到了窗口之外。**最可能的原因是我的测试生成器**：
它随机插入 `SUB/ADD SP, SP, #imm` 却**没有约束累计偏移**，SP 会漂出窗口
（窗口外的地址只有 VM 侧有边界检查，参考侧是稀疏 map 不检查）。
但我**没有在剩余时间里证实**这一点，也不能排除 lifter 的偏移/skew 计算有问题——
所以：**访存 lift 目前只能算"实现完成"，不能算"已验证"**。
差分测试与生成器已存到 `docs/drafts/arm64_mem_test_draft.go.txt`，树保持全绿。

### 62. 本轮验证结果
- `go test ./...`：**9 个包全绿**；`gofmt -l` / `go vet` 干净。
- Windows/amd64 端到端：**32/32**；Linux payload 执行验证 6/6。
- 工具教训（再次）：命令行里带引号/竖线的标记经 PowerShell 传给 Go 工具会被吃掉参数，
  必须用"整文件重写 + `cmd/writefile`"。

## 第十九轮：访存差分把 5 个真 bug 逼了出来（其中一个是解码层的老 bug），但配对访存仍未对齐

### 63. 差分测试从"崩"到"能报出具体差异"，过程中修掉的真 bug
上一轮的失败原因是我自己的测试生成器（无界 SP 调整）——这轮先给它加了**有界 SP 调整**，
再让失败时打印指令序列/IR/字节码。随后逐个揪出：

| # | bug | 位置 | 性质 |
|---|---|---|---|
| 1 | **X 寄存器编号解析错**：参考解码器的 Reg 常量里 W0..W30=0..30，而 X0..X30 在另一区间（X0=32…）；`int(r)` 直接当槽位用 → 所有 X 目标寄存器都变成了 32+ | `decode/arm64` 的 `Insn.Reg()` | **解码层老 bug**，词法按名字解析修掉 |
| 2 | 加减**立即数**形式里 Rn=31 是 **SP** 而不是 XZR（读成 0 导致 SP 变成 -imm） | ARM64 lifter | 真 bug |
| 3 | Rd=31 且不带 S 时目标也是 **SP**（原来当成 XZR 丢弃，SP 寄存器在 VM 里根本不更新） | ARM64 lifter | 真 bug |
| 4 | **前索引写回顺序**：先写回再访问 → 地址错（前/后索引对单次访问等价，应统一"先访问后写回"） | ARM64 lifter | 真 bug |
| 5 | **skew 重复计入**：`spAdjust` 返回 `disp + spDelta + skew`，但 spDelta 已经体现在 VM 的 SP 寄存器里 → SP 相对寻址整体偏移 | ARM64 lifter | 真 bug（x86-64 侧当年就是只加 skew，我这里写重了） |

另外修掉一处分类回归：加载/存储分组的正确划分是
**bits[29:27]=011 字面量 / 111 寄存器 / 101 寄存器对**，
我原来把 011/111 混在一起、又用 bits[25:24]=11 判字面量，导致 `LDR Wt, label` 被当成未缩放访存 ✗。
（这也是差分测试抓到的——现在 `Classify` 按分组判，并补回被误删的 SIMD/FP 数据处理分支。）

### 64. 仍未通过：**配对访存（LDP/STP）**
修完上面 5 个之后，剩余差异集中在 LDP/STP：第二个元素的**目标寄存器/地址**仍有偏差
（调试输出里能看到第二个元素被写到暂存槽 VSCR，说明 `ins.Reg(1)` 在配对形式下返回了 -1 或 >30），
以及少量 VM 侧越界写。**我没有在剩余时间里定位到根因**，因此：
- `mem.go`（访存 lift）留在树里，但状态是**部分验证**：单寄存器访存基本对齐、配对未对齐；
- 访存差分测试与生成器存到 `docs/drafts/arm64_mem_test_draft.go.txt`，`go test ./...` 保持全绿。

### 65. 本轮验证结果
- `go test ./...`：**9 个包全绿**；`gofmt -l` / `go vet` 干净。
- Windows/amd64 端到端：**32/32**；Linux payload 执行验证 6/6。
- 解码层差分（58499 条）、数据类/控制流差分保持零不一致。

## 第二十轮：访存差分再揪出 4 个真 bug（含解释器与符号扩展），并修好 E2E 的偶发假失败

### 66. 本轮修掉的 bug
| # | bug | 位置 | 说明 |
|---|---|---|---|
| 6 | **前索引写回顺序**（配对形式）：先把基址改掉再访存 → 地址用错 | ARM64 lifter | 与单寄存器同一规则：**先访问、后写回** |
| 7 | **后索引语义错**：`[Xn], #imm` 的访问偏移应当是 **0**（立即数只用于写回） | lifter **与参考实现同时错** | 靠汇编文本 `[SP],#32`（立即数在括号外）与 `LDP X29,X30,[SP],#16` 的公认语义定案 |
| 8 | **符号扩展在 uint32 域里做减法** → 负偏移变成 `+2^32-|d|` | `signExtendN` | 症状极典型：两侧数值恰好相差 0x100000000 |
| 9 | **解释器**：ALU 立即数的符号扩展判断没有屏蔽 **keep-flags 位** → 带 keep-flags 的 ADD/SUB 用负立即数时会加 `2^32-|imm|` | C 解释器 **与** Go 参考 VM | 影响 ARM64 客户机（x86-64 侧从不用 keep-flags） |
---

## 补记：第五十八至七十五轮（要点）

> 诚实说明两件事：
>
> ## 第十六轮：根因找到了 —— 崩在 `__security_check_cookie`（栈 cookie 协议）
>
> ### 349. 同一个构建里把崩溃点的字节码解出来
> 用这次打包的 -dumpbytecode 与 manifest 的 opcodeMap：c[0x80A]=0xE3 → 在本次构建里 0xE3 正是 **OP_RET**，
> 与探针记录的 op=0xE3 完全一致 → 探针语义确认（op 就是字节码里的那个字节），且崩溃发生在**函数返回处**。
>
> ### 350. 目标 0x6E40 在原模块里是什么（objdump + 交叉验证）
> · 原模块里 `call 0x180006e40` 出现在多处，其中包括 __pyx_pf_7example_6current_time_str 自己（0x1D48）；
> · 而**能正常工作的 fibonacci 不调用 0x6E40**（它调用的是 *0x1800083e8 / 0x180003c90 / 0x180003dc0 等）——
>   这就解释了为什么同一套 stub/解释器下只有它和 add_dly 崩；
> · 0x180006E40 的第一条指令是 `cmp 0x51b9(%rip),%rcx  # 0x18000c000`，而 0x18000C000 正是 .data 里的
>   `__security_cookie` → 这是标准的 **`__security_check_cookie`**。
>
> ### 351. 机制（与探针读数完全吻合）
> MSVC 的栈保护协议：序言把 `cookie ^ RSP` 存进栈帧，尾声把它取回再 `xor RSP` 还原成 cookie，
> 然后调用 __security_check_cookie 与真实 cookie 比较；不一致就 __report_gsfailure → 写全局并快速失败。
> 我们的 VM 里 RSP 是**模拟栈**：只要序言与尾声用的模拟 SP 不完全一致，还原出的 cookie 就不等于真实 cookie，
> 校验必然失败 —— 于是「VM 调用了本机函数，那个函数写坏了地址（写目标恰好等于它自己的入口）」。
> 结论：**这是 lift 阶段对 guest SP（RSP）追踪的漂移**，不是 stub、不是栈余量、不是我前几轮猜的那些。
>
> ### 352. 下一步（可验证）
> 加一个 guest SP 探针（vm_last_sp），在「取 cookie」与「校验前」两处各记一次：
> 如果两个值不等，就直接坐实 SP 漂移，并能在该函数里定位到是哪条指令（add rsp / pop / call 返回）没把 SP 还原。
> 修好后 current_time_str / add_dly 应恢复，(f) 覆盖率 4/14 → 6/14。
>
> ## 第十五轮：崩溃点 = 最后一次本机调用的目标地址（两者完全相同）
>
> ### 346. 新增探针：最后一次 CALLN/CALLR 的目标
> vm_last_call 记录 CALLN 的 addr（高位清零）或 CALLR 的 addr（最高位置 1 作标记）。崩溃读数：
> ```
> probe BEFORE call = 0x0 / probe2 BEFORE call = 0x0
> last pc=0x80A  op=0xE3
> last native call target=0x7FFF3B7A6E40  (via CALLN)
> 异常写访问目标        =0x7fff3b7a6e40      ← 与上一条**完全相同**
> GetModuleHandleW base =0x7FFF3B7A0000      → 目标 RVA = 0x6E40
> ```
> 也就是说：VM 在 pc=0x80A 处发起了一次 CALLN，目标是「模块基址 + 0x6E40」，紧接着就崩在同一个地址上。
>
> ### 347. 同一个函数的原生代码长什么样（objdump 原 pyd）
> ```
> 180001a91: 41 ff d0            call *%r8
> 180001a96: ff 15 2c 69 00 00   call *0x692c(%rip)   # 0x1800083c8
> 180001ac6: ff 15 1c 67 00 00   call *0x671c(%rip)   # 0x1800081e8
> ```
> 该函数的原生调用几乎全是**经 IAT 的间接调用**（call qword ptr [rip+disp]）。
> 所以最大嫌疑是「这类调用被提升成 CALLN 时，RVA/目标算错了」——目标 0x6E40 落在原 .text 里，
> 而那正是 DbgHelp/RtlVirtualUnwind 一类被 objdump 显示为普通函数的区域；
> 另一个可能是目标正确但**传入的寄存器是错的**（比如把 IAT 槽位的值/RVA 当成了指针），导致被调函数写坏地址。
> 两者都指向 lift 阶段的「间接调用处理」，是下一步要读代码确认的地方。
>
> ### 348. 工具修正记录
> tools/veh_ring.py 增加 --probe2-rva（读第二个探针）；同时修掉我插入代码时的缩进错误（if 落在 try 之外）。
>
> ## 第十四轮：找到并修正探针的第三个错误 —— 崩溃其实发生在**解释循环内部**（pc=0x80A）
>
> ### 343. 错误：读探针时用的模块基址不对
> VEH 回调里我先用 VirtualQuery(故障地址).AllocationBase 当模块基址 —— 实测它给出的是**另一个模块**的基址
> （0x7FFEF3600000），而本模块真实基址是 0x7FFF3B820000。于是我在错的地方读 vm_last_pc，
> 读到的是别人的代码字节，得出「探针没被写过」的结论。
> 改成 GetModuleHandleW(模块名) 之后（并且必须在读探针**之前**取），同一个崩溃变成：
> ```
> probe BEFORE call = 0x0          ← 调用前确实是 0
> last pc=0x80A  op=0x9F           ← 解释循环确实跑到了 pc=0x80A
> ```
> 所以第 9/11/12 轮那三句「崩溃发生在解释循环之前/vm_run 之前」**全部作废**，原因是同一个工具错误。
> 这是这个项目里第三次被自己的探针带偏（前两次：内存扫描器扫到自己的 needle；环形缓冲读错地址），
> 三次都是「没读到」被当成了「没发生」。
>
> ### 344. 修正后的真实现场
> · 崩溃 pc=0x80A，正好是该函数 2059 字节字节码的**最后一个字节**（0x57 = RET），
>   对照 fibonacci 成功时的最后一次记录也是 pc=0x8AE/op=0x57（同样在末尾）→ 说明是**函数返回附近**出问题；
> · 异常是写访问违例，写目标 = 模块基址 + 0x6E40 —— 落在**原模块自己的 .text 区**（RX）→ 有人往代码段写；
> · 故障指令地址属于另一个模块（python313.dll 一带），说明写入是通过库函数/或者指令取指在别处。
>
> ### 345. 下一步
> 1）把 pc=0x80A 前后按指令边界解释出来（需要按本构建的 opcode 编码走，注意 manifest 里的 opcodeMap 是
>    名称到值的映射，字节码字节还经过一次运行期解码）；
> 2）确认返回路径：guest 的 LR/返回地址是否被写到了 .text 里的那个位置（很可能是模拟栈指针算错，
>    把返回地址写进了原模块代码段）。
>
> ## 第十二轮：入口路径阶段计数器 —— 连 stage 1 都没写，故障在 vm_run 之前
>
> ### 340. 做法
> 在非 release 构建里往 vm_last_pc 写阶段值：
> 0xAA000001 已进入 vm_run、0xAA000002 拿到描述符、0xAA000003 即将 AEAD 解密、0xAA000004 解密完成进循环前。
> （vm_last_pc 定义在文件后部，vm_run 里用需要前置 extern 声明，否则是隐式声明错误。）
>
> ### 341. 读数
> 崩溃函数 current_time_str：读到的仍是打包时填充的伪随机字节（同一个 64 位值，两次运行一致）→
> **连 stage 1（vm_run 的第一条语句）都没执行** → 故障发生在 vm_run **之前**：
> 入口补丁 → thunk → **stub asm**（帧分配 + 写 ctx + 反推描述符 + 魔数校验）。
> 这与「写访问违例、目标地址是高地址/栈形状」吻合：stub 的帧分配/ctx 写入落到了栈外。
>
> ### 342. 为什么同一个 stub 却只有这两个函数崩
> stub 的逻辑对所有函数相同，但它的**输入**不同：描述符内容（selfRVA/codeRVA/codeLen）与调用点的栈深度。
> 下一步在 stub asm 里也放 2-3 个阶段标记（帧分配后、反推描述符后、写 ctx 后），
> 就能确定是栈深度还是描述符字段这一类原因；同时可以直接试把 win/x64 的 VM_MARGIN 调大做对照实验。
>
> ## 第十一轮：pc 探针标定成功，并据此重新确认（这次有标定）崩溃发生在解释循环之外
>
> ### 337. 探针：解释器把 pc|op<<32 写进全局 vm_last_pc（仅非 release）
> 不写描述符（描述符所在节是 RX 映射，写它会直接违例），改用 .bss 全局；
> 它的绝对 RVA = sectionRVA + 符号偏移（符号偏移本身就是 blob 内偏移，不能再减 bssOff —— 我第一版减了，
> 读到的自然是垃圾）。标定结果：
>   · 成功调用 fibonacci(10) 之后读该全局 → pc=0x8AE、op=0x57，正好是 2223 字节字节码的最后一个字节偏移；
>   · 说明探针与地址算法都成立（先证明探针能看到数据，再用它下结论）。
>
> ### 338. 崩溃现场（同一个探针）
> __pyx_pf_7example_6current_time_str：异常 0xC0000005 写访问到高地址（栈形状）、故障指令在模块内，
> 而 vm_last_pc 读出来是打包时填充的伪随机字节（不是 pc）→ 解释循环一次都没跑。
> 也就是说：这次（有标定的探针支持）可以确认 —— 崩溃发生在入口路径上
> （入口补丁 → thunk → stub → 描述符 → 解密），而不是跑到某条指令才崩。
> 第 10 轮撤回的那条推断，至此以可复现的证据重新成立。
>
> ### 339. 下一步（入口路径二叉）
> 对比崩溃函数与正常函数的描述符内容（codeRVA/codeLen/encLen/flags/入口补丁），
> 以及 stub 在入口处对 ctx 的写入顺序；重点怀疑大字节码（2059B）在这条路径上的某个长度/偏移计算。
>
> ## 第十轮：标定环形缓冲 —— 结论是「上一轮的读数不可信」，改用一个更硬的探针
>
> ### 334. 标定过程与结果
> 打包 fibonacci（非 release blob），成功调用一次，再在进程里找环形缓冲：
>   · 打包器 report 给出 sectionRVA=0x10000，manifest 给出 bssOff=16384 / vm_ring_hdr=16768
>     → 环形缓冲绝对 RVA = 0x14180（我原先算的地址是对的）；
>   · 但按 magic（VMRING01）全进程搜索：module+0x14180 没有命中，命中的是 module+0x86030，
>     而那里周围的「条目」是 Python/Cython 的字符串（_short_c / ctype / _c_long …）→ 巧合字节，不是环形缓冲；
>   · 也就是说：成功调用之后，环形缓冲并没有像我以为的那样留下可读现场。
>
> ### 335. 因此撤回上一轮的一个结论
> 上一轮我写「崩溃发生在进入解释循环之前/入口附近」—— 那条推断建立在「环形缓冲里只有填充字节」之上，
> 而标定发现环形缓冲本身没有拿到，所以那条结论**不成立，撤回**。
> 教训：先证明探针能看到数据，再用探针下结论；否则只是把「没读到」当成「没发生」。
>
> ### 336. 下一个探针（更硬、不依赖环形缓冲）
> 让解释器在非 release 构建里每条指令把 pc 写进描述符的保留字段（vm_desc_t 的 reserved2，偏移 +28）；
> 描述符绝对地址 = 模块基址 + report 里的 descRVA（已知）→ 崩溃时 VEH 回调直接读这个 u32，
> 就得到「最后执行的 pc」，再用 -dumpbytecode 的明文对照该 pc 处的指令。
> 这条链路不依赖 magic、不依赖偏移推算，是下一步的主线。
>
> ## 第九轮：崩溃函数的定位工具（VEH + 环形缓冲 + 故障地址）
>
> ### 331. 静态对拍没找到差异
> 把 6 个能翻译的函数一起打包并导出 IR（vmpack -v），对比「可用 4 个」与「崩溃 2 个」的 IR 组合：
> 崩溃函数**没有用到任何可用函数没用过的 op/宽度组合**（add_dly 只多一个 NOP）。
> 也就是说：缺陷不是某个 op 没实现，而是某个**操作数/状态组合**下的语义写错了。
>
> ### 332. tools/veh_ring.py：在崩掉的那一刻把现场读出来
> 用 Windows 的 VEH（AddVectoredExceptionHandler）在访问违例时先跑我们的回调：
> 打印异常码/故障地址/所属模块，再按「模块基址 + .vmpb RVA + 环形缓冲偏移」读环形缓冲。
> 两个实现细节：回调对象必须**留引用**（临时对象被回收后回调变野指针，症状是回调根本不触发）；
> 回调里不要用 print（可能在异常上下文里再炸），改成 os.write 写文件。
>
> ### 333. 首次读数
> __pyx_pf_7example_6current_time_str：异常码 0xC0000005、**写访问**（参数 1）到 0x7fff0d8f6e40（高地址、栈状），
> 故障指令在模块内（allocation base = 模块基址）。同时读到的环形缓冲仍是打包时填充的伪随机字节 →
> 说明**还没有任何指令被记录**：崩溃发生在进入解释循环之前/入口附近，而不是跑到一半才崩。
> 下一步要先把环形缓冲的偏移与写入时机核实清楚（例如用 release 与非 release 两份对比），再据此定位。
>
> ## 第八轮 (f)：扩大保护面 —— 多函数实测，覆盖口径改成「翻译 + 运行都对」
>
> ### 328. 一次保护 6 个函数：结构全过，行为 4/6
> 用同目录 `example.map` 按名字定位，单次打包 6 个函数（各一份描述符/thunk/字节码槽）：
> n、2fibonacci、6current_time_str、9add_dly(pw)、pymod_create、bisect_code_objects。
> 结构：6 条补丁全部落在新节、`.pdata` 6 条记录全清、导入期（pymod_create 在 import 时就会跑）正常。
> 行为：fibonacci 55/610 正确、n() 正确、greet 正确；**current_time_str() 与 add_dly() 直接 0xC0000005**。
> 两者**单独打包、单独调用同样崩** → 是解释器在个别函数上的运行时缺陷，不是多函数相互影响。
>
> ### 329. 全量 14 个可命名函数的可翻译性
> 能翻译 6 / 拒绝 8；拒绝里 6 个是「函数末尾不是 RET」（尾声为间接尾调用或跳转桩）、
> 1 个「1/125 条指令无法翻译」、1 个「+0x0 是 JMP」。最终**已验证可用**的多函数集合是 4 个。
>
> ### 330. 多函数产物的对抗复测（4 函数版）
> E9 蹦床 4 条全部指向我们的新节；`.pdata` 记录 0 条；回填（一次补回 4 处）被加载期校验拒绝；
> ChaCha sigma 规范字 NONE；`.vmpb` 熵 7.828；原生与打包后 Python 行为逐项一致。
>
> **补充说明（第 78 轮）**：上面这份补记在我做整文件重排时被**第二次截断**（读取有大小上限，
> 我又用读取结果整文件写回）。教训与第 61 轮那次完全一样：**绝不要用 read 的结果整文件重写大文件**，
> 只能做"读尾部 + 就地 append"。以下是自包含的补记，作为本文件的最终内容之一。
>
> - **58–61**：明文缓存线程安全（描述符指针键控 + 自旋锁，E2E 多线程用例）；ELF 去 RWX（RX/RW/RX 三段 + readelf 断言无 W+X）；PIE(ET_DYN) 用两个装载地址证明；DLL 保护目标 3/3；覆盖率 Go 15.7%→70%+、libstdc++ 52.8%→87%+。
> - **62**：打包 SIMD 算术（PADD/PSUB/PANDN 按 lane）+ 交错/字节移位 → E2E 120→127。
> - **63**：MOVSD/MOVSS 三种形式 + MOVAPD/MOVUPD 别名（仅单测）。
> - **64–65**：原子读改写（OP_ATOMIC + 9 kind + 宿主 `__atomic_*`）。第 64 轮数值不符被 fail-safe 关闭；**第 65 轮找到根因**（取旧值的无条件 exchange 多写一次内存、并破坏 CMPXCHG）→ 改按 kind 分派 fetch_*/compare_exchange；真并发 4×20000=**80000**；E2E 127→133；覆盖率 Go→**86.4%**、libstdc++→**91.4%**。
> - **66**：单操作数 IMUL 与 LEA 跳转表——后者假设被证伪并回退（无收益，如实记录）。
> - **67**：单操作数 IMUL 打通（判据 `args[1] == nil`）；补 kind 表 Go/C 交叉校验测试。
> - **68–72**：浮点标量（OP_FP + KF_*）。第 68 轮打开后 E2E 全崩；第 69 轮查明是**我自己的编辑事故**（残留 `int c = vm_bc_acquire();` 遮蔽字节码指针 → 解释器编译失败 → E2E 拿旧 blob 配新 manifest）；第 70 轮二分到"加回 OP_FP 实现块（即使不执行）就全崩"；**第 71 轮找到根因：gcc -O2 对含浮点代码的解释器整体编译错**（-O0/-O1 正常）→ 解释器改 `-O1`（代价 1.3–1.7×）；浮点启用，E2E **146/146**；第 72 轮把触发点收窄到"整数↔浮点转换那几行"，排除别名/内联/汇编/双关/栈帧溢出（实测最大 `sub rsp` 仅 0x98），**根因未定位**，按承诺收手。
> - **73**：交付 README.md / docs/RUNBOOK.md / .github/workflows/ci.yml。
> - **74**：新增 `tools/gates.ps1`（一条命令全部门禁）；抓到我自己写出的两次假绿（`exit` 终止整个进程；`$PS` 作用域不可见导致 E2E 根本没启动）；实测本机无 pwsh / 无 WSL 发行版 / 无 docker+qemu。
> - **75**：把 ARM64 **客户机**差分从"静默 skip"变成真跑 → **发现真实缺陷**：`vm_types.h` 的 `VRBASE=16` 与 ARM64 的 X16 撞车（ARM64 应为 X0-X30=0..30、SP=31、VBASE/VSCRATCH=32/33、ZR=34）。
> - **76**：修好该缺陷（`vm_types.h`/`vm_abi.h` 按客户机条件定义 → 32/33、256/264），并补上 harness 必须用的 `-DVM_REG_COUNT=35`；**两条 ARM64 客户机差分测试首次真正通过**。
> - **77**：manifest 记录 `guest`/`regCount`；两条测试加**布局守卫**；门禁 5→6 条（新增 `tools/e2e_arm64guest.ps1`）；**更正**第 75 轮那条"已加 CI 作业"的不实记录（当时并没加，本轮才加）。
> - **78**：新增 `docs/FINAL.md`（收尾报告：目标对照 / 覆盖率终测 / 未达标项 / CI 闭环路径）；覆盖率终测 Go **88.6%**、libstdc++ **91.4%**（指令级 99.5–99.6%）；清理文档里 208 处转义残留；门禁 **6/6**。
> - **目标状态**：①–④ 本机达成；**⑤ 只完成一半**（ARM64 客户机语义链已真实验证；ARM64 宿主 blob 构建、Linux/arm64 qemu、ci.yml 实跑需 CI）。因此目标**不能标记为完成**，保持 active。
>
> ## 第七十九轮：最终一致性复验（把文档里的数字重新测一遍）
>
> 原则：**文档里的每个数字都必须能对应到一次实际执行**。本轮把 FINAL.md / README.md 的数字逐条重测：
>
> | 项目 | 文档原值 | 第 79 轮复测 | 处置 |
> |---|---|---|---|
> | x86-64 E2E | 146 passed | **146 passed, 0 failed**（并核对 \`[OK]\` 行数 = 146） | 一致 |
> | check_key protected | 80 ns/iter | **50 ns/iter**（native 0.4，约 125×） | **已更正** |
> | sum_to protected | 1200 ns/iter | **1100 ns/iter**（native 12.5，约 88×） | **已更正** |
> | 覆盖率（Go / libstdc++） | 88.6% / 91.4% | 本轮重测一致（指令级 99.5% / 99.6%） | 一致 |
> | 门禁 | 6 条全绿 | 本轮再跑一次确认 | 一致 |
>
> 性能数字变化的原因：文档里的 80/1200 是第 71 轮（刚切到 -O1 时）测的，之后浮点/原子等代码又改动过。
> 结论：**-O1 的代价比当时估的更小**（约 1.4–1.6×，而不是 1.3–1.7× 的上界）。
>
> 另外补了 \`docs/RUNBOOK.md\` 第 7 节：**推送前最小改动清单**（\`git init\` → 提交 → 推送），
> 并写明两点风险：\`build/\` 里有 AEAD 主密钥（已被 .gitignore 排除，推前请再 \`git status\` 确认一次）；
> CI 首次运行最可能在 \`linux-amd64\` 与 \`linux-arm64\` 两个作业上暴露问题（那两个脚本从未在 Linux 上跑过）。

> ## 第八十轮（最后一轮）：收尾与最终判定
>
> ### 275. FINAL.md 定稿
> - 目标对照表 ① 行补上 **ARM64 实测**（指令级 88.7%、函数级 4.4%），与 x86-64 并列；
> - 文件开头写明**第 80 轮的最终状态**：①–④ 本机达成，**⑤ 只完成一半**；
> - 新增「最关键的后续工作项（量化结论）」：ARM64 函数级只有 4.4% 的原因（一条不支持则整段不算）
>   与优先要补的指令类（SIMD/浮点向量形、MRS/MSR、barrier、部分 LDP/STP 变体）。
>
> ### 276. 本会话的最终验证
> \`tools/gates.ps1\`：**6 条门禁**（gofmt / go vet / go test / x86-64 E2E 146 例 / DLL E2E 3 例 / ARM64 客户机差分）。
> 覆盖率：x86-64 函数级 87.7~91.4%、指令级 99.5~99.6%；ARM64 指令级 88.7%、函数级 4.4%。
>
> ### 277. 目标判定（诚实结论）
> ①覆盖率量化与子集扩展（两个 ISA 都有第一手数字）**达成**；
> ②ELF 去 RWX **达成（本机验证）**；③PIE + Windows DLL + ELF \`.so\` 定位**达成**，运行时 \`dlopen\` 未验证；
> ④明文缓存线程安全 **达成（本机验证）**；
> ⑤**未达成**：ARM64 客户机语义链已完成并纳入门禁，但 **ARM64 宿主 blob 构建、Linux/arm64 qemu 端到端、
> 以及 ci.yml 实跑必须由 CI 或真机执行**。本机已实测确认（无 PowerShell 7、无 WSL 发行版、无 docker/podman/qemu），
> 这个条件在整个后半程持续存在且无法在本机消除。
>
> 因此**不能把目标标记为完成**；按目标工具策略记为 **blocked**，并把上面这条具体条件写进 blocked_reason。
> 后续闭环路径：把仓库推到 GitHub 启用 \`ci.yml\`，或在一台 Linux/arm64 机器上按 \`docs/RUNBOOK.md\` 跑第 2–4 节，
> 把输出贴回来即可继续。
>
> ## 第九十一轮：ELF 重定位修好之后，linux-amd64 的问题变成了"宿主栈深度"
>
> ### 278. 修复生效：PC 相对重定位不再多 +4
> 上一轮找到并修掉的根因（ELF 的 `call/jmp` 被写偏 4 字节）已经生效：差分用例的失败形态**完全变了** ——
> 从"SIGILL、PC 落在指令中间"变成 Go runtime 报栈错误。也就是说**保护后的程序已经在正常执行 Go 代码**了。
>
> ### 279. 新暴露的问题：模拟栈在宿主 RSP 之下，装不进 goroutine 栈
> CI 原文：
> \`\`\`\`
> [FAIL] sum-to(9999): native=49995000 (rc=0) protected=runtime: newstack sp=0xc000077c60 stack=[0xc000078000,0xc000079000] (rc=2)
> runtime: split stack overflow: 0xc000077c60 < 0xc000078000
> fatal error: runtime: split stack overflow
> \`\`\`\`
> 几何关系：模拟栈在宿主 RSP 之下 \`VM_FRAME_SIZE(4544) + 16 + VM_MARGIN(8192) ≈ 12.7KB\` 处；
> 而 Go 程序的 goroutine 栈初始只有 **8KB** → 客户机一压栈就越过栈底。
> （Windows 一直没暴露，是因为那边跑在主线程的大栈上。）
> **调小 VM_MARGIN 不是出路**：\`vmpbuild\` 有检查 \`margin > 解释器最大帧(4544) + 512\`，
> 所以总深度必然 ≥9.6KB；我试了 0x800，构建当场拒绝，已回退。
>
> ### 280. 真正的修法（下一轮做，方案已定）
> 让**客户机使用自己的栈**：在 blob 的 \`.bss\` 里放一块客户机栈，入口 stub 把模拟 RSP 指向它，
> 而不是指向宿主 RSP 之下。这样：
> - 与宿主栈深度解耦（goroutine 8KB 也没问题）；
> - \`FrameSkew\` 对**自己的帧**（disp < 0）退化为 0，对**调用方帧**（disp > 0，例如栈上传参）需要另行处理 ——
>   当前 E2E 的两个目标函数都用寄存器传参，所以先按"客户机栈 + 记录这个限制"来做，并在 FINAL.md 写明。
>
> ### 281. 当前四个作业
> | 作业 | 状态 |
> |---|---|
> | windows-amd64 | **success**（持续） |
> | linux-amd64 | 打包 ✓、无 W+X ✓、PC 相对重定位已修；剩余问题是宿主栈深度（本轮定位） |
> | linux-arm64 | blob 构建 ✓、AArch64 打包 ✓、qemu 首次执行 segfault；另有 payload 段退回 RWX 的缺口 |
> | windows-arm64-blob | 外部工具链缺口 |
>
> ## 第九十三轮：CI 结论写回文档；本机门禁恢复全绿
>
> ### 282. 先修掉"上一个残留"
> 上一轮我报告 `TestConformanceAgainstCInterpreter` 失败 —— 查清后是**产物过期**、不是代码问题：
> 该测试自带 staleness 守卫，明确报出 `build/runbc.exe 比 stub/win/x64/vm_abi.h 旧，请先重建`。
> 重建 harness 后：
> - `go test ./...` **11 个包全绿**；
> - `tools/gates.ps1` **7 条门禁全绿**（gofmt / vet / test / x86-64 E2E 146 例 / DLL 3 例 / ARM64 客户机差分 / Linux 载荷在本机执行）。
>
> ### 283. 文档写回（目标 ③）
> - `docs/RUNBOOK.md` §6「本机 vs CI 边界」：把原来那句『需要 CI/真机』换成**四个作业的真实结论**：
>   windows-amd64 全绿；linux-amd64 打包 ✓、无 W+X ✓、差分因"客户机栈深度"未绿（含根因）；linux-arm64 blob ✓、打包 ✓、
>   qemu 首次执行段错误；windows-arm64-blob 缺 aarch64 COFF 编译器（外部缺口）。
> - `docs/FINAL.md` 新增 §8：四作业结论表 + **对原目标 ⑤ 的判定** + 这一路修掉的 6 个真缺陷清单。
>
> ### 284. 目标 ⑤ 的判定（写进 FINAL）
> - 已达成：CI 矩阵实跑且四个结论可匿名阅读；ARM64 **客户机**语义链在真实差分中验证并纳入门禁；
>   ARM64 **宿主** blob 从"从未构建"到"能构建、能打包、能被 qemu 执行"；
> - 未达成：ARM64 宿主 blob 执行仍段错误；Linux/amd64 差分未全绿（根因已定位）；
> - 结论：⑤ 从『完全受限』推进到『可在 CI 上闭环』，**尚未完成**。
>
> ### 285. 下一轮的候选修法（按风险排序）
> 1. **压缩栈深度**（推荐先做）：把解密缓冲从 `vm_run` 的栈帧搬进 `.bss`（它本来就只在缓存槽全忙时兜底），
>    于是 `VM_FRAME_SIZE` 从 4544 缩到几百字节，再把 `VM_MARGIN` 降到 4KB —— 总深度 ≈4.6KB，装得进 8KB 的 goroutine 栈。
>    已知代价：极深嵌套的"缓存槽全忙"情形会共用同一个兜底缓冲（当前 E2E 的嵌套深度在缓存槽容量内）。
> 2. linux/arm64 的 qemu 段错误：先加"入口补丁检查"（用 aarch64-linux-gnu-objdump 反汇编确认 8 字节补丁在场），
>    再按需给 payload 段扩容 phdr（顺带解决 RWX 退回）。
>
> ## 第九十四轮：栈深度改法在 CI 上**不被接受**，已回退；但拿到了两组明确的新证据
>
> ### 286. 这一轮做了什么
> 按上一轮的计划：把 4KB 解密兜底缓冲从入口栈帧搬到 `.bss` 并改成 **4 槽的池**（取用/归还走
> 与 `vm_bc_cache` 相同的锁与计数），于是 `VM_FRAME_SIZE` 4544→640、`VM_MARGIN` 8KB→4KB。
> 实测（vmpbuild 打印）：`frame=640 margin=0x1000 frameSkew=4752` —— 总深度从 12752 降到 4752，
> **装得进 Go 的 8KB goroutine 栈**。
> 本机验证：x86-64 E2E **146/146**（含 mt 并发用例）、DLL 3/3、Linux 载荷全部匹配、PIE 两个装载地址一致，
> 7 条门禁也曾全绿（`gates_r94b.txt`）。
>
> ### 287. 但 CI 是裁判：两个作业同时变差，所以**不接受**
> - `windows-amd64`：runner 上 **E2E 失败**（本机同一提交连跑三次都是 146/146）→ 怀疑是新增的"池"
>   在 runner 的时序/核数下暴露了竞态（本机跑不出来）；
> - `linux-amd64`：`split stack overflow` **确实消失**（这是好消息，证明"压深度"方向对），
>   但换成了另一种内存/控制流损坏：
>   \`\`\`\`
>   unexpected fault address 0x591180
>   [signal SIGSEGV: segmentation violation code=0x2 addr=0x591180 pc=0x585d0e]
>   runtime: g 1: unexpected return pc for runtime.(*mheap).alloc called from 0xc00011ac30
>   \`\`\`\`
>   结合"客户机可用的栈就是 margin"这一事实，把 margin 从 8KB 砍到 4KB 很可能让客户机压栈越界。
> 按纪律：**未被 CI 接受的东西不留**，已整体回退到 829a277，并复验本机 146/146。
>
> ### 288. 下一轮的可执行路线（两条都要做）
> 1. **池必须先在压力下证明自己**：给 mt 用例加更重的并发形态（更多线程/更长迭代），并连续跑多次，
>    确认不是"有时对"；池的取用/归还再复核一遍（尤其"缓存槽忙着时同时进池"的路径）。
> 2. **深度只压到必要程度**：保留"缓冲搬到 .bss + 帧缩小"（这两项本机重复验证通过），
>    但 margin 只从 8KB 降到 **7KB**（总深度 ≈7.7KB < 8KB），给客户机留足自己的栈空间。
>    这样"split stack overflow"应该解决，又不至于把客户机逼到越界。
>
> ## 第九十六/九十七轮：mt 竞态真因修掉、windows-amd64 在 runner 上转绿；linux-amd64 的损坏与栈深度无关
>
> ### 289. 反馈回路先修好
> CI 的 7 个步骤（4 pwsh + 3 bash）统一改成：失败注解**先放** [FAIL]/MISMATCH/<crash/fatal/panicked/[!] 行（最多 12 行），
> 再补日志尾部 4 行。立刻拿到关键信息：runner 上 windows-amd64 失败的是 **mt(0)**（多线程用例）。
>
> ### 290. mt 竞态：本机复现 + 二分 + 真因
> - 本机把打包产物 `target_vmp.exe mt 0` **循环 200 次**：**24 次不匹配**（E2E 每次只跑一遍，所以一直没暴露）；
> - 二分：把 `VM_BC_CACHE_SLOTS` 4→32（于是永不落到新加的"兜底池"）→ **0/200** → 问题在池；
> - 真因：4 个池槽在"4 线程 × 嵌套调用"下被耗尽 → 返回错误码 → 客户机拿错值继续算；
>   而缓存槽本来就靠引用计数**共享**同一份只读明文，"池"是多余概念；
> - 修法：删掉池，`VM_BC_CACHE_SLOTS=16`（16×4KB=64KB .bss），槽全忙时明确返回错误；stub 里指向栈帧的
>   `vm->scratch` 设置一并删除。
> - 验证：本机 E2E 146/146、DLL 3/3、载荷匹配、**mt 循环 200/150 次 0 错**；CI 的 **windows-amd64 已无失败步骤**（
>   即便同时带着 frame=640 / margin 改动）→ 说明帧与 margin 不是 Windows 的问题。
>
> ### 291. linux-amd64：损坏与栈深度**无关**（重要否定结论）
> CI 日志给出的现场是 `stack=[0xc000078000,0xc000079000]` —— Go 的 goroutine 栈在那个现场只有 **4KB**。
> 依此把 margin 从 7KB 收到 3KB（总深度 640+16+3072 = **3728 < 4KB**，vmpbuild 的检查也满足），
> 结果 **失败地址逐字节不变**（`unexpected fault address 0x599240`，pc 落在 payload 的 .text 里）。
> 说明：**这不是"模拟栈低于宿主 RSP"造成的**；故障点是 payload 内的一个确定性地址，
> 与 blob/载荷布局一起变化（不同构建地址不同）。下一步应当在 Linux 侧对这个地址做映射/权限与
> 访问来源的诊断（例如在探针里报告 faulting access 的类型），而不是继续调栈参数。
>
> ### 292. linux-arm64：有了指令级现场
> `tools/e2e_arm64.sh` 现在在 set -e 下安全捕获退出码，并在失败时用
> `qemu-aarch64 -d in_asm,cpu` 重跑、打印日志尾部。首次结果已经能看到寄存器与 PC：
> `PC=0x4001e4 X00=0x2 ... X30=0x4001f4 SP=0x400000fff630`，`IN: _start` —— 崩溃发生在目标自身代码路径上（rc=139）。
>
> ### 293. 当前四作业
> | 作业 | 状态 |
> |---|---|
> | windows-amd64 | **runner 上无失败步骤**（含 frame 640 / margin 3KB / 16 缓存槽） |
> | linux-amd64 | 打包 ✓、无 W+X ✓；运行期确定性损坏，且**已证明与栈深度无关** |
> | linux-arm64 | blob ✓、打包 ✓、qemu 执行崩溃（现在有 PC/寄存器现场） |
> | windows-arm64-blob | 缺 aarch64 COFF 编译器（外部缺口） |
>
> ## 第九十八/九十九轮：linux-amd64 的故障性质被算术定死（**不是权限问题**）
>
> ### 294. 拿到的硬数据（CI 注解）
> ```
> LOAD  0x225000 0x589000 0x589000 0x11000 0x11000 RW  0x1000   ← .bss 覆盖段（RW）
> LOAD  0x221000 0x585000 0x585000 0x15100 0x15100 R E 0x1000   ← payload（RX）
> payloadVA=0x585000 payloadSize=86272
> bssOff=16384 bssSize=69632 → bss 区间 [0x4000, 0x15000) → VA [0x589000, 0x59A000)
> [FAIL] protected=unexpected fault address 0x599240
> ```
> **算术**：0x599240 落在 [0x589000, 0x59A000) 内 → 它在那个 **RW** 覆盖段里，**是可写的**。
> 所以「内核把 .bss 留在只读 RX 映射里」这个假设**被推翻**（本地 dump 也证实覆盖段存在且尺寸正确：
> `LOAD RW off=0x225000 va=0x589000 filesz=0x11000 memsz=0x11000`）。
>
> ### 295. 剩下唯一的解释：**执行**了不可执行的页
> 覆盖段是 RW（**没有 X**），payload 段是 RX。0x599240 在覆盖段内 → 一旦 CPU 去**取指**就 SIGSEGV，
> 而 Go 的 signal handler 正是报「unexpected fault address <该地址>」。
> 结论：**VM 跳进了 payload 的 .bss** —— 控制流被破坏，不是数据写权限问题。
>
> ### 296. 两条执行路径的差异指向「入口路径」
> 同一个 payload：**探针直接调 thunk 是好的**（CI 的 payload probe 步骤一直通过），
> **经入口补丁进入就崩**（差分用例全红）。两者只差「谁调用 thunk、在什么栈上、寄存器状态如何」。
> 下一步：① 确认打包文件里 5 字节补丁确实是 E9 到 thunk（e2e.sh 已有 objdump 检查）；
> ② 在 Linux 侧捕获信号并打印 VM 状态（模拟 PC / 当前操作码 / 模拟 RSP），看是从哪条指令跳进 .bss 的；
> ③ 重点看「嵌套调用 + 宿主 Go 栈」这一组合（探针走进程主栈，目标走 goroutine 栈）。
>
> ## 第一〇〇/一〇一/一〇二轮：linux-amd64 的排除清单（每个假设都被数据否掉）
>
> ### 297. 探针（都只在 x86-64 客户机上生效）
> - 压栈越界（低于给它的栈下界）→ 返回 **99**；
> - 弹出过多（SP 高过进入值，返回地址必然取错）→ **97**；
> - 未知操作码 → **98**（原本是 1，与 OP_HALT 的正常返回撞在一起；顺带纠正我自己一个错判：
>   主 switch **本来就有** default（“失败而不是猜”），我原先以为它会静默跳过）。
>
> ### 298. 三轮 CI 的判决：97/98/99 **全部没有命中**
> linux-amd64 的失败始终是 `unexpected fault address 0x599240`（逐字节不变）。结合前面已确认的事实：
> - 入口补丁**正确**（本机在打包产物里读了目标函数头 5 字节：`E9` + rel32 精确落在 thunk 上，两个函数都 OK）；
> - 故障地址落在 payload 的 **RW** 覆盖段内（`[0x589000,0x59A000)`）→ 是**取指**到不可执行页；
> - 字节码解密**通过 AEAD 校验**（否则 rc=3）；操作码、SP 记账都正常；
> - 同一个 payload、同一个 blob，**探针直接调 thunk 一直是通过的**，只有经入口补丁进入才崩。
>
> 也就是说：能想到的“寄存器/栈记账”类原因已被逐条排除，剩下的方向是
> **宿主栈被写坏**（客户机某次 store 落到了宿主帧上）或**解释器自身的间接转移**（例如
> `OP_CALLN` 那条按客户机地址调用宿主函数的路径）。这条只能靠“跑飞前最后若干条 (pc, op)”
> 之类的现场记录来定位 —— 已在 STATUS 里列为下一步。
>
> ### 299. 另一个尚未解决的方向（与第 91/92 轮的结论合起来看）
> 客户机“自己的帧”落在宿主 RSP 之下（margin 里），而 CI 现场 Go 的 goroutine 栈只有 **4KB**。
> 这既解释了最初的 `split stack overflow`，也说明“客户机可用栈 = margin”这件事在 Go 上很紧张
> （当前 margin 3KB）。第 92 轮试过“给客户机一块自己的栈”，但因为切断了“调用方帧仍在宿主栈上”
> 的语义，framed / calls_protected 立刻回归。真正的解应当是**按 disp 的正负分开映射**：
> 自己的帧（disp<0）用客户机私有栈，调用方帧（disp>=0）仍指宿主栈。
>
> ## 第一〇三轮：**linux-amd64 修好了** —— 根因是重叠 PT_LOAD 的映射顺序
>
> ### 300. 决定性线索
> 把跑飞关键字加进 CI 注解抓取后露出：
> `[signal SIGSEGV: segmentation violation code=0x2 addr=0x599360 pc=0x585d0e]`
> code=0x2 = SEGV_ACCERR（地址已映射、权限不允许）；addr 落在 `.bss` 的 RW 覆盖段内，pc 在解释器写解密缓存的代码里。
> 也就是「往本该可写的那一页写」被内核拒绝。
>
> ### 301. 根因与修法
> 内核按**程序头表顺序**依次 mmap 各 PT_LOAD，**重叠区间上后面的映射覆盖前面的**。
> 实测：payload 复用 PT_NOTE（索引 1），可写覆盖段落到更低的索引 0（可丢弃的 PT_PHDR），
> 于是 payload 段后映射、把 RW 覆盖段盖回 RX → `.bss` 只读 → 解释器第一次写缓存即 SIGSEGV。
> PE 侧按节合并、写标志生效，所以该问题只在 ELF 上现形。
> 修法：`inject/elf.go` 在添加覆盖段后，若其索引小于 payload 段则交换两者（新增 `load/elf.SwapPhdrs`）。
> 本地验证：打包后顺序变为 `idx=0 va=0x585000 RX` / `idx=1 va=0x589000 RW`；E2E 146/146、DLL 3/3。
>
> ### 302. CI 判决：**linux-amd64 全绿**
> `linux-amd64: failedSteps=[]` —— 打包、无 W+X、payload 探针、差分 E2E 全部通过。
> 四个作业现在：windows-amd64 ✓、linux-amd64 ✓、linux-arm64 ✗（qemu 段错误）、windows-arm64-blob ✗（外部工具链）。
>
> ### 303. 同类缺口（建议加构建期检查）
> `vmpbuild` 目前不检查「blob 里是否出现可写的非 .bss 数据」。上一轮环形缓冲带初始化器落进 `.data`，
> 立刻把本机 E2E 打成 protected 全空 —— 与本次根因同一类（权限归属）。建议：blob 出现 `.data` 就失败，
> 或把 RW 覆盖段扩到包含 `.data`。
>
> ## 第一〇四/一〇五轮：linux-arm64 从「段错误」推进到「不崩但全 0」
>
> ### 304. 修掉的两个 arm64 宿主 bug
> 1. **入口 stub 的寄存器还原**：prologue 只写了 VM_SAVE_LR / VM_SAVE_GUEST_LR 两格，
>    epilogue 却从 `VM_SAVE_BASE + 8*(r-1)` 还原 X1..X29 —— 那块区域从未被写过，
>    于是客户机返回时 X1..X29 全是垃圾，调用方（目标自己的 _start 附近）立刻崩
>    （现场 PC=0x4001e4 / X30=0x4001f4 / rc=139 完全吻合）。改为从 **ctx** 还原 X1..X30。
>    效果：`protected rc=0` —— **不再崩了**。
> 2. **标志位换算**：进入用 `lsr #28`（应为 `and #0xF`）、还原多了一次 `rbit`（应直接 msr）。
>
> ### 305. 当前症状（精确）
> ```
> [!] native   = 213|206|143|2012|86342|6999829|0|28|500500
> [!] protected= 0|0|0|0|0|0|0|0|0
> [!] arm64 end-to-end: MISMATCH (native rc=0, protected rc=0)
> ```
> rc=0 且每个被保护函数都返回 0 —— 说明 VM 跑完了但「没算」（rc=0 对应命中 OP_RET）。
> 已排除：描述符布局（x64/arm64 两个 vm_desc_t 字段一致）、清单/opcode map 用错（e2e_arm64.sh 用的是
> vm_interp_arm64.json）、AEAD 失败（那会是 rc=3）、lifter 产出为空（vmpack 日志显示 6 IR / 42B、8 IR / 54B）。
>
> ### 306. 下一步（明确）
> 给 arm64 也做一份 payload 探针（用 CI 里的 aarch64-linux-gnu-gcc 编、qemu 跑），
> 把「payload 自身」与「入口/加载」分开 —— x86-64 正是靠这个探针把范围收窄到了映射顺序。
>
> ## 第一〇九～一一五轮：arm64 的三个真 bug + 一个假绿
>
> ### 307. 修掉的三个真 bug
> 1. **入口 stub 从未写过的保存区**：prologue 只写了 VM_SAVE_LR / VM_SAVE_GUEST_LR,
>    epilogue 却按 VM_SAVE_BASE + 8*(r-1) 还原 X1..X29 → 客户机返回时全是垃圾，
>    调用方（目标自己的 _start 附近）立刻崩（现场 PC=0x4001e4 / X30=0x4001f4 / rc=139 完全吻合）。
>    改为从 **ctx** 还原 X1..X30。修后：不再崩（rc=0）。
> 2. **标志位换算**：进入用 `lsr #28`（应为 `and #0xF`）、还原多了一次 `rbit`。
> 3. **VM_FRAME_SKEW_EXTRA 被兼容分支误改**：`vmpbuild` 用 `== 0` 判断「宏缺失」，
>    把 arm64 显式写的 0 也改成 16 → lifter 对客户机 `[sp+disp]`（disp>=0，调用方帧）整体偏 16 字节。
>    CI 日志 `FRAME_SKEW=70240 = 4688+16+65536` 是铁证；修后为 70224。
>
> ### 308. 一个假绿（必须写进收尾报告）
> manifest 的 `maxStubStackFrame = 0` —— `vmpbuild` 的 `measureMaxFrame` 只认 x86 的 `sub rsp` 语法，
> 对 aarch64 目标**量不到任何帧**，于是 `margin > 最大帧 + 512` 这条守卫**静默通过**。
> 已确认（读 manifest 即可观察）；修法应当是「测量失败即报错」，而不是让检查形同虚设。
>
> ### 309. 我自己的两次工具自伤（都花掉一个 CI 周期）
> - 替换 margin 时只换掉多行注释的第一行，留下四行悬空注释 → 汇编报 `junk at end of line`；
> - 改 heredoc 时留下 9 行残骸（`PY' 2>/dev/null || true` + 旧 python 主体）→ heredoc 未终止，
>   旧 python 被当成 shell 执行，`set -e` 直接终止脚本 → arm64 一直在探针之前就失败。
>
> ### 310. 当前 arm64 状态
> 故障可复现地落在 `check_key` 字节码的第 6 条（pc=0x29，字节码共 42 字节）；
> 指令级现场显示崩溃前控制流在**解释器**里、之后出现在 **stub 的收尾序列**（野跳）。
> 诊断通道（`MISMATCH` 前缀 + 环形缓冲 + qemu 指令日志）现已全线打通，下一轮直接读语义操作码。
>
> ## 第一一六/一一七轮：解码链路打通，但"明文字节码"其实是密文
>
> ### 311. 看数据这条链路修了三处（都是我的问题）
> 1. placement 的字节码长度字段名是 `bytecodeBytes`（不是 bytecodeSize/codeLen）；
> 2. `codeRVA` 是**目标 RVA**，payload 内偏移要减去 `sectionRVA`（之前切出 0 字节）；
> 3. `tools/e2e_arm64.sh` 里有 9 行 heredoc 残骸，导致脚本在探针之前就被 set -e 终止。
> 修完后终于能打印出 42 字节字节码与环形缓冲的 pc/op。
>
> ### 312. 重要更正：我打印的那个"明文字节码"是**密文**
> 描述符带 `VM_DESC_FLAG_ENC`（打包日志明确写着 ChaCha20-Poly1305），
> 所以 payload 里那 42 字节是**密文**，讲解密后才是指令流。
> 因此"首字节 0x3F 解出 OP_LEA"只是巧合；后面 0xFE/0x62/0x45/0xE7/0xAA 反查不到映射也是理所当然 ——
> **这一轮关于"第 6 条是什么 op"的命名尝试全部作废，不作为结论。**
> 要真正命名，必须拿到**解密后的明文**（例如给 vmpack 加一个显式的诊断开关把明文转储出来），
> 而不是从 payload 里直接读。
>
> ### 313. 仍然成立的事实
> - 故障可复现地落在 `check_key` 的**第 6 条指令**（环形缓冲 pc 序列 0/9/0xF/0x18/0x23/0x29 在多构建间一致）；
> - 崩溃前控制流在**解释器**里、之后出现在 **stub 收尾序列**（野跳）；
> - `maxStubStackFrame = 0`：aarch64 的帧测量失效，`margin > 帧+512` 守卫静默通过（假绿，待修）。
>
> ## 第一一八轮：**第 6 条 = `OP_RET`** —— arm64 的崩溃发生在函数的正常返回路径上
>
> ### 314. 用明文转储终于解出确定答案
> `vmpack -dumpbytecode` 转储的**明文**字节码（42 字节）与环形缓冲的 pc 对上了：
> ```
> pc=0x0  op=0x78 = OP_ALU_RI
> pc=0x9  op=0x49 = OP_ALU_RR
> pc=0xF  op=0x78 = OP_ALU_RI
> pc=0x18 op=0x26 = OP_MOV_RI
> pc=0x23 op=0x49 = OP_ALU_RR
> pc=0x29 op=0x05 = OP_RET      ← 最后一条就是函数自己的返回
> ```
> 也就是说：**解释执行本身是正常走完的**（6 条都是普通 ALU/MOV/返回），
> 崩溃发生在**返回/恢复路径**上 —— 这与早先"崩溃前在解释器、随后出现在 stub 收尾序列"的现场完全吻合。
> 这也说明 arm64 的客户机 lifting 对这个函数是正确的（没有野指令、没有跳飞）。
>
> ### 315. 因此下一步的方向也随之明确
> 查"`vm_run` 返回后、stub 恢复现场时 SP/X 寄存器为何不可用"：
> - 之前加过 `mov x19, sp` / `mov sp, x19` 的诊断，崩溃点**跟着移到了这条还原指令之后**，说明调用期间 `x19`（以及更早一次现场里的 `SP`）被改；
> - 结合已确认的 `maxStubStackFrame=0`（aarch64 帧测量失效、margin 守卫形同虚设），
>   下一步应当把"aarch64 帧测量"补上（测量失败即报错），再据此定 margin。
>
> ## 第一一九/一二〇轮：假绿修掉、栈重叠被否、两个 amd64 回到全绿
>
> ### 316. aarch64 帧测量修好（并否掉一个假设）
> `measureMaxFrame` 已有 AArch64 模式，但它认的是 `sub sp, sp, #imm`；而 arm64 入口 stub 的帧 4688 超过
> `sub` 的 imm12 范围，实际写法是 `mov x9, #4688` + `sub sp, sp, x9` —— 于是恒量不到。
> 补上该组合模式、并在量不到时**大声告警**之后，CI 给出 `maxStubStackFrame = 4688`。
> 这条数字顺带**否决了"客户机栈与解释器帧重叠"**：解释器最大帧 ≤ 4688，而 margin 是 65536。
>
> ### 317. 我自己打红过、也当轮修回
> 上述改动留下一个重复的 `return`，`go vet` 报 unreachable code，把两个 amd64 作业的 Go gates 打红。
> 根因是我的推送前检查只跑了 build/test/gofmt，**漏了 `go vet`**；补上后两个作业恢复无失败步骤。
> 流程修正：推送前跑齐 `go build`、`go vet`、`go test`、`gofmt -l`。
>
> ### 318. 最终结论（提交 72fe836 的 CI 运行）
> - `windows-amd64`：无失败步骤；
> - `linux-amd64`：无失败步骤；
> - `linux-arm64`：blob 构建 ✓、打包 ✓、qemu 端到端**有真实结果**（native 与 protected 的数值对比），运行期尚未算对；
> - `windows-arm64-blob`：外部工具链缺口。
>
> ## 新一轮（用户要求继续）：arm64 的"返回值恒定"根因找到并修好
>
> ### 319. 先纠正一个我自己的假现场
> arm64 探针之前用 `blr` 调 thunk，而被保护函数最终是用**入口补丁存进 x16 的调用方返回地址**返回的 ——
> 于是控制流直接跳回探针调用方、跳过 call_thunk 自己的收尾。之前所有"探针 SIGSEGV / SP 与 x19 被破坏"
> 的推断都是这个假现场。改成与补丁同构（`mov x16, x30` + 尾跳 `br x9`，naked 函数）后，
> 探针第一次返回真实数值，且不再崩溃。
>
> ### 320. 真正的 bug：入口 stub 把返回值存在 x10，然后被还原循环冲掉
> stub 收尾原来是 `ldr x10, [ctx.R0]` → `.irp r,1..30: ldr x\r, [ctx.Rr]` → `mov x0, x10`。
> 而 x10 正是循环里 r=10 的目标 —— 一冲即废。所以：
> - 探针恒得 `0xFFFFFF80`（客户机 X10 的值）；
> - 目标侧恒得 0（那条路径上客户机 X10 = 0）。
> 而解释器**算得完全正确**：新加的 `vm_diag`（.bss，符号进 manifest）显示 `outX0=2012`，与 native 一致。
> 修法：NZCV 还原与帧回收（4688 = 0xFF0+0x260，两次 add 不借寄存器）全部提前，
> 还原 X1..X30 之后再**最后**取 x0。
>
> ### 321. 效果与剩余问题
> - 探针：`check_key(0/1/10/255) = 213/206/143/2012`，与 native 完全一致；
> - 端到端目标：`protected= 213|206|143|2012|86342|6999829|0|1|1`，前 7 项与 native 一致 —— **arm64 第一次算对了大部分**；
> - 剩余：`sum_to`（带循环）在 arm64 宿主上**永不返回**（新加的指令预算诊断以 rc=96 截住，
>   环形缓冲显示 pc 在 0x20/0x26/0x2F 三条之间死循环，累加值恒为 22222221111111）。
>   直路函数已经证明是对的，所以问题在"循环/分支"这一侧；下一步是用 `-dumpbytecode` 的 sum_to 明文
>   把这三条 op 的语义与操作数解出来（CI 注解只留前 12 条匹配，这块输出还需要安置好）。
>
> ## 收尾：arm64 端到端**全绿**（sum_to 循环的根因 = cmp 被静默丢掉）
>
> ### 322. 根因（两处叠加成静默算错）
> 1. `internal/lift/arm64`：寄存器（移位）形式的 ADD/SUB 里，31 是 **XZR** 而不是 SP，
>    但代码对 Rd/Rn=31 直接返回错误 —— 而 `cmp x1,x2` 恰恰是 `subs xzr,x1,x2`（Rd=31）。
>    现在：Rn=31 读零寄存器槽位 34；Rd=31 同样写槽位 34（写被丢弃），带 S 时**标志位照常更新**。
> 2. `cmd/vmpack` 的 arm64 适配器把 `fn.Unsupported` 直接吞掉（`return fn, nil`），
>    于是「lifter 不认识某条指令」被静默丢弃 —— x86 侧是会报错的，这里改为返回错误（fail-fast）。
>
> ### 323. 证据链（全部本机可复现）
> - CI 上 sum_to 的字节码反汇编里**没有任何比较**，循环体只有 add/add + 一个看 C 位的条件分支，
>   于是 C 永不清零 → 永不退出（探针 rc=96，环形缓冲 pc 在 0x20/0x26/0x2F 打转，累加值恒为 22222221111111）；
> - 新增回归测试 `internal/lift/arm64/loop_repro_test.go`：把 `cmp x1,x2 ; b.ls` 那段手写 aarch64 过 lifter，
>   断言 IR 出现「Sub 且 dst=ZR」的比较、字节码出现 `SUB64 R34,...`；**修复前该测试红，修复后绿**。
>
> ### 324. CI 结果（提交 ca96f96）
> | 作业 | 结论 |
> |---|---|
> | windows-amd64 | success |
> | linux-amd64 | success |
> | **linux-arm64** | **success** —— qemu 端到端输出与 native 完全一致（此前是 0|0|… 或 1|1） |
> | windows-arm64-blob | 已知外部缺口：镜像里没有 aarch64-w64-mingw32-gcc；作业显式打印 
> |   | 「no aarch64-w64-mingw32-gcc available: Windows/arm64 blob build is still unverified (known gap, not a regression)」 |
>
> 本机：go build / go vet / go test / gofmt 全绿、x86-64 E2E 146/146、arm64 客户机差分 OK。
>
> ## Windows/arm64 端到端打通（五作业全绿，含原生 arm64 Windows 真跑）
>
> ### 325. 三个提交解决的三件事
> 1. **合并器补齐 AArch64 COFF 重定位**：`BRANCH26`（加数要从 imm26 解码，之前把整条指令字
>    `0x94000000` 当加数 → 分支越界）、`PAGEBASE_REL21`(adrp)、`PAGEOFFSET_12A`(add lo12)、
>    `PAGEOFFSET_12L`(ldr/str lo12，按访问宽度缩放，不对齐就报错)。blob 从此能在 CI 真正产出。
> 2. **`vmpack` 放开 PE/arm64**：按 Machine=0xAA64 选 AArch64 lifter（与 packELF 同构），
>    不再只认 AMD64。入口补丁的 8 字节 `mov x16,x30 ; b thunk` 早已实现且有单测。
> 3. **`scan` 的 PE 函数边界**：原来一律用 x86-64 解码器裁剪并找 RET，arm64 机器码一条都解不出来，
>    报的是「无法用任何符号基准约定确定 check_key」。改为按 Machine 分派：arm64 走保守裁剪
>    （跳过零填充，要求最后一条是 ret/br x30），符号类型的两种 COFF 约定都接受。
>
> ### 326. CI 结果（提交 05c211f）
> | 作业 | 结果 |
> |---|---|
> | windows-amd64 | success |
> | linux-amd64 | success |
> | linux-arm64 | success |
> | windows-arm64-blob | **success**（clang 的 aarch64-w64-windows-gnu 目标 + 内置合并器产出 arm64 COFF blob；并完成 arm64 PE 目标的打包结构检查） |
> | windows-arm64-run | **success**（GitHub 的 windows-11-arm 原生 arm64 Windows：编 blob、编 PE 目标、打包，然后真跑比对） |
>
> 关键证据：原生与打包后跑出**同一个退出码** `native=654184885 protected=654184885`
> （entry 把 check_key(10)/check_key(255)/sum_to(7)/sum_to(1000) 混合成一个 30 位退出码，
> 任一项算错都会变）。
>
> ### 327. 过程中的两个自身教训（都留了防护）
> - 我给 PE 目标写 `sum_to` 时，clang -O1 把求和折成闭式 `n*(n+1)/2`（UMULH + EXTR，不在 lifter 子集内）：
>   先试倒计数写法仍被折，最后用 `optnone` 逼出真正的循环 —— 这也正好是我们想验证的带循环被保护函数。
> - pwsh 包装器结尾会 `exit $LASTEXITCODE`，被保护程序自己的退出码（非 0）把「比较已通过」的步骤判成失败：
>   步骤末尾显式清零。第一次看这个红叉时，注解里其实已经写着两个数相等。







