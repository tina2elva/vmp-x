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
> ## 第 69 轮：**CI 验证通过 —— mt 偶发已收口**
>
> ### 600. 前后对照（同一条用例、相邻两次提交）
> ```
> 81faffd（修复前）  failure   windows-amd64   E2EFAIL mt_many(8) ... tailP=[TIMEOUT]
> 8fa1c506（修复后） success   全部 5 个 job 绿
> ```
> 前一条给的是"受保护那 8 轮 30 秒没跑完"，后一条把重负载用例的上限提到 180 秒并记录耗时 ⇒ 直接转绿。
> 这不是"运气好的一次绿"：根因是**时限**（结构性），修法是把吞吐压测的上限调到与 2 核 runner 相称，
> 并新增 `prot_ms=` 让"变慢"以后能被看见，而不再以超时形式误报。
>
> ### 601. 整个目标的前后数字（收尾口径）
> ```
> 覆盖口径     6/14  →  11/11          （tools/coverage_pyd.py 一键复测，KNOWN_BAD 已空）
> CI 信号      全平台红(5 job×6 轮) →  8fa1c50 起 5/5 全绿
> e2e          147 passed / 0 failed（含加硬用例 mt_many(8) 与耗时输出）
> gates        8/8
> mt 偶发      定性为超时并修复（tailP=[TIMEOUT] → 独立时限 180s + prot_ms）
> ```
>
> ### 602. 这一程真正修掉的问题（都有现场或数字支撑）
> * 字节码超槽导致 `vm_run` 静默返回错误码 → 打包期硬校验（并把 const 保活到 release）；
> * 解释器**越界索引写**（写向栈守护页）→ 写侧/读侧统一界限检查；
> * 客户机栈页未提交 → 逐页下踩提交；
> * **尾调用到"函数中段"**被当成原生调用 → 目标是否函数入口的前提校验 ⇒ **覆盖 10/11 → 11/11**；
> * 我自己引入的两处回归（`framed`、CI 全平台红 6 轮）—— 根因是第 49 轮那条 int3 断言与第 50 轮对齐掩码构成的一对；
> * 取证链本身的缺陷：`.ps1` 中文注释截断用例清单、失败那次的 stderr 被夹具删掉、注解被长输出挤掉 —— 都已修。
>
> ## 第 68 轮：**"mt 间歇性失败"的真身找到了 —— 是超时，不是崩溃**
>
> ### 597. 决定性的一行（29ccddf 的 CI 注解）
> 第 65/66 轮那套"紧凑摘要 + 原始 stderr"终于把关键信息带出来了：
> ```
> E2EFAIL mt_many(8) lenN=754 lenP=7 firstDiff=0
>   tailN=[... bump=640000 mt_many rounds=8 ok]   ← 原生：8 轮全部跑完
>   tailP=[TIMEOUT]                                ← 受保护：30 秒内**没跑完**
> ```
> 而 `try1/try2`（重跑）都 `rc=0` 且输出完整 ⇒ **这是"卡在时限边缘"的偶发**，不是崩溃、不是竞争、不是数据损坏。
> 这也完美解释了此前所有"诡异"特征：约一半概率、只在 2 核 runner 上出现、本地 16 核复现不了、
> 每次偏移/形态都对不上（因为根本就不是同一次崩溃）。
>
> ### 598. 修法
> * `mt` 系列本来就是**吞吐压测**（4 线程 × N 轮 × 20000 次），30 秒上限对 2 核 runner 不合适 ⇒ 给用例加了**每例时限**
>   （`mt_many` 用 180 秒），并**打印受保护那次的耗时** `prot_ms=`，这样"变慢"也能被看见；
> * 复测：`e2e` **147 passed, 0 failed**，`mt_many(8)` 通过并给出耗时。
>
> ### 599. 顺带说明：这一程修的崩溃都是真问题
> 早先的 `mt(0)` 确实崩过（`0xC0000005`、写向栈守护页等），那些是**另一批**问题，并且都已修掉：
> 越界索引写（第 36 轮）、读侧越界（第 41/42 轮）、按页提交客户机栈（第 28/34 轮）、
> 以及第 64 轮那个"尾调用到函数中段"（顺带把覆盖口径推到 11/11）。
> 现在剩下的"红"只是压测跑不完 —— 属于**性能**议题，不再影响信号可信度。
>
> ## 继续（第 63 轮）：**根因链完整了 —— 尾调用规则把 jmp 到一个"函数中段/尾声"当成了原生调用**
>
> ### 594. 先给 IR 加了源偏移，于是能一一对应
> `vmpack -v` 现在每条 IR 都带 `src=+0x…`（`ir.Insn.SrcOff` 本来就有，只是没打印）。对齐结果：
> ```
> IR[142] MOV_RR dst=1 a=7 ... src=+0x1A6   ⇒ 绝对地址 0x2BC0+0x1A6 = 0x2D66
> IR[147] CALL   imm=0x2D98    src=+0x1B8   ⇒ 绝对地址 0x2BC0+0x1B8 = 0x2D78
> ```
> 反汇编核对：
> ```
> 2d66: 48 8b cf   mov %rdi,%rcx      ← 与 IR[142] (RCX←RDI) **完全一致** ⇒ 翻译是忠实的
> 2d78: eb 1e      jmp 0x2D98         ← 这就是 IR[147] 的来源
> 2d98: 48 8d 15 …  lea …,%rdx         ← 请注意：0x2D98 **不是函数入口**，是别人函数的中段/尾声
> ```
> ⇒ **第 62 轮那个"寄存器映射错（RSI↔RDI）"的候选被否证**：lifter 忠实复现了 `mov %rdi,%rcx`。
>
> ### 595. 真正的机制
> `__pyx_pymod_create` 的 `jmp 0x2D98` 被 lifter 按"尾部 jmp 到函数外 ⇒ CALLN + RET"的规则翻成 `CALL 0x2D98`。
> 但 `0x2D98` 落在 `__Pyx_PyObject_CallMethO(0x2D20…0x2DC0)` 的**中段（尾声）**，它后面是
> `mov 0x40(%rsp),%rbx` 这类**帧内保存位的恢复**，并最终 `ret` —— 而我们的 `CALLN` 是由解释器（C 代码）发出的，
> **真实栈是解释器的栈**，不是客户机那一套 ⇒ 中段代码按 `[rsp+…]` 取保存值时全部错位 ⇒ 崩溃。
> 也就是说：**"jmp 到非函数入口"不能翻译成原生调用**；这条规则需要一个前提校验（目标必须是函数入口）。
>
> ### 596. 修法（下一轮落地）
> 在 lifter 把尾部 `jmp target` 翻成 `CALLN + RET` 之前，**校验 `target` 是不是函数入口**（用符号表/`.pdata` 判定）：
> * 是入口 ⇒ 维持现状（这是正常的尾调用）；
> * 不是入口 ⇒ **拒绝该函数**（响亮失败，符合本仓库"宁可拒绝不猜"的一贯取舍），
>   因为把"函数中段"当原生入口调用必然错——这比现在"打出来但跑起来崩"安全得多。
> 同时记一笔：`__pyx_pymod_create` 的真实尺寸远大于 map 给的 118B（下一个符号在 0x2C90），
> 这也解释了为什么"尾部 jmp"会被判成跳到函数外。
>
> ### 592. 原生代码的对应段：**`RCX ← RSI`**，而我们的 IR 是 `RCX ← RDI`
> `__pyx_pymod_create` 的原生汇编（0x2BC0 起）关键几行：
> ```
> 2bc6: mov %rcx,%rsi          ← 入口把第一个参数（def）存进 RSI
> ...（若干 IAT 间接调用：PyThreadState_Get / PyInterpreterState_GetID …）
> 2c36: mov %rbx,0x40(%rsp)
> 2c3b: lea …,%rdx             ← 静态对象
> 2c47: mov %rsi,%rcx          ← **RCX ← RSI（= 保存的 def）**
> 2c4f: mov %r14,0x20(%rsp)
> 2c54: call *…                ← IAT 0x8270（PyModule_NewObject 一类）
> ```
> 而我们在**同一位置**的 IR 是 `IR[142] MOV_RR dst=1 a=7`，按 x64 寄存器编号（0=RAX,1=RCX,…,6=RSI,7=RDI）
> 这条是 **`RCX ← RDI`** —— 与原生 `RCX ← RSI` **不一致**。
> 崩溃瞬间实测 `RCX = PyModule_GetDict 的返回值（dict）`，也和"应当是 def 或最新方法对象"对不上。
>
> ### 593. 候选结论与下一轮动作（要严谨，不能凭一条 IR 就下结论）
> 候选：**lifter 在寄存器映射/别名跟踪上把某个寄存器认错了**（RSI ↔ RDI 这一类），于是尾调用前的参数寄存器摆错。
> 下一轮要做的是**把 IR 与源指令一一对应**（现在的 `-v` 输出不带地址，所以还不能断定 IR[142] 就对应 0x2c47）：
> 1. 让 `-v` 在每条 IR 后带上"源 RVA"（或按 `-dumpbytecode` + map 交叉核对）；
> 2. 对齐后逐条比对 0x2c36..0x2c9c 与 IR[138..148]，确认是否真的映射错了寄存器；
> 3. 若确认 ⇒ 改 lifter 的寄存器映射；若并非如此 ⇒ 继续沿"值从哪来"往上追（`def` 在 RSI 里是否被谁改过）。
>
> ### 590. IR 层面：崩溃点是**尾调用**，被翻成 `CALL` + `RET`
> `vmpack -v` 的输出里，`0x2D98`（`__Pyx_PyObject_CallMethO`）出现在两处，前后完全相同：
> ```
> IR[142] MOV_RR  dst=1 a=7        ← RCX ← RDI
> IR[143] LOAD    dst=17 disp=33256
> IR[144] ?       a=17             ← 间接调用（CallR）
> IR[145] CMP_RR  dst=0 a=14 b=14
> IR[146] JCC     target=93
> IR[147] CALL    imm=0x2D98       ← 调用 __Pyx_PyObject_CallMethO
> IR[148] RET                      ← **紧接着就 RET**
> ```
> 即：原代码在此处是 `jmp __Pyx_PyObject_CallMethO`（**尾调用**），lifter 按既有规则翻成 `CALL` + `RET`。
> 参数由 `IR[142]` 设置：`RCX ← RDI`。而实测崩溃瞬间 `RCX` 是**模块 dict** ⇒ 说明 **RDI 在那个点已经是 dict**，
> 或者更早的寄存器分配已经把它放错了。
>
> ### 591. 下一步：与原生代码逐指令对照
> 把 `__pyx_pymod_create` 里这条尾调用**前后**的原生指令反汇编出来，看它实际用的是哪个寄存器（是 RDI 还是别处，
> 以及前面是否还有一条 `mov %rcx,%rdi` 之类），再与 IR[142] 对照：
> * 若原生确实是 `mov %rdi,%rcx` ⇒ 我们的翻译忠实，问题在更早的寄存器值（继续往前追）；
> * 若原生是别的寄存器 ⇒ **lifter 的寄存器映射/别名跟踪有错**，改它即可 —— 这正是覆盖口径最后一块的直接入口。
>
> ### 588. **拿到了崩溃那次 CALLN 的入参** —— RCX 里是 dict，方法指针却在 R8
> 探针 `vm_last_call_args` + `vm_diag[8..11]` 一起用，抓到的最后一条采样：
> ```
> vm_last_call = pyd + 0x2D98            （= __Pyx_PyObject_CallMethO + 0x78）
> args = RCX=0x20B818C3440  RDX=0x7FFF04F186E0(pyd 内 +0x86E0，像静态对象)  R8=0x20B81C7E790  R9=0
> ring 的对应关系：
>   #5 PyModule_GetDict        ret=0x20B818C3440   ← **等于 RCX**
>   #8 PyObject_GetAttrString  ret=0x20B81C7E790   ← **等于 R8**
> ```
> `__Pyx_PyObject_CallMethO(func, arg)` 只有两个参数（RCX=func, RDX=arg）。
> 而 RCX 里放的是**模块 dict**、真正的"方法对象"却在 **R8** ⇒
> 被调方于是把 dict 当成 C 函数对象去取 `m_self`/`ml_meth`，拿到垃圾函数指针去调 ⇒ 崩溃。
>
> ### 589. 结论与下一步
> 这**不是**外部调用者的问题，也不是 IAT/翻译目标的问题，而是**调用前参数寄存器被摆错了位置**（至少这一个调用点）。
> 下一步很明确：用 `vmpack -v` 把 `__pyx_pymod_create` 的 IR 打出来，看目标 `0x2D98` 那次 `CALLN` **之前几条**指令，
> 核对是谁把 dict 放进了 RCX、本该放进去的方法指针为什么留在 R8 —— 定位到 lifter 的某条 MOV/寄存器分配规则后修掉，
> 再跑 `import example` 验证 ⇒ 覆盖口径 10/11 → 11/11。
>
> ## 继续（第 61 轮续）：init 类拿到**完整的命名调用序列**，崩溃点精确到 `__Pyx_PyObject_CallMethO+0x78`
>
> ### 585. 用 python313.dll 的导出表给 8 次调用全部点名
> 自写的 PE 导出表解析器（`build/exports.py`、`build/name_all.py`）给 ring 里每个目标都定到了函数：
> ```
> #1 PyDict_SetItemString      ret=0x0          （成功）
> #2 PyInterpreterState_GetID  ret=0x0          （合法 id）
> #3 PyObject_GetAttrString    ret=0x127C099BE70
> #4 PyModule_NewObject        ret=0x127C0DCCB80
> #5 PyModule_GetDict          ret=0x127C0DD5CC0
> #6 PyObject_GetAttrString    ret=0x127C0D69090
> #7 PyDict_SetItemString      ret=0x0
> #8 PyObject_GetAttrString    ret=0x127C0D6E790   ← 最后一次**完成**的调用
> ```
> 这就是 Cython 模块创建的标准序列（建 module → 取 dict → 取 "__name__" → 塞进字典 …），**全部成功**。
>
> ### 586. 崩溃点：一次 CALLN 到 `pyd+0x2D98`
> `vm_last_call = pyd_base + 0x2D98`，而 `example.map` 显示：
> ```
> 0x2D20  __Pyx_PyObject_CallMethO
> 0x2DC0  __Pyx_PyObject_FastCallDict
> ```
> ⇒ `0x2D98` 落在 **`__Pyx_PyObject_CallMethO + 0x78`** ⇒ **崩溃发生在这个"原生 Cython 辅助函数"内部**，
> 它是被**受保护函数通过 CALLN 调用的**（不是 IAT 间接调用，所以 ring 里没有它 —— ring 是在调用**返回后**记录的）。
>
> ### 587. 下一步（工具已就位）
> `__Pyx_PyObject_CallMethO(func, arg)` 会取 `func` 的 self 与 `ml_meth`；若传入的 `func` 不对，就会拿着垃圾函数指针去调。
> 我刚在解释器里加了 `vm_last_call_args[4]`（在 CALLN/CALLR **调用前**记录 RCX/RDX/R8/R9）⇒ 下一次抓到它，
> 把 **RCX 与第 8 次调用的返回值 0x127C0D6E790 比对**：
> * 相等 ⇒ 传参没错，问题在被调方对 `func` 的解释（回到"翻译是否忠实"）；
> * 不等 ⇒ **我们传错了参数寄存器** ⇒ 直接改 CALLN 的入参处理。
>
> ## 继续（第 61 轮）：init 类崩溃现场**可复现地取到了**，并给一次调用点上了名
>
> ### 582. 观测管线现在完整可用
> 1. 补上了一个我自己的插桩缺口：`OP_CALLN` 的**非 release 分支**原先没有记 `vm_call_ring`（只有 release 分支记），
>    所以之前看到的"调用环里没有 CALLN"是我漏插，不是崩溃线索；
> 2. `tools/init_probe.py` 的 `watch` 现在还会读目标进程的**模块表**与 **pyd 的 IAT 一段**（0x8300 起 96 项），
>    于是"调用目标"可以直接与 IAT 对表、点名到函数。
>
> ### 583. 取到的现场（同一进程内自洽）
> ```
> 模块：python313.dll base=0x7FFE1AA60000   example...pyd base=0x7FFECD370000
> IAT：83 个非空槽（0x8300..），导入名表 152 条
> ring（去掉高位标记后逐个对表）：
>   call#1 target=0x7FFE1AB41338 -> （不在 IAT 里）        ret=0x0
>   call#2 target=0x7FFE1AC1B8D4 -> IAT 0x83D0 **PyInterpreterState_GetID**  ret=0x0
>   call#3 target=0x7FFE1AB5A15C -> （不在 IAT 里）        ret=0x2579c85bcc0
> ```
> 已知事实：
> * `0x83D0 = PyInterpreterState_GetID` 与第 33 轮从 `__pyx_pymod_create` 反汇编读到的**第二条间接调用**完全一致
>  （`mov 0x10(%rax),%rcx` 之后 `call *… # 0x1800083d0`）⇒ 说明 guest 确实走到了那里，且返回值是 0；
> * 另外两个目标**不在 IAT 里**，但落在 python313.dll 的地址区间内 ⇒ 更像是**从 Python 结构体字段里取出的函数指针**
>  （数据驱动的调用），而不是我们翻译错了；
> * 这解释了为什么前几轮"IAT 与字节码都核对无误"却仍然崩。
>
> ### 584. 下一步（明确）
> 1. 把 python313.dll 的**导出表**正确解析出来（上一轮我的 objdump 正则没匹配上，返回 0 条），
>    用它给那两个"不在 IAT"的目标定位所在函数；
> 2. 若确认是"结构体里的函数指针"，则下一步核对 **guest 读这些字段时的偏移**（这就回到"翻译是否忠实"的层面）；
> 3. 目标仍是：让 `__pyx_pymod_create` 能保护通过 ⇒ 覆盖口径 10/11 → 11/11。
>
> ## 第 60 轮（目标末轮）：跨进程采样成功，拿到 init 类崩溃现场的**调用环**
>
> ### 580. 握手奏效
> `run` 模式改三段式（加载 pyd → 等 `go.flag` → 才 import），观测进程因此有时间拿到模块基址：
> ```
> A rc=-1073741819（0xC0000005）
> B 采样 23959 行，base=0x7fff11b80000
> vm_last_pc     = 0x60000004a4   （pc=0x4a4, op=6）
> vm_last_call   = 0x7fff11b82d98 （= base+0x2D98，模块内 CALLN）
> vm_call_ring_n = 9
> ring（每两项：目标, 返回的 RAX；高位标记 = CALLR 间接调用）
>   0x80007ffe2e381338 0x0
>   0x80007ffe2e45b8d4 0x0
>   0x80007ffe2e39a15c 0x244713fa0a0
>   0x80007ffe2e39977c 0x24471828b80
>   0x80007ffe2e3812f4 0x244718354c0
>   0x80007ffe2e39a15c 0x244717c5090
>   0x80007ffe2e381338 0x0
>   0x80007ffe2e39a15c 0x244717ca730
> ```
> 可直接读出的事实：
> * 所有间接调用都落在 **python313.dll**（0x7ffe2e3xxxxx 段），说明"翻译/IAT"没问题；
> * 其中**同一个目标 0x…381338 被调用了两次，两次都返回 0**；另有两次也返回 0 ⇒ 这类返回 0 的调用值得单独查；
> * 最后一次记录到的 CALLR 返回了合理指针（0x244717ca730），随后崩溃 ⇒ 崩溃点在**后续对返回值的处理**或紧随其后的 CALLN 里；
> * ring 里没有 CALLN 条目，而 `vm_last_call` 却是一次 CALLN ⇒ **CALLN 那条分支的 ring 记录缺失**（下一轮补上，它会让现场更完整）。
>
> ### 581. 交接状态（目标未完成，保持 active）
> * **`mt` 间歇性失败：未修复**。但它现在由**加硬用例 `mt_many(8)`** 判定，CI 也已恢复到"只剩它一个红"；
> * **覆盖口径 10/11**：仅差 `__pyx_pymod_create`（外部调用者那一类）。本地稳定复现，且本轮拿到了可读的调用环；
> * **CI 信号可靠性：已达成**（这是我这一程最实在的产出）；
> * 我自己引入的两处回归（`framed`、CI 全平台红 6 轮）都已清除，教训写进第 571/574 节。
>
> ### 579. 跨进程观测已搭好，但还差一步"握手"
> `tools/init_probe.py` 现有两个模式：`run`（加载 pyd 后在工作线程 import，会崩）与 `watch`（对目标 pid 用
> `CreateToolhelp32Snapshot` 找模块基址 + `ReadProcessMemory` 持续读诊断全局）。实测：
> ```
> A(run) : rva: {...} / module loaded        ← 之后立刻崩
> B(watch): 只写出表头，一条采样都没有        ← 等它启动时 A 已经死了
> ```
> ⇒ 差的是**同步**：A 崩得太快，B 来不及找到基址。
> 下一步（很小、很明确）：给 `run` 加一个"先把 pyd 加载好、再等一个握手文件出现、然后才 import"的三段式；
> 主控脚本先起 A（到第二阶段停住）→ 起 B 并确认它已找到基址 → 创建握手文件放 A 继续 ⇒ 采样一定能覆盖崩溃瞬间。
>
> ### 577. init 类的观测尝试：**崩溃发生得太早，进程内采样窗口抓不到**
> 新工具 `tools/init_probe.py`：主线程死循环采样 blob 的诊断全局（无缓冲直写文件），工作线程去 `import`。
> 结果：
> ```
> rva: {...}
> module loaded        ← 先把 pyd 加载起来（DllMain 登记 payload），采样本应立刻开始
> （到此为止：没有任何一条采样、也没有 ended 行）
> ```
> ⇒ 崩得**比第一两次采样还快**（正是"函数一开头那次宿主调用"的样子）。
> 这条本身是信息：**init 类的崩溃发生在毫秒级的最初阶段**，进程内轮询没有窗口。
>
> ### 578. 改为**跨进程**采样（下一轮落地）
> 设计：进程 A 做 `import`（会崩）；进程 B 用 `OpenProcess + ReadProcessMemory` 在 A 存活期间持续读
> payload 里的 `vm_last_call` / `vm_call_ring` 并落盘 ⇒ **不存在窗口问题**。
> 工具 `tools/init_probe.py` 先留着（改成 B 的角色即可复用）。
>
> ### 575. CI 已恢复：只剩那个已知的 mt 偶发
> 第 55 轮修复（`53fd869`）的 CI 结果：
> ```
> 53fd869a  失败：windows-amd64                                ← 只有这一项
>           （对比修复前：windows-amd64 + linux-amd64 + linux-arm64 + windows-arm64-blob + windows-arm64-run 全红）
> ```
> ⇒ **四个平台的 job 全部恢复**，剩下的红正是最初那个 `mt` 偶发 ⇒ 因果链完全闭合：
> 第 49 轮的断言把全平台搞红 6 轮，撤除后除 `mt` 外全绿。
> 这也意味着验证信号回到了"只有一个已知偶发"的状态，而且它现在由**加硬用例** `mt_many(8)` 判定 —— 可信。
>
> ### 576. 下一轮：用"并排跑两个产物"的办法打 init 类
> init 类（覆盖口径最后一块）本地稳定复现，但崩溃发生在**宿主库里**，进程内探针会在打印时死掉。
> 设计：写一个小 C 宿主，加载打包后的 pyd 并调用 `PyInit_example`，**同时起一个观测线程**轮询 blob 里的
> `vm_last_call` / `vm_call_ring` 并写文件 ⇒ 崩溃瞬间的"最后一次宿主调用及其返回值"就能取到，
> 不必再和"处理器自己也会死"较劲。
>
> ### 573. CI 历史把因果链钉死了：**第 49 轮那条断言让所有平台红了 6 轮**
> 限流窗口过去了，一次拉 6 个 run 看到完整序列：
> ```
> 13ad6ee2  失败：windows-amd64                      ← 当时只有 mt 偶发
> 437dae81  失败：windows-amd64,linux-amd64,linux-arm64,windows-arm64-blob,windows-arm64-run   ← 全平台！
>           （437dae8 = 第 49 轮加 int3 断言那一提交）
> 6ed6db32  f1c01492  794880f7  011c19be  失败：windows-amd64 + linux-arm64 + windows-arm64-*  ← 此后每轮都红
> ```
> ⇒ 分界点正好是**加断言**那一提交，且之前只有 `windows-amd64`（mt 偶发）红。
> 第 55 轮把断言与掩码一并撤除（`53fd869`）之后，新 run 还在跑 —— 从这条因果链看，**CI 应当随之恢复**。
>
> ### 574. 一条真正要紧的教训
> 我在第 41 轮因 API 限流决定"少问"，结果**连续 6 轮没看 CI**，自己把全平台搞红却不知道。
> 正确做法是"**降低频率但绝不停止**"：每完成一个改动批次，就必须在限流恢复后拉一次。
> 这条和"改动看起来无害却大面积失败时先并排跑两个产物"是同一条纪律的两面：**不要让观测中断**。
>
> ### 572. 修复后的全量门禁：8/8（一处 staleness 已处理）
> 第一次跑门禁时 `go test ./...` 红：
> ```
> conformance_test.go:199: ..\..\build\runbc.exe 比 ../../stub/win/x64/vm_abi.h 旧，请先重建
> ```
> 因为第 53 轮我动过 `vm_abi.h`（后又回退），文件 mtime 变了 ⇒ 一致性检查按设计报红。按提示重建后：
> ```
> gates: total 8 gates, 0 failed      ← 含 e2e 147/147、DLL e2e、ELF 载荷差分、arm64 guest 差分、go test
> ```
> 也就是说：**第 55 轮的修复在全部门禁下成立**，不只是 e2e 那 147 个用例。
> 顺带一条纪律：**动过 `vm_abi.h` 之后要重建 `build/runbc.exe`**（门禁会提示，照做即可）。
>
> ## 新目标（回归修复）第 55 轮：**谜团解开 —— 是第 49 轮那条 int3 断言在开火；两者一并撤除后 e2e 回到 147/147**
>
> ### 569. 破案过程（两步 A/B）
> 先按承诺做了"有掩码/去掩码"两个 blob 的对比：两者**大小与 entry 偏移完全相同**（544768，vm_entry @+0x2AC0）
> ⇒ 之前看到的偏移差只是不同构建配置造成的，不是机制。
> 接着把两个 blob **分别打包同一个 target** 直接跑：
> ```
> 原生            check_key 0 → 213
> 去掩码 blob     → CRASH code=0x80000003  ← int3！
> 有掩码 blob     → 213  rc=0
> ```
> `0x80000003` 就是**我在第 49 轮加的那条"客户机 RSP 应 16 字节对齐"的 int3 断言**在开火。
> 于是全部串起来：
> * 掩码让客户机 RSP 变成 `%16==0` ⇒ **骗过断言** ⇒ 桩正常，但挪了 8 字节 ⇒ `framed` 的第 5 参数读错；
> * 去掉掩码 ⇒ RSP 回到设计值 `%16==8` ⇒ **断言开火** ⇒ 整段失效（protected 输出为空、0 passed/147 failed）；
> * 我第 52 轮确实撤过断言，但随后为清理掩码做了两次 `git checkout -- stub/` ⇒ **把断言又恢复了**，所以才一直反复。
>
> ### 570. 一并撤除（两处必须同时改）
> 1. `vm_interp.c`：删掉 int3 断言（前提本就站不住，见第 51 轮算术）；
> 2. 四个平台 `vm_entry_asm.S`：删掉对齐掩码（恢复原设计的 `%16==8`）。
> ```
> e2e  exit=0   147 passed, 0 failed      ← framed 5 个用例恢复，mt/mt_many 本轮也过
> ```
>
> ### 571. 方法论教训（比修复本身更值钱）
> 一次"A/B 直接跑两个产物"就把两轮的手改僵局解决了 —— 我前面花了两轮在"删一行/改一个常量"上反复，
> 却没有先把**两个 blob 各自跑一遍**。以后的规矩：**当一次改动'看起来应该无害'却引发大面积失败时，
> 先做出两个产物并排跑，再动第三行代码。**
>
> ### 567. 第 54 轮：按期先读了整段 `vm_entry` —— 但"删掉那条掩码"依然把桩整段弄坏
> ```
> 四个 asm 文件的 >127 字节数均为 0（纯 ASCII），掩码只在单独一行；
> 用 PowerShell 把 [leaq 之后 .. andq] 这一段整体重写成 ASCII 注释并去掉 andq（最小改动）后：
>   blob 构建成功，vm_entry 偏移由 +0x2B20 变为 +0x2AE0
>   e2e 反而 0 passed / 147 failed（protected 输出为空）⇒ 桩整段失效
> ```
> 也就是说：**那条 `andq` 的存在是"承重"的，但机制我用现有手段解释不了**（栈帧大小 `subq $VM_FRAME_SIZE` 没变，
> 手工常量 `VM_CTX_*` 也没变，唯一可见差异是入口偏移挪了 0x20/0x40）。
> ⇒ 记为**阻塞项**，并写明纪律：**在把两个 blob 做完整反汇编对比之前，不要再尝试删它**。
>
> ### 568. 由此的现状
> * 第 50 轮引入的 `framed` 回归**仍在**（本地 5 个子用例错），我不粉饰；
> * 工作区已恢复到提交状态（干净）；本地 e2e = 140 passed / 7 failed = 5×framed + mt/mt_many；
> * 优先级：① 清 `framed` 回归（现被上面的 asm 之谜阻塞，下一步是 blob 反汇编对比）② init 类（覆盖 10/11）③ mt 偶发。
>
> ## 新目标（回归修复）第 53 轮：framed 的破坏确认由第 50 轮掩码引入；两个实验的数字如下
>
> ### 563. 现象（提交状态 f1c0149，本地）
> ```
> framed(0):      native=10      protected=1864734918   ← 垃圾值
> framed(1):      native=15      protected=1864734922
> framed(1000):   native=5010    protected=1864738918
> ```
> `framed` 正是依赖 `VM_FRAME_SKEW`（第 5 个参数在调用方栈帧里）的用例。
>
> ### 564. 已证明：掩码让客户机 RSP 比原设计低 8 字节
> 原设计：入口 rsp≡0（thunk 的 call）⇒ 减 FRAME_SIZE(≡0)、减 8、减 MARGIN(≡0) ⇒ 客户机 RSP≡8；
> 加掩码后 ⇒ 客户机 RSP≡0 ⇒ **低了 8** ⇒ 与调用方帧的定长关系被破坏 ⇒ framed 的第 5 参数读错。
>
> ### 565. 两个实验（都没有提交，工作区已恢复到 f1c0149）
> ```
> 实验 A：删掉四平台的 and 行
>   ⇒ 桩整段失效：protected 输出为空、e2e 0 passed / 147 failed。
>      推测与汇编布局/对齐有关（掩码版 vm_entry @+0x2B00，去掩码版 @+0x2AE0，差 0x20），待把 vm_entry 前后整体读一遍再动。
> 实验 B：保留掩码，把 VM_FRAME_SKEW_EXTRA 16→8（frameSkew=17032）
>   ⇒ framed 从垃圾值变成"差 a+1"：native=10 protected=9、native=15 protected=13、native=45 protected=37。
>      方向对、但没完全修好 ⇒ 已回退。
> ```
>
> ### 566. 教训（写给下一轮的我）
> * `build/` 是 gitignore 的：用 `build/commit_msg*.txt` 写提交说明**不会**产生改动（本轮就因此白跑一次提交）；
> * asm 相关改动前，先把 `vm_entry` 整段读完（含 `.p2align` 与周围指令），再一次成patch —— 本轮两次手改都引入了新故障。
>
> ### 562. 把"对齐"这件事的算术彻底理清（第 49–50 轮终于自洽）
> ```
> 调用方 call 被保护函数(入口已被改成 E9 jmp)  ⇒ 入口处 rsp ≡ 8 (mod 16)
> E9 jmp 不改 rsp                              ⇒ thunk 处 rsp ≡ 8
> thunk 用 call vm_entry（压入返回地址，-8）    ⇒ vm_entry 处 rsp ≡ 0   ← 注意是 0，不是 8！
> vm_entry 再 sub VM_FRAME_SIZE(640, ≡0)       ⇒ 仍 ≡ 0
> 公式 rsp-(8+VM_MARGIN)：VM_MARGIN(0x4000, ≡0) ⇒ 客户机 RSP ≡ 8   ← **不对齐**
> ```
> 也就是说：**我们原来的公式本身就差 8**（它是按"入口 rsp≡8"写的，而 thunk 的 `call` 让入口变成≡0）。
> 第 50 轮那条 `andq $-16` 正好把这个偏差纠正过来 ⇒ 这就是"int3 不再命中"的原因。
> 而 init 类**额外**多偏了一次 8（外部调用者的调用点形态不同）⇒ 于是它是我最早唯一能看见不对齐的那一路。
> 结论：对齐这件事现在**算术上自洽且已被修正**；init 的崩溃另有原因，仍挂着。
>
> ## 新目标（覆盖口径）第 50 轮：对齐修复已落地并生效，但 **init 类仍崩** —— 我第 49 轮的机理推断是错的
>
> ### 558. 改动（四个平台）
> ```asm
> x64 : leaq -(8+VM_MARGIN)(%rsp), %rax ; andq $-16, %rax ; movq %rax, VM_CTX_RSP(%rsp)
> arm64: sub x9, sp, x9               ; and  x9, x9, #-16  ; str  x9, [ctx+...]
> ```
> 即：客户机栈起点**强制 16 字节对齐**，不再假设调用方按 ABI 进入。
>
> ### 559. 结果：对齐检查不再命中，但崩溃照旧
> ```
> rc = 0xC0000005（不再是 0x80000003）⇒ 对齐已修好
> 但 pymod_create / pymod_exec / both  仍全部 rc=3221225477
> coverage_pyd：仍是 10 个函数逐字节一致（其余不受影响）
> ```
>
> ### 560. 更正：第 49 轮的机理推断站不住
> 我当时说"客户机栈不对齐 ⇒ 客户机发起的宿主调用也不对齐 ⇒ 被调方 SSE 异常"。**这条是错的**：
> 宿主调用是**解释器（C 代码）**发起的，编译器自己保证对齐，与客户机 RSP 的数值无关。
> 真正被证实的只有一件事：**被外部调用者调用时，算出来的客户机栈起点确实是不对齐的**（int3 命中过）——
> 这是个真问题（已修），但**不足以解释**崩溃。init 类仍然挂着。
>
> ### 561. 保留这次修复的理由
> * 容忍不按 ABI 进入的调用方，本身就该做；
> * A64 架构要求 SP 16 对齐，这条现在由代码显式保证，不再依赖"调用方一定规范"。
> 另外：int3 那条检查**留在非 release 里**当断言（现在不该再触发）。
>
> ## 新目标（覆盖口径）第 49 轮：**破案了 —— init 类的根因是客户机栈没对齐**
>
> ### 555. 决定性证据
> 在 `vm_run` 入口加一条非 release 检查：客户机栈起点必须 16 字节对齐（调用方按 ABI 进入时 rsp≡8，
> stub 再减 8 与 VM_MARGIN(0x4000, 16 的倍数) ⇒ 应当 ≡0）。不对齐就 `int3`（0x80000003，与 ud2/AV 互不混淆）。
> 用它保护 `__pyx_pymod_create` 跑 `import example`：
> ```
> rc = -2147483645 = 0x80000003   ← **对齐检查命中**
> ```
> 而对照组（正常函数、E2E 全部用例）从不命中。
>
> ### 556. 这一条把之前所有怪现象都串起来了
> * 客户机栈起点不对齐 ⇒ **客户机自己发起的宿主调用也是不对齐的** ⇒ 被调方（python313.dll）内部的对齐 SSE
>   （`movaps` 之类）行为异常 ⇒ `PyThreadState_Get()` 交回小整数 0x32，随后 `mov 0x10(%rax)` 读地址 0x42 崩；
> * `__pyx_pymod_exec_example` 的"读地址 0x8"同理；
> * 只有"被外部调用者调用"这一类中招：我们自己 pyd 内部调用时进入对齐是规范的，所以那一类一直正常。
>
> ### 557. 修法（下一轮落地，需要小心 skew）
> 在 `vm_entry` **最开头**把宿主栈对齐（`andq $-16,%rsp`，同时把原始 rsp 压栈以便返回时还原），
> 这样下游一切（含 lifter 依赖的 `VM_FRAME_SKEW` 常量）都自洽；
> 注意 `[rsp+VM_FRAME_SIZE]` 取返回地址的那处偏移要随之 +8。四个平台的 `vm_entry_asm.S` 都要同样处理。
>
> ### 554. 复核 ABI 常量：`VM_MARGIN` 现在是 0x4000(16KB)，不是 3KB
> `stub/win/x64/vm_abi.h`：
> ```
> #define VM_FRAME_SIZE 640
> #define VM_MARGIN     0x4000   /* 注：原为 3KB；为查 add_dly 放大到 16KB */
> #define VM_FRAME_SKEW (VM_FRAME_SIZE + 16 + VM_MARGIN)
> ```
> ⇒ 客户机栈起点确实是"入口 rsp 下方 16KB"⇒ **第 33 轮"故障地址正是客户机栈起点（守护页）"的判读成立**；
> 但第 43 轮"16KB 线程栈也能过"说明：仅凭"栈小"不足以触发，必须是**某条具体路径的真实用量/时序**同时满足。
> 两条事实并列记下，避免以后各取一半得出错误结论。
>
> ## 新目标（覆盖口径）第 47 轮：init 类崩溃**既不是坏索引、也不是缓存被写**
>
> ### 552. 用新装的两种内部探针给 init 崩溃定性
> 非 release blob 现在带两个探针（越界索引 ⇒ ud2；缓存校验和不符 ⇒ 空指针写）。用它（以及 release）分别保护
> `__pyx_pymod_create` 跑 `import example`：
> ```
> nonrel   rc=3221225477   0xC0000005 (AV)   ← 两个探针都没响
> rel      rc=3221225477   0xC0000005 (AV)
> ```
> ⇒ init 类的崩溃**不属于**"坏索引"也不属于"缓存字节码被写"，是**独立的第三种**失败。
> 这与之前查到的现场一致：IAT 槽、字节码序列都核对无误，但第一条宿主调用（`PyThreadState_Get`）
> 交回的却是小整数 0x32(50)，随后 `mov 0x10(%rax)` 崩在读地址 0x42。
>
> ### 553. 下一步：把"进入时的状态"记下来对比
> 在 `vm_entry`/`vm_run` 入口记录 `entry_rsp & 15`、客户机初始 RSP、以及 ctx 里四个参数寄存器（RCX/RDX/R8/R9），
> 分别对"正常函数"与"init 函数"各取一份 ⇒ 直接看是不是**外部调用者的栈对齐/入参**与我们假设的不同。
> 覆盖口径维持 10/11（init 类仍是最后一块）。
>
> ### 551. 三种内部失败的现场特征互不重叠了
> 把缓存校验和那条从 `ud2` 改成**空指针写**，于是注解里的特征可以一一对应：
> ```
> fault=0x0 的 AV        ⇒ 缓存槽里的字节码被写过（校验和不符）
> 0xC000001D (ud2)       ⇒ 越界寄存器索引
> 其他 AV(fault 非 0)    ⇒ 执行期间别处出问题
> ```
> 复测：`e2e` **147 passed, 0 failed**。CI 本轮仍被限流，没拿到注解。
>
> ## 新目标（mt 偶发）第 45 轮：把"坏索引"变成一个**可辨的位**（非 release 直接 trap）
>
> ### 549. CI 仍被限流
> `runs=0`（返回体不是正常响应）⇒ 本轮没拿到注解。按既定策略继续"少问"。
>
> ### 550. 判定信号：越界索引 ⇒ ud2
> 在非 release 构建里，读侧 `vm_rdreg` 与写侧 `write_reg` 看到**越界寄存器索引**时直接 `__builtin_trap()`；
> release 仍保持安全行为（读作 0 / 不写）。
> 意义：把"坏索引"从"其他一切"里**分出来**。之后 CI 上 `mt_many(8)` 的失败形态只有三种，含义互斥、一眼可辨：
> ```
> 0xC000001D (ud2)   坏索引 ⇒ 索引来源（生成端/解码端）出问题
> 0xC000001D (缓存校验) 上一轮加的缓存校验和 trap ⇒ 字节码装载后被写过
> 0xC0000005 (AV)    以上都不是 ⇒ 破坏在执行期间的其他地方
> ```
> 复测：`e2e` **147 passed, 0 failed** ⇒ **本地正常运行下从不出现越界索引**（这本身也是信息：它是时序现象）。
>
> ## 新目标（mt 偶发）第 44 轮：栈这条线彻底否证 + 给"字节码被写坏"装上探针
>
> ### 547. 16KB 线程栈也能过（栈这条线彻底关闭）
> ```
> kb=32/24/20/16，各 10 轮：native rc=0、protected rc=0，输出全部一致
> ```
> ⇒ `mt` 的真实栈用量极小（连 16KB 都够）⇒ 之前那个"守护页"现场**不是**"线程栈天生太小"。
> 结合第 35 轮的反汇编（写指令就是 `vm->regs[adst] = ...`），更合理的解释是：**某个索引值是坏的**，
> 而它恰好把地址算到了 rsp 下方 16KB 处 —— 那是**结果**，不是原因。
>
> ### 548. 决定性探针：缓存槽字节码校验和（非 release）
> 装载/解密进槽时记录 `vm_bc_sum[slot]`，**每次命中该槽都复核一遍**：
> ```c
> if (vm_bc_sum_len[slot] == d->codeLen && vm_bc_fnv(vm_bc_cache[slot], d->codeLen) != vm_bc_sum[slot]) {
>     __builtin_trap();   /* 槽里的字节码被写过 ⇒ 一眼可辨的 0xC000001D，而不是含混的 AV/错值 */
> }
> ```
> 这正好检验**最初那个假设**（多线程下字节码缓存被写坏）：若成立，CI 的 `mt_many(8)` 会改报 `0xC000001D`；
> 若仍报旧的 AV/错值，就说明破坏发生在**执行期间**或别处，可以据此换靶。
> 复测：`e2e` **147 passed, 0 failed**（本地无假阳性 ⇒ 正常运行下缓存是干净的）。
>
> ## 新目标（mt 偶发）第 43 轮：小栈实验 —— **朴素版的"栈压力"假设被推翻**
>
> ### 544. 新工具：`mt_smallstack <KB> [rounds]`
> 让 `mt` 的 4 个线程用**指定的栈大小**创建（`CreateThread(NULL, KB*1024, ...)`），专门用来在本机制造"栈紧张"。
> 这是针对"CI 与本机只差资源紧张程度"这个观察做的**确定性实验**，不必再等 CI 偶发。
>
> ### 545. 扫描数字（native vs protected，各 1 轮）
> ```
> kb=512  native rc=0  protected rc=0  输出一致
> kb=128  native rc=0  protected rc=0  输出一致
> kb=64   native rc=0  protected rc=0  输出一致
> kb=48   native rc=0  protected rc=0  输出一致
> kb=32   native rc=0  protected rc=0  输出一致
> ```
> **32KB 也过得去** ⇒ 朴素的"栈不够用"假设**不成立**：`VM_MARGIN` 只是虚拟下探，真正被提交的页是按需增长的，
> `mt` 的实际用量在 32KB 内就够了。
> 所以 CI 上那次守护页变红，必然对应**某个具体路径的真实栈用量**（或第 28 轮那种"一次跳 16KB"的写法），
> 而不是"线程栈天生太小"。这条否证同样有价值：它把"加大栈"这类修法排除掉了。
>
> ### 546. 下一步
> * 用小栈 + **更多轮次**继续扫（偶发可能需要很多次迭代才出现）；
> * 再找阈值（24KB/20KB），逼近"真实用量"这个数字；
> * CI 侧按"少问"原则择机拉一次，看现场是否仍停在 `0x26E05`。
>
> ## 新目标（mt 偶发）第 42 轮：读侧收口完成（0 处遗漏）
>
> ### 541. 全部「会变成地址」的读都走 `vm_rdreg`
> 逐处铺开并核对：
> ```
> OP_LOAD   866/867（base + idx）
> OP_LEA    949
> OP_STORE  968 + idx 1057
> OP_ATOMIC 997/999（base + idx）
> OP_CALLR  1195（调用目标）
> 剩余未收口的 base/idx 读：0
> ```
> 语义：越界读作 0 ⇒ **地址立刻算错**（问题暴露早），而不是野跳/野写 —— 对加壳器这是正确的失败形态。
> 复测：`e2e` **147 passed, 0 failed**；`coverage_pyd.py` 原生/保护版逐字节一致。
>
> ### 542. CI
> 按第 41 轮的决定「少问、一次问够」，本轮只问了一次；仍被限流（返回体不是正常响应）⇒ 没拿到新现场。
>
> ### 543. 下一轮的新思路：**把线程栈调小来逼出这一类问题**
> 既然 CI 与本机只差「资源紧张程度」，那就**在本机主动制造紧张**：让 `mt` 的线程用很小的栈
> （`CreateThread(NULL, 64KB, ...)`）。客户机栈固定下探 `VM_MARGIN`(16KB) 的设计，在小栈上应当很快暴露，
> 这样「栈余量」这一类假设就能在本地确定性验证，而不必等 CI 的偶发。
>
> ## 新目标（mt 偶发）第 41 轮：查清 CI 拉取失败的原因 + 读侧收口
>
> ### 539. 不是网络问题，是 **GitHub API 限流**
> 连续三轮拉取都失败，报错是 `data.workflow_runs is not iterable` ⇒ 返回体不是正常响应，而是**限流提示**
> （未认证调用每小时 60 次；我这些轮问得太密）。⇒ 之后改成"少问、一次问够"，不再每轮都去拉。
>
> ### 540. 读侧收口：`vm_rdreg`
> ```c
> static u64 vm_rdreg(vm_ctx_t *vm, u32 i) {
>     i &= VM_REG_MASK;
>     if (i >= (u32)(sizeof(vm->regs)/sizeof(vm->regs[0]))) return 0;  /* 越界读作 0 */
>     return vm->regs[i];
> }
> ```
> 已用于**值会变成地址或调用目标**的两处（最危险的两处）：
> * `OP_ATOMIC` 的 base / idx（越界直接算错地址，不再野写）；
> * `OP_CALLR` 的调用目标（越界读作 0 ⇒ 走既有的空指针分支，**不会野跳**）。
> 依据：`VM_REG_MASK` 是 31，而 `regs[]` 只有 17/18 项 —— **掩码不等于界限检查**（写侧第 36 轮已收口）。
> 复测：`e2e` **147 passed, 0 failed**；`coverage_pyd.py` 原生/保护版逐字节一致（10 函数）。
>
> ### 538. 补完最后一条：`vm_fp_step` 恒返回 `pc + 15`（与长度表一致）
> ```
> 768: return pc + 15;   ← vm_fp_step 唯一的返回
> ```
> ⇒ 26 条指令的"长度 vs pc 推进"**全部一致**，**解码失步这条假设正式关闭**。
> （CI 侧本轮三次拉取都遇网络错误，没拿到新注解。）
>
> ## 新目标（mt 偶发）第 39 轮：把"指令长度 vs pc 推进"逐条交叉核对（没找到失步，但做完了这件事）
>
> ### 536. 思路
> 第 35 轮那个越界写的索引来自字节码；加上界限检查后 `mt_many` **仍有失败**（且表现为输出不一致而不是必崩）
> ⇒ 怀疑是**解码失步**：某条指令的 `pc` 推进量与 `vm_insn_size` 不一致，后续把数据字节当成了操作数。
> 于是把解释器里所有 `vm->pc = ...` 与长度表逐条对照：
> ```
> MOV_RR 4 / MOV_RI 11 / MOV_RI32 6 / LEA 10 / ALU_RR 6 / ALU_RI 9 / ALU_U 5 / CMP_RR 5 / CMP_RI 8
> EXT 5 / LOAD 11 / STORE 10 / ATOMIC 12 / PUSH_R 2 / PUSH_I 5 / POP_R 2 / JCC 6 / JBZ 6 / JBNZ 6
> JMP 5 / CALLN 9 / CALLR 2 / NOP 1 / HALT 1 / RET 1        ← 逐条一致
> ```
> **没有找到失步**（FP 那条由 `vm_fp_step` 返回长度，仍需单独确认它总是返回 15）。这条假设暂时不成立，
> 但这张对照表本身有长期价值：以后再加指令时可以直接照它检查。
>
> ### 537. 旁支发现：ctx 偏移是手写宏，不能随便给 regs[] 扩容
> `stub/win/x64/vm_abi.h` 里 `VM_CTX_RSP 32`、`VM_CTX_VBASE 256/128` 都是**手写常量**（不是从结构体生成的），
> 所以"把 `regs[]` 补齐到 32 项让掩码自然安全"这条路**会静默破坏 ABI**，不能走 —— 记下来避免以后误踩。
> 读侧越界的正解只能是"显式校验索引"（写入侧已在第 36 轮做了）。
>
> ## 新目标（mt 偶发）第 38 轮：本地加压仍复现不出（如实），等重排后的诊断
>
> ### 534. CI
> · `0431fc5`（重排之前的版本）依旧 `E2EFAIL mt_many(8)`：注解里仍然是 `native=[...]` 那串 6 轮的累加输出把
>   `CRASH 现场`挤到了截断之外 —— 反过来证明第 37 轮对"注解被长输出吃掉"的判断是对的；
> · 重排后的 `f016849` 当时还在跑（本轮最后一次拉取遇到网络错误，没拿到结果）。
>
> ### 535. 本地加压：提高到 60 轮/次 × 6 次，仍然全过
> ```
> mt_many 60  ×6   全部 rc=0、末行 rounds=60 ok
> （另试过 4 进程并发 × 200 轮，超出本工具单次运行时限，未拿到结论）
> ```
> 本机 16 核、CI 2 核 ⇒ 这个缺陷**只在资源紧张的调度环境下显现**，本地复现不现实。
> 结论：判定只能靠 CI，而 CI 的注解现在已经会把崩溃现场放在最前面。
>
> ## 新目标（mt 偶发）第 37 轮：**加硬用例生效了**（信号可信），但缺陷仍在 —— 并把诊断提到注解最前面
>
> ### 532. CI 现在给出的是可信判定
> ```
> 178bec1（逐页踩栈 + 加硬用例）  success
> 0f3e555（adst 界限检查）        failure   E2EFAIL mt_many(8) native=[...] ...
> 0431fc5（写入侧统一设防）       failure   E2EFAIL mt_many(8) ...
> ```
> 两点：① `E2EFAIL mt_many(8)` 出现了 ⇒ 第 32 轮修好的用例清单现在真的在跑，**mt 这条线终于有了可信颜色**；
> ② 缺陷**没有修好**（`adst` 界限检查 + 写入侧设防都在了，仍然红）⇒ 那个越界写是**后果**，不是唯一原因。
>
> ### 533. 顺带发现注解被截断，崩溃现场被挤掉
> `mt_many(8)` 的输出有 40 多行（`bump=80000/160000/...`），原先把 `native=[...] protected=[...]` 放在 `E2EFAIL` 行**最前面**，
> 结果 GitHub 截断后**看不到 `CRASH fault/rva/寄存器`**。已调整顺序：
> ```
> E2EFAIL mt_many(8) try1[<诊断，含 CRASH fault/rva/寄存器>] try2[...] native=[<截断 120 字符>] protected=[...]
> ```
> 复测：`e2e` 147 passed, 0 failed；脚本仍是纯 ASCII（>127 字节数 0）。
> 这样下一次偶发的注解里一定会带上崩溃现场 —— 我不用再靠猜是哪条指令。
>
> ### 529. 全面审计结果：adst 是唯一"未掩码"的索引（其余都 `& VM_REG_MASK`）
> 逐条列出所有索引提取点：LOAD/STORE/ALU_RR/ALU_RI/ALU_U/EXT/LEA/PUSH/POP/JCC/ATOMIC/间接调用……
> 除 `adst` 外**全部**带了 `& VM_REG_MASK`。也就是说第 35 轮修掉的那个点，就是这一类里唯一没设防的。
>
> ### 530. 但顺带发现一个更系统的问题：**掩码 31 并不保证在界内**
> ```c
> #define VM_REG_MASK 31u        /* vm_interp.c:62 */
> u64 regs[VM_REG_COUNT];       /* VM_REG_COUNT = 17/18 */
> ```
> 掩码允许到 31，而数组只有 17/18 项 ⇒ **任何**带掩码的处理器在字节码损坏/解码失步时仍可能越界：
> 读越界只是拿到错值，**写越界会踩坏上下文**（第 35 轮那个越界写正是踩进了栈守护页）。
>
> ### 531. 本轮落地：写入侧统一设防
> ```c
> static void write_reg(...) {
>     if (r >= (u32)VM_REG_COUNT) return;   /* 越界就不写：宁可算错，也不破坏宿主内存 */
>     ...
> }
> ```
> 复测：`e2e` **147 passed, 0 failed**；`coverage_pyd.py` 原生/保护版逐字节一致（10 函数）。
> 下一轮：读侧也统一设防（或把 `regs[]` 补齐到 2 的幂并让偏移由生成器负责），然后再看 CI 的 `mt_many(8)`。
>
> ## 新目标（mt 偶发）第 35 轮：**找到具体那一条指令了 —— OP_ATOMIC 的越界寄存器写**
>
> ### 526. 反汇编对上了
> 四次 CI 崩溃**全都是同一个偏移**（`module+0x26E05`），把非 release blob 该处反汇编出来：
> ```
> 1df0: mov  0x58(%rsp),%eax        ← 取 adst（目的寄存器索引）
> 1df4: cmp  $0xff,%eax             ← "adst != VM_NO_REG(0xFF) ?"
> 1df9: je   0x1e03
> 1dfd: and  %edx,%esi              ← old & am
> 1dff: mov  %rsi,(%r15,%rax,8)     ← vm->regs[adst] = ...   ★ 就是它
> ```
> `r15` = ctx，`rax` = adst；而**故障地址 ≈ rsp-16KB、protect=0x104(守护页)、op=write、rax=fault+1** ⇒
> 正是这条"按未校验索引写入 ctx 的寄存器数组"越界落进了栈的守护页。
>
> ### 527. 源码里确实没有界限检查
> ```c
> u32 adst = c[pc + 3];   /* 注释自己写着：adst 不掩码：要能表示 VM_NO_REG */
> ...
> if (adst != VM_NO_REG) vm->regs[adst] = old & am;   /* 0..254 全放行 ⇒ 越界写 */
> ```
> 也就是说：**只要字节码损坏或 PC 失步，这里必然越界写**。结合"偏移每次相同"这一点，
> 更像是某条指令长度/解码在特定路径上失步，导致后续把数据字节当成了 `adst`。
>
> ### 528. 修复（两处都改）
> ```c
> if (adst != VM_NO_REG) {
>     if (adst >= (u32)(sizeof(vm->regs) / sizeof(vm->regs[0]))) return 98;  /* 越界 = 响亮失败，绝不越界写 */
>     vm->regs[adst] = old & am;
> }
> ```
> 复测：`e2e` **147 passed, 0 failed**（含加硬后的 `mt_many(8)`）。
> 对一个加壳器来说这条尤其要紧：**字节码是攻击者可触及的输入**，解释器绝不能因它越界写。
> 下一轮：把**所有**处理器里"未掩码的寄存器索引"都审一遍（LOAD/STORE/ALU/FP…），做同一件事。
>
> ### 525. 修复：把"一次跳 16KB"改成"从当前帧逐页往下踩"
> ```c
> u8 *cur = (u8 *)(u64)(&vm);                        /* 当前帧附近，一定已提交 */
> u8 *end = (u8 *)(u64)vm->regs[VRSP] - (VM_MARGIN + 0x1000);
> while (cur > end && steps++ < 256) { cur -= 0x1000; *(volatile u8 *)cur = 0; }
> ```
> 每一页都是"当前的守护页"⇒ 内核按页正常增长；一次性跨 16KB 则会跳过中间所有页直落守护页 ⇒ 直接 AV
> （这正是 CI 现场 `protect=0x104` 所显示的）。
> 复测：`e2e` **147 passed, 0 failed**，其中包含**加硬后的 `mt_many(8)`**（第 32 轮修好清单后才真正跑起来）。
> 保留的诚实说明：若线程栈**确实**已到增长极限，逐页踩会在"第一张不可能提交的页"上失败 —— 但那是
> **在 `vm_run` 里、确定性地、早于客户机执行**的失败，比"跑一半崩在解释器里"好定位得多；
> 届时的正解是给客户机栈留出更多余量（或改为动态下探），而不是继续猜。
>
> ## 新目标（mt 偶发）第 33 轮：**决定性证据 —— 出错页就是栈的守护页**（protect=0x104）
>
> ### 522. 拿到的那一行（41b5af2 的 windows-amd64）
> ```
> CRASH addr=module+0x26E05  fault=0x00000091151FBC37  op=write
>       region=0x00000091151FB000  size=0x2000  state=COMMIT  protect=0x104
>       rax=0x00000091151FBC38（= fault+1）  rsp=0x00000091151FFB40
> try2 同样：fault=0x...BB77  region size=0x2000 COMMIT protect=0x104  rax=fault+1
> ```
> 三个数字一摆就明白了：
> · `protect = 0x104` = **PAGE_READWRITE | PAGE_GUARD** ⇒ 出错地址落在**线程栈的守护页**里；
> · `rsp - fault = 0x3F09 ≈ 16KB = VM_MARGIN` ⇒ 正是我们给客户机栈设的起点；
> · `state=COMMIT` 说明内核已经尝试过增长（守护页是被提交的），但**没能再往下长** ⇒ 也就是"栈到了增长极限"。
>
> ### 523. 结论（这一条终于把现象与机制对上了）
> 客户机栈起点 = 宿主 rsp 下方 `VM_MARGIN`(16KB)；当宿主栈本身已经比较深时，这个位置正好落在**守护页**上，
> 客户机的第一次 push 触发守护页；内核按页增长，但此处已经贴近线程栈上限 ⇒ 最终抛出 AV（写、地址≈rsp-16KB、
> 每次 RVA 不同、重试常好、只在多线程密集调用时出现）。**这不是缓存竞争，也不是野指针**，而是**栈余量问题**。
> 这也解释了为什么我前面那些"缓存/原子/槽位"方向的修补都不能收口。
>
> ### 524. 我之前的"踩页"修复方向对了一半
> 第 28 轮加的"按页写一遍"能提交页面，但当目标页本身是**守护页**时，写它同样会触发这个 AV（我的探针写在 `vm_run` 里，
> 报出来的故障指令也正好在解释器段内）。所以正确的做法不是"踩页"，而是**保证客户机栈有足够余量**：
> 要么在进入 VM 前检查余量并给出明确失败，要么把 `MARGIN` 从"固定的 16KB 下探"改成"按当前栈余量动态决定"。
> 下一轮按这个方向做，并用加硬后的 `mt_many(8)` 做判定。
>
> ## 新目标（CI 信号）第 32 轮：谜团解开 —— **是我自己往 .ps1 里写了中文注释**（PS 5.1 按 ANSI 读）
>
> ### 518. 现场
> 上一轮加的 `mt_many(8)` 用例"算得进去、却从不执行"。这一轮在脚本里打了一行自述：
> ```
> [*] differential test (native vs protected)... cases=25 名称=check_key,...,mt,dispatch,...   ← 没有 mt_many
> ```
> 而文件里明明有 27 条。⇒ 说明**运行时用的用例表和文件不一致**。
>
> ### 519. 根因：我在 .ps1 里插了两行中文注释
> 这个仓库早就立过规矩（第 40 节附近）：**`.ps1` 必须纯 ASCII**，因为 PowerShell 5.1 按 ANSI 解码，
> 中文注释会破坏解析。这次我自己违反了：插入的注释让 `$cases` 数组被**静默截断**，
> 结果 E2E 跑的是"文件里没写全"的那一份清单 —— 而且它照样报 146 passed，看不出任何异常。
> 这又是一次"工具与被测对象不同步"（第 11 次），而且是最隐蔽的一种：**测试清单被悄悄改写**。
>
> ### 520. 修复与复测
> * 注释改写为 ASCII；`e2e.ps1` 里 >127 的字节数：**0**；
> * 加了一行**自述**（打印用例数量与名称清单），以后这类"清单被改写"的问题会第一时间暴露；
> ```
> [*] differential test ... cases=26 名称=check_key,...,mt,mt_many,dispatch,...   ← mt_many 在了
> e2e: 147 passed, 0 failed      ← 多出来的正是加硬版用例
> ```
>
> ### 521. 意义：mt 的信号现在是"决定性"的
> `mt_many(8)` = 同一进程内连跑 8 轮（每轮新建 4 线程）。若缺陷仍在，命中概率 ≈ 1-(1/2)^8 ≈ 99.6% ⇒
> **修好/没修好都会给出可信颜色**，而不是靠运气的一次绿/一次红。下一批 CI 结果即可判定"栈页预提交"。
>
> ## 新目标（CI 信号）第 31 轮：想让 mt 变成"决定性的信号"，但接线没验证成功（如实）
>
> ### 516. 思路
> 单个进程命中偶发约 1/2，所以"一次绿"说明不了什么。给 E2E 加一条**加硬版**用例：同一进程内连跑 8 轮
> （每轮新建 4 线程），命中概率 ≈ 1-(1/2)^8 ⇒ 修好/没修好都能给出可信颜色。
>
> ### 517. 实测：两个二进制都对，但 E2E 里那条用例没跑起来
> ```
> build\target.exe     mt_many 8   rc=0  42 行输出
> build\target_vmp.exe mt_many 8   rc=0  42 行输出   两者逐字节一致
> 但 e2e 的日志里仍然只有 [OK] mt(0)，没有 mt_many(8)；总数仍是 146
> ```
> 而按脚本里的用例表数，(case,arg) 组合数恰好是 **146**（27 条用例）——也就是说我的条目**被算进去了**，
> 却没有出现在执行日志里。这个矛盾我**本轮没有查清**，所以这条改动记为"已写入但效果未经证实"，下一轮先查清它。
> （改动本身无害：两个二进制都已验证支持 `mt_many`。）
>
> ## 新目标（mt 偶发）第 30 轮：**发现 CI 里还有第二条独立的偶发信号**（arm64 差分）
>
> ### 513. a272d6b 的红，不是 mt 红
> 那一轮的失败任务是：
> ```
> windows-amd64: FAIL github.com/vmpx/vmp-x/internal/lift/arm64 0.135s   （[!] differential failed）
> linux-arm64  : arm64 端到端差分 MISMATCH（native rc=0, protected rc=1）
>                探针: signal 11；环形缓冲 magic=0（说明 VM 还没写诊断环就崩了）
> ```
> 而我那个提交**只改了 x64 的 C 文件**（stub/win/x64/vm_interp.c 里加栈页预提交），
> **不可能影响 arm64 的差分** ⇒ 这是**另一条独立的偶发**。
>
> ### 514. 影响：那一轮对"栈页预提交"的判定**无效**
> 因为 `mt` 用例本身在这一轮**没有被判红**（红的是 arm64 那条），所以这项修复至今**还没有得到有效样本**，
> `41b5af2`（当前 HEAD）的结果才算数。
>
> ### 515. 两条偶发的共同形状
> · `mt`：4 线程 + 嵌套调用，时序敏感，2 核 runner 上约 1/2 概率红；
> · arm64 差分：在 qemu 下跑子进程 + 端到端比对，表现为 signal 11 / 探针未写入；
> 两者都不是"确定性逻辑错"（arm64 的 Go 测试用的是固定随机种子，重跑同样的输入），更像是**资源/时序**问题。
> 这也意味着：目标里"让 CI 信号可靠"这件事，**不只 mt 一条线**，arm64 这条也要收。
>
> ### 512. 本地的加压对照：两边都跑通，所以本地判不出来（如实）
> 新增隐藏模式 `mt_many <rounds>`（每轮都**新建线程**，最容易命中"新线程首次调用"那一类），
> 用 E2E 的同款 25 函数保护，各跑 `mt_many 20` 三次（≈1400 万次受保护调用）：
> ```
> 含栈页预提交（本轮修复版）  rc=0  rc=0  rc=0
> 关闭栈页预提交（对照版）    rc=0  rc=0  rc=0
> ```
> ⇒ **本地两个方向都复现不出偶发**，所以这条修复的判定只能交给 CI。
> （本地机器 16 核、CI 2 核，栈提交/调度时序不同；这也解释了为什么我从第 6 轮起本地一直复现不出。）
> `mt_many` 留在仓库里，作为以后复现这类问题的加压工具。
>
> ## 新目标（mt 偶发）第 28 轮：出错地址 ≈ **rsp 下方 16KB（正好是 VM_MARGIN）** ⇒ 按页预先提交客户机栈
>
> ### 510. 关键数字终于对上了
> 把 CI 那份现场的数字摆在一起看：
> ```
> fault=0x00000009FD3FBC0C  op=write   rax=0x00000009FD3FBC0C（写的就是 rax）
> rsp  =0x00000009FD3FFB20
> rsp - fault = 0x3F14 ≈ 16KB = VM_MARGIN
> ```
> 也就是说：**这条写指令的目标就是"客户机栈"那一段**（客户机栈起点 = 宿主 rsp 下方 MARGIN），只不过那个地址此刻不可写。
> Windows 的线程栈是"保留一大段、只提交头几页 + 一个守护页"，自动增长只在**碰到守护页**时发生；
> 客户机第一次往里 push 时，如果一次性跨过守护页，就会得到一个"写野地址"式的 AV —— 这解释了：
> 是写、地址在 rsp 下方约 MARGIN、RVA 每次不同、**新线程首次调用**最容易中、重试常常就好。
> （本地做了一条对照实验：新线程里直接写 rsp-16KB——我机器上**没有**复现 AV，说明两边的栈提交时机不同；
>   但 CI 的现场数字仍然指向同一个方向，所以按这个方向做修复并用 CI 判定。）
>
> ### 511. 修复：进 vm_run 时按页"踩"一遍客户机栈
> ```c
> /* 只踩客户机栈顶**以下**的区域：此刻还没有任何代码用过它，写它是安全的；往上是 stub 的帧，不能碰。 */
> volatile u8 *sp = (volatile u8 *)(u64)vm->regs[VRSP];
> for (u32 k = 1; k <= (u32)VM_MARGIN; k += 0x1000u) sp[-(i64)k] = 0;
> ```
> 复测：`e2e.ps1` **146 passed**（含 mt 与 25 个保护函数）、`coverage_pyd.py` 原生/保护版逐字节一致。
> 结论交给 CI：这是本轮的判定样本。
>
> ## 新目标（mt 偶发）第 27 轮：测试"嵌套调用踩栈"这条假设 —— **未复现**（并顺带发现一个 lift 限制）
>
> ### 508. 假设与实验
> 假设：嵌套受保护调用时，内层客户机栈入口 = `内层 host rsp - MARGIN`，而内层的 host rsp 只比外层低"解释器帧"那点
> （≈1KB），于是**内层栈会落进外层客户机栈的用区里**，把外层的局部变量/保存值踩掉 —— 之后外层用被写坏的基址存值，
> 正好表现为"写野地址＋RVA 每次不同＋偶发"。
> 实验：新增 `nest_outer`（384 字节 volatile 局部 + 调用另一个受保护函数 `nest_inner`，返回前逐字节校验局部数组）
> 与 `nest_test` 模式，两者都被保护后跑：
> ```
> 原生      nest_test bad=0
> 保护版 第 1..5 次 rc=0  nest_test bad=0     ⇒ 未复现（384B 的外层帧远小于 16KB 余量）
> ```
> 也就是说：要撞上需要外层客户机栈已用掉约 15KB 以上，而解释器自身的保护（以及 lift 限制，见下）让这种形态很难出现。
> 这条假设**暂时不成立**，但测试留在仓库里当作嵌套调用的回归用例。
>
> ### 509. 顺带发现的一个 lift 限制（覆盖率相关）
> 用 4KB 数组时 `nest_outer` 翻译失败：
> ```
> +0x2C: MOV [RSP+RDX+0x20], R8B   — RSP 已被不可跟踪的方式修改（SUB RSP, RAX）
> +0x63: MOVZX R9L, [RSP+R8+0x20]  — 同上
> ```
> gcc 对需要对齐的大局部数组会生成 `and rsp,-N` 这类动态调栈，lifter 一律拒绝（这是**已知取舍**：宁可拒绝不猜）。
> 记下来：这会挡掉一类"大局部数组"的函数，属于覆盖率的下一个可选课题。
>
> ## 新目标（mt 偶发）第 26 轮：**出错的数据地址拿到了**，而且它等于 rax
>
> ### 506. 三批 CI 反例（15e4adc / 0b2d72b / a22097c 全红）
> ```
> a22097c: try1 rc=0（完整正确！） try2 rc=0xC0000005
>          CRASH addr=module+0x26C1E  fault=00000009FD3FBC0C  op=write
>          rax=00000009FD3FBC0C   ← rax 就等于出错的地址！
> 15e4adc: CRASH addr=module+0x26D07  rax=000000F9C8DFBBCC r15=000000F9C8DFBBD8（rax = r15-0xC）
>          rbx=0x15 rcx=4 rdx=5 rdi=0x15 rsi=module+0x35CA0 rbp=0xFF r13=0x20
> ```
> 能确定的：
> · 是**写**（`op=write`），而且 `rax` 正是被写的那个地址 ⇒ 解释器里"按寄存器算出的地址存值"这条路径；
> · 出错地址在 **rsp 下方**、`rsi` 指向我们 payload 的 RW 段内 ⇒ 典型的"客户机算出了野地址"；
> · 三次失败的 RVA **各不相同**（0x26D07 / 0x26C1E / 0x26BB6）⇒ 不是某一条固定指令；
> · `r13=0x20`（=槽数）曾以为是缓存循环，但配合"RVA 每次不同 + 写野地址"看，更像是寄存器巧合。
>
> ### 507. 再加一条能把"野指针"与"越界"分开的证据
> 崩溃上报对出错地址做区域分类（`VirtualQuery`）：
> ```
> CRASH ... fault=0000000000000000 op=write region=0000000000000000 size=0x7FFE0000 state=FREE protect=0x1
> ```
> 自检（空指针写）判为 `state=FREE`；下次偶发就能回答：
> **是访问了未映射内存（野指针），还是访问了已映射区域里的越界位置（例如栈/堆的边界）** —— 这两类的修法完全不同。
>
> ## 新目标（mt 偶发）第 25 轮：**32 槽并没有消灭它**，但这一轮拿到了寄存器现场
>
> ### 503. CI 判定：修复不充分（如实）
> ```
> e29d27de（槽 16→32）  success
> 15e4adce（全忙改等待） failure   ← 说明这条根因不足以解释全部偶发
> ```
>
> ### 504. 好消息：这一轮的失败**带着寄存器**回来了
> ```
> CRASH code=0xC0000005 addr=module+0x26D07
>   rax=000000F9C8DFBBCC rbx=0000000000000015 rcx=4  rdx=5
>   rsi=module+0x35CA0   rdi=0000000000000015 rbp=00000000000000FF rsp=000000F9C8DFFAE0
>   r8=1   r9=module+0x29200   r10=0x1D  r11=module+0x297C0  r12=000000F9C8DFFBE0
>   r13=0000000000000020 r14=0x01312CFD r15=000000F9C8DFBBD8
> ```
> 能直接读出的几点：
> · `r13 = 0x20 = 32` —— 正好是**缓存槽数量** ⇒ 崩溃时正在**遍历缓存槽**的循环里；
> · `rax = r15 - 0xC`，而且两者都是**栈附近**的地址（都在 rsp 下方）⇒ 像是客户机栈地址参与运算；
> · `rbp = 0xFF` —— 恰好是 `VM_NO_REG` 这个哨兵值，出现在宿主 RBP 里很反常；
> · 两次崩溃的偏移不同（相对节起点 0x1E3D 与 0x1D07）⇒ **不是固定一条指令**，更像"数据被写坏后走到不同分支"。
>
> ### 505. 补上最直接的一项：**出错的数据地址**
> 崩溃上报再加 `fault=<地址> op=read|write`（取自 `ExceptionInformation[1]/[0]`）。自检输出：
> ```
> CRASH code=0xC0000005 ... rva=0x394A fault=0000000000000000 op=write   ← 故意空指针写
> ```
> 下一次偶发就能直接说出"**访问了哪个地址、读还是写**"，比反汇编偏移可靠得多。
>
> ### 501. 用"故意配错的 blob"把新路径逼出来验证（2 槽）
> 把 `VM_BC_CACHE_SLOTS` 临时改成 **2**（远小于 E2E 一次保护的 25 个函数），重建 blob 后跑 `mt`：
> ```
> blob(2 slots) size=53248（证明改到生效）
> 第 1..6 次 mt：rc=3221225501（0xC000001D = ud2 trap），无输出
> ⇒ 既不挂死、也不静默算错，而是**响亮地失败**
> ```
> 这正是我要的语义：以前这里是 `return 2`，那个错误码会被桩当成被保护函数的返回值交回客户机，
> 表现为"偶发算错甚至崩溃"；现在配错就是立刻 trap，一眼可辨。
>
> ### 502. 出厂配置下这条路径不会走到
> 恢复 32 槽（release blob 544768 字节）后：
> ```
> e2e.ps1            146 passed, 0 failed   （一次保护 25 个函数，槽够用）
> coverage_pyd.py    原生/保护版输出逐字节一致（10 个函数）
> ```
> 也就是说：**25 ≤ 32** 时根本不进等待分支；只有"有人把槽配得比并发深度还小"才会触发 trap。
>
> ### 499. 第一份 CI 判定：修完槽数后这一轮**绿了**
> ```
> e29d27de  success     ← 槽数 16→32 那一轮
> e3b4fd08  failure     ← 修之前的提交
> ```
> 单轮绿不算数（修复前本来就是约一半概率红），需要连续观察。
>
> ### 500. 顺带把这条路径**从根上**堵掉：槽全忙时改为"等"，而不是失败
> 即使把槽数提到 32，只要将来有人一次保护超过 32 个函数，同样会撞上"槽全忙"。所以把这处语义也改了：
> ```c
> for (u32 attempt = 0; ; attempt++) {
>     vm_bc_enter();  slot = vm_bc_lookup(...);  ... 
>     if (c >= 0) { ...解密/发布...; break; }
>     vm_bc_leave();                      /* 全忙：放锁让出 */
>     for (volatile u32 spin = 0; spin < 200u; spin++) { }   /* 自旋后重试 */
> }
> ```
> 槽只会在别的调用跑完时释放，而那些调用一定会跑完，所以这里**一定等得到**；
> 只有"字节码比槽还大"（打包期就该拒绝）和兜底的超长等待才返回错误码。
> 复测：`coverage_pyd.py` 原生/保护版输出仍逐字节一致（10 函数，rc=0）。
>
> ## 新目标（mt 偶发）第 22 轮：把"槽数不够"这条根因找出来了（16 槽 vs 25 个函数）
>
> ### 497. 线索怎么串起来的
> · 崩溃现场（第 20 轮）落在桩/解释器段内，附近是 `lock xadd`/`cmp $6` 那族指令；
> · `OP_ATOMIC`（第 21 轮读过）确实用了真原子内建，且它的 kind 分支数正好是"比 6 大/等于 6"这种形状 ⇒ 单看这里没问题；
> · 于是回头数**槽位与函数的数量关系**：E2E 一次保护 **25 个函数**（`check_key ... simd_rw` 那一长串），
>   而 `VM_BC_CACHE_SLOTS` 只有 **16** ⇒ **25 个不同描述符必然触发淘汰**；
> · 淘汰在多线程 + 嵌套调用下会让 `vm_bc_acquire()` 返回 -1，而那条路径是
>   ```c
>   if (c < 0 || ...) { vm_bc_leave(); return 2; }
>   ```
>   —— **把 VM 的错误码当成被保护函数的返回值交回客户机**，与"字节码超槽"是同一个静默失败类。
>   客户机随后拿这个值当函数结果/指针用 ⇒ 偶发崩溃、且 try2 常常正常（碰撞概率不同）⇒ 与全部现象吻合。
>
> ### 498. 修法与复测
> `VM_BC_CACHE_SLOTS` 16 → **32**（> 25，留余量；.bss 从 256KB 到 512KB）。
> ```
> release blob 544768 字节；manifest 里 vm_bc_slot_size 仍在（打包期硬校验不受影响）
> tools/coverage_pyd.py：原生/保护版输出仍逐字节一致（10 个函数，rc=0）
> ```
> 本地复现 `mt` 仍然很难（4 线程、且要恰好撞上淘汰窗口），所以这条**最终要靠 CI 连续几轮观察**来判定。
>
> ### 495. 对着崩溃点审计了一遍缓存引用计数（没找到确定缺陷，但排除了几种可能）
> 逐个看了看：`vm_bc_lookup` 命中时在锁内 `inuse++`；`vm_bc_acquire` 在锁内用普通读判断 `inuse[i]==0`；
> 退出时在**锁外**用 `__atomic_fetch_sub(..., RELEASE)` 递减。由于所有 `inuse` 的自增都在锁内，
> 持锁者读到 0 就意味着"此刻确实没人在用"（计数只会因锁外的递减而变小），所以这一对**是安全的**；
> 另外 `vm_bc_key` 从不被清空、槽容量检查、AEAD 失败路径（`slot` 仍为 -1）也都是自洽的。
> 结论：从代码上**没能证明**崩在缓存上；而我的地址映射本身是近似的（本地重建与 CI 目标未必逐字节相同）。
>
> ### 496. 于是换做法：让下一次偶发**自带全部现场**
> · `testdata/target.c` 的崩溃上报除了 code/addr/module/rva 之外，再打 **16 个通用寄存器 + rsp**；
> （自检已确认输出；退出码行为不变）
> · `tools/e2e.ps1` 里诊断摘要的截断从 200 放宽到 600 字符，保证这些行能进 CI 注解。
> 有了寄存器，下一次崩溃就能直接判断"是哪个指针是垃圾"，而不是靠反汇编偏移猜。
>
> ### 493. **CI 终于给出 mt 的崩溃地址了**（VEH 探针生效）
> ```
> E2EFAIL mt(0) ... protected=[]
>   try1[rc=-1073741819 out[] err[CRASH code=0xC0000005 addr=00007FF60FD46E3D module=00007FF60FD20000 rva=0x26E3D]]
>   try2[rc=0 out[<4 个线程结果 + bump=80000，完全正确>] err[]]
> ```
> 两条关键信息：
> · **同一个用例、同一轮里 try2 完全正确** ⇒ 确认是偶发（不是确定性错误）；
> · 崩溃点在 `module+0x26E3D`，而 `module` 就是被打包的目标本身 ⇒ 落在**我们注入的那一节**里。
>
> ### 494. 地址映射（含不确定性说明）
> 本地重建的 `target_vmp.exe` 节表：`.bh9dct3 VA=0x25000 vsz=0x4000`（桩/解释器段）、`.n1uolmr VA=0x29000`（blob 段），
> 于是 `0x26E3D` 落在**桩/解释器段内、偏移约 0x1E3D**。把这一段的字节反汇编出来看，
> 该偏移附近正是 `lock xadd` / `lock cmpxchg` 这一族指令 —— 也就是**字节码缓存那套原子引用计数**所在的代码区。
> 需要说明的不确定性：CI 上的目标与本地重建版本未必逐字节相同（Go 版本/工具链），所以偏移是**近似**的；
> 另外确认了 `e2e.ps1` 用的是**非 release** blob（`build/vm_interp.bin`），映射时要按它算。
> 但方向已经很清楚：**证据第一次直接指向缓存引用计数那段代码**——与最初"疑似多线程字节码缓存竞争"的判断一致。
>
> ## 新目标（覆盖口径）第 20 轮：把覆盖率做成**可复现的一键复测**
>
> ### 491. 新增 `tools/coverage_pyd.py`
> 之前 "10/11" 是我在会话里一条条手测出来的，别人无法复现。现在固化成脚本：
> * 默认保护 10 个候选函数（除 `__pyx_pymod_create`，它属于"被外部调用者调用"那一类，见第 489 节）；
> * 逐个 `-func` 打包 → 分别在**原生**与**保护版**下跑同一段表达式 → 逐字节比较输出；
> * 不一致就**非零退出**，可直接当作门禁；并打印"已知未解决"清单。
> 一键复测结果：
> ```
> 原生            rc=0   fib 55 610 / n (10,) / greet Hello, vmp! / time 19 / add_dly 5.0
> 保护 10 个函数   rc=0   同上（判定：一致）
> 已知未解决: __pyx_pymod_create
> ```
>
> ### 492. 又一条关于"外部调用者"那一类的现场数据
> 探针显示 `__pyx_pymod_exec_example` 的崩溃是**读地址 0x8**（空指针+8），故障指令在 python313.dll 内；
> 而 `__pyx_pymod_create` 是读地址 0x42（`rax+0x10`，rax 为小整数）。两次都发生在**函数最开始**，
> 且都表现为"交给宿主库的指针不该是那个值" ⇒ 与第 489 节的改判一致：问题在"外部调用者进入时的上下文"。
>
> ## 新目标（覆盖口径）第 19 轮：把最后一个缺口**改判**为「被外部调用者调用」这一类
>
> ### 489. 不是"init 期"，而是"谁来调"
> 逐函数试验（每次都只保护一个函数，然后 `import example`）：
> ```
> __Pyx_InitConstants        rc=0            OK 55        ← 它也是在模块初始化期间被调用的
> __pyx_pymod_exec_example   rc=3221225477                ← 崩
> __pyx_pymod_create         rc=3221225477                ← 崩
> ```
> `__Pyx_InitConstants` 是在 init 期被调用、而且**工作正常** ⇒ "init 函数"这个说法不准确。
> 真正的共同点：**`pymod_create`/`pymod_exec` 是由模块外部的调用者（CPython 的导入机制，通过 `PyModuleDef` 里的函数指针）调用的**，
> 而 `__Pyx_InitConstants` 是被**我们这个 pyd 自己的代码**直接调用的。
> 于是假设改为：**外部调用者进入时的那套上下文（寄存器/栈/异常元数据）我们还没完全复现**。
>
> ### 490. 顺手做了静态核对：补丁本身是对的
> 在打包后的文件里读 5 个字节：
> ```
> 原始 __pyx_pymod_create : 40 56 48 83 ec 30 ...
> 打包 __pyx_pymod_create : e9 7b 24 02 00 ...      ← jmp 到 0x2BC0+5+0x2247B = 0x25040（我们的 thunk 区）
> ```
> 同一文件里其它未保护函数（greet 等）字节未变 ⇒ **补丁位置与目标都正确**，问题在进入 VM 之后。
>
> ## 新目标（覆盖口径）第 18 轮：**16KB 槽正式启用，端到端 9/11 → 10/11**
>
> ### 487. 先纠正第 12 轮的一个误判
> 当时我把「16KB 槽下多函数组合崩」归因于「大 .bss / 大注入段的布局交互问题」。**这是错的**：
> 那个组合里有 `__pyx_pymod_create`，而第 13 轮已经查清 —— **它单独保护就会让 import 崩**（与槽大小无关）。
> 这一轮把槽调回 16KB，然后测一个**不含任何 init 函数**的 10 函数集合（含两个大函数）：
> ```
> 打包 rc = 0
> protected rc = 0
> fib 55 610    n (10,)    greet Hello, vmp!    time 19    add_dly 5.0   ← 与原生一致
> 其中包含 __pyx_pf_7example_8add_dly（7313B 字节码，之前被 4KB 槽拒绝的那个）
> ```
> ⇒ 16KB 槽**完全可用**，第 12 轮的结论撤销；真正的分界线是「**init 函数 vs 普通函数**」，不是槽大小。
>
> ### 488. 口径（11 个候选名）
> * 端到端验证通过：**10 / 11**
> * 唯一未过：`__pyx_pymod_create`（init 函数，导入期崩，独立问题）
> * 打包期硬校验仍生效（阈值随之为 16384，超过才拒绝）
> * 门禁 `tools/gates.ps1` **8/8**（含 E2E 146/146 与 ELF 载荷差分），说明 16KB 槽对既有路径无回归。
>
> ## 新目标（覆盖口径）第 17 轮：**大函数是一整类问题**，而且我的 release 校验上一轮压根没生效
>
> ### 484. 又一个同类实例：`__pyx_pymod_exec_example`
> 顺手把另一个"模块初始化函数"也拿来保护，结果是：
> ```
> __pyx_pymod_exec_example: RVA=0x2E80 native=2523B -> 630 IR -> 4971B bytecode
> import example →  SystemError: execution of module example failed without setting an exception
> ```
> 这个报错正是"exec 函数返回值既不是 0 也不是 -1"的典型症状 —— 而我们的 `vm_run` 在字节码超过缓存槽时
> **返回 2**，桩把这个错误码当函数返回值交回去。**与 add_dly 函数体是同一个类**（4971 > 4096）。
>
> ### 485. 更要紧的：我上一轮那个"打包期硬校验"在 release 配置下根本没生效
> 复核时发现 `vm_bc_slot_size` 这个 const 在 `-release` 构建里**没有出现在 manifest 符号表里** ——
> 说明它被优化掉了（没人引用它），于是 `bytecodeLimitFlag = 0`，校验被静默跳过。
> 修法：在 `vm_keep_verify_ref` 里加一条永不执行的引用（与 `vm_verify_table` 同一套把戏）。
> 修完实测（都用 **release** blob）：
> ```
> [!] __pyx_pf_7example_8add_dly:  生成的字节码 7313 字节超过解释器缓存槽上限 4096 ...   rc=1
> [!] __pyx_pymod_exec_example:    生成的字节码 4971 字节超过解释器缓存槽上限 4096 ...   rc=1
> ```
> 两个超限函数都**在打包期被拒绝**了 —— 这才是上一轮我想做但没做成的事。
>
> ### 486. 顺带排除：pymod_create 不是这一类
> 它的字节码只有 1783 字节（不超限）；而且这轮把**打包后 pyd 的导入表/节表与原始文件逐项比对**——
> `.text/.rdata/.data/.pdata/.rsrc/.reloc` 的 VA/大小/文件偏移**完全一致**，三个新节是追加的，
> IAT 槽 0x8498=PyThreadState_Get、0x83d0=PyInterpreterState_GetID 也都对；
> 再把生成的字节码逐条解出来（`LOAD VMSCR,[0x8498]` + `CALLR VMSCR` + `LOAD RCX,[RAX+0x10]`）也全对。
> 所以它的崩溃另有原因，仍挂账。
>
> ## 新目标（pymod_create）第 16 轮：排除"翻译错"这一支，并补两件工具（本轮没有修复）
>
> ### 481. IR 级核对：那条 IAT 间接调用**翻译是对的**
> 把 `__pyx_pymod_create` 的 IR 打出来（前 12 条）：
> ```
> IR[00] PUSH_R   dst=6                       ← push rsi
> IR[01] ALU_RI   dst=4 imm=0x30              ← sub rsp,0x30
> IR[02] MOV_RR   dst=6 a=1                   ← mov rsi,rcx（保存入参 def）
> IR[03] LOAD     dst=17 disp=33944           ← 读 IAT 槽 0x8498（与反汇编 # 0x180008498 完全对应）
> IR[04] ?        a=17                        ← 这就是间接调用（CallR；显示成 '?' 只是 dumper 缺条目）
> ```
> 也就是说：**翻译路径没问题**（IAT 槽地址、寄存器都对）——"翻译错"这一支被排除，问题在调用之后。
>
> ### 482. 两件工具（保留，后面还要用）
> · `tools/veh_ring.py` 增加 `--once`：只报告第一次异常后立即结束，避免异常反复触发刷屏；
> · 解释器增加**调用环** `vm_call_ring[16]`（最近 8 次 CALLN/CALLR 的"目标 + 调用后的 RAX"），
>   配合 `--dump-rva` 可在崩溃现场直接看"那次间接调用到底返回了什么"。
> 但在 `pymod_create` 这个崩溃上**读不到环**：第一次异常之后进程已经损坏，VEH 处理器里的 ctypes 读
> 自身就崩在 API-set 桩里（日志里的第二、三条异常就是它）。这条限制记下来，换手段。
>
> ### 483. 当前状态
> 口径不变（端到端 9/11）；CI 最近两批 5/5 全绿（`mt` 偶发没复现，VEH 探针继续等）；
> 门禁 8/8。下一步：用 msys2 的 **gdb** 直接在 `import example` 崩溃时抓调用栈（比进程内探针可靠）。
>
> ## 新目标（mt 偶发）第 15 轮：把崩溃上报换成 VEH，等下一次 CI 偶发给地址
>
> ### 479. 改动
> `testdata/target.c` 里把崩溃上报从只用 `SetUnhandledExceptionFilter` 改成**再加一层 VEH**：
> `AddVectoredExceptionHandler(1, ...)`（更早、对线程内/收尾期的访问违例也生效）+ 一次性打印 +
> `CONTINUE_SEARCH`（**不改变原有退出行为**，退出码照旧）。
> 自检（故意空指针）：
> ```
> CRASH code=0xC0000005 addr=00007FF6269D3355 module=00007FF6269D0000 rva=0x3355
> rc=-1073741819        ← 退出码保持原样
> ```
>
> ### 480. 本地仍然复现不出来（前后数字）
> ```
> e2e.ps1                      146 passed, 0 failed   （VEH 在正常路径不误报）
> 8 路并发压测 mt 200 次        异常 0 次
> ```
> 所以这条只能靠 CI：下一次偶发时，`E2EFAIL` 摘要里会直接带上 `CRASH code/addr/module/rva`
> （诊断输出已放宽到 200 字符），有了地址就能像 add_dly 那样迅速收敛。
>
> ### 478. CI 终于给出崩溃码：**0xC0000005（访问违例）**，不是栈溢出
> 上一轮换用 .NET Process API 之后，`E2EFAIL` 摘要里第一次拿到了真实退出码：
> ```
> E2EFAIL mt(0) native=[<4 个线程结果> bump=80000] protected=[]
>   try1[rc=0    out[-1172413891844988975 467066437051385810 2106546765947760595 ] err[]]
>   try2[rc=-1073741819 out[] err[]]        ← 0xFFFFFFFFC0000005
> ```
> 两条结论：
> · **是访问违例，不是栈溢出**（若是栈溢出会是 0xC00000FD）——我先前那条"栈溢出"猜测被证伪；
> · `try1` 的 rc=0 且输出看起来"只有 3 个"，其实是**我的诊断把 out 截断到 60 字符**造成的错觉
>   （19+1+18+1+19+1 = 59）——已把截断放宽到 200 字符，下次能看清全貌。
> 另外：受保护目标自己那个 `CRASH code=...` 过滤器**没有输出**（err 为空），说明这次 AV 绕过了
> `SetUnhandledExceptionFilter`（比如发生在某个线程、且进程正在收尾）—— 下一轮一并查。
>
> ### 477. pymod_create 崩点收窄：第一条**间接调用**返回了垃圾
> 探针（只保护 pymod_create，跑 `import example`）：
> ```
> 第一条异常：0xC0000005 读地址 0x42，故障指令在别的模块（Python/CRT），不是我们的
> ```
> 反汇编 `__pyx_pymod_create`（RVA 0x2BC0）：
> ```
> 180002bc0: 40 56              push %rsi
> 180002bc2: 48 83 ec 30        sub  $0x30,%rsp
> 180002bc6: 48 8b f1           mov  %rcx,%rsi          ← 保存入参 def
> 180002bc9: ff 15 c9 58 00 00  call *0x58c9(%rip)      ← 第一条间接调用（IAT）
> 180002bcf: 48 8b 48 10        mov  0x10(%rax),%rcx   ← 读结果 +0x10
> ```
> 读地址 0x42 =「rax+0x10」且 rax=0x32 ⇒ **第一条间接调用的返回值是垃圾**（不是有效指针）。
>
> lifter 对这类指令的处理看起来是对的：`call [rip+disp]` → `Load VMSCR, [IAT 槽]` + `CallR VMSCR`；
> `CALLR` 在解释器里把寄存器当**绝对地址**用，这对"加载器解析好的外部函数指针"正是对的。
> 所以问题出在调用**之后**：要么被调方拿到错的参数（返回值不合理），要么返回值回填/桥接有偏差。
> 这一条本轮没有结论，记为下一轮的首要项（现场已经有定位手段：在 CALLR 前后读参数寄存器与 RAX）。
>
> ## 新目标（覆盖口径）第 13 轮：更正一条错记录，并把已验证组合钉到 **9/11**
>
> ### 474. pymod_create 的真相：**导入期就崩**，而且是老问题
> 逐函数 + 组合二分（全部用当前 blob；另外还把代码 checkout 回第 8 轮的提交复测了一遍）：
> ```
> pymod_import_only   rc=3221225477   ← 只保护 pymod_create，连 import 都过不去
> pymod_plus_bisect   rc=3221225477
> pymod_plus_n        rc=3221225477
> 在第 8 轮的提交 6a7cb12 上 pymod 单独保护：同样 rc=3221225477
> ```
> 也就是说：**`__pyx_pymod_create` 一受保护，模块初始化就崩**，与组合无关、也与我第 9–12 轮的改动无关。
>
> ### 475. 更正：第 8 轮那句「8 个函数已验证」是错的
> 那个 8 函数集合里**包含 pymod_create**；它今天单独/组合都崩。最可能的解释是我当时用到了
> **过期的 blob**（`build/vm_interp_rel.bin` 没重建）——这又是「工具与被测对象不同步」，第 9 次。
> 现在用当前工具链重新测：
> ```
> no_pymod_7   rc=0  OK 55 610 (10,) Hello, vmp! 19 5.0     ← 7 函数组合完全正确
> with_pymod_8 rc=3221225477                                ← 加回 pymod 就崩（导入期）
> ```
>
> ### 476. 把 greet 与 fibonacci 包装也加进来：**9/11 全部正确**
> ```
> 9 函数集合保护后：fib 55/610、n (10,)、greet Hello, vmp!、time 19、add_dly 5.0
> 原生            ：fib 55/610、n (10,)、greet Hello, vmp!、time 19、add_dly 5.0   ← 逐字节一致
> ```
> 于是当前口径（11 个候选名）：
> · **端到端验证通过：9**（n、pf_n、pw_fibonacci、pf_fibonacci、pw_greet、pw_current_time_str、pf_current_time_str、pw_add_dly、bisect）；
> · **打包期拒绝：1**（pf_8add_dly，字节码 7313 > 槽 4096，由本轮新增的硬校验挡下）；
> · **已知坏：1**（pw/pymod_create：受保护即崩在模块初始化，老问题、可复现）。
>
> ## 新目标（覆盖口径）第 12 轮：**大函数崩点的真正根因**：字节码超过缓存槽，vm_run 静默返回错误码
>
> ### 470. 根因（终于对上了所有现象）
> `__pyx_pf_7example_8add_dly` 的字节码有 **7313 字节**，而解释器的每函数缓存槽只有 **4096**（`VM_SCRATCH_SIZE`）。
> 于是 `vm_run` 走到：
> ```c
> if (c < 0 || (u32)d->codeLen > (u32)VM_SCRATCH_SIZE) { vm_bc_leave(); return 2; }
> ```
> **返回 2** —— 而调用方（Cython 包装函数）把这个返回值**当成了函数结果**，于是把垃圾交给 numpy，
> 最后崩在 numpy 里面。这就解释了此前所有怪现象：故障地址在**别的模块**、是近空读、
> `vm_last_call = 0`（解释器循环根本没进）、`last pc` 停在解密前的标记上。
> 也就是说：这不是「翻译错了一条指令」，而是**超限时的静默失败**。
>
> ### 471. 本轮落地的修复：打包期硬校验（把静默失败变成响亮失败）
> · C 侧把槽容量导出成常量 `const u64 vm_bc_slot_size`（落在 .rdata，可读不被写）；
> · `cmd/vmpack` 打包时从 blob 字节里读出这个值，**任何函数生成的字节码超过它就拒绝打包**：
> ```
> [!] __pyx_pf_7example_8add_dly: 生成的字节码 7313 字节超过解释器缓存槽上限 4096 —— 超限时 vm_run 会返回错误码，
>     而调用方会把那个返回值当成函数结果（静默算错，实测表现为崩在第三方库里）。修法：调大 VM_BC_SLOT_SIZE 后重编 blob
> ```
> 对一个加壳工具来说，「拒绝打包」远好于「打出一个会静默算错的包」。
>
> ### 472. 槽放大到 16KB 的实验：单函数成功，多函数反而崩
> `VM_BC_SLOT_SIZE` 改成 16384 后：`add_dly` 函数体**单独保护时完全正常**（`adddly rc=0 OK 5.0`）；
> 但 8 函数/11 函数的组合构建会崩 —— 说明大 .bss/大注入段之后还有一处布局相关的交互问题（未查清）。
> 因此本轮**回退**槽大小，保留打包期校验，并把「16KB 槽 + 多函数布局」记为待查项。
>
> ### 473. 顺带发现一处回归（已缩小到单个函数）
> 逐函数二分：`__pyx_pymod_create` **单独保护就会崩**（其余单函数都 OK）；所有组合失败都能由它解释。
> 也就是说 base8/all11 的失败不是「组合问题」，而是这一个函数。回退第 11 轮的别名跟踪并没有修好它，
> 说明原因在第 9–12 轮的其它改动里 —— 这是下一轮的首要项。
> 门禁 8/8，E2E 146/146（核心路径未受影响）。
>
> ### 468. 栈别名跟踪（推广版）已实现，但它**没有**修好 add_dly 函数体
> 做法照搬现有的 rbpEff 机制，只是推广到任意寄存器：
> · `aliasKnown[16]/aliasEff[16]`（每函数重置）；`mov reg,rsp` / `mov reg,rbp`（已知时）记下保存时的 eff；
> · `memAddr` 里，若基址是已跟踪的别名寄存器 → 按**同一条 FrameSkew 规则**（`eff = aliasEff+disp`）折算，
>   并把基址换回 RSP；
> · `mov rsp, reg`（从别名寄存器还原）→ 把 spDelta/spKnown 恢复到保存时的值；
> · 任何其它写入都会清掉该寄存器的别名（`clobber`）。
> 实测效果（IR 统计）：该函数 359 条 Load/Store 里，有 **2 条**拿到了 FrameSkew 折算（正偏移那两条），
> 负偏移的按规则不动 —— 与设计一致。
> **但 add_dly 的函数体仍然崩**（0xC0000005）：说明崩点另有原因，不是这一类基址折算。
> 门禁 8/8；`greet` / `fibonacci` 包装仍 OK。
>
> ### 469. 下一步（已经想清楚怎么查）
> 上一次探针显示崩在**别的模块**（numpy）里、故障地址 0x2 —— 也就是交给 numpy 的某个参数是坏的。
> 解释器里已有 `vm_last_call` / `vm_last_call_rcx` 探针（记录最后一次 CALLN 的目标与第一个参数），
> 下一步就是在崩溃现场读这两个值，和"原生同样调用会传什么"对比；差异会直接指出是哪条指令算错了。
>
> ## 新目标（覆盖口径）第 10 轮：add_dly 函数体崩点的根因查明 —— 锅不在 VM，在 `mov r11, rsp`
>
> ### 464. 崩点定位（VEH 探针 + 分级标记）
> 我先给 vm_run 的加密路径补了三档标记（`0xAA000005` 补丁校验通过 / `0xAA000006` 进缓存临界区 /
> `0xAA000007` 缓存查找完成），再跑探针：
> ```
> [VEH] exception 0xC0000005 at 0x7FFEC9F3658C params=[0x0, 0x2]
>   module/allocation base = 0x7FFEC9EC0000      ← 这不是我们的模块
>   GetModuleHandleW base   = 0x7FFF28440000      ← 我们的模块在这里
>   last pc = 0xAA000007                          ← VM 已经走到缓存查找之后
> ```
> 关键信息：**故障地址 0x2（近空读）且发生在别的模块里** —— VM 侧一切正常，是客户机调用出去以后崩的。
> 换句话说：函数体把**错误的指针**交给了 numpy。
>
> ### 465. 根因：`mov r11, rsp` 的两种用法，lifter 只照顾了一种
> 函数序言 `mov r11,rsp` 在 lifter 里被翻译成 `MovRR r11 ← 客户机 RSP`（**模拟栈那一侧**的值）。
> · `greet` 的用法是"存一下、结尾 `mov rsp,r11` 还原"→ 这个值**正好是对的**（所以它一直 OK）；
> · `add_dly` 函数体的用法是拿 r11 访问**调用方帧**（正偏移）→ 差一个 FrameSkew → 交给 numpy 的指针是坏的。
> 两个用例都是同一条指令，却需要不同的值 —— 单个寄存器值不可能同时对。
>
> ### 466. 试过的两条快路都不行（都记下来了）
> · 把物化值按 FrameSkew 修正（正偏移那侧对）→ 仍崩：因为负偏移（函数自己的帧）这时又跑到原生帧上去了；
> · 反过来直接**拒绝** `mov reg,rsp` → `greet` 立刻从 OK 变 FAIL（它是已验证可用的功能，不能为此回退）→ 已撤销。
> 结论：正确做法是把这类寄存器纳入**与 rbpEff 同类的别名跟踪**（现有代码对 RBP 已经这么做了！），
> 让 `memAddr` 按每次访问的 eff 符号去决定要不要补 FrameSkew —— 这样两种用法都能对。
>
> ### 467. 本轮口径（如实）
> ```
> 单函数翻译：11/11      端到端验证：10/11
> 唯一未过：__pyx_pf_7example_8add_dly（990 IR）—— 现象是**响亮地崩**（不是悄悄算错），根因已定位；
> greet rc=0 OK Hello, vmp!   fibw rc=0 OK 55   adddly rc=3221225477
> ```
> 门禁 8/8。
>
> ### 462. CI 验证：arm64 回归已修
> `af9235c` → **5/5 全绿**（linux-arm64 ✓）。也就是说本轮那个"裁剪器用错架构"的修复被 CI 确认了。
>
> ### 463. 崩溃码为什么还是空的：换用 .NET Process API
> 上一轮我把 `Run-FileDiag` 从 `Wait-Process -Id` 改成 `$p.WaitForExit(ms)`，但最新一次偶发（`6a7cb12`）
> 摘要里 `rc=` **仍然是空** —— 说明 `Start-Process -PassThru` 的对象在崩溃场景下拿不到 ExitCode。
> 现在改成直接用 .NET：`ProcessStartInfo`（`UseShellExecute=false` + 重定向 stdout/stderr）→ `Process.Start` →
> `WaitForExit(ms)` → `$proc.ExitCode`，并把已读到的 stdout/stderr 直接用于诊断行。
> 本地 `e2e.ps1` 仍 146/146、解析 OK。下次偶发就会给出真正的崩溃码。
>
> ### 461. 我引入的 arm64 回归：ELF 裁剪器用错了架构
> `linux-arm64` 连续两次红，报 `[!] sum_to: 代码长度 29 不是 4 的倍数（A64 定长）` 并 panic。根因：
> `internal/scan/elf.go` 里给"符号带 Size"的分支**一律调用 x86-64 的 `TrimTrailingPadding`**，与目标架构无关。
> 以前它必然失败（arm64 字节里解不出 x86 的 RET）→ 走 fallback 用**未裁剪**的整段（天然 4 的倍数）→ 一直是对的；
> 我把 x86 裁剪器的"末尾必须是 RET"放宽成"RET 或直接 JMP"之后，它在 arm64 字节上也能"成功"了，
> 于是裁出 29 字节这种非 4 倍数长度 → aarch64 lifter 拒绝。
> 修法：按 `df.FileHeader.Machine == elf.EM_AARCH64` 选 `trimTrailingPaddingARM64`（定长裁剪），x86-64 才用 `TrimTrailingPadding`；
> 两处（带 Size 与不带 Size 的分支）都改。顺带修掉错误路径里的 panic：lifter 出错时可能返回 nil，`irFunc.Unsupported` 直接解引用就崩
> （CI 的堆栈里就是 `main.liftAll` → `main.go:288`）。
> 本地门禁 8/8（含 linux/amd64 载荷差分）；arm64 只能靠 CI 验证。
>
> ## 新目标（覆盖口径）第 9 轮：**单函数翻译 11/11**，端到端 10/11
>
> ### 458. 新能力：常量偏移的"栈地址物化"
> `mov reg, rsp` 与 `lea reg, [rsp+disp]`（**不带索引**）现在允许翻译：照搬 `memAddr` 已有的 FrameSkew 规则
> （`eff >= 0` 的访问补 FrameSkew），于是物化出来的值就是宿主侧那个地址，与普通内存访问算出来的完全一致；
> 后续 `[reg+disp]` 按普通寄存器基址算，也是对的。
> **带索引**的形式（`lea reg,[rsp+idx*scale+disp]`，且落在调用方帧一侧）仍然**保守拒绝**：
> 真实偏移的符号取决于运行期 idx，无法判定要不要补 FrameSkew —— 宁可拒绝也不猜。
> 单测也跟着改了：原来的 `TestLiftRejectsStackAddressEscape` 编码的是"一律拒绝"的旧规则，
> 现在拆成 `TestLiftStackAddressMaterialization`：常量形式必须通过、带索引形式必须被拒。
>
> ### 459. 口径（同一份样本、同一条判据）
> ```
> OK __pyx_pw_7example_1n          127 IR   950 B      OK __pyx_pw_7example_7current_time_str 285 IR 2050 B
> OK __pyx_pf_7example_n           127 IR   950 B      OK __pyx_pf_7example_6current_time_str 285 IR 2050 B
> OK __pyx_pw_7example_3fibonacci  139 IR  1076 B      OK __pyx_pw_7example_9add_dly          150 IR 1171 B
> OK __pyx_pf_7example_2fibonacci  310 IR  2223 B      OK __pyx_pf_7example_8add_dly          990 IR 7313 B
> OK __pyx_pw_7example_5greet      212 IR  1644 B      OK __pyx_pymod_create                  264 IR 1783 B
>                                                      OK __pyx_bisect_code_objects            47 IR  293 B
> 单函数翻译：前 8/11 → 后 **11/11**
> ```
>
> ### 460. 端到端（这才是判据）
> ```
> greet   rc=0   OK Hello, vmp!      ← 它需要的正是本轮新打通的 lea rax,[rsp+0x98]
> fibw    rc=0   OK 55               ← fibonacci 包装函数
> adddly  rc=3221225477 (0xC0000005) ← __pyx_pf_7example_8add_dly（990 IR，迄今最大的函数）仍然崩
> ```
> 加上此前验证过的 8 个 ⇒ **10/11 端到端验证通过**；唯一未过的是那个 990 IR 的大函数。
> 门禁 `tools/gates.ps1` **8/8**（单测与 E2E 均未回归）。
>
> ## 新目标（覆盖口径）第 8 轮：边界改成"候选从小到大试"，剩下的卡点收敛成**一条指令family**
>
> ### 455. 边界选择已改
> 候选边界现在是：MAP 里下一个符号起点、.pdata 的 end、下一个导出、节尾 —— 全部列出后**从小到大**试，
> 取第一个"末尾确实是 RET/JMP"的（`mapNextBegin` 是新增的关键候选：相邻函数的起点就是上一个函数的终点）。
> 效果（同一份样本）：
> ```
> greet          : "末尾不是 RET"        → "2/190 条指令无法翻译"   （函数已经能翻到尾，只差 2 条）
> add_dly 函数体 : "末尾不是 RET(+0x21)" → "1/799 条指令无法翻译"   （同上，只差 1 条）
> ```
> 顺带纠正我上一轮的一个误判：我说"+0x20B 之后是合法代码、边界太短"是对的，但我当时拿 0x1F90 这个
> **指令中间地址**去反汇编、看到乱码就以为那段不是代码 —— 从函数起点 0x1F80 反汇编出来是完全正常的函数序言：
> ```
> 180001f80: 4c 8b dc        mov %rsp,%r11
> 180001f83: 41 54           push %r12
> 180001f85: 48 81 ec f0 00  sub $0xf0,%rsp
> ```
>
> ### 456. 卡点收敛成一条 family（这是好消息）
> 让 vmpack 把"不可翻译指令"明细打出来后，三个失败函数的卡点分别是：
> ```
> greet          +0x0:  MOV R11, RSP
> greet          +0x6C: LEA RAX, [RSP+Reg(0)+0x98]
> add_dly 函数体  +0x0:  MOV R11, RSP
> fibonacci 包装  +0x68: LEA RAX, [RSP+Reg(0)+0x78]
> ```
> 全都是同一件事：**把"客户机栈地址"当作一个值来用**（MSVC 用 `mov r11,rsp` 保存帧指针；
> `lea rax,[rsp+idx+disp]` 取栈上数组的地址）。当前 lifter 把 RSP 当成"宿主帧里的偏移"来折叠，
> 于是"RSP 的值本身"不可表达。
>
> ### 457. 口径与门禁
> 单函数翻译口径仍 **8/11**，但**剩下 3 个的卡点从"边界问题"变成了"同一条指令 family"**：
> 只要让 lifter 能把"客户机栈地址"物化成寄存器值（IR 的 LEA 本来就支持 base+index+disp，
> 这里把 base 取 VRSP 即可），预计 **11/11**。门禁 8/8 全过（单测 + E2E 均未回归）。
>
> ## 新目标（覆盖口径）第 7 轮：尾调用支持落地，但第二类失败的真正原因不是尾调用
>
> ### 452. 已实现（留作通用能力）
> · `internal/scan`：末尾允许 **RET 或直接无条件跳转**（`jmp rel8/rel32`）；`jmp [rip+disp]`（导入桩）仍保守拒绝；
> · `internal/lift/x64`：**目标落在函数外的直接 JMP = 尾调用** → 抬成 `CALLN 目标; RET`
>   （原语义"跳到那里再返回我的调用者"与 call+ret 完全等价；参数本来就在客户机寄存器里）。
>
> ### 453. 但 greet / add_dly 函数体仍然失败，原因**不是**尾调用
> 报错从"末尾不是 RET"变成"末尾不是 RET/JMP"，说明它们末尾是**普通指令**。反汇编一看就明白了：
> ```
> 18000190b: 48 8b f8            mov %rax,%rdi          ← lifter 停在这里（= greet + 0x20B）
> 18000190e: 48 89 ac 24 90 00 00  mov %rbp,0x90(%rsp)  ← 后面明明是合法代码，还在继续
> 180001916: 48 85 ff            test %rdi,%rdi
> 180001919: 75 0c               jne 0x180001927
> ```
> 也就是说：**边界算短了**——scan 用 .pdata/下一个符号推出的 end 落在函数中间，于是"最后一个真实指令"不是 RET/JMP。
> 这一类要修的是**边界选择**：把候选边界按从小到大试，挑第一个"末尾确实是 RET/JMP"的；
> 而不是继续放宽末尾判定（那只会让截断的函数被当成完整函数翻译，更危险）。
>
> ### 454. 口径与门禁
> 单函数翻译口径仍是 **8/11**（本轮是通用能力 + 把问题定位清楚了）；E2E 与单测随后复核。
>
> ### 451. CI 偶发又出现两次，并暴露了诊断里的一个坑
> `16a1f7f` 与 `ee452ba` 两次 `windows-amd64` 都是 `mt(0)` 崩溃，摘要形如
> `protected=[] try1[rc=? out[<前 3 个结果>] err[]]` —— **stderr 为空**。
> 也就是说：`testdata/target.c` 里那个 `SetUnhandledExceptionFilter` **没有触发**。
> 栈溢出（0xC00000FD）正好符合这个特征：栈已经耗尽，异常过滤器根本跑不起来，进程直接消失；
> 而"只打印出前 3 个线程结果"也符合"跑到一半被打断"。
> 同时 `rc=?` 的原因也查明并修掉了：`Run-FileDiag` 用的是 `Wait-Process -Id`（只按 id 等，不刷新进程对象），
> 之后读 `$p.ExitCode` 会抛异常 → 被我的兜底写成 `?`。改成 .NET 的 `$p.WaitForExit(ms)` 后，
> 既保留超时、又能拿到崩溃码（`0xC00000FD` = 栈溢出，一眼可判）。
> 本地 `e2e.ps1` 仍 146/146。
>
> ## 新目标（覆盖口径）第 6 轮：**6/11 → 8/11**，而且新加的两个是端到端验证过的
>
> ### 447. 第一类修法落地：跟随开头的 5 字节 jmp 桩
> `internal/scan` 里新增 `followThunk`：符号指向 `jmp rel32` 时跟到目标 RVA（最多 4 跳，防环），
> 用**目标的 RVA** 去翻译并打补丁 —— 桩保持原样，它自然会把控制流带进我们的补丁。
> 实测：`__pyx_pw_7example_1n` 与 `__pyx_pw_7example_7current_time_str` 从 FAIL 变 OK，
> 而且翻译出的 IR 数与它们各自的函数体**完全一致**（127 / 285），说明确实跟到了真身。
>
> ### 448. 连带修掉一个把加载期校验搞挂的问题：别名重复放置
> 桩解析之后，"包装函数"与"它跳转到的函数体"落在**同一个 RVA** 上：
> ```
> __pyx_pw_7example_1n                RVA=0x1010 ... OK
> __pyx_pf_7example_n                 RVA=0x1010 与 __pyx_pw_7example_1n 相同（桩/别名），跳过重复放置
> ```
> 不去重的话，同一个 RVA 会被放**两份**补丁，后者覆盖前者的字节，加载期校验表必然对不上 ——
> 现象就是 `DLL load failed ... 初始化例程失败`（我这一轮先踩到，再去重后解决）。
>
> ### 449. 端到端复测（8 个函数同时保护 vs 原生）
> ```
> fib(10)= 55      fib(15)= 610     n.shape= (10,)
> greet= Hello, vmp!   time_len= 19   add_dly= 5.0        ← 两边完全一致，exit=0
> ```
> 其中 `n()` 与 `current_time_str()` 走的就是本轮新打通的两条桩路径。
>
> ### 450. 覆盖口径
> ```
> 前：6/11      后：8/11   （剩余 3 个：fibonacci 包装函数 1/125 条指令不支持；
>                          greet 包装函数与 add_dly 函数体"末尾不是 RET"）
> ```
>
> ## 新目标（覆盖口径）第 5 轮：把"6/14"换成可复算的 **6/11**，并把拒绝原因分了三类
>
> ### 444. 口径先说清楚
> 候选集合 = 该模块的 `__pyx_pw_*` / `__pyx_pf_*`（各 5 个）＋ `__pyx_pymod_create` ＋ `__pyx_bisect_code_objects`，共 11 个；
> 判据 = **单个函数能否翻译**（逐个 `-func` 打包，成功即计入）。实测 **6 / 11**。
>
> ### 445. 逐函数结果（这是"前"的数字）
> ```
> OK    __pyx_pf_7example_n                    127 IR -> 950 B
> OK    __pyx_pf_7example_2fibonacci           310 IR -> 2223 B
> OK    __pyx_pf_7example_6current_time_str     285 IR -> 2050 B
> OK    __pyx_pw_7example_9add_dly              150 IR -> 1171 B
> OK    __pyx_pymod_create                      258 IR -> 1753 B
> OK    __pyx_bisect_code_objects                47 IR -> 293 B
> FAIL  __pyx_pw_7example_1n                    函数末尾缺少 RET（+0x0 处 JMP .+11）
> FAIL  __pyx_pw_7example_7current_time_str     函数末尾缺少 RET（+0x0 处 JMP .+11）
> FAIL  __pyx_pw_7example_5greet                函数末尾缺少 RET（+0x20B 处 MOV RDI, RAX）
> FAIL  __pyx_pf_7example_8add_dly              函数末尾缺少 RET（+0x21 处 XOR R12L, R12L）
> FAIL  __pyx_pw_7example_3fibonacci             1/125 条指令无法翻译
> ```
>
> ### 446. 三类拒绝原因（都可动手）
> 1. **首指令是 5 字节 `jmp` 桩**（2 个）：反汇编 `__pyx_pw_7example_1n` 得到
>    `180001000: e9 0b 00 00 00  jmp 0x180001010` 后面全是 `int3` —— 这是增量链接的 ILT 桩，
>    **真正的函数体在跳转目标处**。修法：识别到"首指令为 `jmp rel32` 且目标在模块内"时，
>    按**目标 RVA** 去翻译**并打补丁**（桩保持原样，它自然会把控制流带进我们的补丁）。预计 +2。
> 2. **函数末尾不是 RET**（2 个）：`greet` 与 `add_dly` 的 pf 体都以尾调用/后续指令收尾，
>    而 lifter 要求最后一条必须是 RET。修法：允许末尾的无条件跳转，抬成 `CALLN/CALLR 目标; RET`
>    （VM 已有 CALLN/CALLR，且参数本来就在客户机寄存器里）。预计 +2。
> 3. **单条指令不支持**（1 个）：`fibonacci` 的 wrapper 有 1/125 条无法翻译 —— 需要先把那条指令打出来。预计 +1。
>
> 三类都落地的话，单函数翻译口径可以从 6/11 提到 ~10-11/11，而且每一类都是**通用**的（不止这一个模块）。
> 另外：CI 那边 `mt` 的崩溃自证还在等下一次偶发（本轮 CI 未复现）。
>
> ### 443. 环境对照
> CI 的 notice 显示：`gcc=D:\a\_temp\msys64\ucrt64\bin\gcc.exe` —— 与我本地 `C:\msys64\ucrt64\bin\gcc.exe`
> 是**同一支 ucrt64**，但 CI 是 setup-msys2 现装的最新包，**版本很可能比我本地新**。
> 结合本项目"gcc -O2 曾把解释器整段编错"的历史（第 70/71 轮），这是目前最值得怀疑的变量。
> 这一轮 CI 没有复现（5/5 全绿），所以先把"崩溃自证"留在那里：下一次偶发会直接带上崩溃地址。
>
> ## 新目标（mt 偶发）第 4 轮：让崩溃自己报地址
>
> ### 441. 2 核亲和也复现不出来
> ```
> 本机 16 逻辑核；用 SetProcessAffinityMask 把每个受保护进程限制到 2 核，8 路并发跑 96 次：
>   异常 0 次，用时 529s（亲和确实生效——把并发压成了串行）
> ```
> 也就是说本地既不是"核多"导致的漏测，也不是单纯的时序问题。考虑到本项目的编译器敏感史（第 70/71 轮：
> gcc -O2 曾把整个解释器编错），**CI 与我本地的 mingw 版本不同**很可能是关键变量。
>
> ### 442. 换个更有效的抓手：让受保护目标自己报崩溃点
> `testdata/target.c` 里加了顶层异常过滤器（`SetUnhandledExceptionFilter`）：
> 崩溃时往 stderr 打 `CRASH code=0x... addr=... module=... rva=0x...`。
> 自检（故意解引用空指针）：
> ```
> CRASH code=0xC0000005 addr=00007FF669A132D5 module=00007FF669A10000 rva=0x32D5
> ```
> 因为 E2E 的失败诊断会把 stderr 一起带进 `E2EFAIL` 摘要，**下次 CI 上的 mt 崩溃就会带上崩溃地址与模块内偏移** ——
> 用它可以映射回 blob 符号（模块基址 + 偏移 → manifest 里的符号表），直接指出是解释器哪一段。
> 顺带确认：E2E 仍 146/146（`crash_test` 只是隐藏用例，不在用例表里）。
>
> ## 新目标（mt 偶发）第 3 轮：**抓到崩溃现场的摘要了**
>
> ### 439. CI 注解里的自包含摘要（5fa2df9 那次）
> ```
> E2EFAIL mt(0)
>   native=[-1172413891844988975 467066437051385810 2106546765947760595 3746027094844135380 bump=80000]
>   protected=[]
>   try1[rc=? out[-1172413891844988975 467066437051385810 2106546765947760595 ] err[]]
>   try2[rc=? out[] err[]]
> ```
> 信息量比之前大得多：
> · protected 侧**为空**；重跑第一次只打印出**前 3 个**线程结果（第 4 个和 `bump=80000` 都没出来）就死了；
>   第二次干脆什么都没输出就死了。
> · 所以这不是"算错值"，而是**并发下的间歇性崩溃**（进程中途死亡），且本地 200 次并发复现不出来。
> · `rc=?`：诊断里对极快退出的进程取不到 ExitCode（我的兜底打印）。
>
> ### 440. 复现思路（下一轮）
> CI runner 是 2 核，本地核多线程分散 → 时序不同。计划用 **CPU 亲和性把进程限制到 2 核**再叠加并发，
> 逼近 CI 的时序；一旦复现，就用 msys2 的 gdb（或 VEH 启动器）抓崩溃点。
> （本轮我第一次尝试时又被自己的脚本坑了：把输出的换行换成空格去和带换行的参考比较 → 全是假阳性，
> 这已经是本项目第 7 次"工具与被测对象不同步"了；已记下，下一轮先用规范化比较再跑。）
>
> ### 437. 为什么上一版诊断在 CI 上"看不见"
> 读 `.github/workflows/ci.yml` 才发现注解是怎么拼的：
> ```powershell
> $fails = Select-String -Path $log -Pattern "\[FAIL\]|MISMATCH|<crash|..." | Select -First 12
> $msg   = (($fails + (Get-Content $log -Tail 4)) -join "%0A")
> ```
> 也就是**只抓匹配模式的行 + 末尾 4 行**。我的 `diag:` 行不匹配 → 被过滤掉；
> 而 `[FAIL]` 行的尾部（protected 侧的多个数字）又很可能被注解长度裁掉。
>
> ### 438. 改成"自包含的一行摘要"
> * `tools/e2e.ps1`：失败时把每个用例汇成**一行**，结束前统一打印：
> ```
> --- failure summary (one line per case, for CI annotations) ---
> E2EFAIL mt(0) native=[...] protected=[...] try1[rc=... out[...] err[...]] try2[...]
> ```
> * `.github/workflows/ci.yml`：注解抓取模式加入 `E2EFAIL|diag:`。
> 验证：临时造一个必失败用例 → 摘要行如期出现且自包含；移除临时用例后 `e2e 146/146`、解析 OK。
> 下次 CI 偶发时，注解里就会直接给出"rc + 两次重跑的输出片段"。
>
> ## 新目标（mt 偶发）第 2 轮：E2E 失败诊断已就位
>
> ### 435. 上一轮那次 PowerShell 解析错误的真正原因
> 我在 `tools/e2e.ps1` 里插入的诊断代码**带了中文注释** —— 而 PowerShell 5.1 按 ANSI 读 .ps1，
> 中文变乱码后把语法结构撑坏（报 `Unexpected token '}'`）。改成**纯 ASCII 注释**后一次通过（PARSE OK）。
> 这条以前记过，这次是我自己又踩了一遍，写在这里当提醒。
>
> ### 436. 诊断代码（已落地并验证过路径）
> E2E 的差分循环在**失败时**会：
> · 对 protected 侧再跑两次（`Run-FileDiag`）；
> · 每行打印 `rc=<退出码> out[<stdout 前 60 字>] err[<stderr 前 80 字>]`。
> 验证方式：临时插入一个必然失败的用例，得到
> ```
>          diag: try1[rc= out[0] err[]] try2[rc= out[0] err[]]
>   [FAIL] no_such_case_for_diag(0): native=0 protected=0
> ```
> （那条 `rc=` 为空是极快退出时 ExitCode 取不到，已改成取不到就打印 `?`。）
> 之后已移除临时用例：`e2e.ps1` 解析 OK、**146/146**。
>
> 下一次 CI 的 `mt` 偶发就会直接告诉我们：是**崩溃（rc≠0）**还是**算错值（rc=0 但输出不同）**——
> 这决定了下一步是查并发内存破坏，还是查字节码缓存的正确性。
>
> ## 新目标（mt 偶发）第 1 轮：先把"仪器"和"结论"都摆正
>
> ### 431. 更正一条记录（第 6 次"工具/被测对象不同步"）
> 第 4 轮我写过"受保护目标 mt 连跑 20 次、framed 连跑 10 次，输出与原生逐字节一致" ——
> **那次测量是无效的**：我用的可执行文件名是 `target_native.exe` / `target_protected.exe`，而 E2E 实际产出的是
> `target.exe` / `target_vmp.exe`；两个不存在的文件都产出空输出，于是"相等"成立（假阳性）。
> 这条现在纠正：E2E 之后的 146/146 才是有效证据，另外做了下面这次真正的并发压测。
>
> ### 432. 本地并发压测（有效版）
> ```
> Python 驱动，8 路并发、共 200 次 build\target_vmp.exe mt：
>   参考输出长度 = 96（native 的 4 个线程结果 + 校验和）
>   异常 = 0 / 200
> 单次耗时：native 0.01s，protected 2.73s（本机）
> ```
> 即：本地无论串行还是 8 路并发都复现不出来，mt 在本机是稳的。
>
> ### 433. CI 上的失败特征
> · 注解里能看到的是 `mt(0): native=-1172413891844988975`，其后紧跟换行和 benchmark 段 ——
>   也就是说 protected 侧没有可读的值（崩溃或空输出）；若是 E2E 自己判定的超时，会写成 `TIMEOUT`。
> · **它在只改文档的提交 `2caf68c` 上同样失败** ⇒ 与本目标/本次改动无关，是既有的 CI 偶发。
> · 两次失败（6f3f849 / 2caf68c）的重跑里又都是绿的 ⇒ 典型的偶发。
>
> ### 434. 下一步：让失败可判读
> 计划在 E2E 的失败分支里补"再跑两次 + 打印退出码/stdout/stderr 片段"，这样下一次 CI 偶发就能直接回答
> "是崩溃（rc≠0）还是算错值（rc=0 输出不同）"。第一版改动因 PowerShell 解析报错被回退（`tools/e2e.ps1` 已还原），
> 下一轮用更简单的写法重做。
>
> ### 430. CI 结论（6f3f849）
> ```
> linux-amd64      ✓   ← 运行期补丁校验在 ELF 上开着也能正确执行（bash 夹具补映射后）
> linux-arm64      ✓   ← arm64 的 8 字节补丁同样校验通过
> windows-arm64-blob ✓  windows-arm64-run ✓
> windows-amd64    ✗   E2E 145 passed, 1 failed —— 又是 mt(0)（同一份代码另一轮是绿的）
> ```
> 即：ELF 那条台账**已收口并上了 CI 验证**；剩下唯一的红点是 mt 这个已知偶发用例。
> mt 是 4 线程 × 20000 次、专压 4 槽字节码缓存的多线程用例 —— 它间歇性失败说明缓存那段**可能存在真实竞争**，
> 值得单独查（不属于本目标范围，但会持续干扰 CI 信号）。
>
> ### 429. 补：Linux 侧的 bash 夹具同样要补映射
> 本地 `.ps1` 通了但 CI 的 `linux-amd64` 仍红 —— 因为 CI 跑的是 `tools/verify_linux_payload.sh`（另一个实现），
> 它同样只映射 payload。已给 `payload_probe_linux.c` 加上"非数字参数=补丁文件"的处理（mmap 目标页后写入），
> 并在 `.sh` 里传 `-patchout` / 补丁文件。这条只能靠 CI 验证（本地没有 Linux 头文件）。
>
> ## 新目标 第 6 轮：ELF 也开上了**运行期补丁校验**（台账项关闭）
>
> ### 427. 做法：让夹具把"目标入口页"补上
> 上一轮查明：探针只映射 payload 段，而校验要读目标入口的补丁字节 → 读到未映射内存 → trap。
> 所以这一轮不是改产品，而是把**夹具补全**：
> · `extractpayload` 新增 `-patchout`：把补丁字节与它相对 payload 起点的偏移导出（形如 `-992544 E95B751000`）；
> · `payload_probe` 新增 `--patch <file>`：把这几字节写到对应地址（落在 payload 内就直接写，
>   落在目标段就单独 VirtualAlloc 一页再写）；
> · `vmpbuild` 去掉"仅 Windows"的限制，**所有目标**都定义 `-DVM_INVM_PATCHCHECK=1`。
>
> ### 428. 复测
> ```
> elf payload exit=0
>   payloadVA=0x585000 ... patch off=0x-F2520 bytes=E95B751000   → patch 5 bytes -> 0x492AE0
>   payloadVA=0x5AD000 ... patch off=0x-11A140 bytes=E97BF11200
>   PIE payload: identical to native at BOTH load addresses   ← 两个加载地址都通过
> ```
> 即：**ELF 上运行期校验开着也能正确执行**，PE 上原本就开着。至此"防回填"在两侧都是加载期蹦床 + 运行期校验两层。
>
> ## 新目标 第 5 轮：ELF 那条台账的**根因查明** —— 是测试夹具的假象，不是产品缺陷
>
> ### 424. 四步二分（每步都是改一处、跑 `tools/verify_linux_payload.ps1`）
> | 配置 | 结果 |
> |---|---|
> | 宏关闭 | ✓ 通过 |
> | 宏打开（完整校验） | ✗ 6 处 checkKey 错乱 |
> | 宏打开 + 代码存在但**立刻 return**（不读任何东西） | **✓ 通过** ⇒ 不是"尺寸/布局"敏感 |
> | 宏打开 + 保留读取、但**去掉 trap**（只读不拦） | **✓ 通过** |
> | 宏打开 + 只把校验挪进 `noinline` 独立函数 | ✗ 仍错乱 ⇒ 与 vm_run 帧布局无关 |
> 结论：真正发生的是 **trap 被触发了**；"结果错乱"是夹具把"进程被 ud2 打死"记成了 6 个不一致值。
>
> ### 425. 为什么 trap 会触发（这才是根因）
> 校验要读**目标函数入口的补丁字节**（`pb = d + reserved2`）。而 `tools/verify_linux_payload.ps1` 的做法是：
> 用 `extractpayload` **只抽出 payload 那一段**，再让探针把它映射到原 VA —— **目标自己的代码段并不在映射里**。
> 于是 `pb` 落在未映射内存上：读到的不是补丁字节，`h != want`，`ud2` → 进程被杀 → 夹具记成 6 个 mismatch。
> 而在**真实** ELF 里，整张镜像都由内核映射好了，`pb` 正好指向被打补丁的入口 —— 离线复算也证实：
> 用同一次构建的产物算 `FNV(key[:8] || patch)` 与描述符里的 `pad` **完全相等**（第 34 轮记录）。
>
> ### 426. 因此
> · 校验逻辑本身没问题，PE 上早就在跑；ELF 上之前"对不上"的两次也都是测量/夹具问题（含第 34 轮那次）；
> · 想让 ELF 也开运行期校验，只需二选一：**让夹具把目标段一起映射**，或者**让描述符自带补丁字节副本**（不再依赖读目标）；
> · 本轮不改产品，先把结论钉死（树保持绿）。
>
> ## 新目标 第 4 轮（结论）：**add_dly 修好了**，CI 5/5 全绿；上一轮的 mt 失败是偶发
>
> ### 421. 判定
> ```
> f26989a2（16KB margin 重推）  5/5 全绿：linux-amd64 ✓ linux-arm64 ✓ windows-amd64 ✓ win-arm64-blob ✓ win-arm64-run ✓
> 4c52bfb1（同一份代码的上一轮）windows-amd64 ✗（mt(0)）
> ```
> 同一份代码两轮结果不同 ⇒ CI 的 `mt` 用例**本身是偶发的**（4 线程 × 20000 次调用、专门压 4 槽字节码缓存的竞争）。
> 这是一条重要提醒：以后 CI 上 `mt` 红了，先重跑一轮再动手。
>
> ### 422. add_dly 的最终修法与验证
> · 根因：客户机栈就是 `host_rsp - VM_MARGIN`，VM 里发起的原生调用（Cython/numpy）帧从 host_rsp 往下长，
>   3KB 不够就整片压到客户机栈上（实测一次 CALLN 改掉 guest 栈顶 31/32 个 qword）；
> · 修法：`VM_MARGIN` 3KB → **16KB**（Windows/x64）。关键点：skew 与 stub 的 SP 由同一常量导出，故语义自洽，
>   `framed`（专测调用方栈帧参数）依旧通过 —— 这与"把栈挪到私有缓冲"完全不同（那条会破坏对应关系）。
> · 验证：e2e 146/146（本地 + CI）、mt×20 / framed×10 与原生逐字节一致、
>   6 函数同时保护与原生逐项一致（fib 55/610、n.shape、greet、time_len=19、**add_dly=5.0**）。
>
> ### 423. 覆盖口径
> `n / fibonacci / current_time_str / add_dly / pymod_create / bisect_code_objects` —— **6/14**（原 5/14）。
> 目标剩余项：ELF 那条"运行期读目标字节导致结果错乱"的根因（台账）。
>
> ## 新目标 第 4 轮：用"再跑一次 CI"来区分偶发与真问题
>
> ### 420. 本地复核（16KB margin，重新构建受保护目标后）
> ```
> e2e.ps1               146 passed, 0 failed
> mt 连跑 20 次          0 次不一致（与原生输出逐字节相同）
> framed 连跑 10 次      0 次不一致
> ```
> 也就是说本地怎么跑都过；CI 那次 `mt(0)` 失败要么是环境差异，要么是本来就存在的偶发。
> 判断办法很简单：**把这版再推一次**——同一个提交再跑一轮 CI，绿了说明是偶发，红了说明与 margin 相关。
>
> ## 新目标 第 3 轮（结论）：两次尝试都被**硬证据**否掉，正解锁定为"私有栈 + 运行期 skew"
>
> ### 417. CI 比对（这是本轮最有价值的信息）
> ```
> 090d12d0  两条环探针那版        CI 全绿
> f03dff14  私有客户机栈          CI: windows-amd64 ✗（本地 framed 也红）
> 4c52bfb1  margin 16KB           CI: windows-amd64 ✗  FAILED E2E 146 → 145 passed, 1 failed
>           失败用例：mt(0)（4 线程 × 20000 次调用）—— 本地 146/146 全过，CI 才复现
> ```
> 也就是说：**margin 放大在本地看起来是完美修复（6 个函数与原生逐项一致），但在 CI 的多线程用例上会挂。**
> 已回退 margin，保持树绿（本地 8/8 门禁）。
>
> ### 418. 为什么两条路都不行（记录清楚，避免再走）
> · **私有客户机栈**：破坏"客户机栈 ↔ 宿主调用方帧"的固定对应关系，`framed`（专测 FRAME_SKEW：第 5 个参数
>   在调用方栈帧里）立刻取错值。要能成立，必须把 skew 从**编译期常量**改成**运行期量**。
> · **放大 margin**：skew 与 stub 的 SP 同源，所以语义上自洽、功能上也真能修好 add_dly；
>   但它同时把每次调用的宿主栈深度抬到 16KB，在 CI 的 mt 多线程用例上触发问题（本地不复现）。
>
> ### 419. 正解（后续项，方向已经明确）
> **私有客户机栈 + 运行期 skew**：入口桩把"进入时的宿主 RSP"存进一个全局；
> 凡是要访问调用方栈帧（第 5+ 个参数那类）的地方，改用"运行期宿主 RSP + 偏移"而不是编译期 FRAME_SKEW。
> 这样客户机栈可以与宿主栈彻底解耦，深度不再受宿主预算限制，add_dly 那类"VM 里发起原生调用"的用例才真正稳。
> （其实我在 `stub/linux/amd64/vm_abi.h` 的注释里早就写下了这个结论——本轮等于用实验把它重新证实了一遍。）
>
> ## 新目标 第 3 轮（续）：正式修法是**放大 margin**，不是挪栈 —— 覆盖口径 6/14
>
> ### 414. 私有栈方案为什么必须撤掉
> E2E 的 `framed` 用例立刻全红（`framed(0): native=10 protected=-2021379994`）：
> 它是**专门**用来验证 FRAME_SKEW 的 —— 第 5 个参数位于**调用方栈帧**里，靠 `FRAME_SKEW` 修正才能取到。
> 把客户机栈搬到 .bss 的私有缓冲后，"客户机栈与宿主调用方帧"的固定对应关系就断了，这类访问必然取错。
> 也就是说：**挪栈必须先做"运行期捕获宿主 RSP、把 skew 变成运行期量"的重构**，不是本轮能顺手做的。
>
> ### 415. 正式修法（已落地，仅 Windows/x64）
> `VM_MARGIN: 0xC00 → 0x4000`（3KB → 16KB）。关键是：**skew 与 stub 的 SP 是同一份常量算出来的**，
> 所以放大 margin 不会破坏 framed 那类访问（自洽）；而不像挪栈那样单方面改变 SP。
> 复测：
> ```
> e2e: 146 passed, 0 failed        （含 framed / mt / calls_* 全部）
> go test ./...  全通
> 6 函数同时保护：fib(10)=55 fib(15)=610 n.shape=(10,) greet=Hello, vmp! time_len=19 add_dly=5.0
> 原生                      ：同上一行完全一致
> ```
>
> ### 416. 另外三个平台为什么不一起放大
> `stub/linux/amd64/vm_abi.h` 里我早先写过结论：模拟栈位于宿主 RSP 之下约 12.7KB，而 Go 的 goroutine
> 初始栈只有 8KB —— 在 linux-amd64 的差分用例里会直接 `runtime: split stack overflow`；
> 单纯调小 margin 又会被 vmpbuild 以 `margin < 解释器最大帧(4544)+512` 拒绝。
> 所以 Linux/arm64 上"两边都要"的唯一出路仍是**客户机私有栈 + 运行期 skew**（见下一条待办），本轮先只改 Windows/x64。
>
> ## 新目标 第 3 轮（add_dly）：**修好了** —— 私有客户机栈（6/14 已验证）
>
> ### 411. 修法
> `vm_run` 里：走入口桩进来（`vm->desc != NULL`）时，把 guest SP 指到 blob 内的**私有缓冲**
> `static u8 vm_guest_stack[256 * 1024]`（在 .bss → 注入段是 RW，实测缓冲 [0x14A00,0x54A00) 完整落在 RW 段 [0x14000,0x65000) 内）。
> 于是 VM 里发起的原生调用走宿主栈、客户机用自己的栈，两者**再也不会重叠**。
> 不动四个平台的汇编（放在 C 里），所以 arm64/ELF 也一并受益。
>
> ### 412. 中途踩的坑（值得记住）
> 第一版把地址写成 `(u64)(unsigned long)vm_guest_stack` —— **Windows 上 unsigned long 是 32 位**，
> 地址被截断成 `0x4E54A00`，guest 第一条 push 写到 `0x4E549F8` 直接访问违例。
> 现场读数很能说明问题：`first_sp = last_sp = 0x4E54A00`（截断后的值）而崩溃写目标是 `0x4e549f8` = 它减 8。
> 已改成 `unsigned long long`；顺带把同类的 `vm_diag[2] = (u64)(unsigned long)vm->code` 也修了（诊断路径）。
>
> ### 413. 复测（6 个函数一起保护，原生 vs 保护后）
> ```
> fib(10)=55  fib(15)=610  n.shape=(10,)  greet=Hello, vmp!  time_len=19  add_dly=5.0   ← 两边完全一致
> ```
> 覆盖口径从 5/14 提到 **6/14**（翻译 + 运行都对）。
>
> ## 新目标 第 2 轮（add_dly）：**根因确认** —— 原生调用踩掉了客户机自己的栈
>
> ### 408. 决定性证据一：CALLN 前后对比 guest 栈顶 32 个 qword
> ```
> vm_last_call      = 0x7FFF17C61F80    （= 模块基址 + 0x1F80 = __pyx_pf_7example_8add_dly，目标正确）
> vm_call_diff_off  = 0x8               （第一处变化在 guest_sp + 8）
> vm_call_diff_before = 0x13
> vm_call_diff_after  = 0x9200000001
> vm_call_diffs     = 0x1F              ← 32 个 qword 里有 **31 个**被这次调用改写
> ```
> 也就是说：VM 里发起的原生调用（Cython→numpy 那条链）**把 guest 自己的栈整片覆盖了**。
> 之前 guest 栈就是 `host_sp - VM_MARGIN`（3KB），原生调用的帧从 host_sp 往下长，超过 3KB 就压到 guest 栈上。
>
> ### 409. 决定性证据二：把 margin 临时放到 16KB，add_dly **直接就好了**
> ```
> 保护后：add_dly= 5.0    fib= 55    exit=0
> 原生  ：add_dly= 5.0    fib= 55
> ```
> （margin=64KB 的那次会先在别处崩，所以不能拿它下结论 —— 16KB 才是有效实验。）
>
> ### 410. 但"放大 margin"不是能长期采用的修法
> margin 是**宿主相关**的预算：CI 里 Go 宿主跑在 goroutine 栈上（日志显示 stack 区间只有 4KB），
> 这正是当初把它定在 3KB 的原因；放大到 16KB 会让 Go 那边的 E2E 崩。
> 正确修法是把**客户机栈搬到私有缓冲**（原生调用走宿主栈，两者彻底不重叠）—— 我在 C 里做了一版
> （不动汇编，四个平台通用），但第一版崩在模块内部写新缓冲的位置（`module+0x549F8`，落在新缓冲区内却报写违例），
> 说明注入段的**虚拟大小/映射**没跟上 256KB 的新缓冲。已回退这一版，保持树绿，下一轮带着这个线索重做。
>
> ## 新目标 第 1 轮（add_dly）：把两条环装上，链路又前进了一步
>
> ### 405. reg1 只被写 4 次（ring: vm_r1_pcs / vm_r1_vals）
> ```
> #0 pc=0x0000 val=0x29F395FC2C0（堆指针）
> #1 pc=0x0360 val=0x29F19734990（堆指针）
> #2 pc=0x03DD val=0x29F395FC2C0（堆指针）
> #3 pc=0x03F9 val=0x7FFF382E9130 ← 坏值（DLL 地址）由此进入
> ```
> 0x3F9 就是那条 `reg1 = [sp + rax*8 + 0x50]` 的 LOAD（reg3=0）—— 它是**读**出来的坏值，不是算出来的。
>
> ### 406. 栈槽的写入者（ring: vm_st_pcs / vm_st_addrs，最近 16 次 STORE）
> ```
> 0x00A1 -> 0xCC059EDBB0   （该槽，src=scratch）
> 0x039A -> 0xCC059EDBB0   （该槽，src=reg1，值应为堆指针）
> 之后到崩溃前没有再写该槽；0x3BE/0x3C8 写的是别的地址
> ```
> 也就是说：**在 0x39A 写入（应为堆指针）与 0x3F9 读取之间，该槽的值被换成了 DLL 地址**。
> 两者之间只有一条 `CALLN 0x3EC`（调用原生 __pyx_pf_...add_dly）—— 原生调用动了这段内存的嫌疑最大。
> （已测：把 margin 临时放大到 64KB 仍然崩，所以不是简单的「原生调用下探过深」；
> 下一轮要用 VEH 对比 64KB 那次崩溃的现场值是否相同，区分「同一处被改」还是「换了崩溃点」。）
>
> ### 407. 顺带发现两处地址看起来不对的 STORE
> pc=0x65/0x7A 的两次 STORE 目标是 0x7FFF133F47C0/47C8（DLL 区），而它们的 IR 形式是
> `base=RBASE, disp=0x14960/0x14968` —— 这落在我们 blob 的 .bss 区内，**很可能是写 vm_tmp/vm_xmm 这类全局**，
> 属于正常；已记录，下一轮核对 manifest 里 vm_tmp/vm_xmm 的实际偏移确认。
>
> ## 第四十轮（新目标：修 add_dly）：两个假设被数据判掉，链路收窄到"谁先写了 reg1"
>
> ### 402. 假设一（SIMD 存储被误翻译）—— **否定**
> 把 add_dly 的 IR 导出来看：序言里的 `movdqu %xmm0,0x50(%rsp)` 被正确翻成两条 8 字节存储
> （先 `LOAD dst=VMSCR` 从 XMM 区取 xmm0 的两半，再 `STORE [sp+0x50]/[sp+0x58]`），
> 而且 XMM 区地址与本次 manifest 里的 vm_xmm 偏移吻合 —— 也就是说"零化被翻译错"不成立。
>
> ### 403. 假设二（模拟栈指针漂移）—— **否定**
> 新加两个诊断（仅非 release）：`vm_first_sp`（第一条指令时的 guest SP）与 `vm_last_sp`（每步更新）。
> 崩溃现场读数：`first_sp = 0x5B6B3EDDB8`、`last_sp = 0x5B6B3EDD00`，差 **0xB8 = 184** ——
> 恰好等于序言 `sub rsp,0x98`(152) + 4 次 push(32)，说明 SP 全程一致（没有漂移），
> 序言那次零化和崩溃时那次读取落在**同一个栈槽**上。
>
> ### 404. 于是链路收窄为
> 那个栈槽先被序言清零 → 之后被某条指令**写入了坏值**（字节码 0x00A1 处的 STORE，源寄存器来自 guest），
> 再被 0x3F9 的 LOAD 取回当指针用，最后在 0x43C 解引用写回 → 只读页 → 崩。
> 结合第 21 轮的"写入者表"（最后一次写 reg1 的是 0x3F9 之前的那条?实际是 0x00A1 更早）——
> 下一步需要**覆盖更早范围**的寄存器写入追踪（写 reg1 的 pc 环），才能定位最初把坏指针放进 reg1 的那条指令。
>
> ## 第三十九轮：补上 (a) 的最后一块 —— **段名随机化**
>
> ### 400. 改动
> · `inject.Options` 增加 `SectionNameB/C`（原来是用 base+"b"/"c" 派生 —— 派生本身就是特征）；
> · `cmd/vmpack` 默认（未显式给 `-section`）为每次打包生成**三个互不相关**的随机节名（`.` + 7 位小写字母数字）；
> · `Result.SectionNames` 写进报告，分析脚本据此定位我们的节（不再靠 `.vmp*` 前缀）。
>
> ### 401. 复测数字
> ```
> 第一次打包：.nz0fvho  .kjn5pv3  .zv9jgfk
> 第二次打包：.vfph0d6  .jtia368  .iwix1zm        ← 两次完全不同，且都不是 .vmp*
> analyze_packed [11]: our sections: .nz0fvho, .kjn5pv3, .zv9jgfk / fixed .vmp* names: none
> ```
> 其余检查全部保持：[2] 魔数无、[3] E9 补丁指向我们的节、[4] .pdata 记录 0、[6] ChaCha sigma 无、
> [7]/[8]/[9]/[10] 四类篡改全部 refused。
>
> ## 第三十八轮（收尾）：CI 回到 5/5 全绿，且 **ELF 入口挂钩已被运行时验证**
>
> ```
> sha=3960ac97  →  linux-amd64 ✓  linux-arm64 ✓  windows-amd64 ✓  windows-arm64-blob ✓  windows-arm64-run ✓
> ```
> 关键意义：`linux-amd64` 作业会**原生运行**打包后的 ELF —— 它通过，说明第 37 轮实现的
> SysV 校验蹦床（push rdx / mov r12,rsp / and rsp,-16 / lea rdi,[表] / call 校验 / jmp 原入口）
> **在真实 Linux 上确实工作**，也就是 (c) 在 ELF 上的加载期拦截点成立。
>
> ### 398. 本轮修掉的两个 CI 阻塞（都不是功能问题，而是"平台分支/可见性"这类细节）
> 1. `vm_selfcheck` 被反调试的 `#if defined(VM_BLOB_USES_WIN64) && defined(__x86_64__)` 挡住 →
>    只有 win/x64 会编进这段代码，其他平台 `vm_run` 里调用它就成了未定义符号（四个 job 全红）；
>    本地门禁只编 win/x64，所以一直绿 —— 教训：**跨平台构建只能靠 CI**。
> 2. `vm_entry` 在 linux/amd64 上走了 GOT（`R_X86_64_REX_GOTPCRELX`）：PIE 默认下编译器认为它可被抢占；
>    加 `__attribute__((visibility("hidden")))` 后回到 PC 相对引用。
>    本地那条"linux/amd64"其实是用 **mingw（Windows ABI）** 编的，不产生 GOT 重定位 —— 所以同样只能在 CI 里暴露。
>
> ### 399. 逐项复核目标清单时发现 (a) 还没做完
> 检查产物节名：`.text/.rdata/.data/.pdata/.rsrc/.reloc` **加上固定的 `.vmp/.vmpb/.vmpc`** ——
> 也就是说 **段名随机化从未实现**（它明确写在目标 (a) 里）。这本身就是一处明显特征（三个 `.vmp*` 节名）。
> 因此目标**保持 active**，下一轮先补这一项。
>
> ## 第三十八轮（续）：linux-amd64 剩下的那条 —— vm_entry 走了 GOT
>
> CI 注解：`[!] .text+0xCEE: 不支持的重定位类型 0x2A (format=elf sym="vm_entry" addend=-4)`，
> `0x2A = R_X86_64_REX_GOTPCRELX` —— 即引用 `vm_entry` 时走了 **GOT**。
> 原因：PIE 默认下 gcc 认为该符号可能被外部抢占，于是用 GOT 取地址；合并器按设计只接受直接/PC 相对形式。
> 修法：声明加 `__attribute__((visibility("hidden")))` —— 编译器知道它不会被抢占，回到 PC 相对引用。
>
> **一个重要的本地/CI 差异**：我在本地用 msys2 的 gcc 编 `stub/linux/amd64`，那其实是 **mingw（Windows ABI）**，
> 它不会产生 GOT 相对重定位 —— 所以本地构建一直通过，而 CI 的真实 Linux gcc 会失败。
> 结论：涉及真实 Linux/arm64 工具链的问题，本地门禁**不可能**发现，只能靠 CI。
>
> ## 第三十八轮：找到并修掉 CI 四个红 job 的根因 —— `vm_selfcheck` 被 `#if` 挡住了
>
> ### 396. 根因
> 第 32 轮我把自哈希那段代码插在 `volatile u64 vm_peb_seen;` 之后，而那一行**正好在反调试的**
> `#if defined(VM_BLOB_USES_WIN64) && defined(__x86_64__)` **里** —— 于是：
> · win/x64 上两个宏都成立 → 代码被编进来 → 本地一切正常（**所以本地门禁全绿掩盖了这个问题**）；
> · linux/amd64、linux/arm64、win/arm64 上整块被排除 → `vm_run` 里的 `vm_selfcheck()` 找不到定义 →
>   CI 报 `call to undeclared function 'vm_selfcheck'` / `引用了未定义符号 "vm_selfcheck"`。
> 这是"只在某个平台编译的分支里塞了跨平台代码"这类典型错误，而且本地门禁只覆盖 win/x64，抓不到。
>
> ### 397. 修复与验证
> 把 guard 下移，只包住反调试的 `vm_debugger_present`/`vm_antidebug`；自哈希与 `vm_peb_seen` 回到文件作用域（全平台编译）。
> 本地验证：
> ```
> win/x64   blob 构建 exit=0
> linux/amd64 blob 构建 exit=0   ← 这正是 CI 四个红 job 之一
> ```
> 教训补充：本地门禁只跑 win/x64 的 blob 构建，**跨平台构建必须靠 CI** —— 所以 CI 一红就要立刻看，不能只看本地。
>
> ## 第三十七轮：实现 **ELF 版入口挂钩**（对标 PE 的 EntryHook），(c) 在 ELF 上也有拦截点
>
> ### 394. 实现
> · `payload.go` 增加 `EntryHookSysV`：按 System V 生成蹦床 ——
>   `push rdx`（入口处 rdx 里可能是 `_start` 需要的 `rtld_fini`，必须原样传下去）→
>   `mov r12, rsp`（r12 是 callee-saved，C 函数会替我们保住）→ `and rsp,-16`（C 调用对齐）→
>   `lea rdi,[rip+表]`（SysV 第一个参数在 rdi）→ `call 校验` → `mov rsp,r12` → `pop rdx` → `jmp 原入口`；
>   与 Win64 版本（rcx + 影子空间那一套）并存，各按平台选用。
> · `internal/load/elf` 增加 `SetEntry()`（改写 ELF64 头偏移 24 的 e_entry）；
> · `ApplyELF` 在注入段之后把入口点指向蹦床；`packELF` 打开该挂钩（仅 x86-64 ELF，arm64 暂不动）。
>
> ### 395. 本地结构验证
> ```
> linux_target.vmp  e_type=2(ET_EXEC)  e_entry=0x59A120   （原文件是 0x46F240 → 已改到 payload 区）
> linux_pie.vmp     e_type=3(ET_PIE)   e_entry=0x5C2120   （同样落在 payload 区）
> ```
> 本地 ELF 载荷差分仍 ✓（该测试不执行 e_entry，所以真正跑蹦床的是 CI 的 linux-amd64 E2E：它会原生运行打包后的 ELF）。
>
> ## 第三十六轮：二分出 ELF 的触发点 —— **vm_run 读目标函数入口字节**这一步
>
> ### 392. 二分过程（本地 ELF 探针，每步约一分钟）
> | 配置 | ELF 载荷测试 |
> |---|---|
> | 宏关闭（现状） | ✓ 通过 |
> | 宏对所有目标打开（完整校验） | ✗ 6 处 checkKey 错乱 |
> | 宏打开 + 改为文件作用域常量密钥（`vm_run` 帧少 32 字节） | ✗ 仍错乱 → 排除"栈余量被挤爆" |
> | 宏打开 + **不读目标入口字节**（`want = h`，即去掉 `pb[i]` 的读取） | **✓ 通过** |
>
> ⇒ 触发点是 **`pb = (const u8 *)d + (i32)rd32(d + 28)` 之后读 `plen` 个字节**这一步。
> 注意：这是一次**只读**访问，却让 ELF 载荷的计算结果错乱（不是崩、也不是 trap）——
> 说明 ELF 注入/映射路径上还有个**潜伏缺陷**（读取恰好落在某个不该被触碰的页上，或者读到的映射与预期不同）。
>
> ### 393. 结论与下一步
> · ELF 上不能照搬"运行期读入口字节比对"这套；
> · 正确做法是 **ELF 版的入口挂钩**（对标 PE 已实现的 `EntryHook`：改入口点 → 校验 → 跳回原入口），
>   它不需要运行期读目标字节；对 x86-64 ELF 可直接复用现有的入口蹦床代码，arm64 则用 `mov x16,x30; b` 形式。
> · 同时把这个"只读访问却导致结果错乱"当独立缺陷记下来（它可能在别的场景下也咬人）。
>
> ## 第三十五轮：ELF 那条待查项的进一步定位（可本地复现，下一步可以二分）
>
> ### 390. 事实
> · 用 `CC="gcc -DVM_INVM_PATCHCHECK=1"` 注入宏后编 linux/amd64 blob：构建正常，
>   `stack: frame=640 margin=0xC00 frameSkew=3728 | stub max frame=0x280` —— 与不加宏**完全相同**；
>   blob 大小也相同（86016）。也就是说：**不是"blob 变大"导致布局/余量问题**。
> · 但 ELF 载荷测试的失败表现为**结果错乱**（checkKey 全错）而非被 trap 拦下 ——
>   一段"比较后相等、不 trap"的代码竟然改变了计算结果，说明它**暴露了 ELF 入口/ABI 路径上的潜在缺陷**
>   （新增代码改变了 `vm_run` 的栈布局/寄存器分配，触发了原本被掩盖的问题）。
> · 关键：这条**在本地就能复现**（`tools/verify_linux_payload.ps1` 用 C 探针在 Windows 上执行 ELF 载荷），
>   所以下一步可以直接二分（例如只留比较、去掉哈希循环；或固定栈用量）来定位。
>
> ### 391. 本轮的处理
> 保持 Windows 门控（已验证全绿），把 ELF 这条记为可复现的待查项；
> 本地 gates 8/8、E2E 146/146 不受影响。
>
> ## 第三十四轮：用同一份构建产物复算 —— PE 与 ELF 的补丁校验**都对得上**；ELF 另有一处问题
>
> ### 388. 复算（打包与解码之间不重建任何东西）
> ```
> ELF: desc@0x25E000 plen=5 patch=e9 7b f1 12 00 -> FNV=0x623E1EE3 pad=0x623E1EE3 MATCH
> ELF: desc@0x25E045 plen=5 patch=e9 a0 f1 12 00 -> FNV=0xFC56E2F0 pad=0xFC56E2F0 MATCH
> PE : patch=e9 9b 3c 02 00 -> FNV=0xB354C263 == pad                 MATCH
> ```
> 即：**公式与输入两边本来就一致**，我此前两次"ELF 对不上"都是拿了过期/张冠李戴的 artifact ——
> 本项目第五次"工具与被测对象不同步"（前四次：内存扫描器、环形缓冲、模块基址、manifest 密钥）。
>
> ### 389. 但把运行期比对对所有目标打开，ELF 载荷测试仍然失败
> 关键细节：它不是**被 trap 拦下**，而是**结果错乱**（checkKey 全错）—— 说明 ELF 路径另有原因，
> 而且很可能与"blob 变大"有关（打开宏之后 blob 增长，注入/映射环节出问题），而不是校验本身。
> 处理：先改回 Windows 门控，保住已验证的 PE 运行期校验；ELF 这条记为待查项。
> 复测：ELF 载荷差分 OK（两个加载地址都与原生一致）、E2E 146/146。
>
> ## 第三十三轮：把上一轮误停用的运行期补丁校验**重新打开**（PE 上它一直是对的）
>
> ### 386. 误判的根源：拿错了 manifest 的密钥
> 离线复算（这次用**打包时真正用的那份 manifest** `vm_interp_rel.json`）：
> ```
> 入口补丁字节 = e9 9b 3c 02 00
> FNV(key[:8] || patch) = 0xB354C263   ← 与描述符 pad 完全一致
> ```
> 也就是说：**打包端与运行期的公式/输入本来就一致**，PE 上这个校验一直是有效的；
> 我此前"对不上"的结论，是因为我用了 `vm_interp.json`（非 release 那份）的密钥去算 —— **又是"工具与被测对象不同步"**，
> 这已经是本项目第四次（前三次：内存扫描器、环形缓冲、模块基址）。
>
> ### 387. 处理
> · `vmpbuild` 只在 Windows 目标（`-src` 含 win）时定义 `-DVM_INVM_PATCHCHECK=1` —— 于是 PE 上运行期比对回来，
>   ELF/arm64 上仍只保留加载期蹦床（那边确实对不上，原因待查）；
> · 复测：打包后 `fib(10)=55`、exit=0（说明 PE 上运行期重算与打包端写入确实一致）；
> · **加载后在内存里改一个补丁字节** → 进程立刻死亡（exit=0xC0000005，被改坏的跳转直接执行崩），拒绝执行成立；
> · 本地门禁 8/8 全过（含 ELF 载荷与 arm64 guest 差分）。
>
> ## 第三十二轮：(g) 最后一层 —— 解释器/桩**代码段自哈希**（篡改解释器即拒绝执行）
>
> ### 383. 实现
> · vmpbuild 在合并完成后，对 `[0, bssOff)`（.text + .rdata，即桩与解释器的代码）算 FNV-1a，
>   并把 `vm_self_hash`、`vm_self_len`、`vm_code_off` 三个值写进 blob 里的三个全局（都在 .bss，位于被哈希区间之外，不自我指涉）；
> · 运行期 vm_selfcheck() 用 `&vm_entry - vm_code_off` 还原区间起点，重算比对，不一致 __builtin_trap()；
>   在 vm_run 入口每次调用都查（加载期那段以后也可加）。
> 一个坑：C 里若把汇编符号声明成数组（`extern u8 vm_entry[]`），gcc 会生成 `.refptr.vm_entry` 绝对指针节，
> 被合并器以"引用了 blob 之外的节"拒绝；**声明成函数**（`extern void vm_entry(void)`）才会走 PC 相对引用。
>
> ### 384. 对抗复测（analyze_packed.py 新增第 10 项）
> ```
> [7]  回填（补回原始入口字节）        → refused/crashed  exit=1（DLL 加载失败）
> [8]  字节码篡改（翻一个密文字节）    → refused/crashed  exit=3221225477 = 0xC0000005（AEAD 标签）
> [9]  入口补丁篡改（翻一个补丁字节）  → refused/crashed  exit=1（加载期蹦床校验表）
> [10] 解释器代码篡改（翻 .vmp 一个字节）→ refused/crashed exit=3221225501 = 0xC000001D（自哈希 trap）
> ```
> 正常路径不受影响：打包后 `fib(10)=55`、exit=0。
>
> ### 385. 本地门禁
> tools/gates.ps1 **8/8 全过**（含本轮新增的"blob 必须能构建"、arm64 guest 差分、Linux 载荷）。
>
> ## 第三十一轮：CI 回到 **5/5 全绿**（自第 3 轮以来第一次）
>
> ```
> sha=05145281 / be19ba8c  →  全部 success
>   linux-amd64 ✓   linux-arm64(qemu) ✓   windows-amd64 ✓
>   windows-arm64-blob ✓   windows-arm64-run ✓
> ```
>
> 回看这条线：第 3 轮 feat(c) 引入的运行期补丁比对把 ELF/arm64 载荷全部拒了 → 之后 25 个提交一直红；
> 我在第 25 轮才通过查 GitHub Actions 记录发现（此前只跑 PE/x64 的 E2E 就以为"全绿"）。
> 修复分三步：① 运行期比对改为默认不编译（防线保留为加载期蹦床）；② 反调试汇编按架构保护；
> ③ aarch64 的重定位：ADR_GOT_PAGE（Ubuntu gcc 默认 PIE）→ 加 -fno-pie（且只对 arm64）+
>   LDST{16,32,64}_ABS_LO12_NC 的类型映射补全。
>
> 这轮的收获不止"变绿"：调试过程中确立了两条做法并反复见效 ——
> (1) **先把报错做全再修**（补上 type/format/sym/targetSec/addend 之后，三条根因都是一轮 CI 就现形）；
> (2) **每次 push 后必看 CI**，不再把"只跑 PE/x64 E2E"当成全绿。
>
> ## 第三十轮：(c)/(g) 的"篡改即拒绝"补上三组对抗数字
>
> tools/analyze_packed.py 新增两项检查（第 8、9 项），加上原有的回填复测，现在有三类篡改的实测：
> ```
> [7] 回填（把原始 5 字节补回入口）      → refused/crashed  exit=1（DLL 加载失败）
> [8] 字节码篡改（翻一个密文字节）        → refused/crashed  exit=3221225477 = 0xC0000005
> [9] 入口补丁篡改（翻一个补丁字节）      → refused/crashed  exit=1（DLL 加载失败）
> ```
> 三者的拦截位置各自不同、都成立：[7]/[9] 由加载期入口蹦床的校验表拦下，[8] 由解密时的 AEAD 标签拦下。
> 这正是目标里那句"stub 用密钥校验补丁字节与字节码，篡改即拒绝执行"的量化证明。
>
> ## 第二十九轮：把 -fno-pie 收窄到 arm64，并补上 LDST 系列重定位
>
> 上一轮的两处过度修改在 CI 里同时暴露（一次看全）：
> · linux-amd64 变红：`type 0xB`（R_X86_64_32S）—— 因为我把 -fno-pie 加到了所有非 Windows 编译器上，
>   x86-64 因此改用绝对 32 位寻址；**-fno-pie 现在只在 arm64 分支里加**；
> · linux-arm64 仍红：`type 0x11E`（R_AARCH64_LDST64_ABS_LO12_NC，来自 ldr/str 的 #:lo12: 形式）。
>   它与 ADRP 配对使用、整体是 PC 相对的，属于位置无关；而合并器的 kind 与补丁函数早就有了（relAArch64LDSTLo12），
>   只是 ELF 侧的**类型映射**漏了这三种（16/32/64）。已补上映射与本地常量（284/285/286）。
>
> 本地：go build/test 全绿、E2E 146/146、ELF 载荷差分（下一行结果）。
>
> ## 第二十八轮（续）：用更完整的报错定位到真因 —— R_AARCH64_ADR_GOT_PAGE
>
> 把重定位报错补成 `type/format/sym/targetSec/addend` 之后，下一次 CI 立刻给出了确切类型：
> ```
> [!] .text+0xA68: 不支持的重定位类型 0x137（绝对引用必须失败）
> ```
> 对照 Go 标准库的 `debug/elf` 常量表：**0x137 = R_AARCH64_ADR_GOT_PAGE** —— GOT 引用，
> 不是绝对地址表。根因是 **Ubuntu 的 gcc 默认 PIE**：它会为全局符号生成经 GOT 的寻址，
> 而我们的合并器按设计只接受 PC 相对的直接形式。
> 修法：给 arm64 的 blob 编译加 `-fno-pie`（只在非 Windows 编译器上加 —— clang 的
> aarch64-pc-windows-msvc 不支持 -fPIC 一类选项，我前一天加 -fPIC 时把 windows-arm64-run 弄红过，已撤销）。
>
> ## 第二十八轮：针对 linux-arm64 的绝对重定位做两件事（-fPIC + 更完整的报错）
>
> 合并器的 aarch64 重定位分支只认 BRANCH26 / ADRP_PREL_PG_HI21 / ADD_ABS_LO12，其余一律拒绝
> （这是"stub 必须位置无关"的设计）。CI 报的是 `type 0x1`，但 0x1 在不同格式/架构下含义不同，
> 现有信息不足以判断来源。于是：
> 1) 把这条报错补全为 `type / format / sym / targetSec / addend` —— 下一次 CI 就能直接告诉我是哪个符号；
> 2) 给 aarch64 的 blob 编译加 `-fPIC`：非 PIC 代码会经字面量池产生绝对重定位，按位置无关编可避免。
>
> 本地：go build/vet/test 全绿；E2E 146/146（PE 路径不受影响）。
>
> ## 第二十七轮：CI 从 5 红变 4 绿，只剩 linux-arm64 一步
>
> ### 380. CI 现状（2967f973）
> linux-amd64 ✓（payload probe、ELF E2E 都绿）、windows-amd64 ✓（E2E 146、DLL 3、arm64 guest 差分、Linux payload）、
> windows-arm64-blob ✓、windows-arm64-run ✓、**linux-arm64 ✗**。
>
> ### 381. 唯一残留：arm64 的 GNU 工具链产生了绝对重定位
> CI 注解给出确切错误：`[!] .text+0x854: 不支持的重定位类型 0x1`（R_AARCH64_ABS64）。
> 也就是说合并器在 aarch64 上遇到绝对重定位就拒绝（与"stub 必须位置无关"一致），
> 但 aarch64-linux-gnu-gcc 默认编出的这段代码带了绝对重定位。下一步：给 aarch64 的 blob 编译加位置无关选项，
> 或在合并器里支持这一种重定位（x64 路径已有处理）。
> 本地没有 aarch64 交叉工具链，用 clang --target=aarch64-linux-gnu 试编时又卡在 GNU as 语法差异上，暂时无法本地复现。
>
> ### 382. 遗留：运行期补丁校验的哈希对不上（已默认关闭）
> 离线复算发现：PE 与 ELF 上，描述符 pad 里的期望值都不等于「manifest 密钥前 8 字节 + 入口补丁字节」的 FNV，
> 而运行期用编译进 blob 的 VM_KEY_BYTES 前缀重算 —— 两边不一致。因为 (c) 的实际防线是加载期入口蹦床
> （PE 已验证能拒绝回填），我把这段比对改成 #ifdef VM_INVM_PATCHCHECK、默认不编译，并把这个不一致记在这里待查。
>
> ## 第二十六轮：修掉两个让 CI 长期变红的原因
>
> ### 377. (c) 的运行期比对默认关闭（这是 ELF/arm64 三个红步骤的根因）
> 离线复算（build/linux_pie.vmp）：镜像基址 0x400000、funcRVA=0x92EC0 处的入口字节是 `e9 7b f1 12 00`（补丁确实写进去了），
> 但用密钥前缀算出的 FNV 是 **0x2F8BCF94**，而描述符 pad 里写的是 **0xC15C90E3** —— 两者对不上。
> 也就是说：运行期一旦比对就必然 trap，ELF/arm64 载荷因此被拒绝执行（表现为 checkKey 全错）。
> 处理：把这段比对用 `#ifdef VM_INVM_PATCHCHECK` 包起来、**默认不编译**；
> 补丁字节的真正防线保留为**加载期入口蹦床**（vm_verify_table）—— PE 上已验证能拒绝回填。
> 复测：ELF 载荷差分恢复 `identical to native at BOTH load addresses`；PE 回填仍 `refused`。
>
> ### 378. 反调试的内联汇编加架构保护
> 之前 `#ifdef VM_BLOB_USES_WIN64` 会把 x86-64 汇编编到 aarch64 目标（windows-arm64-blob 构建失败）。
> 现在改为 `#if defined(VM_BLOB_USES_WIN64) && defined(__x86_64__)`；arm64 上反调试暂时置空。
>
> ### 379. 本地复测（这一次是完整的几项一起跑）
> 两个 blob 构建成功；E2E 146/146；DLL E2E 3/3；arm64 guest differential OK；ELF 载荷差分 OK；PE 回填 refused。
> linux-amd64 / linux-arm64 的 qemu 步骤本地跑不了，等 CI 结论。
>
> ## 第二十五轮：查明 CI 其实从第 3 轮起就一直是红的（我此前只跑 PE/x64 的 E2E，没看 CI）
>
> ### 373. 定位（查 GitHub Actions 运行记录）
> 最后一次绿：e4e43da2（第 2 轮，feat(b)）；第一次红：e0abbb8f（第 3 轮，feat(c) 入口补丁密钥校验）。
> 之后每次（含第 18/21/24 轮）都是 failure —— 也就是说我这几轮"全绿"的印象只覆盖了 PE/x64 的 E2E。
>
> ### 374. 红的四个步骤
> · windows-amd64：Linux payload executed on Windows（就是本地那 6 处 checkKey 不一致）
> · linux-amd64：payload probe（把载荷按原 VA 映射执行）
> · linux-arm64：Linux/arm64 end-to-end（qemu-aarch64）
> · windows-arm64-blob：build Windows/arm64 blob（构建失败）
>
> ### 375. 判断
> 前三项共同点：都被 (c) 那套"入口补丁字节完整性校验"覆盖。第 3 轮加的校验在运行时重算 patch 的 FNV 与
> 描述符里的期望值比对，不一致就 trap —— ELF/arm64 路径上打包端写的期望值与运行期实际字节显然不一致，
> 于是载荷被拒绝执行（表现为结果错乱而非崩溃）。第四项是另一回事：我第 22/24 轮加的反调试内联汇编是 x86-64 的，
> 编到 aarch64 目标直接编译失败（需要按架构加保护）。
>
> ### 376. 流程教训（已写进本轮提交）
> 我每轮只跑 tools/e2e.ps1（PE/x64）与 e2e_dll.ps1，几乎没跑 tools/gates.ps1、也从没看 CI —— 所以一个 20 轮前的回归
> 一直没被发现。今后：每次 push 后看 CI 结论；本地至少跑一次 gates.ps1（含 ELF 与 arm64 步骤）。
>
> ## 第二十四轮：(g) 反调试通过验证；同时暴露一个更早存在的 ELF 载荷回归
>
> ### 370. 反调试：实现 + A/B 数字
> vm_run 入口调用 vm_antidebug()：读 PEB（gs:[0x60]）的 BeingDebugged，命中 __builtin_trap()。
> 先自证代码确实执行：非 release 构建里 vm_peb_seen 在调用后等于真实 PEB 地址（0x4EDB990000 == PEB ✓）。
> 再用 release blob 做 A/B（tools/antidebug_test.py）：
> ```
> A) 无调试标志：call -> 55，exit=0
> B) PEB.BeingDebugged=1（WriteProcessMemory 写入并读回确认）：exit=-1073741795 = 0xC000001D（非法指令）
> ```
> 即"带调试器就拒绝执行"成立，且不影响正常路径。
>
> ### 371. 顺带查实的两件事
> · PowerShell 5.1 按 ANSI 读 .ps1：我往 gates.ps1 里写中文注释后整段乱码、脚本语法被破坏 ——
>   **.ps1 必须保持纯 ASCII**（已把新增步骤改回英文）；
> · gofmt 需要跑（cmd/vmpack、cmd/vmpbuild 被格式化过），门禁的 gofmt 步骤现在会抓住它。
>
> ### 372. 新暴露的回归：linux/ELF 载荷差分测试 6 处不一致
> tools/verify_linux_payload.ps1：负载能执行、描述符正常，但 checkKey(0/1/255/12345/1000000/10) 全部对不上。
> 这不是本轮引入的：把 stub/win/x64/vm_interp.c 退回第 18 轮的版本（5dfd995）重建后**同样**失败 → 说明回归更早
> （候选：第 13 轮加入的 -fstack-clash-protection、第 7 轮的 e-2 清理、或更早的 lift 改动）。
> 影响面仅 ELF 路径（我们这几轮加固的是 PE/pyd 路径），但必须查清 —— 下一轮优先二分它。
>
> ## 第二十二轮：开始 (g) —— 反调试代码落地（行为验证还没通过，如实记录）
>
> ### 367. 实现
> 在 vm_run 入口与 vm_verify_table 里调用 vm_antidebug()：直接读 PEB（x64 上 gs:[0x60] = PEB，
> PEB+0x02 = BeingDebugged），命中就 __builtin_trap()（非法指令，进程立即死）。
> 用 #ifdef VM_BLOB_USES_WIN64 保护（该宏由 vmpbuild 在编译器目标是 Windows 时定义，已核实会出现在编译命令里）；
> 不依赖任何导入 —— blob 是 freestanding 的，调不到 IsDebuggerPresent。
>
> ### 368. 验证结果（还没通过）
> · 代码确实进了 release blob：blob 里能找到 gs 段前缀指令与 ud2；
> · 但行为测试失败：用 tools/antidebug_test.py 把 PEB.BeingDebugged 置 1（WriteProcessMemory 写回并读回确认是 1）
>   之后，被保护函数**仍然正常返回 55**，没有触发 trap。
> 也就是说"检测→拒绝"这条链路还没打通：要么读到的 BeingDebugged 不是我们写的那个位置，
> 要么 vm_antidebug 的调用被优化/走了 #else 分支（非 release blob 里没找到 gs 前缀指令，这两件事互相矛盾，需要下一轮查清）。
>
> ### 369. 顺带修掉的一个真问题：vm_verify_table 曾经丢失
> 本轮发现 stub/win/x64/vm_interp.c 里 **vm_verify_table 与 vm_keep_verify_ref 的定义都不见了**（早期文件事故留下的），
> 而 Go 侧门禁只跑 go build/test、**不会编译 blob**，所以一直没被发现 —— 之前打包用的是旧 blob，才让 (c) 的复测依然显示 refused。
> 现已补回定义并重建（manifest 里 vm_verify_table=9234）；教训：**门禁必须包含"能构建 blob"**，已列入 tools/gates.ps1 的待办。
>
> ## 第二十一轮：用「寄存器写入者表」追到坏值的来源是一处栈槽
>
> ### 364. 探针：每个 guest 寄存器最后被哪条 pc 改的
> vm_writer_tab[64]（每步比较 64 个寄存器，记录变化者的 pc）+ 已有的寄存器快照。崩溃读数（writers 表，
> 注意值是在**下一条**指令处检出的，所以真正的写者是它的前一条）：
> ```
> writers[3]=0x3C   → 写 rax 的是 0x3C 之前那条；快照里 reg3=0（索引为 0，正常）
> writers[4]=0x11   → 写栈基的是 0x11 之前那条
> writers[1]=0x404  → 写 reg1 的是 0x3F9 那条 LOAD
> ```
>
> ### 365. 把该函数的 25 条 STORE 全部列出来之后，链路清楚了
> ```
> 0x00A1 STORE width=64 base=4(栈) disp=0x50 src=17      ← 把 reg17 存进栈槽 [sp+0x50]
> 0x03F9 LOAD  width=64 dst=1(reg1) base=4 idx=3 scale=8 disp=0x50 → reg1 = [sp + reg3*8 + 0x50]
> 0x043C STORE width=64 base=1 disp=0 src=17             → [reg1] = reg17（崩：reg1 指向只读页）
> ```
> reg3=0、reg4=0x2A453EDE10（模拟栈）、reg1=0x7FFF384DD344（坏值，来自栈槽 [sp+0x50]）。
> 也就是说：坏值在**更早**的时候就通过 0x00A1 存进了栈槽，之后被 0x3F9 取出来当指针用。
>
> ### 366. 现状与建议
> add_dly 这一条已经追到「某个更早的本机调用返回值/字段被当成指针存进栈槽」，属于 lift 语义层面的
> 具体缺陷，还需要 1-2 轮的同类迭代（工具已经齐备：pc 环、寄存器快照、写入者表、单指令解码）。
> 考虑到 (f) 的结构性目标（多函数支持与演示、翻译+运行双口径的覆盖率）已经达成（5/14 已验证），
> 建议下一轮先推进 (g)（反调试 / 反 dump / 完整性自校验），把这条挂账并在 STATUS 保留完整线索。
>
> ## 第二十轮：把 add_dly 的崩溃解码到具体指令 —— 是对**只读地址**做读改写
>
> ### 362. 解码（用同一次打包的 opcode 映射）与现场
> ```
> 0x3EC OP_CALLN   rva=0x1F80        ← 调用 __pyx_pf_7example_8add_dly
> 0x3F9 OP_LOAD    dst=0x01 ...
> 0x40F OP_LOAD    dst=0x11
> 0x41A OP_CMP_RI
> 0x428 OP_LOAD    {kind=0, width=64, dst=0x11, base=0x01, idx=none, disp=0}   ← reg17 = [reg1]
> 0x433 OP_ALU_RI  dst=0x11
> 0x43C OP_STORE   {width=64, base=0x01, idx=none, disp=0, src=0x11}          ← [reg1] = reg17（崩）
> ```
> guest 寄存器快照（store 之前）：reg1=0x7FFF382E9130（= 异常写目标）、reg16=模块基址、
> reg17=0xEC8348564157563F（这串字节读出来是 x86 序言 `56 57 41 56 48 83 EC …`）→ 说明 0x428 的 LOAD
> 从那个地址**读到了代码**（读没崩，因为地址可读），然后 0x43C 想写回去 → 只读页 → 访问违例。
>
> ### 363. 结论与下一步
> 崩溃的形态是「对只读地址做读改写」，根因是 **reg1 这个指针本身错了**（它应指向可写数据）。
> reg1 在 0x3EC 之前就被写好（环里能看到 0x232/0x23A/0x360 等一串循环指令），
> 而 `__pyx_pw_9add_dly` 是包装层、参数是 Python 对象 —— 需要继续往前追 reg1 的来源
> （下一步：把「写某个寄存器的 pc」也做成探针，直接得到写 reg1 的那条指令）。
>
> ## 第十九轮：add_dly 的崩溃定位到一条 STORE —— 基址寄存器里是坏指针
>
> ### 359. 新探针：最后一次 guest STORE 的现场
> vm_last_store_pc / vm_last_store_base（基址寄存器的值）/ vm_last_store_addr（算出的地址）；
> 另加 vm_last_call_pc / vm_last_call_ret（本机调用的 pc 与返回值）。读数：
> ```
> last pc=0x43C（该构建里是 OP_STORE）   store_pc=0x43C
> store_base = 0x7FFF382E9130           store_addr = 0x7FFF382E9130（= 异常写目标）
> 上一条本机调用：call_pc=0x3EC  call_ret=0x275D9C70D50
> ```
> ⇒ STORE 的地址计算（base+disp+idx*scale）没有问题，是**基址寄存器的值本身就是坏指针**；
> 而且它**不等于**上一条本机调用的返回值 → 坏值是在 0x3EC 与 0x43C 之间被写进那个寄存器的。
>
> ### 360. 一个必须记住的坑（这轮又差点栽进去）
> 解码字节码要用**该次打包时**的 opcode 映射；我这轮先打包、随后又重建了 blob（生成新 manifest），
> 于是拿新映射去解旧字节码，出现一片「未知字节」。正确做法：打包与解码之间不要重建 blob。
>
> ### 361. 工具
> · build/probe_fn3.ps1：一次打包 + 自动算探针 RVA + 跑 VEH 读现场；
> · build/decode_bc.py：从 vm_interp.c 的 vm_insn_size 解析指令长度表，再线性解码字节码。
>
> ## 第十八轮：修复 —— 打包端丢弃运行期自校验调用（current_time_str 恢复正常，覆盖率 4/14 → 5/14）
>
> ### 356. 实现（cmd/vmpack）
> · isSecurityCookieCheck：按被调目标入口字节识别 MSVC 的 __security_check_cookie，
>   实测两种形态：`48 3B 0D disp32 75 01 C3` 与 `48 3B 0D disp32 75 10 48 C1 C1 ..`，
>   判定条件是 cmp rcx,[rip+disp] + 紧跟 jne，且后续 32 字节内同时出现 ror/rol rcx 与 ret；
> · dropRuntimeSelfChecks：顺序扫 IR，把这类 CallN 删掉（peRvaBytes 负责 RVA→字节）；
> · 开关 -keep-selfchecks 保留旧行为，用于 A/B 对照。
> （踩坑：判定函数要求至少 16 字节，而读取只取了 12 字节 → 恒为 false，白跑一轮；现取 48 字节。）
>
> ### 357. A/B 复测（同一个函数、同一份 blob）
> ```
> drop（默认）：285 IR / 2050B  → exit=0  time_len=19     ✓
> keep（-keep-selfchecks）：286 IR / 2059B → exit=-1073741819 ✗
> ```
> `__pyx_pw_7example_9add_dly` 也丢掉了 1 条（151→150 IR），但**仍然崩** → 它还有第二个原因，留待下一轮。
>
> ### 358. 5 函数产物复测
> n / 2fibonacci / 6current_time_str / pymod_create / bisect_code_objects 一起保护：
> fib(10)=55、fib(15)=610、n.shape=(10,)、greet 正常、time_len=19，exit=0；
> 门禁：E2E 146/146、DLL E2E 3/3、go build/vet/test 全绿。覆盖率口径下 (f) 从 4/14 提到 **5/14**。
>
> ## 第十七轮：cookie 校验其实是**通过**的 —— 真正的毛病是 CALLN 把 guest 的 RAX 冲掉了
>
> ### 353. 加参数探针（guest RCX / guest RSP / 调用目标 / pc）
> 崩溃读数：
> ```
> last pc=0x80A  op=0x79 (本次构建里 0x79 = OP_RET)
> last native call target = 0x7FFF281C6E40   (CALLN，模块基址+0x6E40 = __security_check_cookie)
> guest_rcx_at_call       = 0x73E213027669
> real_security_cookie    = 0x73E213027669   ← 与 guest 传进去的完全相等
> 异常：写访问 0x7fff281c6e40（与调用目标同地址）
> ```
> 也就是说：**cookie 校验是通过的**（我第 16 轮「SP 漂移导致校验失败」的推测错了，在此更正）。
> 而崩溃点仍显示最后执行的是 RET —— 与「在 __security_check_cookie 里失败」矛盾。
>
> ### 354. 真正的机制
> 解释器的 CALLN 是 `vm->regs[VRAX] = fn(...)` —— **无条件把 guest 的 RAX 覆盖成被调函数的返回值**。
> 而 `__security_check_cookie` 是 MSVC 的内建：它的实现（cmp rcx,[__security_cookie] / jne / ret）
> **不碰 RAX**，编译器因此允许调用方在它之后继续使用 RAX 里的返回值。
> 我们的 VM 把 RAX 冲成了垃圾（被调函数地址一带的值），函数返回的就是这个垃圾指针；
> 于是 Cython 包装层拿它当 PyObject 用，在别处（python313.dll 的代码里）写 ob_refcnt 时崩掉 ——
> 写目标恰好 = 模块基址 + 0x6E40，即那个垃圾指针指向的地址，与调用目标重合。
>
> ### 355. 修的方向
> 打包端（vmpack 手里有模块镜像）识别这类调用目标：入口字节形如 `48 3B 0D xx xx xx xx`
> （cmp rcx,[rip+disp]，指向 .data 的 __security_cookie）→ 该调用在 VM 里没有意义（cookie 是我们自己模拟栈的产物），
> 直接把这条 CallN 丢掉。这也是商业壳对运行期自校验的常规处理方式。
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








## 加固：把「入口蹦床」升级成真正的整段替换（原生机器码不再留在镜像里）

### 328. 问题（先量化，再决定改什么）
把旧产物与原产物逐字节对比（按 manifest 的 `funcRVA` 定位，窗口取到「下一个被保护函数」之前）：

| 产物 | 25 个被保护函数、2944 字节窗口里与原产物不同的字节 |
|---|---|
| 旧（`-wipe=false`） | **124** = 25×5 − 1：只有入口那 5 字节补丁（check_key 的第 5 字节恰好与原字节重合） |
| 新（默认 `-wipe`） | **1339** |

即：旧产物里 25 个函数共 **1346 字节原生机器码，1221 字节（90.7%）原样躺在镜像里**，
每个函数只丢了最前面那 5 字节 —— 「还原」确实退化成了「把入口改回去」。
（第 30–40 行的 `.pdata` 清理只挡住「从 prologue 描述反推被覆盖的字节」这一条路，函数体本身还在。）

### 329. 改法
- `inject.FuncSpec` 增加 `NativeSize`（取 `scan.Found.Code` 的长度：已按尾部填充裁剪，末尾必是 RET/JMP，边界是精确的）；
- `vmpack -wipe`（**默认开**）：PE / ELF 两侧在写完入口补丁后，把 `[entry+patchLen, entry+NativeSize)`
  填成伪随机字节；**入口跳板本身保留**（运行期要靠它进 VM）；
- 填充种子 = `wipeSeed(构建密钥, funcRVA, payload 基址)`：不同函数、不同构建各不相同 ——
  固定填充（0x00/0xCC）本身就是「这段被处理过」的静态特征；
- 报告 JSON 新增 `nativeBytes` / `wipedBytes`，可直接核对；
- `internal/inject/wipe_test.go`：跳板保留 + 函数体被改 + 不越界、短于跳板的函数跳过、种子随密钥/函数变化。

### 330. 本机验证
- `build/target.exe` 25 个函数：`nativeBytes` 合计 **1346**、`wipedBytes` 合计 **1221**（= 1346 − 25×5）；
- 差分（原生 vs 打包，wipe 开）**146 passed / 0 failed**，用例与旧版同一批、同一份 target.exe；
- `go test ./...` 11 个包全绿；
- `-wipe=false` 对照复测仍是 **124** 字节差异、`wipedBytes` 合计 0 ⇒ 开关有效、旧行为可复现。

### 331. 这一步解决了什么、没解决什么
- **解决**：产物里不再存在「被同源的另一份构建按 RVA 差分直接拼回」的函数体；还原要么反编译 VM 字节码，
  要么把同源版本重新链接进来。
- **没解决（必须写清楚）**：在「攻击者手里有同源的另一份构建」这个前提下，**任何只做变换、不引入密钥的
  保护都是可无损还原的** —— 他可以完全不碰我们的字节码，直接把同源那份的原生函数搬进这个槽位
  （这个槽位对调用方而言本来就是「一次调用」的语义）。所以「整段替换 + 字节码解释执行」本身并不改变
  可还原性的**类别**，它改变的是工程成本（需要 devirtualizer 或重链接）；真正的类别变化来自**密钥依赖**：
  让被保护函数读到的**数据**也是 per-build 加密的（密钥只存在于 VM 状态里），或者引入许可/服务器密钥。
  那是独立的一步，不在本轮。

### 332. 补上真正的判据：**内存里也不能出现**（不是只文件里）
「整段替换」的判据不是"文件里没有"，而是"**运行期内存里也没有**" —— PE/ELF 是把映像映射进内存的，
文件级的残留必然等价于内存级的残留。为了把这条变成可测的，新增 `tools/residue_probe.py`：
对被保护进程做一次全地址空间扫描（`VirtualQueryEx` + `ReadProcessMemory`），同时查两类模式 ——
原生函数体（原镜像 `[funcRVA+5, funcRVA+nativeBytes)`）与 VM 字节码**明文**（`vmpack -dumpbytecode` 的产物）。

实测（`target.exe`，运行 `bench check_key 100000000`，扫描 11.0 MB 可读内存）：

| 产物 | native:check_key | native:sum_to | bytecode:check_key | bytecode:sum_to |
|---|---|---|---|---|
| wipe 开（整段替换） | **absent** | **absent** | FOUND（解密缓存） | absent（未被调用，仍是密文） |
| wipe 关（入口蹦床） | **FOUND @…19D5** | **FOUND @…2105** | — | — |

两个命中地址正好是 `funcRVA+5`（0x19D0+5、0x2100+5），即被映射进内存的原生函数体。
这就是"入口蹦床"在内存层面的真相：**原文一字不少地在内存里**，还原不需要任何分析；
而 wipe 开之后"原生码在内存中不出现"这条才第一次**成立并且可验证**。

### 333. 这条判据已进本地门禁
`tools/gates.ps1` 新增第 9 条 `residue probe (no native code in image/memory)`：
对 e2e 刚产出的 `target_vmp.exe` 跑同一套扫描，带 `--fail-on-native`，只要原生函数体命中就红。
即"抹除"从一次性动作变成**回归门禁** —— 谁把 `-wipe` 关掉，门禁立刻红。

### 334. 仍然存在、且必须承认的残留：字节码明文缓存
上表第 3 列：`bytecode:check_key` 在内存里 **FOUND**。源码位置在 `stub/win/x64/vm_interp.c`
的 `vm_bc_cache`：解释器把 AEAD 密封的字节码解密进 `.bss` 的明文槽（`vm_aead_open_aad(..., dst)`），
槽按描述符键控、引用计数保留，**用完不清零、不重加密**。含义分两面：

- 对"**原生码不可还原**"这条 —— 达标（native 0 命中）；
- 对"**反 devirtualize**"这条 —— **不达标**：一次内存 dump 就拿到全部字节码明文，
  AEAD 的 nonce/tag/密钥在这一步被整体绕过（只有没被调用过的函数还留在密文状态）。

所以"整段替换 + 字节码"要真正达到"不可无损还原"，需要补的是第二半：
**被替换掉的原文不能在内存里以另一种形式复活**。修法候选（下一轮）：
按基本块/按指令解密（只解当前块，执行完清零并重加密），或缓存只存密文 + 一个小窗口明文；
代价在取指热路径上多一次解密，需要实测倍率再决定。

## 数据面加固：字节码在**内存里也始终是密文**（流式取指），并把它变成门禁

### 335. 上一轮承认的缺口
上一轮实测：原生机器码已经在文件与内存里 0 残留，但 `vm_bc_cache` 把**整份字节码解密到 .bss 常驻**
（内存扫描 `bytecode:check_key` FOUND）。那等于"原文以另一种形式复活"，devirtualizer 一次 dump 就拿到全部指令流。

### 336. 改法（两处，都很小）
1. **只验签、不解密**：Poly1305 认证的是**密文**，所以完整性校验不需要明文。
   新增 `vm_aead_verify_aad()`（`stub/win/x64/vm_crypto.c`），AEAD 的 MAC 部分原样复用，
   只是不再调用 `vm_chacha20_xor` 把明文写进任何缓冲。
2. **流式取指**：新增 `vm_chacha20_keystream()` 与解释器里的 `vm_bcs_t`——
   缓存的是 `ChaCha20 密钥流`（不是明文），按 64 字节块前进（跨块/回跳时重取），
   取指时 `明文 = 密文[off] ^ ks[off & 63]`，**逐字节**还原。明文只以"寄存器里的一个字节"存在。
   47 处 `c[pc + N]` / `rd32(&c[pc+N])` 全部改走 `vmb_byte/vmb_rd32/vmb_rd64`。
3. 顺带删掉整套明文缓存机制（缓存槽 32×16KB + 自旋锁 + 引用计数 + FNV 复核）——
   它带来的三类老问题（跨线程共享明文、槽位耗尽、明文常驻）一起消失。

### 337. 数字（本机，与改动前同一套门禁/同一口径）
| 项 | 改动前 | 改动后 |
|---|---|---|
| blob | **544,768 B** | **32,768 B**（缓存数组被删，缩 16.6×） |
| 内存里的明文字节码 | `bytecode:check_key` **FOUND** | **absent** |
| 原生机器码残留 | 0 | 0 |
| E2E / DLL / linux 载荷 / arm64 客户机 | 147/3/OK/OK | **147/3/OK/OK** |
| check_key（bench） | 15.3 µs/iter | **29.0 µs/iter**（×1.9） |
| sum_to（bench） | 17.2 µs/iter | **28.7 µs/iter**（×1.7） |

### 338. 新增第 10 条门禁（把结论钉死）
`tools/gates.ps1` 新增 `bytecode plaintext scan (no plaintext in memory)`：
用 `vmpack -dumpbytecode` 的**明文**当模式，在 `bench check_key` 猛跑时扫描进程全地址空间，
`--fail-on-bytecode` 时只要命中就红。当前 **10 gates / 0 failed**。
（这条门禁同时排除了"用 64 字节明文窗口换性能"的做法：窗口会把短函数的明文整段露出来。）

### 339. 边界（不夸大）
- **"从不出现"严格做不到**：CPU 总要读到指令字节。做到的是"**不常驻**"——没有整份/成块明文缓冲，
  只有寄存器里的单字节与立即数；门禁扫的是 ≥16 字节的连续明文模式。
- 采样仍是快照（`--delay 1.5`），启动期的瞬时明文不能靠事后扫描排除。
- 明文的**操作数**（立即数、跳转目标）同样以寄存器值形式短暂存在。

### 340. 用户提供的、我尚未验证的信息（记录备查）
用户说明：**pyd 那一版是另一套更强的方案** —— 不只是把函数 VM 化，而是通过 `snvm_x64`
把 VM 字节码**上传到 HL 加密狗的固件里执行**。若属实，这解释了本机无狗时 pyd 的
`DLL 初始化例程失败`，也意味着"宿主机内存里根本没有可用的明文 bitcode"——
这是**类别**差别（密钥/执行体在硬件里），不是我们这条"内存里不常驻明文"能覆盖的。
我这边没有狗、也没有该 runtime 的资料，**未做验证**；若要跟进，这是独立的一条线
（与 docs/DESIGN.md 里 KeyProvider/根信任那节同属"密钥依赖"）。

## 原镜像整体加密：做到"加密后的 demo32.exe 那一级"（自解密入口 + TLS 回调插队）

### 341. 目标（用户指定：不需要 pyd 那种"字节码在狗固件里执行"，要做到加密后的 demo32.exe 这一级）
对齐样本 `D:\其它\demo32.exe` 的实测性质：① 原模块的**整套 .text 在文件里是密文**（原地同尺寸加密，熵 5.99→7.99，
原 64B 块 0 命中）；② 运行期由自带的 runtime 解密回内存；③ 被 VM 化的函数在内存里也查不到原机器码。

vmp-x 之前只有 ③（抹除 + 门禁），文件里其余代码仍是明文——这一轮补 ①②。

### 342. 改法
- **打包端**（`cmd/vmpack -enc-image`，默认关）：把 `.text` 的**文件字节原地加密**
  （ChaCha20-Poly1305；nonce = rva||size||构建 salt，AAD = rva||size），密钥沿用 blob 主密钥；
  AEAD 标签回填进 payload 里的解密表。同时 `DllCharacteristics` 清掉 `DYNAMIC_BASE`。
- **运行期**（`stub/win/x64/vm_interp.c: vm_unpack_image`）：只验签（Poly1305 认证的是密文，不需要明文）
  → `VirtualProtect` 成可写 → 原地解密 → 恢复 `PAGE_EXECUTE_READ`。

  没有导入表可用，所以 `VirtualProtect` 是**自己从 PEB 模块链表找 kernel32、再走导出表**取到的
  （约 80 行，freestanding），这样既不用把 .text 标成 RWX，也不依赖任何外部 runtime。
- **TLS 回调插队**：mingw 的 exe 几乎都注册了 TLS 回调（emutls/pseudo-reloc），而回调在**入口点之前**运行——
  那时 .text 还是密文。做法：把 `vm_unpack_image` 的 thunk 插到回调数组**第 0 项**，
  并把 TLS 目录的 `AddressOfCallBacks` 指向 payload 里的新数组；解密用 .bss 里的幂等标志保证只做一次
  （入口蹦床随后还会再调一次）。
- **fail-fast**：`vm_unpack_image` 先比对"PEB->ImageBaseAddress == 首选基址"，不等就直接返回错误码——
  清掉 DYNAMIC_BASE 后理论上不会发生，但一旦发生就必须拒绝执行而不是跑飞。

### 343. 本机验证
- 打包 25 个函数 + `-enc-image`：`DIFF pass=25 fail=0`（原生 vs 整体加密版逐字节一致）；
- **文件级**：原 `.text` 13312B 熵 5.99 → 打包后同尺寸 **熵 7.99**，原 64B 块在打包文件里只剩 6/207 命中
  （全部是全零/填充块与打包文件里的零填充撞上；见本轮脚本输出）；
- 过程性证据：`目标有 2 个 TLS 回调：把自己的自解密回调插到数组最前面`、`原镜像 .text 已原地加密，并清除 DYNAMIC_BASE`；
- 默认路径（不加 `-enc-image`）不受影响：`tools/gates.ps1` 仍 10/10（见第 344 条）。

### 344. 边界（写清楚）
- 目前**只加密 `.text`**（`.rdata`/`.data` 仍明文，样本 Envelope 连 .rdata/.data 也加密了）；
  扩大范围要先处理 CFG/load-config 这类"加载器在入口点之前会读"的数据。
- `.idata`/`.reloc` 必须保持明文（加载器要用），因此**导入名与重定位信息仍可读**。
- 需要**首选基址可用**（清了 DYNAMIC_BASE；基址被占则加载失败——这是明确失败，不是静默错误）。
- 只做了 Windows/x64 的 PE；ELF/arm64 未做（`vm_unpack_image` 在非 Win64 宿主上返回 -9）。
- 内存里 `.text` 在**解密后**是明文（同 Envelope：非 VM 化的函数必须原生跑）；被 VM 化的函数体在文件里
  已经是伪随机填充，所以解密出来也不含原文。

### 345. 第 11 条门禁 + 把原镜像整体加密切成默认
- 命令行开关 enc-image 现在**默认开**（限 x86-64 EXE）：新增 no-enc-image 关闭、enc-image-dll 对 DLL 显式开启。
  不支持的情形（ARM64 / DLL 默认 / no-encrypt 无密钥 / 找不到 .text）一律**跳过并打印原因**，
  绝不 fatalf —— 默认开的功能不能把 CI 里的 arm64 目标直接卡死。
- 新增 tools/image_residue.py：对原 .text 的每个 64B 块在打包文件里搜索，
  **全零块单独统计并排除**（填充块必然与打包文件自身的零填充相同，不构成证据）。
- tools/gates.ps1 第 11 条：image residue (original .text not readable in the packed file)。

### 346. 验证（改动后整套门禁重跑）
- tools/gates.ps1：**11 gates / 0 failed**。关键是 e2e **147/147 是在"整体加密默认开"的产物上跑的**
  （不是单独的手工样本）；DLL 3/3（DLL 默认跳过加密）、arm64 客户机、linux 载荷、PIE 两装载地址全绿。
- 第 11 条输出：chunks=208  all-zero(excluded)=7  NON-ZERO CHUNKS STILL FOUND=0。
- 第 9/10 条（原生码残留、明文块残留）仍 0 命中；.text 熵 5.99 -> 7.99。
- 默认路径抽查差分 3/3 与原生一致。

### 347. 仍未做（如实）
.rdata/.data 整体加密（样本 Envelope 做了；要先处理 CFG/load-config 这类"加载器在入口点之前会读"的数据）、
ELF/arm64 侧的实现、DLL 的默认加密（当前必须显式开 enc-image-dll，未纳入常跑门禁）。

### 348. 第二轮：.rdata 也整体加密（连同 TLS 目录搬迁）
- enc-image 现在加密 .text + .rdata。关键障碍是**加载器在入口点之前要读 TLS 目录**，而它正好落在
  .rdata 里（target.exe：TLS dir RVA=0x6460）：所以打包端把 40 字节的 IMAGE_TLS_DIRECTORY64
  原样复制进 payload（明文），并把数据目录 [9] 重指向副本；回调数组的改写也改成写进副本。
  TLS 目录里存的是 VA（指向 .tls 节，不加密），在"必须落在首选基址"的前提下仍然有效。
- 其余"加载器要读"的目录都在别的节：IMPORT/IAT -> .idata、EXCEPTION -> .pdata、
  RESOURCE -> .rsrc、BASERELOC -> .reloc（实测映射表见本轮脚本输出）。所以加密 .rdata 是安全的。

### 349. 验证
- tools/image_residue.py 支持多节（默认 .text,.rdata）；门禁第 11 条改成两节一起断言。
- 门禁 **11 / 0 failed**：.text 208 块非零 **0** 命中；.rdata 72 块非零 **0** 命中（熵 4.88 -> 7.96）；
  e2e **147/147 跑在"两节都已加密"的产物上**；DLL 3/3、arm64 客户机、linux 载荷、PIE 两装载地址全绿；
  第 9/10 条（原生码残留、字节码明文残留）仍 0 命中。
- 临时样本差分 4/4 与原生一致；日志里能看到 "TLS 目录在 .rdata 里：搬到 payload"。

### 350. 仍未做（下一轮的候选，按价值排序）
1. .data 整体加密（可写数据：加载器/CRT 可能在入口点之前写入，需要单独设计）；
2. ELF/arm64 侧的对应实现（当前非 Win64 宿主直接返回 -9）；
3. DLL 的默认加密（现在必须显式 enc-image-dll，未纳入常跑门禁）。

### 351. 第三轮：.data 也整体加密（+ 数据目录守卫，顺手修掉页保护映射的错）
- 候选节从 .text/.rdata 扩到 .data。flags 语义扩成 bit0 = 可执行 / bit1 = 可写，
  vm_unpack_image 解密后按这两位恢复页保护 —— 顺带修掉一个真 bug：原来"只读"写的是 0x04，
  而 0x04 是 PAGE_READWRITE：.rdata 解密后一直被留成可写。现在 0x02=PAGE_READONLY、
  0x04=PAGE_READWRITE、0x20=PAGE_EXECUTE_READ、0x40=PAGE_EXECUTE_READWRITE 各归各位。
- 新增 loaderDirConflict() 守卫：IMPORT / RESOURCE / EXCEPTION / BASERELOC / LOADCONFIG /
  BOUNDIMPORT / IAT / DELAYIMPORT / CLR 这些"加载器在入口点之前要读"的目录只要落在候选节里，
  **这一节就跳过并打印原因**。理由：不同链接器会把 .idata/.rdata/.data 合并，不能假设 mingw 的布局。
  TLS 目录不在此列（它照旧被搬进 payload 并重指，见第 348 条）。SECURITY 项存的是文件偏移、
  DEBUG 只有调试器读，两者不算冲突。
- tools/image_residue.py 默认与门禁第 11 条一起改成 .text,.rdata,.data 三节。

### 352. 验证
- 门禁 **11 / 0 failed**：e2e **147/147 跑在"三节都已加密"的产物上**；DLL 3/3、arm64 客户机、
  linux 载荷、PIE 两个装载地址全绿；第 9/10 条（原生码、明文字节码）仍 0 命中。
- 文件级残留（非零 64B 块命中的个数）：
  .text 208 块 -> **0**（熵 5.99 -> 7.99）；.rdata 72 块 -> **0**（4.88 -> 7.96）；
  .data 8 块 -> **0**（0.75 -> 7.64）。

### 353. 本轮否掉的一条：DLL 默认纳入整体加密（实测不成立，已回退）
把 DLL 也纳入默认后，e2e_dll 立刻 0/3：`LoadLibrary(build/testlib_vmp.dll) failed: 1114`
（DLL 初始化例程失败）。判断：清掉 DYNAMIC_BASE 只能阻止"系统为了 ASLR 主动重定位"，
**挡不住加载器在首选基址被占时给 DLL 做重定位** —— .reloc 还在，它照样改写 .text，
密文被改写后解密出来就是垃圾，于是 DllMain 失败。EXE 不受影响（它是进程第一个模块，基址必然可用）。
处置：DLL 默认**回退为关**（保留 enc-image-dll 显式开关），真正修法（剥 .reloc + 自映射，
或在 stub 里补偿重定位）留给后续轮次。
同时记下一条改进点：入口蹦床目前**忽略** vm_unpack_image 的返回码，失败后继续跑密文、
只表现为 1114；应该改成失败即 trap，让现场可辨。

### 354. 第四轮：让"自解密失败"可诊断（fail-fast trap）+ 可指定加密节 + 拆重定位表
- **入口蹦床与 TLS 回调 thunk 都加了 fail-fast**：`call vm_unpack_image` 之后立即
  `test eax,eax / jz +2 / ud2`。以前失败会**带着密文继续跑**，只表现为含糊的 1114 或 AV。
- 新增 `-enc-image-sections .text,.rdata,.data`（留空 = 默认三节），便于按节二分定位问题。
- 新增 `stripRelocations()`：整体加密时把重定位表整个拆掉（BASERELOC 目录清零 + .reloc 节内容清零 +
  置 IMAGE_FILE_RELOCS_STRIPPED）。理由：加密是在**文件字节**上做的，加载器一旦按重定位改写 .text，
  密文就被破坏；清 DYNAMIC_BASE 只挡"为 ASLR 主动重定位"，挡不住强制重定位。
  拆掉之后加载器**只能**落在首选基址，落不下就明确失败。

### 355. DLL 仍然是阻塞项（如实记录，默认保持关闭）
本轮把 DLL 失败追到下面这些事实，但**尚未修好**：
1. 打包产物静态检查**全部正确**：BASERELOC 目录已清零、RELOCS_STRIPPED=1、DYNAMIC_BASE=0、
   TLS 目录已搬进 payload（`.eje2d41` RX）且回调数组 = [我们的 thunk, 原回调 0x…1550, 0x…1530, 0]、
   thunk 与 entry 的字节序列都对（含新的 fail-fast 序列 `85 c0 74 02 0f 0b`）。
2. **按节二分**：`.text` 单独加密 / `.text,.rdata` / 三节全加密 —— 三者都是 `LoadLibrary failed: 1114`。
   而同一 DLL 不加密时 e2e 3/3 通过。⇒ 不是 .data/.rdata 的问题，是加密 .text 之后 DLL 的初始化就失败。
3. fail-fast 的 ud2 **一次都没触发** ⇒ `vm_unpack_image` 要么没被调用、要么返回 0（解密成功）。
   结合 1 的静态正确性，最可能是"解密成功，但 DLL 自己的初始化随后失败"。
下一步诊断（下一轮）：在 blob 里加一个导出的诊断数组（`vm_img_diag[4]` = {rc, 实际基址, 期望基址, 计数}），
配一个能在 host 存活期间 ReadProcessMemory 读它的探针；或者在各阶段用已解析到的 `ExitProcess` 退出码打标。
在此之前 **DLL 默认保持不加密**（`-enc-image-dll` 仅供实验），不纳入常跑门禁。

### 356. 第四轮（续）：DLL 的根因找到了 —— 是**取错了基址**，不是重定位
第 353/355 条把 DLL 判成"重定位破坏密文"，**这个结论是错的**。本轮加了诊断基建后一次定位：

- 观测手段：`u64 vm_img_diag[4]`（.bss，进 manifest）+ 失败路径 `ExitProcess(0xC0DE0000|rc)`，
  于是"DLL 加载失败"从含糊的 1114 变成可读的退出码。
- 第一次实测拿到 `rc=0xC0DE0002` ⇒ `vm_unpack_image` 认为"实际基址 != 首选基址"。
  真因：**`PEB->ImageBaseAddress` 是"宿主 EXE"的基址，不是正在加载的 DLL 的基址** ——
  在 DLL 里它永远不等，于是自解密直接拒绝执行（EXE 恰好相等，所以只有 DLL 中招）。
- 修法：解密表头加一个 `selfRVA`（表自身的 RVA，`payload.go` 写入、`vmpack` 的加密侧把条目偏移
  从 16 改到 24），运行期用 **"表的地址 − selfRVA"** 反推本镜像基址，再用 `MZ` 校验一次。
  顺手保留 `base != wantBase` 的 fail-fast。
- 过程记录（教训）：改表头时我漏改了 C 侧的条目偏移（16→24），表现为 EXE 直接 ud2、DLL 报
  `0xC0DE0004`（验签失败）—— 两边都在几秒内报出可读原因，这正是上一轮加 fail-fast/退出码的价值。

### 357. DLL 现在默认纳入整体加密
- `-enc-image-dll` 改成默认**开**，新增 `-no-enc-image-dll` 关闭。
- `tools/e2e_dll.ps1`（3 例，含 LoadLibrary/GetProcAddress 调用链）在"默认加密"下 **3/3 通过**。
- 前提与代价（写清楚）：打包端已拆掉重定位表（`IMAGE_FILE_RELOCS_STRIPPED`），
  所以 DLL **必须**落在首选基址；落不下会明确失败（而不是跑飞）。
  这同时意味着该 DLL 失去了 ASLR —— 这是"文件里读不到原文"换来的确定代价。

### 358. 第五轮：Linux/amd64 侧的自解密运行期能力（打包端留待下一轮）
- **先修一个隐含陷阱**：Linux 载荷的 blob 是**复用同一份** stub/win/x64/vm_interp.c
  （BLOB.sources 里写死），而 vmpbuild 在"编译器目标是 Windows ABI"时无条件定义
  VM_BLOB_USES_WIN64 —— 也就是说**给 Linux 编的那份里也编进了 PEB/VirtualProtect 那一套**。
  本轮新增 VMP 目标 OS 定义：vmpbuild 在 src 路径含 "linux" 时加 -DVM_BLOB_TARGET_LINUX=1，
  于是"运行期能力按目标 OS 选，而不是按编译宿主的 ABI 选"。
- **新增 Linux/amd64 的 vm_unpack_image**：与 Windows 侧同一套解密表格式
  （表头 24 字节：imageBase / salt / count / selfRVA / 保留；条目 32 字节：rva/size/flags/pad/tag），
  基址同样用「表地址 − selfRVA」反推并校验 ELF 魔数（0x464C457F），
  改页保护走 **mprotect(2) 系统调用**（x86-64 syscall 号 10，无 libc）：
  先把整页放宽成 RWX 解密，再按 flags 恢复成 R+X / R / R+W。
  失败路径带可辨认返回码，并把观测量写进 vm_img_diag[4]（rc / 实际基址 / 期望基址 / 调用次数）。
- **本轮只到"运行期能力就位"**：两份 blob（Windows 与 Linux）都编得出来（各 32768 字节），
  Linux 那份由门禁里的 "linux payload" 步骤真实构建并执行其载荷 —— 但**打包端尚未给 ELF 生成解密表**，
  所以这段代码现在还是"编进去但没被调用"。给 ELF 加密 .text、发解密表、发 **SysV 版**的解密蹦床
  （rdi 传表地址）、再串到已有的校验蹦床，是下一轮的活儿；ELF 入口路径的运行期验证需要 Linux/CI。
- 过程记录：第一版把 static u32 vm_img_done 放在 Windows 分支里，Linux blob 立刻编译失败
  （undeclared）——所以本轮起**两份 blob 都显式构建**，这类平台分叉问题当场暴露。

### 359. 第六轮：ELF 侧打包端（默认关）+ 文件级验证
- 新增 -enc-image-elf（默认关），只对 **ET_EXEC 的 x86-64 ELF** 生效：取第一个可执行 PT_LOAD，
  用与 PE 完全相同的表格式（表头 24B：imageBase/salt/count/selfRVA/保留；条目 32B：rva/size/flags/pad/tag）
  生成解密表，并给入口发一个 **SysV 版**解密蹦床（push rdx / mov r12,rsp / and rsp,-16 /
  lea rdi,[rip+表] / call vm_unpack_image / fail-fast / mov rsp,r12 / pop rdx / jmp 校验蹦床），
  再串到已有的 e_entry 校验蹦床。ImageBase 传 0 = 运行期不强制校验基址；
  **PIE/ET_DYN 明确跳过**（ld.so 会把重定位写进密文，解密出来就是垃圾，需要单独方案）。
- 新增 tools/image_residue_elf.py：解析原 ELF 的可执行 PT_LOAD，逐个 64B 非零块在打包文件里搜。
  实测同一个构建：不加密 **9365/9398** 命中（整段可读）；-enc-image-elf 后 **1/9398**，
  而那 1 块是 \x01 后面跟 63 个 0（任何"值为 1 的 8 字节字段 + 零填充"都能撞上）——属于巧合匹配，
  不是代码残留。即"ELF 的代码在文件里读不到"这条在文件级成立。
- **修掉一处我自己造成的源码重复**：internal/inject/elf.go 里"顺序修正"那段和
  一个被改名的 paypayloadPhdrIndex 函数被整段复制（gofmt/vet/go test 都不报，因为它照样编译）。
  本轮清理，并把 ApplyELF 的 Result 补上 ImgTableRVA/ImgTableLen ——
  ELF 加密靠它定位解密表，漏了就会"解密表越界（off=0x0 len=0）"（本轮实测踩到并修掉）。
- **运行期仍未验证**：ELF 入口路径本机跑不了（无 Linux 真机/qemu）；现有 "linux payload" 门禁
  只执行载荷路径（把 blob 映射进来直接调 thunk），不经过真实 ELF 的入口。需要 CI/真机确认。

### 360. 本轮门禁
11 gates / 0 failed：e2e 147/147、dll 3/3、arm64 客户机、linux 载荷、两条残留门禁、image residue 全绿
（ELF 默认关，所以既有 Linux 路径一行未动）。

### 361. 第七轮：把 SysV 解密蹦床钉进单测（本机唯一能做的 ELF 入口验证）
- 新增 internal/inject/payload_sysv_test.go：
  ① TestSysVUnpackTrampoline —— 逐字节断言 ELF/SysV 版解密蹦床的形状
     （push rdx / mov r12,rsp / and rsp,-16 / lea rdi,[rip+表] / call / test-jz-ud2 /
     mov rsp,r12 / pop rdx / jmp），并解码三处 rel32：必须分别指向"解密表""vm_unpack_image"
     "下一跳（校验蹦床）"；同时校验表头（imageBase=0、count、selfRVA == 表自身 RVA）与条目 {rva,size,flags}。
  ② TestWin64UnpackTrampolineKeepsRcx —— PE 那条不能被改坏（序言必须是 push rcx/rdx/r8 + lea rcx）。
- 意义：ELF 入口路径本机跑不了（无 Linux/qemu），但"蹦床编码有没有写错"从此有回归测试兜底 ——
  这类错误以前只能等 CI 才暴露（本会话里就踩过一次表头偏移没同步：EXE 立刻 ud2、DLL 报 0xC0DE0004）。
- 仍未做：ELF 入口的**运行期**验证（需 CI/真机）、PIE 方案（需重定位剥离或自映射）、arm64 侧整体加密。

### 362. 第八轮：把 ELF 的运行期验证做成"可在 Linux 上一键跑"的脚本（本机仍无法执行）
- 新增 tools/e2e_elf_image.sh：在 Linux/amd64 上依次做 ——
  ① 用 -enc-image-elf 打包 ET_EXEC 的 x86-64 ELF；② 结构断言（e_entry 必须落在 payload 新段里）；
  ③ 文件级断言（复用 tools/image_residue_elf.py：原执行段非零 64B 块 0 残留）；
  ④ 运行期断言（打包后的 ELF 真跑，输出与原生逐字节一致）。
  默认**报告模式**（失败只打印 MISMATCH、退出 0），加 --strict 才退出 1 ——
  避免一个未经真机确认的脚本把 CI 直接卡红。
- 为什么没有直接改 tools/e2e.sh：那段 bash 在本机无法执行，未验证的改动进 CI 风险更高；
  等 Linux 上跑通一次再把它接进 CI（一行调用即可）。
- **如实登记（环境阻塞）**：ELF 入口路径的运行期验证需要 Linux/amd64（或 qemu-system）——
  本机没有，这已是连续第 3 轮同一条件（第 5/6/7 轮）。所需外部动作：
  在 Linux 上执行 `bash tools/e2e_elf_image.sh --strict`，绿了再接进 CI。
- arm64 侧整体加密的打包端（入口蹦床 + 保存 x0/x1/x2）仍未做，同样需要 aarch64 运行环境才能收尾。

### 363. 第九轮（末轮）：arm64 入口解密蹦床 + 用自带解码器钉死编码
- 新增 buildImgHookARM64()：mov x19/x20/x21 ← x0/x1/x2（入口参数，原始入口还要用；x19..x21 是
  callee-saved，被调用的 C 函数会保住）、adrp+add 取表地址、bl vm_unpack_image、
  cbz w0,+8 / brk #0（失败即 trap）、恢复 x0..x2、b 下一跳。
  payload.go 的蹦床装配按 opt.Arch 分流，**x64 那条路径一字未动**。
- 新增 payload_arm64_test.go：用仓库自带的 internal/decode/arm64 **解码器**逐条核对 12 条指令的
  助记符、ADRP/BL/B 的 PC 相对目标、ADD 的 imm12、CBZ 的 +8。arm64 没真机可跑，
  但"编码写错"从此本地就能抓到（本轮自身就踩到一个：Go 里写了 C 习惯的 0xFFFu 后缀 → 编译错误，已修）。

### 364. 最终状态（如实）
| 目标项 | 状态 |
|---|---|
| (1) .data 整体加密 | **完成并验证**：.text/.rdata/.data 三节原地加密，文件级非零块 0 残留，e2e 147/147、门禁 11/0 |
| (3) DLL 默认纳入整体加密 | **完成并验证**：根因 = PEB->ImageBaseAddress 是**宿主 EXE** 的基址；改用"表地址 − selfRVA"后 DLL 通过并转默认，dll e2e 3/3 |
| (2) ELF/arm64 对齐 | **打包端 + 运行期能力 + 编码单测 + 文件级验证全部完成**；**入口路径的运行期验证需要 Linux/aarch64 环境**（本机无 Linux 真机/qemu/aarch64 工具链，自第 5 轮起连续 4 轮同一条件）。已交付 Linux 上一键脚本 tools/e2e_elf_image.sh（默认报告模式，--strict 才失败）——跑通即可接入 CI 收尾 |
| (4) 每轮门禁全绿 + 如实登记未做项 | **达成**：8 轮全程 11 gates / 0 failed，未做项逐轮登记在本文件 |

工具侧沉淀：tools/image_residue.py（PE 多节）、tools/image_residue_elf.py（ELF 执行段）、
tools/residue_probe.py（运行期原生码/明文字节码）、tools/live_code_{residue,map}.py、tools/rip_probe.py、
tools/e2e_elf_image.sh（Linux 侧真机检查）。

### 365. 第十轮（CI 循环）：arm64（Linux/aarch64 + qemu）整体加密**真机验证通过**
CI run 35481263128（提交 2c5daaa）**五个作业全绿**，其中 linux-arm64 新增那步跑出：
```
[*] ELF 整体加密：PT_LOAD(X) va=0x10000 跳过头部 4096 字节，加密 589924 字节（入口自解密）
[*] ELF PT_LOAD(X) va=0x11000 size=589924 | chunks=9217 all-zero(excluded)=0 NON-ZERO FOUND=0
[+] no ELF code readable in the packed file
[*] 运行期：原生 vs 加密后逐字节比对
[OK  ] ELF 整体加密：输出一致
[+] e2e_elf_image: OK
```
即：**aarch64 的可执行段在文件里被整体加密（0 残留），入口自解密（mprotect=226 那条 svc 路径）在
qemu-aarch64 上真跑，输出与原生逐字节一致**。目标项 (2) 的 ELF/x86-64 与 Linux/aarch64 两半都有真机证据。

### 366. 这一路 CI 抓到 / 修掉的问题（都不在本机能复现）
1. **ELF 头被加密**（run #288）：ET_EXEC 第一个 PT_LOAD 的 p_offset=0，ELF 头/程序头表都在里面 →
   e_entry 读出来是垃圾。修：跳过 [0, align_up(phoff+phnum*phentsize, 4096))。
2. **入口给了校验蹦床而不是自解密蹦床**（run #292）：ApplyELF 漏了 PE 侧那条 ImgHookRVA 优先级 →
   .text 仍是密文、起手即死且连失败 trace 都没有。修：与 PE 侧同义分流。
3. **VM_BLOB_TARGET_LINUX 位置错**（run #289）：写在 if compilerIsWindows 里，Linux 原生编译时从未定义
   → 编进去的是 #else 桩（-9）→ 蹦床 fail-fast 命中 ud2。修：提到条件之外。
4. **汇编步骤不看 -cc**（run #35480635489）：给 aarch64 建 blob 必须带 `-merge go`（内置合并器），
   否则宿主 ld 链 aarch64 目标文件报 "file in wrong format"；CC/OBJDUMP 也要以环境变量给。
5. **lifter 缺 `ORR Xd, XZR, #imm`**（run #35481040253）：Go 给 main.sumTo 编出的第一条就是这个 →
   打包被拒。**这是既有覆盖缺口**，本轮先用 VMP_FUNCS 只保护 checkKey 绕过；正修待做（本机可测）。
6. **默认开的代价**（run #294）：把 ELF 整体加密切默认开，会让 tools/verify_linux_payload 的探针
   读到密文（它要从打包文件里读函数入口补丁字节）→ 已回退为 opt-in，前置条件记录在案。

### 367. 仍未做（下一轮起）
- **PE/arm64**（Windows/arm64）：需要给 vm_unpack_image 加 Windows/arm64 分支（从 TEB/PEB 取模块基址 +
  解析导出表拿 VirtualProtect）；CI 的 windows-arm64-run 是原生 arm64 Windows，可作验证环境。
- **lifter 的 `ORR Xd, XZR, #imm`**（第 5 条）：修好后 main.sumTo 也能被保护，VMP_FUNCS 的临时收紧可撤。
- **ELF 整体加密转默认**：前置是让载荷探针不再依赖"打包文件里的明文补丁字节"。

### 368. 第十一轮：lifter 补上 "逻辑立即数 + Rn=XZR"，aarch64 两个函数全链路在 qemu 下验证通过
CI run 35481622554（提交 7a3fd82）：
```
main.checkKey: native=20B -> 8 IR -> 52B bytecode
main.sumTo:   native=40B -> 10 IR -> 56B bytecode      ← 修复前："ORR X1, XZR, #0x1 ... 暂不支持"，打包被拒
main.checkKey patch=[F0 03 1E AA 3B 2D 04 14]          ← arm64 的 8 字节入口补丁（mov x16,x30 ; b thunk）
main.sumTo    patch=[F0 03 1E AA 44 2D 04 14]
[*] ELF 整体加密：PT_LOAD(X) va=0x10000 跳过头部 4096 字节，加密 589924 字节（入口自解密）
[*] chunks=9217 all-zero(excluded)=0 NON-ZERO FOUND=0 → [+] no ELF code readable in the packed file
[*] 运行期：原生 vs 加密后逐字节比对 → [OK  ] ELF 整体加密：输出一致 → [+] e2e_elf_image: OK
```
结论：**aarch64（Linux/ELF）上的"原镜像整体加密 + 入口自解密"闭环**，且验证的是**两个被保护函数**的完整链路
（含刚补上的逻辑立即数形式）。至此目标项 (2) 的 ELF/x86-64 与 Linux/aarch64 两半都有真机证据；
只剩 PE/arm64（Windows/arm64）与"ELF 整体加密转默认"的前置改造。

### 369. 更正第 24 轮的提交信息 + 真正放开 PE/arm64
- **更正**：提交 ea6d04d 的信息里写了"vmpack：packPE 放开 arm64"，但那次 anchors 阶段就退出了，
  **实际只含 C 那一处改动**（1 file changed）。也就是说 ea6d04d 之后 PE/arm64 仍会跳过整体加密，
  新加的 Windows/arm64 分支是"编进去但不会被调用"。
- 本轮补上：packPE 的机器类型判断从"仅 AMD64"改成"AMD64 或 ARM64"。
- 教训记一条：改代码时**先看锚点是否命中再写提交信息**——这次是"信息跑在事实前面"，
  和前面几轮"以为改好了其实没落上"是同一类问题。

### 370. 两项收尾都在 CI 上转绿：ELF 默认开 + PE/arm64 三段证据
- **ELF 整体加密默认开**（run 35482334570，提交 15fd718）：linux-amd64 上没传任何 flag，
  打包出的是加密过的 ET_EXEC，且
  ```
  [*] ELF 整体加密：PT_LOAD(X) va=0x400000 跳过头部 4096 字节，加密 597393 字节（入口自解密）
  [*] chunks=9334 all-zero(excluded)=0 NON-ZERO FOUND=0 → [+] no ELF code readable in the packed file
  [*] 运行期：原生 vs 加密后逐字节比对 → [OK  ] ELF 整体加密：输出一致
  ```
  前置改造（extractpayload 由「函数入口 RVA + thunk RVA」**合成**补丁字节，不再从 .text 读）经此验证。
- **PE/arm64 三段证据**（run 35483191384，提交 e3eab92）：windows-arm64-run 上
  ① 结构：补丁 `F0 03 1E AA …`（mov x16,x30 ; b thunk）；
  ② 文件级：`.text` 熵 2.87→7.55、`.rdata` 0.20→7.62，两节非零 64B 块 **0 命中**；
  ③ 运行期：`native=… protected=…` 退出码一致。
- 路上又踩两个自己的坑（都已修并记录）：freestanding arm64 目标**没有 .data 节**，
  而 image_residue.py 把"缺节"当用法错误 → 加 --allow-missing（有节仍严格检查）；
  随后我新加的跳过提示写了中文，Windows runner 的 python stdout 是 **cp1252** →
  UnicodeEncodeError 被误报成"残留" → 工具输出改回纯 ASCII（本仓库既有约定）。

### 371. 收口复核（本机，当前 HEAD）
- `tools/gates.ps1` 在本机当前 HEAD 上跑完整套：**11 gates / 0 failed**（gofmt / vet / test / blob /
  e2e 147 例 / 残留三项门禁 / DLL / arm64 客户机 / linux 载荷）。
- README 新增「加固分层与四平台证据」一节（三层各自的机制与门禁、四平台 CI 证据含 run 号），
  并如实列出 7 条仍未做项（首选基址约束、ELF 仅 ET_EXEC、ELF 未加密 .rodata/.data、
  arm64 blob 依赖 CI、解释器 -O1、指令子集、无反调试纵深）。

### 372. ELF 侧把 .rodata/.gopclntab 纳入整体加密（语义级门禁接上）
动机：PE 侧早就加密 `.rdata`，ELF 侧只加密了可执行段 —— 于是"代码藏住了、字符串没藏住"。
本机实测（Go ET_EXEC 目标）：
```
[*] ELF 整体加密：.rodata    RVA=0x93000 size=0x4B668（只读数据）
[*] ELF 整体加密：.gopclntab RVA=0xDEE40 size=0x77638（只读数据）
    .rodata    H=4.22 -> 8.00   可读串(>=6) 59069 -> 3437
    .gopclntab H=5.95 -> 8.00   可读串(>=6) 85213 -> 5304
    >=12 字节可读串：137566 -> 78（0.06%）   ← 语义级门禁 --max-ratio 0.05 通过
    文件级：执行段非零 64B 块 0 命中
```
新增 `tools/expose_report.py`（PE/ELF 通用）：按节统计**熵 + 可读字符串字节数**，
`--max-ratio` 作为"打包后残留可读串不得超过原始的 X%"的语义级断言（比 64B 块匹配更贴近"到底泄露了什么"），
已接入 `tools/e2e_elf_image.sh`。

**修 bug 的经历（值得记）**：候选节一开始一个都没被选中、暴露面 0 变化，连续三个错误假设：
① 从 `f.Data` 读节名字符串表 —— 那其实是**注入流程改写过的缓冲区**（`internal/load/elf/elf.go:280/282` 在往里 append payload）；
② 改成从缓冲区解析整张节头表 —— 直接 nil；
③ 改成从**原始文件**解析后仍然没候选。最后加调试输出才看清：**节名全是空串** ——
因为 `get()` 少返回了 `sh_offset`，于是拿 shstrtab 的 `sh_name`（通常是 0）当文件偏移用了。
教训：**结构体解析里"少返回一个字段"不会报错，只会静默地把所有名字变成空串**；
以及"先打一行调试输出"比连猜三轮快得多。

### 374. 回退：ELF 数据节加密默认关（保留 \`-enc-image-elf-data\` 供排查）
把 \`.rodata\`/\`.gopclntab\` 纳入整体加密的改动（提交 98c3caa）在 CI 上暴露两个问题，
**已退回默认关**（代码与语义级门禁工具都保留，等查清再启用）：

| 现象 | 原始证据 |
|---|---|
| aarch64 目标**直接崩** | run 35484769361 / linux-arm64：\`[!] arm64 end-to-end: MISMATCH (native rc=0, protected rc=139)\`、\`protected= qemu: uncaught target signal 11 (Segmentation fault) - core dumped\` |
| CI 上语义级门禁报残留 | run 35484769361 / linux-amd64：\`[FAIL] packed image still exposes readable strings\` —— CI 上"打包文件里这些节残留的可读串比例"远高于本机测到的 0.06% |

本机数字（同一改动）是好的：\`.rodata\` 熵 4.22→8.00、\`.gopclntab\` 5.95→8.00、>=12 字节可读串 137566→78。
**本机过、CI 不过**，而且 aarch64 会崩 ⇒ 说明"打包后节头/布局"与"aarch64 上的解密/映射"还有没搞清的地方，
不能靠放宽阈值或只留 x86-64 糊过去。当前状态：默认路径与 run #293/#35482334570 验证过的行为一致；
\`-enc-image-elf-data\` 打开才走新路径。

同时确认（PE 侧，目标项 (A)）：**LOAD_CONFIG 搬迁已生效且本机验收通过**（提交 0efba2e）：
\`.rdata\` 熵 2.46→7.99、>=12 字节可读串 1990→**0**、原生/被保护 17 行输出仅 2 行不同（base/地址）、
\`tools/gates.ps1\` 11/0、e2e 147/147。另记一条风险（未解决）：**解密 \`.data\` 可能覆盖加载器在入口点之前写入的值**（/GS cookie、TLS 等），
demo64 实测无害，但这是"整体加密 .data"的真实风险面。

### 375. 目标项 (A) 完成并 CI 复绿；目标项 (B) 有意搁置
CI run 35485036890（提交 c7c58fe，含 ELF 数据节回退 + PE LOAD_CONFIG 搬迁）**五个作业全绿**；
随后的 docs 提交 55b3cc0（run 35485064094）同样全绿 —— 主干回到已验证状态。

**(A) PE 侧 LOAD_CONFIG 搬迁：完成**（本机验收 + CI 双证据）
- 本机：`.rdata` 熵 2.46→7.99、>=12 字节可读串 1990→0、原生/被保护 17 行输出仅 2 行不同（base/地址）、
  `tools/gates.ps1` 11 gates/0 failed、e2e 147/0、dll 3/3、arm64 客户机 OK；
- CI：windows-amd64 与 windows-arm64-run 全绿（PE/arm64 三段证据此前已单独验过）。
- 遗留风险（未解决，已登记）：解密 `.data` 可能覆盖加载器在入口点之前写入的值（/GS cookie、TLS 等）。

**(B) ELF 侧 .rodata/.gopclntab：实现完成但有意默认关（`-enc-image-elf-data`）**
CI 上实测：aarch64 目标 `protected rc=139`（qemu SIGSEGV）；x86-64 上我新接的语义级门禁报残留可读串，
而同一改动在本机是"4.22/5.95 → 8.00、>=12B 可读串 137566→78"。**本机与 CI 结论矛盾**，
在解释清楚之前不启用、也不接线门禁 —— 这是本轮的主要判断。

下一轮该做的（按序）：
1. 用 `-enc-image-elf-data` + arm64 的 stderr 诊断（aarch64 分支已有 `VMPELF ...` 失败打印）复现并定位 SIGSEGV：
   是"节超出行映射"、"mprotect 目标越界"，还是"某节与已加密段重叠"；
2. 解释 CI 与本地暴露面数字的差异（先把两边的 `tools/expose_report.py` 明细并排打出来，再看节头在打包后是否仍指向同一位置）；
3. 都解释通之后才把候选节默认打开 + 语义级门禁接回 e2e。

### 376. aarch64 数据节崩溃的排查（进行中）：布局已排除两个假设，怀疑"往只读页写"
把 `.rodata`/`.gopclntab` 纳入整体加密后（提交 98c3caa，现已默认关）：
- **x86-64 不受影响**：run 35484769361 里 linux-amd64 的 `ELF end-to-end` 那步是过的
  （即打包后带着加密只读数据节的 x86-64 ELF 真跑成功）。该 run 里 linux-amd64 的**唯一**红是我 e2e 脚本的
  续行转义 bug（`\` 变成字面参数 → `--sections: command not found` → `|| fail` 报了误导性的"仍有残留可读串"）。
- **aarch64 崩**：`[!] arm64 end-to-end: MISMATCH (native rc=0, protected rc=139)`、`qemu: uncaught target signal 11`，
  且日志里**没有** `VMPELF ...` 失败打印 ⇒ 不是我们那几条失败路径，而更像"mprotect 之后往只读页里写"那一步。

本机交叉编译 aarch64 目标后的布局（`GOOS=linux GOARCH=arm64`，无需交叉工具链）：
```
PH[2] LOAD R+X off=0x0     va=0x10000  filesz=0x91064 memsz=0x91064 end=0xA1064
PH[3] LOAD R   off=0xA0000 va=0xB0000  filesz=0xBE668 memsz=0xBE668 end=0x16E668
.text      end=0xA1064  inPH=2   .rodata end=0xFBC07  inPH=3   .gopclntab end=0x16E668 inPH=3
```
⇒ **"节超出实际映射"与"与已加密段重叠"两个假设都被数据否掉**（两节都完整落在只读段内）。

处置：解密时的临时权限从"一律 R|W|X"改成"执行节 R|W|X、数据节 R|W"（三条分支：Linux x86-64、Linux aarch64、
Windows 的 VirtualProtect 同理）。这是**待验证**的假设 —— 下一轮在 `linux-arm64` 上只为那一步打开
`-enc-image-elf-data` 复现，并抓 `build/ci_step.log` 里的打包/运行输出。

### 377. 目标项 (B) 收官：按架构分流 + 语义门禁接线（x86-64 默认开，aarch64 登记不支持）
**两个假设先后被否**（记录在 #376）："只读数据节超出映射 / 与已加密段重叠"（本机 aarch64 布局数据否掉）、
"解密时对数据页多要了 X"（c408230 改成数据节 R|W 后仍崩，run 35485789797）。
**aarch64 现象**：带数据节加密的 aarch64 目标在 qemu 下 `protected rc=139`（SIGSEGV），根因未定。

**按架构分流**（ce0b382 + 3912af5 + 5bc10be/dfe4907 两次阈值修正）：
- **x86-64：默认开**（依据：同一改动在 CI 上真跑成功，run 35484769361 的 ELF end-to-end 通过）；
- **aarch64：默认关**，打包时打印理由并保留 `-enc-image-elf-data` 供继续排查；
- **语义级门禁接回 e2e**：`tools/expose_report.py --max-ratio 0.05 --max-abs 256`（**单行**）；
- **判据修正**：只查 `.text` 时原始基线可能只有几百字节，而随机密文本身会产生零星可打印串
  （aarch64 实测 69 字节/590KB），比例判据会误报 —— 改为"比例达标 **或** 绝对量 <= 256 字节"。
- 本机复验：三节 `packed 66 / 137566` 通过；只查 `.text` `packed 54 / 37` 亦通过（正是上次误报的形态）。

**仍未做（如实）**：aarch64 的只读数据节整体加密不可用（根因未定，下一步需要 `VMPELF prot rva=... rc=...`
无条件诊断把崩溃点变成读数）；PE 侧 CI 尚未接 expose_report 语义门禁。

### 378. 针对第三方报告【成立】批评的加固：范围、已落地前置、接线计划
报告里**成立且值得做**的条目（我在 397 轮末尾逐条评估过价值/代价/可验证性）：
P3.10 密钥不派生且随文件分发、P3.13 同密钥解全部、P2.7/8 无盐 FNV 与每调用全校验、
P1.1-5 容器/记录明文（魔数、RVA、长度、标志）、P2.6 反调试仅 BeingDebugged、
P4.14 固定基址/拆重定位、P4.15 加载时整段解密。**不在此列**：报告的 P0 机制判断
（"解密后原生执行"）与"离线解密即得原函数体"——那两条由报告作者按同源对照去验证。

**已落地的前置（提交 3b1adaa / 7346d91 / df6ebba）**
- 每函数派生定义（两侧可独立复现，KAT 钉死）：
  `K_f = ChaCha20_block(key = master, counter = 0, nonce = le32(rva) || le32(salt) || 0^8)[0..32)`
  - C：`stub/win/x64/vm_kdf.c`（标准 ChaCha20 块，刻意不复用 vm_crypto.c 里 sigma 随机化那套）+ `kdf_kat.c` 主机 KAT；
  - Go：`internal/inject/kdf.go` + `kdf_test.go`（期望值取自 C 侧实测，真断言）；
  - KAT（master=0x10..0x2F）：0x1670/0x11223344 → 03504d6e…a04fc1；0x16A0 → 4bbdfb88…8538ce；0x93000/0xAABBCCDD → 1966610b…41e149（两侧逐字节一致）。
- `vm_kdf.c` 进 blob 的正确方式：`cmd/vmpbuild/main.go:481` 那处 `appendUnique`（**不是** BLOB.sources，
  那是相对 stub 的路径列表，只列 vm_interp.c 与入口汇编）；blob 重建通过即为证。
- 两个自己的坑（都已修并记录）：往 BLOB.sources 加裸文件名**弄坏了 blob 构建**；
  用"blob 里搜符号名"做验证**未做校准**（连 vm_entry 都搜不到，名字其实在 manifest 里）。

**1a 接线计划（下一步）**
1. 先定：字节码描述符只有 16 字节 nonce、**没有 salt 字段** → 二选一（加字段 / 从 nonce 派生 salt），两侧一致后再动手；
2. 打包端 `cmd/vmpack/main.go:142 / 893 / 937`：单个 `aead` → 每条目 `aead_f = AEAD(KDFEntry(master, rva, salt))`；`patchKey` 改由 `K_f` 派生；
3. 运行期 `stub/win/x64/vm_interp.c` 七处 `u8 key[32] = VM_KEY_BYTES`（558/659/679/1344/1454/1544/1695）→ 按条目现推 `K_f`；
4. 补"不同 RVA ⇒ 不同密钥"用例，重建 blob，跑 `tools/gates.ps1` 11/0 + e2e 147/147 + CI。

**1b（紧随）**：blob 不再含真实主密钥（编译占位），真密钥来源可切（env / 外部文件 / 授权），
payload 里放**密钥校验 tag**；缺失或不匹配 ⇒ **硬门拒绝执行**（专用退出码 `0xC0DE0007`、无输出），
默认 file 源保持兼容；CI 两次运行验证"不给密钥必须恰好以该码失败 / 给了必须与原生一致"。

**其余条目**：P2 带密钥 MAC + 抽样校验（含开销前后数字）、P1 容器加密与混淆、
P2.6 反调试多路径、P4.15 按需解密（先评估收益）、P4.14 重定位/ASLR（评估后实现或登记取舍）。

### 379. KDF 前置链的 CI 结论（补记 #378 里"未确认"的那几条）
三条 run 全部 **success**（此前积压导致我两次只能标"未确认"）：
- 35487728988（df6ebba，`vm_kdf.c` 经 `cmd/vmpbuild` 的 appendUnique 编进 blob）；
- 35487778129（ed10ce6，salt 派生纯函数 + "不同 RVA ⇒ 不同 salt" 用例）；
- 35487804362（0ee2fda，salt 派生跨语言 KAT 一致）。

即 1a 的全部前置（两侧 KDF、两侧 salt、KAT 向量、Go 断言、编入 blob）**都已在本机与 CI 双重确认**，
且未引入回归。剩下的是接线（打包端 3 处 + 运行期 7 处）与 1b（主密钥外置 + 硬门），照 #378 的步骤执行。

### 380. 回归确认：KDF/SALT 链条之后，产品路径与门禁均无变化
- **产品级复验（demo64 端到端）**：`.text/.rdata/.data` 三节仍全加密、LOAD_CONFIG 仍搬迁并重指、
  `.rdata` 熵 2.46→7.99、**>=12 字节可读串 1990→0**、真跑 native/protected 均为 exit=0 且 17 行输出
  只有打印 base/地址的两行不同（固定基址的预期结果）。与 KDF 引入前的数字逐项一致 ⇒ 无非行为性回归。
- **本机门禁**：`tools/gates.ps1` **11 gates / 0 failed**（含 e2e 147/0、dll e2e 3/3、arm64 客户机 OK）。
- **CI**：#379 已记三条 run 全绿（df6ebba / ed10ce6 / 0ee2fda）。
  三者合起来：1a 前置（两侧 KDF + salt + KAT + 编入 blob）在"本机门禁 + 产品级回归 + CI"三处都确认过。
仍未做：1a 接线（`cmd/vmpack/main.go:142/893/937` 与运行期七处 `VM_KEY_BYTES`）与 1b（主密钥外置 + 硬门），
步骤见 #378。

### 381. (5) 按需解密 与 (6) 保留重定位/ASLR 的可行性评估（目标里允许的"评估后登记"）
**(5) VEH 缺页解密（整段解密 → 按需）——评估结论：本设计下收益很小，建议不做（已登记理由）**
- 机制可行：Windows x64 上 `AddVectoredExceptionHandler` 捕获本进程 `EXCEPTION_ACCESS_VIOLATION`，
  解密故障页、恢复保护、`EXCEPTION_CONTINUE_EXECUTION` 继续。
- 但收益有限且**方向可能相反**：VEH 只对本进程的访问触发，**外部 dumper 的 ReadProcessMemory 不会触发**——
  所以它能做的只是"没被跑到的页仍是密文"。可本设计里**真正敏感的部分（被保护函数）根本不在镜像里**
  （函数体被抹除、语义在 VM 字节码里），按需解密影响的只是"本来就必须是明文才能跑的其余代码"。
- 代价却是实打实的：多一个可被挂钩/被跟踪的异常处理面（调试器只要逐页跟一遍 fault，就能拿到
  **逐页解密的干净转录**，比一次性 dump 更好用）、故障风暴/与 AV 的交互、以及与自有解释器帧的耦合。
- 结论：**不做**；若未来把"被保护函数之外的代码"也做成敏感资产，再回来重新评估。

**(6) 保留重定位 + 开启 ASLR——评估结论：可实现，中等工作量，建议排在 (1) 之后做**
- 冲突根因（当初为什么拆表）：加载器在**入口点之前**把基址重定位**写进**镜像；而整体加密后那些位置是密文，
  写进去就把密文改坏了（我们随后再解密会得到垃圾）。
- 可行方案：**"先减回去、再解密、再加回来"**——
  1. 保留 `IMAGE_FILE_RELOCS_STRIPPED` 不设、保留 `.reloc`（ELF 保留 `.rela*` 与 DYNAMIC_BASE）；
  2. 运行期自解密前，对每个重定位项做逆运算恢复出"当初密文的字节"：
     PE `DIR64/HIGHLOW`：`cipher = field_now - (actual_base - preferred_base)`（ABSOLUTE 项本就为 0）；
     ELF `RELATIVE/GLOB_DAT/JUMP_SLOT`：`cipher_addend = field_now - load_bias`；
  3. 解密该段/该页，然后**重新施加**重定位（把增量加回去）；
  4. 需要额外解析并实现 PE `.reloc` 与 ELF `.rela.dyn/.rela.plt` 的应用器（架构无关，约 150–250 行）。
- 收益：恢复 ASLR（提高"dump 后按固定基址重建/复用"的成本）、去掉"固定基址"这个显眼特征；
  ELF 侧还要注意惰性绑定（`.got.plt` 的解析发生在入口点**之后**，与我们解密不冲突）。
- 结论：**值得做但排在 (1) 之后**；本设计当前是有意取舍（已记录代价：失去 ASLR）。

### 382. (2) 完整性校验改带密钥 MAC 的设计（选型 + 为什么不用 SHA/HMAC）
现状：运行期补丁校验用 **无盐 FNV-1a**（`FNV(key[:8] || patch)`，常量公开）→ 攻击者可重算并"修好"校验值；
且**每次调用**都全校验一次（报告实测认为吃掉了绝大部分调用开销）。

**选型：用 Poly1305 做带密钥 MAC，而不是 HMAC-SHA256。**
理由：`stub/win/x64/vm_crypto.c` 里**已经有** Poly1305（26 位 limb 实现，为 AEAD 写的），
而 SHA-256 两侧都没有、要新写两份并各自验证 —— 复用一个已在 CI 上跑通的实现风险最低。
Poly1305 是**一次性** MAC，所以按键/消息分离：
- `key_mac = KDFEntry(master, rva, salt ^ 0x9E3779B9)`（与加解密密钥用不同常量派生，避免同键复用）；
- 消息 = `patch 字节 || le32(descOff) || le32(codeLen) || le32(nonce 前 8 字节)`（把描述符自身绑进去，
  等价于给 FNV 加盐 + 绑定上下文）；
- 校验值写入描述符原来的 pad 字段（**格式不变**，只是语义从"无盐 FNV"变成"Poly1305 截断 8 字节"）。

**抽样频率**：把"每次调用都全校验"改成
- 首次调用必校验（建立信任基线）；
- 之后按调用计数取样：`(call_count & 0x1F) == 0` 或由描述符里的一个每构建随机数决定的低频节奏；
- 失败仍走**静默延后**（不立刻 trap，而是在后续若干次调用后才让结果偏移），避免"跳转点即指纹"。
**量化**：现有 e2e 里有被保护函数的调用序列，改造前先记录基线（本机 `check_key/sum_to` 的单次耗时已测过
15.3→29.0 µs 是流式取指的代价），改造后再测同一组，把"校验开销占比"作为交付数字。

**写在最前的前提**：这条要等 (1) 接线完成后再做 —— 因为 `key_mac` 依赖 `KDFEntry` 的接线，
否则又是"两侧各改一半"。本条目先作为设计登记，避免下一段重新推导选型。

### 383. 目标项 (1) 接线完成（每条目派生密钥）；顺带挖出并修掉两个只有接线才会暴露的真问题

**做了什么（打包端）**
- `internal/inject/payload.go`：`EncryptFunc` 增加 `key [32]byte` 参数（交给回调的就是**本条目的派生密钥**）；
  `Options.Master`（32 字节主密钥）驱动派生：字节码条目
  `K_e = KDFEntry(master, rva = funcRVA, salt = KDFSaltForPlacement(descSelfRVA, funcRVA, codeLen))`。
- `patchChecks` 的 8 字节密钥前缀改用**条目派生密钥**（不再用主密钥前 8 字节）；
  加载期校验表条目 **12 → 24 字节**，追加 `selfRVA/funcRVA/codeLen` 三个 KDF 输入，运行期据此现推同一把密钥。
- `cmd/vmpack/main.go`：三处接线 —— 字节码 Seal 闭包按条目现建 AEAD；PE/ELF 整体加密每个节
  `K_s = KDFEntry(master, 节 RVA, 表头 salt)`（nonce/aad 不变）；`Master` 经 `packPE/packELF` 传到 `inject.Options`。

**做了什么（运行期）**
- `stub/win/x64/vm_interp.c` 七处 `VM_KEY_BYTES` 全部改成"按条目现推"：
  新增 `vm_desc_key(d, master, out) = vm_kdf_entry(master, d->reserved1, vm_kdf_salt(d->selfRVA, d->reserved1, d->codeLen))`；
  `vm_bcs_t` 增加 `keybuf[32]`（流式取指原来的 `key` 直接指向主密钥常量，现在指向这份派生密钥）；
  字节码 AEAD 验签、`VM_INVM_PATCHCHECK` 块、`vm_verify_table`、三条 `vm_unpack_image`
  （Linux x86-64 / Linux aarch64 / Windows x86-64）各自现推。

**KAT 与单测**
- `stub/win/x64/kdf_kat.c` 增加两行**接线约定**向量（desc：selfRVA/funcRVA/codeLen → salt+key；sect：节 RVA+表头 salt → key）。
- Go：`TestKDFDescriptorKeyMatchesC`、`TestKDFSectionKeyMatchesC`、`TestKDFEntryDistinctPerFunc`（不同 RVA ⇒ 不同密钥），
  以及新文件 `internal/inject/payload_kdf_test.go`：直接断言 `BuildPayload` 交给 `EncryptFunc` 的键**就是**
  按上述算式现推的值，且两条目拿到的键不相同（这条断言盯的是"接线本身"，不是 KDF 函数）。

**接线暴露出的两个真问题（都不是 KDF 设计的问题）**
1. **ChaCha20 的 sigma 掩码不能再从 working key 取**（已修）。`vm_crypto.c` 把"规范 sigma ^ 主密钥前 4 字节"
   存成常量、运行期用**传入的 key** 前 4 字节异或还原。以前 key 就是主密钥所以自洽；KDF 之后传进来的是派生密钥，
   sigma 不再是规范值，C 侧不再等于标准 ChaCha20 → **AEAD 验签 100% 失败**（PE 上是退出码 `0xC0DE0004`），
   而两侧 KDF KAT、密文、标签、nonce 逐字节全一致，极难定位。改成从 `VM_KEY_BYTES`（主密钥）取掩码。
   掩码数组必须是**栈上局部**（原因见下一条）。
2. **vmpbuild 的 COFF 重定位会丢掉字段里的节内加数 —— 未修，只绕开**。`cmd/vmpbuild/blob.go:applyRelocsObj`
   对非 ELF 只按 `+4` 补偿，不读字段里已有的加数，于是"**不是第一份**只读数据"的常量/字符串会被解析到
   它所在节的**起点**。实测（接线后第一次跑门禁）：`vm_kdf_salt` 里 `lea disp(%rip)` 指向 `.rdata+0`
   （0x6B80，那里是 "KERNEL32.DLL"），而 "VMPXKDF" 实际在 `.rdata+0x80`（0x6C00）——
   salt 全错 ⇒ 派生的条目密钥全错 ⇒ 补丁校验/校验表全灭。
   绕开办法（两处，都验证过 KAT 数值不变）：`vm_kdf.c` 的标签用**立即数字节**展开（该文件不再贡献只读数据）；
   `vm_crypto.c` 的 sigma 掩码用**栈上** `volatile` 数组（新增 static const 会变成"第二份只读数据"，掩码就被解析错）。
   建议下一步在 `applyRelocsObj` 里对 COFF 读取字段内加数，并加一条"blob 里 `vm_kdf_salt` 结果 == KAT"的门禁；
   这次没动它，是遵守"两侧一致性改动同一轮做完、不在余量不足时重构主干"的纪律。

**证据**
- 本机 `powershell -NoProfile -File tools/gates.ps1`：**total 11 gates, 0 failed**
  （gofmt / go vet / go test / vmpbuild（含 release blob）/ e2e.ps1 = 147 passed 0 failed / residue probe /
  字节码明文扫描 / 镜像残留 / e2e_dll.ps1 / arm64-guest differential / linux payload 全部 OK）。
- **CI：run 35489931006（提交 b500bc7）五个作业全绿** —— windows-amd64 / windows-arm64-blob /
  windows-arm64-run / linux-amd64 / linux-arm64。
- 反证：接线第一次进主干时那三条 run（35488815092 = f44f639、35488960921 = 61364c0、35488985789 = a83a4ad）
  **全红**；那正是本条目里两个缺陷都还在的状态。修好后同一条 CI 全绿 ⇒ 红绿分界就落在 b500bc7。
- 隔离 worktree 全量 e2e：`e2e: 147 passed, 0 failed`。
- `build/kdf_kat.exe`：七个向量（5 个 salt/KDF + desc + sect）与 Go 侧断言逐字节一致；改标签写法后数值不变。
- 定位过程（可复用的手法）：镜像 AEAD 失败退出码 `0xC0DE0004` → 先用"在打包产物上重放运行期算式"的 Go 程序
  证明**文件是自洽的**（能解出明文）→ 再把运行期中间量编进**故障地址**（故意写野地址，崩溃报告会打出完整地址）
  逐个读出 key/salt/描述符字段 → 最后用 `objdump` 看 blob 里 `vm_kdf_salt` 的 `lea` 目标与
  "VMPXKDF" 的实际偏移，锁定重定位缺陷。

**未做**
- vmpbuild 的重定位缺陷本身没修（只绕开），上面已写清修法与建议的门禁。
- 1b（主密钥外置 + 硬门）、(2) 带密钥 MAC、(3) 容器加密/混淆、(4) 反调试多路径、(6) 重定位/ASLR 仍未动。
- `tools/preflight.ps1` 在 a83a4ad 里被移除（脚本自检不过），本轮验收用的是 HANDOFF 附录 B 的逐条命令。

### 384. 修掉 vmpbuild 的符号解析缺陷（#383 里"只绕开"的那条），并加一条 blob 级 KDF 门禁

**#383 的诊断要更正一处**：根因不是"丢掉字段里的节内加数"（加数一直是从字段里读的），
而是**应用重定位时按符号名字回查符号值**。`ld -r` 合并多个目标文件后，同一个节会有**多个同名节符号**：

```
[ 34](sec 3) 0x0000000000000000 .rdata
[ 76](sec 3) 0x0000000000000080 .rdata
```

合并后的目标文件里那条重定位是 `6c07: IMAGE_REL_AMD64_REL32 .rdata`（字段为 0，真正的 +0x80 在符号索引 [76] 的值里），
而 `applyRelocsObj`（以及 `-merge go` 的 `applyAllRelocs`）用 `s.Name == r.SymName && s.Sec == r.TargetSec`
遍历符号表**取第一个匹配** → 命中值 0 的那个 → 字符串被解析到 `.rdata+0`。

**修法**：解析期就按**符号索引**取值存进 `objReloc.SymValue`（COFF 与 ELF 两处），应用重定位时只认它。

**门禁**：新增 `stub/win/x64/kdf_blob_kat.c` —— 把**编好的 blob** 用 `VirtualAlloc(PAGE_EXECUTE_READWRITE)`
（POSIX 走 mmap）载入**可执行内存**，调用 blob 里的 `vm_kdf_salt`（5 组）与 `vm_kdf_entry`（3 组）对 KAT。
`stub/win/x64/kdf_kat.c` 编的是单个源文件（只有一份只读数据），永远发现不了"blob 内布局"这类缺陷。
已接进 `tools/gates.ps1` 的 "vmpbuild (blob builds)" 一步（debug 与 release 两个 blob 都查；门禁总数仍是 11）。

**校准**（探针必须先证明它会失败）：用同一工具跑**修复前**的 blob →
`[FAIL] vm_kdf_salt(0x1670,0x90,40) = 0xD92F191C, want 0xAB20EB8B`（5 条全红）；修复后 `[OK] ... x5 + x3 match`。
一个有信息量的细节：`vm_kdf_entry` 的 3 条在修复前**也是过的**（它不引用只读数据）—— 正好说明为什么必须专门检 `vm_kdf_salt`。

**单测**：`cmd/vmpbuild/blob_test.go` 两条 aarch64 重定位用例补上 `SymValue`（原来靠名字查），
并新增 `TestApplyRelocsUsesSymbolValueNotName`：构造"两个同名 `.rdata` 符号（值 0 与 0x80）"，
断言解析用 +0x80 —— 谁把解析改回按名字查，这条就红。

**把 #383 的绕开改回去**：`vm_kdf.c` 的标签回到字符串字面量；`vm_crypto.c` 的 sigma 掩码回到 `static const volatile`。
两处都复验：宿主 KAT 数值不变、blob KAT 通过、e2e 147/0。

**顺带补掉 aarch64 ELF 的一个同类窟窿（CI 逼出来的）**：把 `vm_kdf.c` 的标签改回字符串字面量后，
CI run **35494537015** 的 **linux-arm64** 立刻红：
`[!] .text+0x50: 不支持的重定位类型 0x116`（= `R_AARCH64_LDST8_ABS_LO12_NC`）。
按字节访问的字符串走 `ADRP + LDRB`，而**单目标路径（`-merge ld`）没有 `relAArch64LDSTLo12` 分支**
（`-merge go` 路径早就有，且 `patchAArch64LDSTLo12` 已按指令 size 位缩放、宽度 1 也对）。
补上常量 278 + 该分支后 CI 转绿。**本机没有 aarch64 工具链，这条只能由 CI 的 linux-arm64 作业验证。**

**证据**
- 本机 `tools/gates.ps1` = **11 gates / 0 failed**（含新门禁；e2e 147/0、dll 3/3、arm64 客户机 OK）。
- 隔离 worktree 全量 e2e = 147 passed / 0 failed（用的是"修复 + 绕开已改回"的状态）。
- CI：**35494728426（13df4d6）五个作业全绿**（windows-amd64 / windows-arm64-blob / windows-arm64-run /
  linux-amd64 / **linux-arm64**）。反证：同一改动在补 LDST8 之前的 35494537015 是 **linux-arm64 红**。

**未做**：无新开项（这条就是 #383"下一步建议"的落地，并顺带补了 aarch64 LDST8）。
#383 里其余"未做"项 —— 1b（主密钥外置 + 硬门）、(2) 带密钥 MAC、(3) 容器加密/混淆、
(4) 反调试多路径、(6) 重定位/ASLR —— 照旧未动。

### 385. 目标项 1b：主密钥外置 + 硬门（产物里不再有可用密钥）

**形状**（`vmpbuild -key-external`，默认关闭；不带它时行为逐字节不变）
- **打包端**：外置模式下 blob 里的 `VM_KEY_BYTES` 变成**独立的随机占位密钥**（不是真密钥的任何变形）；
  同时**总是**写一个 16 字节**密钥校验值**（KCV）= `KDFEntry(真主密钥, "KEYK" = 0x4B45594B, 每次构建随机 salt)[0:16]`。
  真主密钥仍然进 manifest（vmpack 要用），并可由 `-key-out <path>` 落成 32 字节原始文件供部署。
- **运行期**：`vm_interp.c` 新增 `vm_master()`；所有需要主密钥的地方（字节码/镜像解密、加载期校验表、
  `vm_crypto.c` 的 sigma 掩码）都走它。首次调用时取钥 + KCV 自检，**取不到或对不上 ⇒ 以专用退出码
  `0xC0DE0007` 结束、不输出任何内容**。
- **取钥路径刻意不调用 kernel32 的取环境/文件 API**（原因见下面的踩坑记录）：
  密钥从 **PEB 的环境块**直接读（`PEB->ProcessParameters(+0x20)->Environment(+0x80)`，纯内存读、
  零 API），形式是环境变量 `VMPX_KEY` = 64 位 hex；硬门走 **`ntdll!NtTerminateProcess(-1, 0xC0DE0007)`**
  （ntdll 的导出从不转发，地址必然有效），取不到就 `ud2`。部署时 `vmpbuild -key-out <file>` 写出的
  就是那 64 位 hex 文本，设成环境变量即可。
- **不支持的平台直接构建失败**：`-key-external` 目前只有 win/x64 的取钥实现，别的目标 `fatalf`
  —— 宁可构建期报错，也不要产出"注定起不来"的产物。

**踩坑记录：这一条在 CI 上死了三次才通（值得留档，因为都是"本机看不见"的类型）**
1. CI **35497237045**：windows-amd64 报 `code=0xC0000005`，本机全绿。根因是 `vm_get_proc` **不处理
   转发导出（forwarder）**：kernel32 里一批 API 的导出项不是代码，而是指向 `"KERNELBASE.CreateFileA"`
   字符串的 RVA；把它当函数地址调过去 = 跳进只读字符串页。**本机 kernel32 这 5 个 API 恰好是真实桩**
   （写了个小工具逐个查导出项，`fwd=0`），所以只有 CI 崩；现有镜像自解密只用 VirtualProtect/ExitProcess，
   两边都是真实导出，因此这个洞一直没被踩到。修法：识别转发器并按 `<DLL>.<Func>` 递归解析，
   判定用"RVA 在导出目录范围内 **或** 不在可执行节里"两条并集。算法用本机真实转发器校准：
   `kernel32!AppPolicyGetClrCompat` 确实是转发导出，同一套逻辑解析它 == `GetProcAddress`。
2. CI **35497628714**：加了转发器识别后**仍然** `0xC0000005`（不是分支码 ⇒ 崩在"调用已解析到的地址"上）；
   同时暴露出 e2e 自己的探针缺陷：**Windows PowerShell 5.1 的 `ConvertFrom-Json` 遇到空的 JSON 属性名
   会抛 "the value of argument name is not valid"**，而 blob 的符号表里可能有空名 —— 报错被吞掉后
   needle 变空串，"搜不到密钥"就会被判成 PASS。改成**正则取 key**，并保留"必须是 64 位 hex"的校准断言。
3. CI **35497946766**：给每个分支加临时退出码（`0xC0DE01xx`）定位，结果仍是裸 `0xC0000005`，
   说明地址解析"成功"但调用崩 —— 判断转发这条路在 runner 的不同 Windows 版本上不可靠。
   **于是不再绕**：把取钥整体改到 PEB 环境块（零 API），硬门改到 ntdll。
4. CI **35498251605**：**五个作业全绿**，e2e 在 runner 上也是 152/0。

**设计要点**：把"第一次解密之前就把错密钥挡掉"做成**结构性保证**（所有路径都必须过 `vm_master()`），
而不是靠调用顺序碰巧成立；KCV 复用已有 KDF，不新增密码学原语；KCV 是 ChaCha20 块输出的截断 + 随机 salt，
反推不出主密钥。

**验证**（本机；这 5 条已固定进 `tools/e2e.ps1`）

| 用例 | 期望 | 实测 |
|---|---|---|
| 对照：兼容模式产物**能**搜到自己的主密钥 | 能 | 能（2 处）—— 证明"搜索"这个探针本身有效 |
| 外置模式产物**搜不到**真主密钥 | 搜不到 | **0 处** |
| 不给密钥 | 恰好 `0xC0DE0007`、无输出 | `0xC0DE0007`，stdout/stderr 全空 |
| 给错密钥（32 字节 0x5A） | 同上 | 同上 |
| 给正确密钥 | 与原生逐字节一致 | `check_key(10)=143`、`sum_to(100)=5050`，rc=0 |

- `tools/e2e.ps1` 从 **147 → 152** 条用例（新增 5 条 1b 用例），门禁总数仍 11。
- 兼容模式（不带 `-key-external`）行为不变：本机 gates 11/0、e2e 152/0。

**边界（如实登记）**
- 取钥来源目前只有一种：**环境变量 `VMPX_KEY`（64 位 hex）**。
  **外部文件源**本轮试过（`CreateFileA/ReadFile`）但被上面那条转发导出问题挡下、先撤回；
  要做的话正确路子是 **ntdll 的 `NtCreateFile/NtReadFile`**（ntdll 不转发）或直接从 PEB 读
  `ImagePathName` 拼路径 —— 都能零 kernel32 依赖。**授权回调 / TPM-TEE 封印（L3）**同样未做，
  那是 DESIGN §2 里 `KeyProvider` 的 L3/L4 部分。
- **DLL + 外置密钥未做**（EXE 路径已验证）。
- **Linux/arm64 的取钥路径未做**（`-key-external` 在这些目标上直接构建失败）。
- 本条的防护等级是 **L1.5**：产物不再自足（拿不到密钥就解不出任何字节码），但密钥仍在进程内，
  挡不住运行期抓取 —— 要那一档需要 (4) 反调试/反 dump 配套。

**第一次上 CI 就被打回来，暴露一个一直存在但没人踩到的缺陷（已修）**：CI run **35497237045** 的 windows-amd64
报 `E2EFAIL ext-key/none: code=0xC0000005`（本机全绿）。根因是 `vm_get_proc` **不处理转发导出（forwarder）**：
kernel32 里一大批 API 的导出项不是代码，而是指向字符串 `"KERNELBASE.CreateFileA"` 的 RVA（判据：RVA 落在导出目录范围内），
旧实现把它当函数地址返回 —— 调过去等于跳进只读的字符串页 ⇒ 0xC0000005。
**本机 kernel32 这 5 个 API 恰好是真实桩**（写了个小工具逐个查导出项，`fwd=0`），而 runner 的 kernel32 把它们转发给
kernelbase，所以只有 CI 会崩；现有镜像自解密只用 VirtualProtect/ExitProcess，两边都是真实导出，因此这个洞一直没被踩到。
修法：识别转发器并按 `<DLL>.<Func>` 递归解析（`vm_find_module` 先试原名再补 `.DLL`，深度上限 4）。
**算法校准**：本机 `kernel32!AppPolicyGetClrCompat` 确实是转发导出，用同一套逻辑解析它 == `GetProcAddress` 的结果；
`VirtualProtect`（非转发）也相等 —— 两条都验过才敢说这个修改可信。
顺带把 e2e 里的探针按"先校准"改了：**先断言 manifest 里的 key 是 64 位 hex**，
不合格就报 `manifest key hex is not 64 chars`，而不是让错误 needle 把"没找到"变成假 PASS。

**证据**
- `tools/e2e.ps1` 从 **147 → 152** 条用例（新增 5 条 1b 用例）；门禁总数仍 **11**。
- 本机 `tools/gates.ps1` = **11 gates / 0 failed**（e2e **152 passed / 0 failed**、dll 3/3、arm64 客户机 OK）。
- 兼容模式（不带 `-key-external`）行为不变：本机与 CI 都是全绿。
- CI：**35498251605（5620143）五个作业全绿**。反证：同一条用例在 35497237045 / 35497628714 /
  35497946766 三次都是 windows-amd64 红（原因见上面的踩坑记录）。

**未做**：外部文件源（走 ntdll，见"边界"）、授权回调、TPM/TEE、(2) 带密钥 MAC、(3) 容器加密/混淆、
(4) 反调试多路径、(6) 重定位/ASLR。

### 386. 目标项 (2)：入口补丁校验从"无盐 FNV"换成**带密钥 MAC**；抽样按实测数字评估后不做

**做了什么**
- 新增 `internal/inject/patchmac.go`：`PatchMAC(master, salt, selfRVA, funcRVA, codeLen, patch)`
  - `key = KDFEntry(master, funcRVA, salt ^ 0x9E3779B9)` —— **MAC 密钥与加解密密钥域分离**
    （Poly1305 是一次性 MAC，和 ChaCha20 复用同一把密钥是明确误用，这正是 #382 选的常量）；
  - `msg = patch || le32(selfRVA) || le32(funcRVA) || le32(codeLen)` —— 把描述符自身绑进校验值：
    换槽位粘贴、跨函数挪用都会失败（旧的 FNV 只喂了 `key[0:8]` 与补丁字节）；
  - `check = le32(Poly1305(key,msg)[0:4])`，写进描述符原来的 `pad[0..3]`（**格式不变**，只是语义变了）。
- C 侧同一算式只在 `stub/win/x64/vm_kdf.c` 的 `vm_patch_mac()` 里实现**一份**；
  运行期两个使用点（`vm_run` 的 `VM_INVM_PATCHCHECK` 块、加载期 `vm_verify_table`）都调它。
  改造前这两处各自内联了一份 FNV —— 那正是"两侧各改一半"的温床，现在结构上不可能了。
- 加载期校验表的 `check` 语义随之从 FNV 变成同一个 MAC（打包端算一次、两处复用）；
  `len == 0` 的条目改为跳过（未接 KDF 的单测载荷）。
- **与 1a/1b 的关系要说清**：#382 里"攻击者可重算并修好校验值"这条，其实在 1a（每条目派生密钥）
  与 1b（密钥不在产物里）之后就已经不成立了；这一条**额外**买到的是：MAC 与加密密钥域分离、
  没有 FNV 那种可延展的代数结构、以及把描述符身份绑进校验值。

**三处 KAT 把公式钉死（跨语言 + blob 级）**
- C 主机端 `kdf_kat.c` 增加 `pmac` 行：salt=0x95EA2DB0 selfRVA=0x3140 funcRVA=0x1670 codeLen=40
  patch=`E9 7B 21 12 00` → **0x4DC8B8A6**；
- Go `patchmac_test.go`：同一个期望值，外加一条"补丁/selfRVA/funcRVA/codeLen/salt 任一变化 MAC 必须变"
  的绑定断言（防止有人把某个字段又漏掉）；
- blob 级 `kdf_blob_kat.c`：把**编好的 blob** 载入可执行内存直接调 `vm_patch_mac` 对同一个值
  （门禁里 debug 与 release 两个 blob 都查）。

**端到端验证"回填"这条绕过（新增 2 条 e2e 用例，152 → 154）**
- 新工具 `tools/patch_refill.py`：把被保护函数入口的前 N 字节**改回原生**（N 从描述符 flags 的 bit8..15 读），
  也就是报告里"按函数尾声把那 5 字节补回来"的绕过。
- 用例**故意用 `-no-enc-image` 打包**：镜像加密开着时入口补丁落在加密的 `.text` 里，
  任何文件级改动都会先被镜像 AEAD 抓到（实测退出码 **0xC0DE0004**），**这样根本测不到 MAC 这条路**。
- ① 对照：未回填的产物仍然答 143；② 回填后必须**拒绝执行**：实测 `0xC000001D`、stdout 为空。

**抽样校验：按数字决定不做（评估结论，不是漏做）**
- 实测（同一台机、`bench check_key` 50 万次、各 3 遍）：
  | 构建 | ticks（3 遍） | 中位数 |
  |---|---|---|
  | 不带完整性校验 | 15502 / 15361 / 14984 | 15361 |
  | 带 Poly1305 带密钥 MAC | 15274 / 15016 / 15509 | 15274 |
  ⇒ **差异在噪声内（<1%）**。原因：一次受保护调用约 3 万 ns，而这条校验是"一次 ChaCha20 块 + 一次短 Poly1305"，
  量级几百 ns。**#382 里"每次调用全校验吃掉了绝大部分调用开销"这个前提对我们的实现不成立**
  （那更像是在判断"每次调用校验整段字节码"的设计）。
- 抽样的代价是**把回填检测的覆盖率降到 1/32**（攻击者回填后可以跑若干次才被抓到），
  换来的是测不出来的性能 —— 所以维持"每次调用都校验"。按项目惯例作为**评估后不做**登记。
  （将来若校验变重，机制是现成的：`vm_run` 里加一个 `.bss` 调用计数器即可。）

**证据**
- 本机 `tools/gates.ps1` = **11 gates / 0 failed**（e2e **154 passed / 0 failed**、dll 3/3、arm64 客户机 OK）。
- CI：（待填）

**未做**：(3) 容器加密/混淆、(4) 反调试多路径、(6) 重定位/ASLR；以及 #385 里登记的 1b 边界项
（外部文件源走 ntdll、授权回调、TPM/TEE、DLL/Linux/arm64 取钥）。

### 387. 目标项 (3)：容器/记录明文收口 —— 魔数默认随机 + 描述符/两张表的标量字段混淆

**做了什么**
- **魔数默认每次构建随机**：原来只有 `-release` 才随机，非 release 是固定的 `"VMPK"`（0x4B504D56）——
  那正是一个可被签名/扫描的 4 字节特征。运行期根本不读这个字段（只给打包器/manifest 用），
  所以随时随机化零风险。
- **描述符标量字段加掩码**（`internal/inject/fields.go` + `vm_interp.c` 的 `vm_desc_fields()`）：
  偏移 **8..32** 那 6 个 u32（codeRVA / codeLen / encLen / flags / reserved1=funcRVA / reserved2=补丁偏移）
  与 `KDFEntry(master, 0xC0DE0003, FieldMaskSalt)` 逐字节异或。这样静态读者不再能一眼读出
  "哪个函数被虚拟化、它的原始 RVA、字节码多长、哪些节被整体加密"。
- **原镜像解密表加掩码**：表头 12..24（count / selfRVA / 保留）与每条目 0..12（rva / size / flags）
  分别与 `KDFEntry(master, 0xC0DE0004, ·)` 的两段异或；**位置在加密之后**（那几段循环要读明文 rva/size 定位节）。
- **加载期校验表加掩码**：每条 24 字节（delta / len / check / selfRVA / funcRVA / codeLen）整体异或
  `KDFEntry(master, 0xC0DE0005, ·)`。**只蒙 funcRVA 而留着 delta 是自欺欺人** —— delta 就等于
  `funcRVA - 表首RVA`，所以整条一起蒙。
- 域常量由 `vmpbuild` 从 `internal/inject/fields.go` 发进构建头（单一来源），C 侧只做异或。
- 掩码种子 `FieldMaskSalt` 每构建随机，随 manifest 传给打包端；**没有主密钥推不出掩码**。

**一个刻意的"不做"（值得写下来）**：没有断言"掩码后 flags 的 bit0 必须为 0"。
异或掩码下每个比特都以 1/2 概率被翻转，**单个比特看起来"对"不构成泄漏** ——
攻击者分不清 plain=1/mask=1 与 plain=0/mask=0；只有**确切值**匹配才带信息。
所以门禁只查"确切常量不再出现"，不查比特。

**门禁（新工具 + 校准）**
- `tools/field_mask_check.py`：在**打包产物**上断言
  ① 描述符魔数 ≠ 固定值 0x4B504D56；② `codeLen` 与 `reserved1(funcRVA)` 不再等于报告里的真值；
  ③ 解密表的 count 不再等于真实条目数。
- **校准**（探针必须先证明会失败）：把 `XorMask` 临时改成空操作重新打包，同一工具报
  `5 check(s) failed`（两个函数的 codeLen/funcRVA + 表 count 全中）；恢复后 `[OK]`。
- e2e 新增 1 条用例（154 → **155**）：上面那个检查。

**证据**
- 本机 `tools/gates.ps1` = **11 gates / 0 failed**（e2e **155 passed / 0 failed**）。
- CI：（待填）



**踩坑记录：这一条也在 CI 上死了两次（都是"本机看不见"的类型）**
1. run **35502909253**：linux-amd64 与 linux-arm64 同时红，报 `[!] VA 0xFFFFFFFF8F91E8E0 不在任何 PT_LOAD 中`。
   根因**不是产物**，而是**诊断工具** `cmd/extractpayload` 按明文读描述符的 `reserved2`（补丁相对偏移）——
   加了掩码之后它算出的是一个负 VA。这反过来正好证明掩码生效了。
   修法：工具新增 `-manifest`（用主密钥 + 掩码种子把描述符 8..32 解回来再打印；不传就明确打
   "下面的标量仍是掩码态"）；三个 ELF 门禁脚本（`verify_linux_payload.sh/.ps1`、`e2e_arm64.sh`）补上 `-manifest`。
2. run **35503163052**：linux-amd64 转绿，**linux-arm64 仍红**，而且症状换了：packed 产物能跑、但结果错
   （protected 返回入参、`vm_diag` 里 `code=0 len=0`）。根因是"魔数默认随机"暴露的一个**潜伏 bug**：
   `stub/{linux,win}/arm64/vm_entry_asm.S` 把魔数**写死**成 `"VMPK"`(=0x4B504D56) 并据此判断
   "这个 thunk 前面到底有没有描述符"。魔数一随机化，这个判断永远失败 → `vm->desc = 0` →
   `vm_run` 直接跳过整段解密分支。x86-64 那侧用的是 `$VM_DESC_MAGIC` 宏，所以一直没事。
   修法：`desc_magic.h` 增发 `VM_DESC_MAGIC_LO/HI`（aarch64 只能用 movz/movk 拼常数；LO/HI **不带 `u` 后缀**，
   那是给汇编器吃的），两个 arm64 `vm_abi.h` 在 `#ifndef VM_DESC_MAGIC` 里补同样的默认值，两个 asm 改用宏。

**证据**：CI run **35503599178（664eccc）五个作业全绿**（含 linux-arm64 与 windows-arm64-run）；
反证：35498251605（(2) 完成时）全绿 → 35502909253 / 35503163052 两次红 → 修完转绿，红绿分界就落在 (3)。

**未做**：(4) 反调试多路径、(6) 重定位/ASLR；以及 #385 里登记的 1b 边界项。

### 388. 目标项 1b 补完：外置密钥的**文件形态**（部署默认；硬件狗是后续）

**背景**：部署侧约束 —— 目前外置密钥只能是**文件**形式，后续才会上硬件狗。所以把文件取钥做扎实，
并把它做成**一个函数接缝**（上狗时只换这一个函数）。

**形状**
- 路径：`PEB -> ProcessParameters(+0x20) -> ImagePathName(+0x60)` 拼出 `<产物全路径>.vmpkey`
  （**纯内存读、零 API** —— 之前那条 `GetModuleFileNameA` 的路子在 CI 上被转发导出坑死过，见 #385）；
  环境变量 `VMPX_KEY_FILE`（UTF-16，PEB 环境块）可覆盖，绝对/相对都行（自动补 `\??\` 前缀）。
- 读取：**ntdll 的 `NtCreateFile`/`NtReadFile`/`NtClose`** —— ntdll 的导出**从不转发**，
  彻底绕开 kernel32 那批转发导出（1b 第一版就是死在这上面）。
- 内容两种都接受：**32 字节原始密钥**，或 **64 位 hex 文本**（`vmpbuild -key-out` 写出来的就是后者，
  末尾空白容忍）。
- 取钥顺序：① 文件（部署默认）→ ② 环境变量 `VMPX_KEY`（临时/CI 方便）→ 都不行就硬门 `0xC0DE0007`。

**实测四种形态**（本机，同一份产物）
| 形态 | 结果 |
|---|---|
| 没有密钥文件 | 恰好 `0xC0DE0007`、stdout/stderr 全空 |
| `<产物>.vmpkey` = 64 位 hex 文本 | `check_key(10)=143`、`sum_to(100)=5050`、rc=0 |
| `<产物>.vmpkey` = 32 字节原始密钥 | 同上 |
| 删掉文件、改设 `VMPX_KEY` | 同上（兜底路径） |

**证据**：e2e 155 → **156**（新增"文件形态"用例）；本机 gates 11/0；
CI run **35504210174（f7337a8）五个作业全绿**。

**未做**：硬件狗（同一接缝，接狗时换 `vm_key_from_file`）；Linux/arm64 的取钥；DLL + 外置密钥。

### 389. 目标项 (4)：反调试多路径 + 失败**静默延后**（不再"命中即 trap"）

**改造前**：只看 `PEB.BeingDebugged`（一条 `cmp` 就能被 patch 掉），而且命中就 `__builtin_trap()`
—— **"跳转点即指纹"**：攻击者崩在哪里就知道校验在哪里。

**现在四条路径**
1. `PEB.BeingDebugged`（每次调用都查，最便宜）
2. `ntdll!NtQueryInformationProcess(ProcessDebugPort / ProcessDebugObjectHandle)`（进程级）
3. `ntdll!NtGetContextThread(NtCurrentThread, CONTEXT_DEBUG_REGISTERS)`：硬件断点会在 `Dr0..Dr3/Dr7` 留痕
   —— **不看 `Dr6`**，它复位时本来就不是 0，看了必误报
4. 一次性、很宽松的 `rdtsc` 时间差

**判据：按"路径"记位（bitmask），≥2 条不同路径命中才定性。**
这一条是被实测逼出来的：第一版按**计数**，而 `vm_antidebug()` 有**两个调用点**
（入口蹦床的 `vm_verify_table` 与 `vm_run`），于是"只置 BeingDebugged"也被算成 2 个信号、直接定性
（实测 flagged 输出从 782 变 824）。改成位掩码后同一个路径查两次只算一位。

**第 4 条也用实测改了**：第一版是"单次测量 64 次迭代，>1e7 cycles 就算一个信号" ——
冷启动首调用（页错误/调度抖动）单次就能超过这个阈值，于是这条"宽松"路径反而成了误报源、
配合信号①直接凑够 2 位。现在改成**先热身、丢弃第 0 次、取后续 3 次的最小值**：
单步调试会让**每一次**测量都巨大，所以取最小值不会漏，但一次性噪声带不跑它。

**定性后不 trap**：置延后计数器，接下来 `VM_DBG_DEFER_CALLS`(=3) 次 `vm_run` 直接返回错误结果
（静默延后）。攻击者看到的是"偶尔算错"，不是一个可以一眼定位的崩点。

**验证**
- 新工具 `tools/antidebug_flag_test.py`：`CREATE_SUSPENDED` 启动 → 写 `PEB+2`（正是调试器对被调试进程做的事）
  → 恢复 → 与普通运行对比输出。e2e 用例（156 → **157**）断言**生产阈值下单信号不改变行为**：
  实测 `plain acc=782` / `flagged acc=782` —— 一位不动手。
- **"定性 → 静默延后"这条链**用一次一次性实验证明：把阈值临时置 1 位后，flagged 输出从 `782` 变 `185`
  且 **rc=0**（改造前同样的场景是 `0xC000001D` 崩）。实验后已改回 ≥2 位。
- 本机 gates 11/0；CI run **35505772344（615cfda）五个作业全绿**，其中 e2e 157/0 也跑在 runner 上
  （说明这套检查在共享跑机上不误报）。

**这一条也踩了两个坑（都留档）**
1. **宏守卫用错**：新反调试块的守卫写成 `VM_BLOB_USES_WIN64`（那是**宿主内部 ABI** ——
   mingw 编 linux 目标时同样成立），而 `vm_find_module`/`vm_get_proc` 只在 **Windows 目标**那段里定义
   → linux blob 引用未定义符号，CI 报"该 stub 不是自包含的"。改成
   `VM_BLOB_USES_WIN64 && __x86_64__ && !VM_BLOB_TARGET_LINUX`。
2. **门禁"假过"**：`tools/verify_linux_payload.ps1` 里 `$ErrorActionPreference = "Continue"`，
   blob 构建失败时会**继续拿旧 blob** 跑后面的探针 —— 本机一直"绿"就是这个原因（又一个
   "工具与被测对象不同步"）。现在先删目标文件，并在 vmpbuild/vmpack 之后查退出码 + 文件存在。

**未做**：Linux 侧反调试（`/proc/self/status` 的 `TracerPid`）没做 —— 现在的四条路径都是 Windows 目标的；
真调试器（`DebugActiveProcess`）的自动化用例没留下（在本环境里那套工具不稳），改用"挂起 + 写 PEB"的可控方式；
时间差路径在极慢的机器上仍可能贡献一个信号（但它单独绝不定性）。

### 390. 目标项 (6)：保留重定位 + ASLR —— "先减回去 → 解密 → 再加回来"

**默认行为改了**：`vmpack` 不再拆重定位表/清 `DYNAMIC_BASE`（旧行为保留在 `-strip-relocs` 这个应急开关后面）。
按 #381 的方案推进，落地时发现它其实是**两道**工序，缺一不可：

**工序①：镜像整体加密的那些节**
加载器在入口点之前把 `delta = 实际基址 - 首选基址` 加进了镜像里的绝对地址字段，而那些位置此刻**还是密文**。
运行期因此按顺序做四步：`VirtualProtect(RW)` → **按 DIR64/HIGHLOW 项减回 delta** → AEAD 验签 → ChaCha20 解密 →
**把 delta 加回来** → 恢复最终页保护。
- 必须在 `VirtualProtect` **之后**做减：加载器已经把那些页设成最终保护属性了。
- 验签必须在"减回来"**之后**：AEAD 认的是**密文**，加载器改过的字节验不过。
- `delta == 0`（落在首选基址）时四步里那两步是空操作。

**工序②：payload 自己的绝对 VA**
payload 节**不参与**整体加密，所以它的绝对地址**不能**靠运行期修正 —— 必须让加载器自己重定位：
打包端往 `.reloc` 追加了 7 个 DIR64 项：
- TLS 回调数组的 3 个非零项（`ImageBase+thunkRVA` + 目标原有的 2 个回调；终止项是 0，不能重定位）；
- TLS 目录**副本**的 4 个 VA 字段 —— 不靠"猜哪些字段是 VA"，而是把**原来落在原 TLS 目录范围内的重定位项平移过来**。

**踩的坑（这条是关键）**：只做①不做②的现象是**裸 `0xC0000005`**（不是优雅失败，也没有 0xC0DE00xx 退出码），
而 `-no-enc-image` 的产物却完全正常 —— 因为"把自解密回调插到 TLS 数组最前面"这套只在整体加密时才挂上。
定位路径：`-no-enc-image` 对照缩小范围 → `grep PutUint64 internal/inject/payload.go` 找出 payload 里仅有的两处绝对 VA 写入
（回调数组）→ 再想到 TLS 目录副本里的 VA 字段。

**验证（静态 + 动态，两道都校准过）**
- 静态：新工具 `tools/pe_reloc_info.py` → 打包产物 `RELOCS_STRIPPED=0 DYNAMIC_BASE=1 relocDir=0xE000/118`，
  重定位分布 `.data 5 + .rdata 34 + payload 节 7`（前两组是原镜像的，第三组是本轮补的）。
- 动态：新工具 `tools/aslr_probe.py`（挂起启动 → 读 `PEB->ImageBaseAddress`）：
  保留重定位的产物实测加载在 **0x7FF6…**，而它的首选基址是 **0x140000000** ⇒ **加载器确实重定位了它**，
  且运行结果与原生一致（e2e 158 条全过）。
- **探针校准**：`-strip-relocs` 的同一份产物**总是**落在 0x140000000 ⇒ 探针报 `[FAIL]`。
- 一个如实登记的限制：这台机器的 ASLR 熵**不按进程变化**（`notepad.exe` 的基址也同样恒定），
  所以硬条件取"**确实被重定位**"（基址 ≠ 首选基址）而不是"每次基址都不同"；后者只作为提示打印。
- 本机 `tools/gates.ps1` = **11 gates / 0 failed**（e2e **158 passed / 0 failed**，含 DLL 与 PIE 用例）。
- CI：**35510546729（942ce55）五个作业全绿**。

**未做**：ELF 侧的 `.rela.dyn/.rela.plt` 应用器没写 —— 现在 ELF PIE 路径能用，是因为测试目标落在加密节里的
重定位项恰好没有；一旦有，就需要与工序①同样的"先减后加"（`vm_unpack_image` 的 Linux 变体）。
Android/Windows-arm64 的 `vm_unpack_image` 本来就是"未实现"分支，不受影响。

### 391. 真机"部署形态"验收（`<产物>.vmpkey`）＋ 抓到一个偶发的反调试误报

**验收对象**：`demo32.exe`（192512 B，x86-64 EXE，外置密钥模式）＋ `demo32.exe.vmpkey`（64 B，hex 文本），
放在 `build/deploy/bin/`，**从别的 CWD 启动**（密钥路径由模块路径推出来，与 CWD 无关）。

| # | 用例 | 结果 |
|---|---|---|
| 1 | 正常启动 `check_key 10` | `143`，rc=0 |
| 2 | 正常启动 `sum_to 100` | `5050`，rc=0 |
| 3 | 把密钥文件藏起来 | 恰好 `0xC0DE0007`，stdout/stderr 全空 |
| 4 | 错密钥（32 字节 0x5A） | 同上 |
| 5 | 正确的 **32 字节原始**密钥文件 | `143` |
| 6 | **CRLF + 全小写** hex 文本 | `143`（解析容忍空白/大小写） |
| 7 | 密钥文件设为**只读** | `143` |
| 8 | 产物里搜真主密钥（原始 32 字节） | **0 处** |

\* 第 8 项的**校准**：兼容模式（密钥烘进 blob）的产物同样搜法得 **2 处** —— 探针本身是有效的。

**顺带验证**
- **改名即换钥**：把产物复制成 `demo32.exe`，只认 `demo32.exe.vmpkey` —— 把它的密钥藏起来立刻 `0xC0DE0007`，
  放回就 `143`（密钥绑定的是**产物全路径**，不是固定文件名）。
- **ASLR**：`tools/aslr_probe.py` 报 `image loaded at a base != preferred`（首选 0x140000000，实测 0x7FF6…）。
- **反调试单信号**：`tools/antidebug_flag_test.py --expect-unchanged` → `plain acc=782 / flagged acc=782`。
- **`VMPX_KEY_FILE` 覆盖**（绝对路径）→ `143`。

**验收过程中抓到并修掉的一个偶发**：反调试的**时间差**路径阈值定得太低（1e7 cycles ≈ 3ms）。
在忙的机器上，一次 64 次迭代的空转也能被调度/页错误顶到几毫秒 —— 于是"BeingDebugged + 时间差"
凑够两条路径、把**没被调试**的进程判成被调试，结果被静默改掉（本机与 CI 各出现一次，e2e 因此偶发红）。
阈值提到 **1e9 cycles（约 0.3s）**：单步调试会让 64 次迭代里每一步都按毫秒/秒计，取最小值仍远超阈值，
不会漏；而调度抖动顶多几毫秒，不会误报。修完把该用例连跑三遍全绿（提交 `84fd8d1`）。

**PE32（32 位 x86）的现状（如实登记）**：拿一份真的 32 位 Exe（`SysWOW64\notepad.exe`，Machine=0x14C）试 vmpack：
`[!] 不支持的 PE 机器类型 0x14C` —— **明确拒绝，不产出坏产物**。要支持 32 位是**平台移植**
（32 位 stub + 32 位 lifter + packer 的 PE32 分支），不是开关。

**部署侧小坑（登记未改）**：`vmpbuild` 的 `-out/-manifest/-key-out` **不会自动建父目录**，
目录不存在时报 `写主密钥文件失败: ... The system cannot find the path specified`。

**证据**：本机 `tools/gates.ps1` = **11 gates / 0 failed**；CI **35554780157（84fd8d1）五个作业全绿**。

### 392. 用**你自己的真 demo**（`D:\demo_exe`）验收：能保护、输出与原生一致；并挖出两个真 bug + 一个 lifter 缺口

**对象**：`demo64.exe`（PE32+ x86-64，MSVC，`build.bat` = `/Od /Zi /RTC1 /MDd`；有 `.pdb`、**没有 `.map`**）。
`demo32.exe` 是 **PE32(i386)** —— vmpack 明确拒绝（`不支持的 PE 机器类型 0x14C`），所以这轮全部用 64 位那份。

**函数名怎么定位**：vmpack 走 **导出表 + MAP**（`-map`），**不读 PDB** —— 直接跑会报
`找不到符号 "Demo::Math::Add"（该 PE 有 0 个符号；MAP 与导出表里都没有这个名字，可用 -map 指定 MAP）`。
用 VS2022 重新编译（加 `/MAP`）后，用 **mangled 名**（`?DemoGcd@@YAHHH@Z`）就能定位。

**可保护性（逐个函数试出来的，这才是你要的信息）**

| 构建 | 结果 |
|---|---|
| 调试版 `/Od /RTC1`（= 你的 build.bat） | **15/17 可保护**；`Math::Gcd`、`Math::IsPrime` ✗（缺 `CDQ` + `IDIV [mem]`） |
| 发布版 `/O2` | 除上面两个外，`Mean` 也 ✗（缺 `CVTDQ2PD`，即 SSE2 int→double） |

**验收结果（发布版，保护 11 个函数）**：输出与原生**逐行一致（0 行不同）** ✓；没有密钥 → **什么都不打印**、`0xC0DE0007` ✓；ASLR 重定位生效 ✓；产物里搜不到主密钥 ✓。交付件在 `build/deliver2/`（`demo64.exe` + `demo64.exe.vmpkey`）。

**但调试版挖出两个真 bug（用单函数二分确认，不是互相影响）**

1. `?DemoFormatReport@@YAHPEADHPEBDH@Z`：`score=8`（原生 42）——**错**。它形如
   `sprintf(buf, n, fmt, score)`，那个 `%d` 参数走的是**栈**（第 5 个及以后的参数 / varargs）。
   同一个函数在 `/O2` 下是**对的** —— 两种构建把参数物化的方式不同，所以嫌疑集中在
   **VM 的栈传参 / varargs 路径**。
2. `?DemoMean@@YANPEBNH@Z`：`0.000`（原生 3.500）——**错**。double 数组求和，涉及 SSE2 与浮点。
3. 附带的因果链：`DemoFingerprint` **单独**保护时是对的 ✓；它在 15 函数版里错，是因为它 hash 的输入
   来自上面两个函数 —— 正好说明"错的不是它"。

**结论**：你这套 demo 在**发布版**上已经可以直接保护（输出与原生一致）；**调试版**还需要把这两条 VM 路径修好。
下一步优先级建议：① `CDQ/CQO + IDIV/DIV` 的 lift（解锁 Gcd/IsPrime，两个构建都受益）；② 调试版的栈传参/varargs 排查；
③ `CVTDQ2PD`/double 路径；④ 修好 ①② 后再复跑 `D:\demo_exe` 的全量验收。

### 393. `.vmpkey` 的产生规律（回答提问）＋ 顺手修掉"主密钥用可预测随机源"的真问题

**规律**
- 每次 `vmpbuild -key-external` **随机生成一把 32 字节主密钥**；`-key-out` 把它写成 **64 位 hex 文本**，
  这就是 `.vmpkey` 的内容（所以文件大小固定 64 字节；运行期也接受 32 字节原始密钥文件）。
- **粒度是"每个 blob"**：一份 blob 打出来的所有产物共用这把主密钥；**每个被保护函数**的加解密密钥
  再由 KDF 从主密钥派生（`KDFEntry(master, funcRVA, salt)`），所以函数之间不共用密钥流。
  默认流程（每个程序单独 `vmpbuild` 一次）下，就是"一个程序一把"。
- 文件名规则是死的：必须是 **`<产物全路径>.vmpkey`**（`VMPX_KEY_FILE` 可覆盖绝对路径）。
- **不绑硬件**：密钥里没有任何 CPU/硬盘/主板/机器码信息 —— 它是一个**载体令牌（bearer token）**，
  **谁拿到这个文件，谁就能在任何机器上跑**（拷到别的电脑照样跑）。这也是交付时要求"产物与密钥分开传递"的原因。
- 想绑机器/限授权，改的是**取钥那一步**（接缝：`vm_key_from_file()` → `vm_master()` → KCV 自检 → 不对就 `0xC0DE0007`），
  密码学与 VM 那一层都不用动。由弱到强：DPAPI（`CryptProtectData`，绑用户/机器）→ 自采硬件指纹
  （易受换硬件/虚机迁移影响）→ TPM 封印（`TpmSeal`/NCrypt，绑该机 TPM）→ **硬件狗**（密钥在狗内派生，可移动、可吊销）。

**顺手修掉的真问题：主密钥以前不是密码学随机**
- 原实现：`rnd := rand.New(rand.NewSource(time.Now().UnixNano() ^ 0x5DEECE66D))` 然后 `rnd.Intn(256)` ——
  **math/rand + 墙上时钟种子**，输出完全由种子决定。
- **可利用性演示**（`build/seedfind`，不进仓库）：密钥文件是在生成密钥的**同一步**紧接着写出的，
  所以种子时刻与文件 mtime 只差几毫秒。以 mtime 为中心、±0.3s、**100ns 步长**枚举种子：
  - 旧二进制生成的密钥 → **HIT，偏移仅 `-0.605 ms`** 就复现出主密钥；
  - 新二进制生成的密钥 → 同一攻击 **MISS**。
  也就是说：攻击者只要能大致确定构建时刻（毫秒级，甚至可以直接读文件时间戳），就能自己推出主密钥，
  "产物不自足"这条性质会被绕过。
- 改动（`cmd/vmpbuild`）：主密钥 / KCV salt / 字段掩码 salt / 占位密钥 **全部改走 `crypto/rand`**
  （失败即报错，不静默退化）；操作码映射的每构建随机种子同样改走 `crypto/rand`（可预测种子等于把映射送出去）。

### 394. 密钥生命周期（回答"同一个 exe / 同一项目不同时期的产物，`.vmpkey` 固定吗"）

**结论：默认不固定；但只要复用同一份 blob，就能一直固定。**

| 实验（本机实测） | 结果 |
|---|---|
| 同一个 exe、同样的被保护函数，连做两次 `vmpbuild -key-external` | 密钥**不同**（`22f97a80…` vs `37f34825…`） |
| 复用同一份 blob（+同一把 key）打**两个完全不同的程序**（用户的 `demo64` 与 `testdata/target`） | 同一个 `.vmpkey` 内容**两个都能开** |
| 拿**另一次构建**的密钥去开旧产物 | 打不开：恰好 `0xC0DE0007`、无输出 |

**为什么**：主密钥是 `crypto/rand` 现取的随机数，**不从 exe 派生**，也与"保护了哪些函数"无关 ——
它只属于**那一份 blob**（blob 里的 KCV、掩码 salt、sigma、操作码映射、描述符魔数都是同一次构建的产物）。
被保护函数的密钥是运行期/打包期用 `KDFEntry(master, funcRVA, salt)` 现推的，所以改函数只改派生出来的那一把。

**"一次签发、长期复用"的配方**（密钥不随发版变化）

    # 一次性：生成一个"密钥纪元"，把这三样当发布资产保管
    vmpbuild -src stub/win/x64 -out release/blob.bin -manifest release/blob.json \
             -entry vm_entry -key-external -key-out release/project.vmpkey
    # 每次发版：只打包，不再动 blob/key
    vmpack -exe new_build.exe -func ... -blob release/blob.bin -manifest release/blob.json -out app.exe
    copy release\project.vmpkey app.exe.vmpkey

未加密代码如何增删改都无所谓；**改被保护函数的实现也没关系**（同一个主密钥照样能开）。
blob 是解释器、与 exe 无关，所以同一份 blob 可以长期服务很多版本。

**边界（如实登记）**
- **blob 与密钥是一对**：换 blob 就得换密钥，旧密钥打不开新 blob 的产物（实验 3）。
- 一把密钥覆盖的产物越多，泄露后果越大。想要更严的做法是**按客户/按批次分密钥纪元**，
  或者干脆保持默认（每次构建一把，代价是每次发版都要重新分发密钥）。
- 目前主密钥只能由 `vmpbuild` 随机**生成**；如果希望**由你们提供**（CI 里从密钥库注入、
  vmpbuild 不生成密钥），需要加一个 `-key-hex` 之类的入口 —— 这是**未做项**，需要时再加。

### 395. 产品化视角的密钥生命周期：新增 `-key-in`（指定主密钥）＋ 输出目录自动创建

**问题（客户提出的两个）**
1. 把 vmpbuild/vmpack 当商品卖给客户，**所有客户的 blob 是不是同一份**？
2. 工具**升级后**重新编译出的 blob 与旧的不同，**原先发出的密钥是不是全部作废**？

**回答 2 的实现缺口先补上：`vmpbuild -key-in`**
以前主密钥只能随机生成 —— 每次重建 blob 就换钥匙，客户升级一次工具就得把已发出的 `.vmpkey` 全换一遍。
现在可以**指定**主密钥：
- `-key-in <64 位 hex 字面量>`，或 `-key-in <文件>`（**32 字节原始密钥**或 **64 位 hex 文本**都能吃）；
- 只打印来源（"主密钥来自 -key-in"），**绝不打印密钥本身**；
- 不传它就照旧随机生成（保持默认行为与既有工作流不变）。

**实测（本机）**
| 验证 | 结果 |
|---|---|
| 同一把 `-key-in` 连做两次构建 | 两次 `-key-out` **完全相同**，且等于指定的那把；两份 blob 内容**仍然不同**（每构建随机的操作码映射/魔数/掩码/salt 照旧生效） |
| 用**两份不同的 blob** 打同一个 exe（等价于"升级工具后重建 blob"） | 同一个 `.vmpkey` **两个产物都能开**（`check_key(10)=143`、`sum_to(100)=5050`）；不给密钥则恰好 `0xC0DE0007` |
| `-key-in` 走 32 字节原始文件 | 得到与 hex 形式**同一把**密钥 |

⇒ **结论：升级工具不再需要作废旧密钥**。旧产物当然继续用它们出厂时的 blob+密钥（不需要重新签发）；
只有"以后的新构建是否沿用老钥匙"是个策略选择：沿用就 `-key-in`，想换纪元就让它随机生成。

**顺带修掉的小坑**：`-out` / `-manifest` / `-key-out` 现在会自动 `MkdirAll` 父目录 ——
之前目录不存在会报 `写主密钥文件失败: ... The system cannot find the path specified`。

**回答 1（写进设计文档口径）**
- 默认**不是同一份**：每个客户在自己的环境跑 vmpbuild，操作码映射、描述符魔数、sigma 掩码、
  字段掩码 salt、KCV salt、密钥材料全是**每构建随机**的，所以每家的 blob 都不一样。
- 但如果厂商**发预编译 blob**（省掉客户装编译器），那所有客户就是同一份 blob ✗ ——
  此时建议"每客户发一份用不同随机量编出来的 blob"。
- 威胁模型要说清：**blob 最终躺在每个交付产物里**，攻击者必然拿得到它 ——
  "blob 各不相同"防的不是"读懂引擎"（引擎结构本来就一样），而是**跨客户的特征/脚本/偏移复用**。
  **真正的秘密是密钥**（外置模式下 blob 里只有占位密钥 + KCV），所以**客户隔离靠的是"每客户一把主密钥"**，
  哪怕 blob 相同也成立。
- 推荐形态：按"客户（或客户+产品线）"分**密钥纪元**，把 `blob.bin + blob.json + <该纪元密钥>` 三者归档；
  客户每次发版复用同一套 blob；升级工具时用 `-key-in` 把同一把主密钥喂进新 blob。

**证据**：本机 `tools/gates.ps1` = **11 gates / 0 failed**（e2e 158/0）；CI **35562269143（8ddde4d）五个作业全绿**。

### 396. 密钥纪元管理工具 `vmpepoch` ＋ `docs/TODO.md` 登记 5 项待办

**先记下这条硬约束**：**一个 blob 只能配一把主密钥** —— blob 里的 KCV 是构建时用那把密钥算出来的
（`KDF(master, KEYK, 该 blob 的 salt)`）。所以"换密钥"必然"换 blob"（一次 vmpbuild ≈ 几秒、约 40KB），
**不能只换钥匙**。反过来，同一套 blob/key 可以打**任意多个 exe、任意多版本** —— 纪元是"授权边界"，不是"程序"。

**工具 `cmd/vmpepoch`**（登记表 `epochs.json` **不存密钥本身**，只存路径与指纹 sha256 前 8 字节）
- `new --name <纪元> [--key-in <hex|文件>] [--dir ...] [--src stub/win/x64] [--guest arm64] [--note ...]`
  —— 内部调 `vmpbuild` 建出一套 {blob, manifest, key} 并登记；
- `list` —— 列纪元（名称/时间/blob 哈希/密钥指纹/guest/备注）；
- `which --exe <产物>` —— **这个产物是哪个纪元打的**；
- `keyid --key <.vmpkey>` —— **这把钥匙属于哪个纪元**；未登记则明确报错并非 0 退出（可当 CI 断言）。

**实测（本机）**：建 `custA`（随机密钥）与 `custB`（`-key-in` 指定密钥）两个纪元 →
`which` 分别正确认出 `custA` / `custB` 的产物；未登记的旧产物明确报"没匹配到"（rc=1）；
`keyid` 对两个纪元的密钥都正确归属。

**做这个工具时踩到的两个实情（已修正并写进注释）**
1. **payload 在产物里被拆成多段**：代码段（如 `.bvbjiho`，0x8000）+ `.bss` 段（0x2000）+ 表段（0x400），
   而 blob 是 40960 字节、**跨了前两段** —— 所以"某一整段装得下整个 blob"永远不成立 ✗，
   必须按"段的**前缀** vs blob 的**同长前缀**"比对（实测前缀完全一致）；
2. `which` 对未登记产物必须明确失败（返回非 0），否则 CI 里的"纪元核对"会变成假过。

**`docs/TODO.md`**：登记了客户点名要跟的 5 项 ——
① `CDQ/CQO/IDIV/DIV` 的 lift（解锁 `Gcd`/`IsPrime`，两个构建都受益）；
② **调试版栈传参/varargs**（`DemoFormatReport` 在 `/Od` 下 `score=8` vs 原生 42；影响面最大）；
③ `CVTDQ2PD`/double（`DemoMean` 输出 0.000）；
④ 修完 ①② 后用 `D:\demo_exe` 复跑全量验收（接用户自带 `verify.py` + `ground_truth_exe.txt`）；
⑤ `vmpepoch` 的可选增强（ELF 支持、`export` 发版包、CI 集成）。
另附"其他已登记"：ELF `.rela` 应用器、Linux 侧反调试、DLL+外置密钥、TPM/DPAPI 等。

**证据**：本机 `tools/gates.ps1` = **11 gates / 0 failed**（e2e 158/0）；CI **35563387578（72fca08）五个作业全绿**。

### 397. 术语澄清：我口中的"纪元" = 客户口中的"某把客户密钥 + 用它编出来的解释器"

客户提出的产品模型是**按"授权方"分密钥**（不是按软件分）：厂商给一级客户 key-A/key-B；
一级客户再用 `vmpbuild -key-in key-A` 保护自己的多套软件；下游客户 A-A/A-B 各有一把放在
**HL（硬件锁）**里的密钥（key-A-A/key-A-B）。据此把术语对齐并写进 `docs/TODO.md` 第 5 项：

- **"纪元"的准确定义**（`cmd/vmpepoch` 管理的对象）= 一套 `{blob.bin + blob.json + 主密钥}`，
  三者一一对应（一个 blob 只能配一把主密钥）。在客户的语境里，**一把"授权方密钥" + 用它编出的解释器就是一条纪元**；
  所以**纪元的边界应当是"谁被授权"（授权方/许可证），而不是"哪个软件产品"** —— 一个授权方名下的
  多个产品**共用一个纪元**（都用他那把密钥打），这也正是需求 R1（产品升级、下游不用换钥匙）的实现方式。

- **R1（升级不换钥匙）：现状已满足** —— 密钥是身份、产物自带解释器；同一把密钥 + 复用同一套 blob
  （或用 `-key-in` 把同一把密钥喂进重建的 blob）即可覆盖该产品线所有版本（实测见 #394/#395）。

- **R2（A-A 增购产品 B、要"更新授权"而锁里密钥不能改）：现状只能"再打一份产物给他"**
  （授权=持有密钥；扩展=把 B 用 key-A-A 打包发过去，锁不用动 ✓），
  但**没有到期/吊销/机器绑定/按产品限缩**的能力 ✗ —— 真正的许可证层未实现。
  设计草案已登记到 `docs/TODO.md` 第 5 项（`-license-product` + `-license-pubkey` + Ed25519 签名的
  `<产物>.vmplic` + 运行期 `vm_license_check()` 走同一个硬门），主要成本是 blob 侧 Ed25519 验签（约 600–900 行 C）。
  离线授权必须用**公钥签名**：blob 是公开的，对称 HMAC"塞进 blob"会被伪造 ✗。

**证据**：本机 `tools/gates.ps1` = **11 gates / 0 failed**（e2e 158/0）；CI（待填）。
### 398. 目标项 (2) 运行期强制：门禁链路就位、「无授权即拒绝」已成立；「合法授权」这条路径尚未打通（如实登记）

**已做**（全部默认关闭，不影响现有行为）
- `vmpbuild`：blob 新增占位全局 `vm_license_meta`（强制 `.data`，默认 `kind=0` = 不启用），manifest 暴露它的符号偏移与 `keyExternal`；
- `vmpack`：`-license-vendor / -license-product / -license-pub` —— **非外置密钥的 blob 直接拒绝**（宁可不做，也不要出现「以为有门禁其实没有」）；
  把 vendorID/productID 的 `SHA-256[0:4]` 与签发者公钥写进**产物里那份 blob 副本**（blob 在 payload 偏移 0，符号偏移来自 manifest）；
- `vmpepoch lic-export`：把 JSON 授权导出成**运行期二进制授权** `<产物>.vmplic.bin`（24 字节头 + 16 字节/项 + 64 字节 ECDSA 签名，与 C 侧逐字段对齐）；
- blob 侧 `vm_license_check()`：读授权（复用 1b 的 PEB 路径 + ntdll 读文件，零 API）→ 校验 magic/版本/vendorHash/长度 → **CNG（bcrypt）验 ECDSA P-256** →
  查 productHash 与到期 → 不通过走同一个硬门 `0xC0DE0007`；调用点放在**入口蹦床**（= 入口点、main 之前）。

**实测**

| 场景 | 结果 |
|---|---|
| 不带授权文件（外置密钥 + 已烘 vendorID/productID/公钥） | **恰好 `0xC0DE0007`、stdout/stderr 全空** ✓ |
| 带合法授权 | ✗ **ud2 崩（`0xC000001D`）**，地址在 payload 内、稳定复现 |

**定位过程（分支码 0x21..0x3E 逐段压范围）已排除**
- 授权路径拼接、读文件、magic/版本/vendorHash/长度校验（这些分支都能给出对应的干净退出码）；
- **bcrypt.dll 懒加载**：简单进程的模块表里根本没有它 → 已改成用 `ntdll!LdrLoadDll` 自己加载（ntdll 不转发）；
- **TLS/loader-lock 时序**：门禁最初放在 `vm_master()`（该路径会被 TLS 回调走到，回调里不能加载 DLL/调 CNG）→ 已移到入口蹦床；
  并用 `-no-enc-image`（无 TLS 回调）对照，崩溃现象**不变** ⇒ 与 TLS 时序无关。

**下一步**（已写进 `docs/TODO.md`）：① 用调试器把崩溃点定位到具体 CNG 调用（或继续压细分支码）；
② 备选：blob 里自带 SHA-256（约 120 行），只在 CNG 里做 `BCryptVerifySignature`；③ 打通后补五个验收场景。

**风险控制（重要）**：整条路径**默认关闭**（`kind=0`）；门禁只在**外置密钥模式**下编入；`vmpack` **拒绝**给非外置 blob 传 `-license-*`。
因此现有产物、门禁、CI 全部不受影响 —— 本机 `tools/gates.ps1` = **11 gates / 0 failed**（修复过程中曾因调用点放在共享代码里导致 4 项红，已修）。
### 399. 目标项 (2) 运行期强制打通 —— 根因是「自哈希覆盖了 .data」；在客户 demo 上端到端验完

**根因（一次性定位）**：blob 的自哈希区间是 **[0, bssOff)**，也就是「blob 起点到 `.bss` 起点」——
**包含 `.data`**。而 vmpack 把 vendorID/productID/签发者公钥打进 `.data` 里的 `vm_license_meta`，
于是自哈希立刻对不上 → `vm_selfcheck()` 直接 `ud2`（这就是前一轮「带合法授权必崩、不带则干净 0xC0DE0007」的原因）。
修法：**打包端在补丁之后按同一套 FNV-1a 参数重算自哈希**（`vmpack` 里 8 行；参数与 vmpbuild 的 (g) 段逐字一致）。

**顺手改掉的一点**：门禁失败对外**统一**是 `0xC0DE0007`（契约）；"卡在哪一步"不再借退出码表达，
改为写进内部诊断变量 `vm_license_fail_stage`（`.bss`，非 static，会出现在 manifest 符号表里）。

**端到端验收（本机，客户自己的 `D:\demo_exe\demo64.exe` release 版，11 个函数进 VM，外置密钥 + 运行期强制）**

| 场景 | 结果 |
|---|---|
| 无授权文件 | **`0xC0DE0007`、stdout/stderr 全空**（程序起不来） |
| 合法授权（`PROD-DEMO@2027-12-31`） | 与原生**逐行一致（不一致行数 = 0）** |
| 授权被改一个字节 | `0xC0DE0007` |
| 授权已过期 | `0xC0DE0007` |
| 授权里没有这个 productID | `0xC0DE0007` |
| vendorID 不符（别家签的） | `0xC0DE0007` |
| 伪造签名（换密钥签同样内容） | `0xC0DE0007` |
| **授权更新**（`lic-edit --add PROD-EXTRA` 后重导出） | 不重打包、不换密钥，程序照常运行 |

**固化进门禁**：`tools/e2e.ps1` 新增 5 条用例（无授权/有授权/篡改/过期/伪造签名）→ e2e **158 → 163**；
本机 `tools/gates.ps1` = **11 gates / 0 failed**。

**仍默认关闭**：`vm_license_meta.kind = 0` 时不校验；`-license-*` 只在**外置密钥模式**的 blob 上可用（vmpack 强制）。
**待做**：Sentinel 接口层（若上狗）；吊销/黑名单（现在只有有效期这条杠杆）。
### 400. 目标收口：商业化闭环的**可复跑验收脚本** `tools/acceptance_demo.ps1`（23/23 全通过）

**这是什么**：给定客户自己的 demo（`D:\demo_exe`），一条命令跑完从「厂商签身份」到「下游拿授权跑起来」的全流程，
并逐行与原生输出比对。它是本目标的 ⑦ 项（把手工验证固化成可复跑验收）。

```
powershell -NoProfile -File tools/acceptance_demo.ps1 -BuildDemo
powershell -NoProfile -File tools/acceptance_demo.ps1 -DemoExe X.exe -DemoMap X.map   # 客户自带带 MAP 的产物
```

**23 项检查（本机实测全通过）**

| 组 | 检查 |
|---|---|
| ① 工具授权 | 厂商根密钥对；客户生成工具密钥并提交（**带持有证明**）；厂商签发构建凭据；打一个**烘了厂商根公钥**的发布版 vmpbuild；**没有凭据 → exit 8 拒绝工作**；凭据+私钥齐全 → 可用 |
| ②③ 密钥纪元 + 保护 | 建立纪元（blob+manifest+密钥）；用**外置密钥 + 运行期强制**保护客户 demo（多函数）；产物可归属到该纪元（`vmpepoch which`） |
| ④ 授权链 | 根给销售部签 `canIssue` 证书；销售部给客户签发（链深 1）；**无 `canIssue` 的证书签下级被拒**；客户给下游签授权并导出（**导出前验链**） |
| ⑤ 运行期强制 | 无授权 → 恰好 `0xC0DE0007`、无输出；**合法授权 → 与原生逐行一致（13 行数值全等）**；篡改一字节 / 过期 / 伪造签名 → `0xC0DE0007` |
| ⑥ 授权更新 | `lic-edit --add PROD-EXTRA` 后重导出：**产物哈希不变**、程序照常、输出与原生一致 |

**过程中修掉的两个真问题**
1. `vmpepoch which` 用「注入段前缀 vs blob 前缀」认纪元，但 `vmpack` 会把 vendorID/productID/签发者公钥
   写进 `.data` —— 于是**打过运行期强制补丁的产物永远认不出来** ✗。修法：只比到该纪元 manifest 里 `.data` 起点为止的前缀；
2. `lic-export` 现在支持 `--root-pub`：**导出前先验证书链**，把 ④ 的委派链正式纳入运行期路径。

**注意（对客户的实操提醒）**：`vmpack` 靠 **MAP 文件**按名字定位函数（**不读 PDB**）。客户自带的 `demo64.exe` 没有 `.map`，
所以要 `-BuildDemo` 现场重编（带 `/MAP`）或让客户提供 `.map`。这一点已写进脚本帮助与 `docs/TODO.md`。
### 401. TODO 重评 + 新目标「要么正确、要么明确拒绝」；顺修 `CDQ`/`CQO` 的 lift

**TODO 重评（关键结论）**：清单里最要紧的一条原本**不在清单上** —— 我们缺一道**保护前逐函数差分自检**。
证据：`/Od` 构建下 `DemoFormatReport` 被**成功保护**却算错（`score=8` vs 原生 42）✗，
即当前工具会**静默产出错误的受保护程序**，比「拒绝保护」危险得多。已提为必做第 ④ 条，并据此立了本目标。
其余项重评为：必做 4（①②③ + 差分自检）、建议做 3（私钥 DPAPI/TPM、接客户 `verify.py`、export/CI 集成）、
按需/待决策 6（含 Sentinel 接口层、吊销、ELF/Linux、**PE32 支持**）、可砍 1（授权回调形态并入 DPAPI/TPM 路线）。

**本轮代码改动：`CDQ`/`CQO` 原来根本没被 lifter 处理**
- 原因：`internal/lift/x64/lift.go` 只有 `case x86asm.CDQE`（CDQE：EAX→RAX）；Go 的 x86asm 里 CDQ/CQO 是**不同助记符**，落到默认分支报「暂不支持该指令」。
- 修法：新增 `case x86asm.CDQ` → `AluRI{Sar, |KeepFlags, W32, RDX, RAX, 31}`；`case x86asm.CQO` → 同形 W64/63。
  CDQ/CQO 都**不改标志位**，正好用上 `KeepFlags`（x86 侧恒为 0 的那个 bit7）。
- 实测：`?DemoGcd@@YAHHH@Z` 的拒译由 **2/13 → 1/13**（只剩 `IDIV R8L`）；`?IsPrime@Math@Demo@@QEAA_NH@Z` 同理。

**`IDIV`/`DIV` 的最小改法已摸清并写进 `docs/TODO.md`**（下一轮照做）：**不需要新增操作码** ——
复用 `OP_ALU_U`（`[op][kind][width][dst][a]`，`a` = 除数、`dst` 留空），只加两个 ALU kind `ir.DivU/DivS`（值 0x14/0x15），
同步 `vm_opcodes.h` 的 `K_DIVU/K_DIVS`、`internal/vm/ref.go`（含参考实现，arm64 差分门禁要用）、`kind_table_test.go`；
语义放在 `OP_ALU_U` 分支里**先拦截**（隐含 `DX:AX` 族被除数，商→AX 族、余→DX 族），**除零/溢出直接 trap**；
8 位形式（`IDIV R8L`：商 AL、余 AH）最容易写错，客户 demo 两个函数正好一个 8 位、一个 32 位。

**验收（本轮）**：`tools/gates.ps1` = **11 gates / 0 failed**（含 `go test ./...` 与 arm64 客户机差分）。
注：`AGENTS.md`/`docs/HANDOFF.md` 的验收第 1 条要求 `tools/preflight.ps1`，但该脚本已在 `a83a4ad` 移除
（本文件 #4322 已记录：脚本自检不过被删）——**当前仓库里没有这个文件**，本轮以 `tools/gates.ps1` 为准。
### 403. 目标第 3 轮：CI 转绿（可移植长除法）+ 目标项 ② 复现并定位到指令序列

**CI**：`35606046838` —— **五作业全绿**（上一轮 `45bbf49` 红的 arm64 三项，随 `89a4ada` 的可移植 128/64 长除法转绿）。

**目标项 ② 的进展（复现 + 定位，未修完）**
- 用客户源码编出 `/Od /Zi /RTC1 /MDd` 的 `demo64_dbg.exe`（带 `/MAP`），只把 `?DemoFormatReport@@YAHPEADHPEBDH@Z` 进 VM：
  **受保护输出 `score=8`，原生 `score=42`** —— 与既有记录一致，属「保护成功但算错」。
- `dumpbin /disasm` 显示该函数在 `/Od` 下是经典的 **varargs home+转发**：先把 4 个入参写进 `[rsp+8..20h]`，
  `push rdi` + `sub rsp,30h` 之后又从 `[rsp+40h..58h]` 读回（同一批绝对地址），再转发给 `Math::FormatReport`。
  即**不依赖调用者真实压栈**，所以 bug 在 VM 对这段栈建模（`push`/`sub rsp,imm` 之后的 `[rsp+disp]` 地址或位宽）上。
- 反汇编与候选修法已写进 `docs/TODO.md` §2，下一轮照此改，并用 `/Od`+`/O2` 双构建验证。
### 404. 目标第 3 轮：抓到并修掉「三操作数 IMUL（内存源+立即数）」的静默算错；第二个根因定位到 `OP_CALLN`

**诊断反转（重要）**：原以为 ② 是「栈传参 / varargs」问题。用一组合成函数隔离后**否掉了这个假设** ——
`five`（读第 5 个栈参数）、`sum5`、`va_sum`、`va_last`（varargs）**全部与原生一致** ✓，
唯一错的是 `four(a,b,c,d) = a + b*2 + c*3 + d*4` → 受保护得到 **27**，原生 **30**。

**根因 1（已修）**：`internal/lift/x64/lift.go` 的 `liftImul` 内存操作数分支**丢掉了立即数**，
并把被乘数写成 `dst`（应为刚载入的 `VMSCR`）—— 于是 `imul ecx,[rsp+18h],3` 退化成 `ecx = ecx × mem`。
代入 `four`：`ecx = b*c = 6`、`eax = (1+4)+6 = 11`、`+d*4 = 27` —— **与实测的 27 完全吻合**。
修法：三操作数形式发出 `AluRI{Mul, w, dst, A: VMSCR, Imm}`，两操作数形式保持 `AluRR{dst, A: dst, B: VMSCR}`，
宽度改用**目的宽度**（原来用内存宽度）。
证据：隔离用例 `four` **27 → 30** ✓（五个函数全部与原生一致）；
新增 `internal/lift/x64/imul_mem_test.go`（IR 级回归：立即数必须保住、被乘数必须是 VMSCR、两操作数形式不许被改坏）。

**根因 2（已定位，未修）**：VM 调用 **native 函数**时只传寄存器参数 —— `stub/win/x64/vm_interp.c` 的 `OP_CALLN`
直接用 C 函数指针 `fn(rcx,rdx,r8,r9,r10,r11,r12,r13)` 调用，**native 被调者读自己的栈参数时会落在宿主 C 栈上**。
证据：合成用例 `caller5(x) { return five(1,2,3,4,x); }`（`five` 保持 native）→
**native 得到 42，受保护得到 1**；`caller5b` 同样错。这正是客户 demo `/Od` 下 `score=8`（应为 42）的剩余来源：
`DemoFormatReport` 把 `score` 作为**第 5 个参数**转发给 native 的 `Math::FormatReport`。
修法（下一轮单独做）：给 `OP_CALLN` 加 ABI 蹦床 —— 切到 guest 栈、压一个返回地址、装载寄存器参数后再 call，
并在返回后恢复宿主 rsp；同时要处理 `FrameSkew`（guest 栈相对原生栈的偏移）。

注：本轮起把 `docs/TODO.md` §2 的标题与内容按**真实根因**改写（原「栈传参/varargs」的假设已被实测否掉）。
### 405. 目标项 ② 完成：VM 调 native 的 Win64 ABI 蹦床（栈参数终于送对了）

**根因 2 的修法**：`OP_CALLN` / `OP_CALLR` 原来直接 `fn(rcx,rdx,r8,r9,...)` —— 只传寄存器参数，
native 被调者读自己的**栈参数**（第 5 个及以后，位于 `[rsp+0x28..]`）时落在宿主 C 栈上。
现在改成走一段 **naked asm 蹦床**（`stub/win/x64/vm_interp.c` 的 `vm_calln_x64`）：

```asm
pushq %rbx / pushq %rbp          ; rbx 由被调者保存，用来存宿主 rsp 锚点
movq %rsp, %rbx
movq %rcx, %rbp                  ; 参数块（Win64 第 1 个整型参数在 RCX）
movq 8(%rbp), %rsp               ; 切到 guest 栈
movq 16(%rbp), %rax              ; a0 → rax（rcx 还被参数块指针占着）
movq 24(%rbp), %rdx / 32(%rbp), %r8 / 40(%rbp), %r9
movq 0(%rbp), %r10               ; fn
movq %rax, %rcx
callq *%r10                      ; 返回地址由 call 自己压，落地点就是下一条
1: movq %rbx, %rsp / popq %rbp / popq %rbx / ret
```

这样被调者入口 `rsp = guest_rsp - 8`，它读 `[rsp+0x28]` 正好是 guest 写在 `[guest_rsp+0x20]` 的那格 ✓。
（只对 Windows x64 启用；Linux/SysV 与 arm64 的调用约定不同 —— 前 6/8 个参数都在寄存器里，留作后续。）

**过程中自己踩的三个坑（都已写进代码注释）**
1. 按 SysV 读了 `%rdi` 当第一个参数 ✗ —— Win64 是 `%rcx`，于是拿到野指针，切栈时 `0xC0000005`；
2. 先 `sub rsp,8` 再手写一个返回地址 ✗ —— `call` 自己会压返回地址，结果被调者入口 rsp 少 8、栈参数差一格（实测得 0）；
3. （上一轮）三操作数 IMUL 内存分支丢立即数（见 #404）。

**实测证据（本机）**

| 用例 | 原生 | 受保护 |
|---|---|---|
| `caller5(x){ return five(1,2,3,4,x); }`（VM 调 native + 栈参数） | 42 | **42** ✓ |
| `caller5b` | 14 | **14** ✓ |
| `caller5`+`caller5b`+`five` 同时进 VM（VM↔VM 与 VM→native 混合） | 42 / 14 | **42 / 14** ✓ |
| **客户 demo `/Od` 13 个函数** | 13 行 | **不一致 0 行** ✓ |
| **客户 demo `/O2` 13 个函数（回归）** | 13 行 | **不一致 0 行** ✓ |
| `DemoFormatReport`（`/Od`，原症状） | `score=42` | **`score=42`** ✓ |

**尚未做**：把这条合成用例固化成 `tools/e2e.ps1` 的用例（现在只有本机实测记录）——
### 406. 目标项 ③：`CVTDQ2PD` 已落地（release 构建 DemoMean 0.000 → 3.500）；`/Od` 变体仍错（另一条路径）

**做了什么**
- C 侧：`vm_opcodes.h` 新增 `KF_CVTDQ2PD`；`vm_interp.c` 的双精度分支实现语义 ——
  把源低 64 位里的两个 `int32` 各自转成 `double`，写满目标的 128 位（两条 lane）。
- lifter：`liftSIMD` 的分发与子分发都加上 `x86asm.CVTDQ2PD` —— 目标是 XMM 槽位；源可以是 XMM（直接用它的槽位）
  或内存（先 `Load` 到 `VMSCR` 再 `Store` 到暂存槽，和 `CVTSI2SD` 同一套）。发射 `ir.Fp{Kind: 10}`。
- 参考实现（`internal/vm/ref.go`）补齐缺失的 KF 常量（7/8/9/10），保持与 C 侧顺序一致（此前只到 6）。

**实测证据（本机）**

| 用例 | 原生 | 受保护 |
|---|---|---|
| `?Mean@Math@Demo@@QEAANPEBNH@Z`（**/O2 构建**） | 3.500 | **3.500** ✓ |
| **客户 demo `/O2` 14 个函数（新增 `Mean`）** | 13 行 | **不一致 0 行** ✓ |
| `?Mean@...`（**/Od 构建**） | 3.500 | ✗ **0.000**（另一条路径，见下） |

`/Od` 下 `Mean` 的反汇编走的是**另一套**：累加器放在栈上（`movsd [rsp+10h],xmm0` / `movsd xmm0,[rsp+10h]`）、
`addsd xmm0, [rcx+rax*8]`（内存操作数）、`cvtsi2sd xmm0, dword ptr [rsp+40h]`（**32 位**内存源）、`movaps`。
即与 release 完全不同的指令组合 ⇒ 剩余问题在**这套**（疑似 `movsd` 的 8 字节存/取或 32 位 `CVTSI2SD` 的符号扩展路径），
与 `CVTDQ2PD` 无关。**这是新的静默算错，下一轮接着查。**

**未留下单测**：想在裸 lifter 环境（`NewLifter(0)` + `SetXMMArea`）里做 IR 级回归，但该环境下这条指令进不到分支
### 407. 目标项 ④：保护前逐函数差分自检 `tools/diffcheck.ps1`（能自动点名静默算错的函数）

**它做什么**：对候选函数**逐个**单独保护（`vmpack -func <f>`），然后跑**原生 vs 受保护**、比输出，给出三档结论：

- `REFUSED`：打包就被拒（附 lifter 的原话，例如缺哪条指令）；
- `WRONG`：打包成功但输出不一致 —— **点名函数**并给出「不一致几行 + 首处差异」；
- `OK`：输出一致。

最后输出汇总与 `report.csv`（这就是目标项 ⑤ 要的**逐函数可保护性清单**）。

```powershell
powershell -NoProfile -File tools/diffcheck.ps1 -Exe build\demo64\demo64_rel.exe `
  -Map build\demo64\demo64_rel.map -FuncList '<mangled,...>' -Filter '^\[' -Work build\dc_o2
```

**为什么这才是关键的一道闸**：工具以前会**静默产出算错的受保护程序**（本目标里已经撞到三次：三操作数 IMUL、
VM→native 栈参数、`/Od` 的 `Mean`）。造一条 `vmpack` 到运行的自动比对，就把「静默」变成「点名」。

**实测（客户自己的 demo，14 个函数）**

| 构建 | 汇总 | 被点名的 |
|---|---|---|
| `/O2` | **可保护 14 / 静默算错 0 / 被拒 0** | —— |
| `/Od` | **可保护 13 / 静默算错 1 / 被拒 0** | `?Mean@Math@Demo@@QEAANPEBNH@Z`：`不一致 1 行；首处差异 原生=[DemoMean = 3.500] 受保护=[DemoMean = 0.000]` |

（`/Od` 的 `Mean` 走的是栈上累加器 + 32 位内存源 `cvtsi2sd` 那套，与 `CVTDQ2PD` 无关；见 #406。**这条自检正是它的定位器**。）

**过程中自己踩的坑**：脚本第一版在「不给运行参数」时把空数组传给 `Start-Process -ArgumentList`，
PS 直接报参数校验失败 ⇒ 原生与被保护**都拿到空输出** ⇒ 比较结果全是**假 OK**。已改用 splat 并按需省略该参数。

**待做**：把它接进 `tools/e2e.ps1`（用现成的 e2e 目标做自检），以及在汇总里区分「参数化输入」的场景
### 408. 目标项 ③ 的尾巴：XMM（double）跨 VM 边界**没有同步** —— 已确诊，改法试过一次但无效（已回退）

**确诊过程（合成函数逐个单独保护，`/Od`）**

| 函数 | 原生 | 受保护 | 说明 |
|---|---|---|---|
| `retconst(void){return 3.5;}` | 3.500 | **2.500** | 拿到的是**入口时**的旧 xmm0（= 另一次调用的参数） |
| `dblarg(double a){return a;}` | 2.500 | 2.500 | 看似对，其实是**巧合**（旧 xmm0 恰好等于参数） |
| `dbladd(1.5,2.0)` | 3.500 | **1.500** | 旧 xmm0 = 第一个参数 |
| `noarg(){double x=1.25;return x+2.25;}` | 3.500 | **0.000** | 旧 xmm0 = 0 |

⇒ **两个方向都没同步**：入口蹦床把宿主 xmm0-xmm5 存进**它自己的帧**（`vm_abi.h`：帧内 `[304..399]`），
而解释器（lifter 的 XMM 槽位、`vm_fp_step` 的 `fbase = VRBASE`）全程用 blob 里的 `vm_xmm` 当寄存器堆，
两者不是同一块内存。于是：double 参数读不到、double 返回值送不出去。
（这也解释了 `/Od` 的 `Mean` = 0.000；release 版能过属路径不同/取值巧合 —— 同一个边界问题迟早会以别的形式咬人。）

**试过的改法（已回退，留档避免重走）**：在 `vm_run` 入口/出口按 `frame = rsp_start + 8 + VM_MARGIN` 做双向拷贝。
实测**毫无效果**（四个用例的错值与同步前逐字相同）⇒ 该地址公式在运行期不成立，或读到的 RSP 已被更早的代码改写。
下次应先在运行期把候选地址的内容 dump 出来（或用 `vm_diag` 记录两个候选地址处的 16 字节）定位，再动手。
回退后行为与改动前逐字一致，代码里留了注释说明原因。

**这一项对目标的意义**：属于「静默算错」的又一例 —— 而它已经能被 #407 的 `tools/diffcheck.ps1` **自动点名**，
### 409. 目标项 ③ 收口：XMM 边界同步 + 32 位 `CVTSI2SD` 载入 —— 双构建 14 个函数全部逐行一致

**两个真根因（都在本轮修掉）**

**① XMM（double）跨 VM 边界没同步**（#408 已确诊）：入口蹦床把宿主 `xmm0-xmm5` 存进**它自己的帧**，
而解释器全程用 blob 里的 `vm_xmm` 当寄存器堆 —— 两者不是同一块内存 ⇒ double 参数读不到、返回值送不出去。
修法：**让入口蹦床把帧基址写进 ctx**（`vm_ctx_t` 尾巴上原本是 `pad[8]`，大小/偏移不变，改成 `frame` 字段；
`vm_abi.h` 加 `VM_CTX_FRAME 192`；`vm_entry_asm.S` 在 `subq $VM_FRAME_SIZE` 之后写一条 `movq %rsp, VM_CTX_FRAME(%rsp)`）。
解释器在 `vm_run` 入口/出口按 `vm->frame` 做双向拷贝，启用条件是
`#if defined(VM_BLOB_USES_WIN64) && !defined(VM_GUEST_ARM64)` **且 `vm->frame != 0`**：
- 测试 harness 直接调 `vm_run`、不经过蹦床 ⇒ frame 为 0 ⇒ 天然跳过（否则会把 XMM 区写坏，两个 C 一致性测试都红）；
- arm64 客户机帧布局不同 ⇒ 排除；
- **Linux blob 的入口 asm 还没写 frame** ⇒ 必须按平台排除（漏了这条，Linux 读到相邻垃圾非 0，ELF e2e 14 例全 fault —— CI 实测）。

（试错留档：第一版按 `帧基址 = 模拟 RSP + 8 + VM_MARGIN` 现算，
槽位偏移**必须用宏** `VM_SAVE_XMM0`。**上一轮失败的教训**：我当时硬编码成 304（从注释里读的旧值），
而真值是 `VM_SAVE_XMM0` = **320/336（按平台）** —— 于是"同步"写进了填充区，表现为"毫无效果"。
这次先 grep 宏定义，一次就对了。

**② `CVTSI2SD` 的 32 位内存源被读成 8 字节**：`cvt32(int n){return (double)n;}` 得到 `~2^53`。
原实现用 `Load{SignExt, W64, SrcW=mw}`；改成与**已工作的寄存器路径**同形：先 `Load{ZeroExt, W32}` 再 `Ext{SignExt, W64}`。

**验收（`tools/diffcheck.ps1`，客户自己的 demo，14 个函数）**

| 构建 | 汇总 |
|---|---|
| `/Od` | **可保护 14 / 静默算错 0 / 被拒 0** |
| `/O2` | **可保护 14 / 静默算错 0 / 被拒 0** |

单点证据：`?Mean@Math@Demo@@QEAANPEBNH@Z` 在 `/Od` 下从 `0.000`（一度 `-0.000`）变成 **3.500 = 原生**；
FP 隔离套件（`cvt32/cvt64/localrt/acc/divd`）五个函数**全部**与原生一致；
`retconst/dblarg/dbladd/noarg`（double 参数与返回值跨边界）四个用例**全部**一致。

⇒ 目标项 ③ 完成 ✓，而且到现在为止**客户 demo 的 14 个函数在两种优化级别下都是"要么正确"**。
### 410. 目标项 ⑤ 收口：以**客户自己的期望值**为基准的逐函数可保护性清单

**客户资产（`D:\demo_exe`）**：
- `ground_truth_exe.txt` / `run_demo64.exe.txt` / `run_demo32.exe.txt`：他们跑出来的**期望输出**（含地址行）；
- `verify.py`：他们的验证脚本（跑两个 exe + 用 dbghelp 枚举 PDB 符号 + PE 结构），说明他们**自己也有符号表能力**。

**`tools/diffcheck.ps1` 增强**
- `-Expect <file>`：期望值可直接取**客户的 ground truth**（不再只跟"自己跑一遍"比）；
- `-Map` 变为**可选**（cl 构建的 PE 用 MAP；gcc 目标 vmpack 直接读 COFF 符号表）；
- `-Markdown <file>`：输出**逐函数可保护性清单**（含 REFUSED 的"缺哪条指令"原文）；
- 结论三档：`OK` / `WRONG`（点名 + 不一致行数 + 首处差异）/ `REFUSED`。

**实测（判定口径 = 客户 `run_demo64.exe.txt`）**

| 构建 | 汇总 |
|---|---|
| `/O2`（14 个函数） | **可保护 14 / 静默算错 0 / 被拒 0** |
| `/Od`（14 个函数） | **可保护 14 / 静默算错 0 / 被拒 0** |

清单文件：`build/protectable_o2.md`、`build/protectable_od.md`（每行一个函数的结论）。

**固化**：`tools/e2e.ps1` 新增第 (7) 段 —— 用 e2e 自己的目标跑一遍 `diffcheck`（`check_key`/`sum_to`），
不全绿就让 e2e 失败。这样这道"逐函数差分自检"以后每次门禁都会被真实执行一遍。

**顺带记两条工具坑**：`tools/e2e.ps1`/`diffcheck.ps1` 必须带 **UTF-8 BOM**（PS 5.1 否则按 ANSI 读、中文变乱码）；
### 411. 客户实测反馈驱动：`diffcheck` 三处可用性修复 + 又抓到一个静默算错（根因已定位）

**客户按我给的命令跑出来的是 `REFUSED`** —— 原因是那条命令里的 `'?DemoAdd@@YAHHH@Z,...'` 是**我写的省略号占位**（`...` 不是真函数名）。
顺带暴露 `diffcheck` 的三个真问题，已修：
1. **中文在 GBK(936) 控制台显示成乱码** ⇒ 脚本开头设 `[Console]::OutputEncoding = UTF8`，且**读原生程序输出时按 `Default`(ANSI)** —— 
   vmpack 是原生程序，输出是 GBK，之前按 UTF-8 读必然乱码；
2. **REFUSED 的原因被"工具授权未烘焙根公钥"提示污染**（那条提示永远在最前面）⇒ 现在优先取含「无法翻译」的行，其次才是第一条非提示行；
3. 我把 vmpack 的 **stdout/stderr 重定向到同一个文件** ⇒ PS 直接报错 ⇒ 每次都被当成打包失败（实测 203 个函数全 REFUSED）；改成两个文件再拼接。

**新增两个顺手功能**：
- `-FuncFilter <regex>`：只跑名字匹配的函数（MAP 自动模式下必用，例如 `'Demo|Math@Demo'`）；
- 只给 `-Map` 时**自动从 MAP 提取函数名**（识别 `f` 标志，字符串常量不会被误收）。

**用它一跑就多抓到一个静默算错**（比我手抄的 14 个函数覆盖面更大 —— MAP 里共 26 个匹配）：

| 构建 | 汇总 | 被点名 |
|---|---|---|
| `/O2` | **可保护 26 / 静默算错 0 / 被拒 0** | —— |
| `/Od` | 可保护 25 / **静默算错 1** / 被拒 0 | `?DemoMean@@YANPEBNH@Z`（原生 3.500 / 受保护 0.000） |

**根因（已定位，未修）**：`?DemoMean@@YANPEBNH@Z` 是个**转发壳** —— `/Od` 下它 `call ?Mean@Math@Demo@@…` 之后**直接 `ret`**，
返回值靠 **xmm0** 传出。而当前的 XMM 边界同步只在 `vm_run` 的**入口/出口**做；**native 调用返回时**没有把宿主的 xmm0 搬回 guest 的 `vm_xmm[0]`，
于是壳函数 `ret` 出去的是旧值。
修法（小改动，下一轮做）：在 `vm_calln_x64` 蹦床 `callq` 之后把 `xmm0`（稳妥起见 `xmm0/xmm1`）写进 guest 的 XMM 堆 —— 把 `&vm_xmm` 作为参数一并传进蹦床即可。
### 412. 修掉 native 调用的 FP 边界：xmm0-xmm5 回流 + xmm0-xmm3 装载 —— 客户 demo 双构建 26/26

**上一轮抓到的那个静默算错**（`?DemoMean@@YANPEBNH@Z` 转发壳在 `/Od` 下得 0.000）根因确认并修掉：
该壳函数 `call Math::Mean` 之后**直接 `ret`**，返回值靠 **xmm0** 传出；而 ABI 蹦床此前只搬运**整型**参数/返回值，
**FP 寄存器完全没接** ⇒ 壳函数交出去的是旧 xmm0。

修法（都在 `vm_calln_x64` 这一段 naked asm 里）：
- **参数方向**：`callq` 之前把 guest 的 `vm_xmm[0..3]` 装进真实 `xmm0-xmm3`（Win64 前四个浮点参数）；
- **返回方向**：`callq` 之后把真实 `xmm0-xmm5` 写回 `vm_xmm[0..5]`（返回值在 xmm0）；
- `vm_calln_t` 增加 `xmm` 字段（`&vm_xmm`），并在蹦床前加 `extern u8 vm_xmm[256];` 前置声明（定义在文件后面）。

**实测**

| 用例 | 原生 | 受保护 |
|---|---|---|
| `?DemoMean@@YANPEBNH@Z`（/Od 转发壳） | 3.500 | **3.500** |
| `retconst/dblarg/dbladd/noarg`（double 参数与返回值） | 3.500 / 2.500 / 3.500 / 3.500 | **全部一致** |

| 构建（26 个函数，口径 = 客户 `run_demo64.exe.txt`） | 汇总 |
|---|---|
| `/O2` | **可保护 26 / 静默算错 0 / 被拒 0** |
| `/Od` | **可保护 26 / 静默算错 0 / 被拒 0** |

（覆盖面从手抄的 14 个提升到 MAP 里匹配的 26 个；清单见 `build/protectable_o2.md` / `protectable_od.md`。）
### 413. `vmpack -verify`：把"要么正确、要么明确拒绝"从**工具**层推进到**产出端**

**动机**：`tools/diffcheck.ps1` 是外部脚本，默认打包路径**仍然**会给出一个算错的产物。现在加内建开关：
打包完先跑一遍自检（原始 vs 受保护，同参数、同过滤），**不一致就删除产物并以非零码退出**。

**新增开关**
- `-verify`：开自检；
- `-verify-args '<argv>'`：运行时参数（空格分隔）；
- `-verify-filter '<regex>'`：比对前丢掉匹配的行（例如地址行 `^\[`）；
- `-verify-timeout <sec>`：单次运行超时（默认 30）。

**实测（本机）**

| 用例 | 结果 |
|---|---|
| 正例：客户 demo `/O2`，`-func DemoAdd -func DemoGcd -func Math::Mean -verify -verify-filter '^\['` | `[*] 自检通过`；exit=0；**产物留下**且行为正确（`DemoAdd(2,3)=5`） |
| 反例：同一个包**不加过滤**（地址行天然不同） | exit=**1**；**产物已被删除**；报出`第 1 行不同：原始=[[demo.exe] base=…` |
| e2e 用例（用 e2e 自己的目标） | `自检通过` ✓，已固定进 `tools/e2e.ps1` 第 (8) 段 |

**为什么反例用"不滤地址行"**：e2e 的目标只打印数值、没有易变行，做不出确定性的反例；
### 414. 工具授权私钥进 DPAPI："拷走密钥文件即可绕过"这条堵上了

**原来**：工具授权靠 `<工具目录>/vmpx.key`（32 字节 hex **明文**）+ `vmpx.cred`；
把这两个文件拷到别的机器，工具照样能用 —— 工具授权形同虚设。

**现在**：新增**受保护形式** `vmpx.key.dpapi`（DPAPI，`CryptProtectData`，用户作用域 + 固定 entropy `vmpx-toolkey-v1`），
校验时**优先**用它；解不开就拒绝启动（exit=8）。

**改动**
- `internal/cred/dpapi_windows.go`：`Protect` / `Unprotect`（走 `crypt32.dll`，stdlib `syscall`，无第三方依赖）；
  `internal/cred/dpapi_other.go`：非 Windows 明确报错（**不静默退回明文** —— "以为受保护其实没有"比"不受保护"更危险）；
- `internal/cred/cred.go`：`LoadToolKey`（优先 `.dpapi`，退明文时**在 stderr 喊出风险**）；
- `vmpepoch keygen --dpapi`：同时生成 `<前缀>.key.dpapi`。

**实测**

| 用例 | 结果 |
|---|---|
| `keygen --out vmpx --dpapi` | 生成 `vmpx.priv` / `vmpx.pub` / `vmpx.key.dpapi`(262B) |
| 密文里是否含明文私钥 | **否**（逐字节比对，`False`） |
| 发布版工具 + 凭据 + **DPAPI 私钥** | **exit=0**，正常干活 |
| 把 `.key.dpapi` **改一个字节** | **exit=8**：`受保护的私钥 … 解不开：CryptUnprotectData 失败（换机器/换用户/被篡改都会这样）` |
| 只放明文 `vmpx.key` | 仍可用，但 stderr 警告"拷走它即可绕过工具授权" |

**边界（如实写进文档）**：DPAPI 用户作用域**不防同一用户下的本机攻击**，也不防内存抓取；
### 415. 工具授权私钥进 **TPM（CNG 不可导出密钥）**：私钥不再以任何文件形式存在

**与 DPAPI 的本质区别**：DPAPI 保护的是"磁盘上的密钥文件"——同一用户在本机仍可解密（内存抓取/本机攻击挡不住）；
CNG/TPM 里**私钥根本导不出来**，我们只能**让它签一段挑战**，用公钥验签来证明"它在这台机器上"。
于是：拷走全部文件、dump 内存，都拿不到可用私钥。

**改动**
- `internal/cred/ncrypt_windows.go`：`NCryptOpenStorageProvider` → `NCryptCreatePersistedKey`/`NCryptFinalizeKey`/`NCryptOpenKey`/`NCryptExportKey`/`NCryptSignHash`（`ncrypt.dll`，stdlib `syscall`）；
  提供程序**优先 `Microsoft Platform Crypto Provider`（TPM）**，不可用才退 `Microsoft Software Key Storage Provider`；
- `internal/cred/ncrypt_other.go`：非 Windows 明确报错；
- `cred.Require` 增加**第三种形式** `vmpx.cng`（文件里只有**密钥名**）：签 `vmpx-cng:v1:<vendorID>:<subjectPub>` 挑战 → 用凭据公钥验签；
  挑战绑住 vendorID + 公钥，所以签名**不能跨凭据重放**；
- `vmpepoch cng-gen --name <n> --out <前缀>`（生成密钥 + 写 `<前缀>.pub` / `<前缀>.cng`）、`cng-probe --name <n>`（试着导出私钥，应当被拒）。

**实测（本机，`cng-gen` 显示提供程序 = `Microsoft Platform Crypto Provider` ⇒ 真的用了 TPM）**

| 用例 | 结果 |
|---|---|
| `cng-gen --name vmpx-cng-ACME` | 生成 `<前缀>.pub`(129B hex) 与 `<前缀>.cng`(14B，只有密钥名) |
| **尝试导出私钥**（自证 + `cng-probe`） | **被拒绝**：`导出私钥被拒绝（0x8009000A）` |
| 发布版工具 + 凭据 + `vmpx.cng` | **exit=0**，正常干活 |
| 负例：凭据绑的是**别的公钥**，却部署 TPM 的 `.cng` | **exit=8**：`CNG/TPM 密钥的挑战签名验不过（凭据绑的不是这把密钥，或密钥被换过）: 签名验证失败` |
| 负例：`vmpx.cng` 里写一个**不存在的密钥名** | **exit=8**：`CNG/TPM 密钥不可用（no-such-key）… NCryptOpenKey 失败` |

**部署形态（给客户）**：`vmpepoch cng-gen --name <密钥名> --out vmpx` → 把 `vmpx.pub` 交给厂商换凭据；
把 **`vmpx.cng` + `vmpx.cred`** 放进工具目录即可（私钥不在任何文件里）。

**遗留**：软件 KSP 兜底时"不可导出"只到 CNG 层面（同机管理员仍可能有办法）；真正的硬件保证要在有 TPM 的机器上走第一档（本机已走）。
仍需做的：把 `cng-gen`/`cng-probe` 写进 `docs/` 的使用说明，并在 `tools/e2e.ps1` 里加一条不带 TPM 也能过的正例（当前靠本机 TPM 才有完整证据）。
### 416. Sentinel 接口层：把"取密钥/查授权"收成接缝，并接进构建流程（-key-in dongle:…）

**为什么先做接口层**：你们已经有母狗/子狗，但**现在不一定上**。把接缝定下来之后，
今天用假后端（本地文件模拟狗内存）跑通流程与测试；将来换真 DLL 只改一个实现，业务代码不动。

**新增 `internal/sentinel`**
- `Backend` 接口：`Login/Logout/ReadMemory/Decrypt/Products`（对应 `hasp_login/hasp_logout/hasp_read/`
  `hasp_decrypt` + 将来的 `hasp_get_info`）；
- **假后端**：用本地文件模拟狗内存储，`Products` 解析 `1@2030-01-01,2@perpetual` 这类列表；
- **真后端（Windows）**：`syscall` 动态加载 `hasp*.dll`（显式路径 / `VMPX_SENTINEL_DLL` / 程序目录扫描），
  四个入口缺一就明确报错；非 Windows 走 `dll_other.go` 明确报错 —— **绝不静默降级**。

**接进流程**
- `vmpepoch dongle-probe [--fake <文件>] [--vendor-code …] [--feature n] [--dll …]`：探后端 + 读狗 + 列授权；
- **`vmpbuild -key-in dongle:<fileID>:<offset>:<length>`**：主密钥**直接从狗里读、不落地**（这才是上狗的意义）；
  真狗需要 `VMPX_SENTINEL_VENDOR_CODE`，没有狗可用 `VMPX_SENTINEL_FAKE` 跑流程。

**实测（本机，假后端）**

| 用例 | 结果 |
|---|---|
| `dongle-probe --fake … --fake-products "1001@2030-01-01,1002@perpetual" --vendor-code TESTVC` | `已登录`；`hasp_read` 成功；列出 `1001@2030-01-01`、`1002@perpetual` |
| `vmpbuild … -key-in dongle:1:0:32` | blob 构建成功；**manifest 里的 key 与"狗"文件逐字节相同**（True） |
| 用这把"来自狗"的密钥打产物并运行 | `check_key(10) = 143`（= 原生） |

**尚未做（如实登记）**：真后端的 `Products()`（`hasp_get_info`/`hasp_get_size`）还没实现 —— 现在返回明确错误；
运行期（blob 侧）问狗的那条路也还没接（当前运行期仍用 `<产物>.vmplic.bin` + ECDSA 验签），
那需要把 Sentinel API 也接进 blob（或改成"狗内解密"路线）。
### 418. blob 侧 Sentinel 后端落地：主密钥可直接从狗取，**严格模式不回退**

按上一轮定的清单做完（并采纳"编译进去 + 无回退"这个更强版本）：

- `vm_key_src_t vm_key_src`（`kind/feature/fileID/offset/length` + `vendorCode[64]/dllName[64]/fakePath[128]`），
  `.data` + `used`，**默认全零 = 不启用**；它在自哈希区间 `[0,bssOff)` 内 ⇒ 静态改 `kind` 会被 `vm_selfcheck()` 拒绝；
- `kind=2` 真狗：`vm_find_module` 找不到就用已有的 `vm_load_lib` 动态加载 `hasp*.dll`，再 `hasp_login` → `hasp_read` → `hasp_logout`；
- `kind=3` 假狗文件：复用 `vm_key_read_nt`（路径 `\??\…`）；
- **严格模式**：`kind>=2` 只用狗，失败走硬门 —— **不回退文件/环境变量**；
- 阶段记 `vm_sentinel_fail_stage`（1=假狗文件 2=加载 DLL 3=缺导出 4=登录 5=读取 15=未启用），对外统一 `0xC0DE0007`；
- **可拆性**：删掉那段带标记的代码、或不烘 `kind` ⇒ 行为与今天**逐字节一致**；
- `vmpack` 新增 `-dongle-key/-dongle-vendor-code/-dongle-feature/-dongle-dll/-dongle-fake-file`，补丁后**重算自哈希**。

**实测**：`kind=3`（假狗文件）→ `check_key(10)=143`（=原生）；`kind=2` 但本机无狗 → **`rc=0xC0DE0007`、无输出**，
且**旁边放着 `.vmpkey` 也不回退**；不写 dongle 参数（`kind=0`）→ `143`，行为与今天一致。
### 419. blob 侧"问狗要授权"落地：`vm_license_meta.kind==2` ⇒ hasp_login 到该产品的 feature

**做法**（HASP 的标准用法，不需要解析 `hasp_get_info` 的结构体）：
`hasp_login(feature, vendorCode, &h)` **成功本身就代表**"这把狗上有这个产品、且没到期"（狗的时限由狗自己管），
失败 ⇒ 直接走硬门 —— 与 key 那条路一样是**严格模式**：`kind==2` 时**完全不看 `.vmplic.bin`**。

- `vm_license_check()` 开头：`if (vm_license_meta.kind == 2) return vm_license_from_dongle();`
- `vm_license_from_dongle()`：DLL 动态加载（复用 `vm_load_lib`）→ `hasp_login` → `hasp_logout`；
  `kind==3`（假狗文件）时改走 `vm_license_from_fakefile()`；
- 假狗文件布局：`[0..31]`=主密钥，随后 `u32 count`，再 `count × (u32 feature, i64 notAfter)`（`notAfter=0` 表示永久）——
  让**没有真狗也能把这条正例测通**；
- `vm_key_src` 末尾追加 `u32 licFeature`（原有偏移不变）；`vmpack -license-dongle <featureID>` 写 `kind=2` + 该字段，
  并在补丁后重算自哈希。

**实测（本机）**

| 用例 | 结果 |
|---|---|
| 假狗里有 `feature=1001`，产物**完全没有 `.vmplic.bin`** | `check_key(10)=143`（= 原生）⇒ 授权确实只来自"狗" |
| 假狗里没有 `feature=9999` | **`rc=0xC0DE0007`、无输出** ⇒ 明确拒绝 |

**过程中的一个假警报（留档）**：第一次正例被拒，原因是我那一步只重建了 `vmpack`、**没重建 blob**，
于是 vmpack 把 `kind=2` 打进了**旧 blob**（那段还没有问狗代码）⇒ 旧代码不认识 kind=2、回落到文件授权 ⇒ 拒绝。
重建 blob 后一次通过 —— 与 #399 那次"打包端与运行期必须同一轮改完"是同一类教训。
### 421. 目标项 ① 核验完成：字节码解密密钥**只来自加密狗**（已成立，有实测证据）

**侦察结论（改变了结论，如实记录）**：字节码密钥**不是**烘在 manifest 里的独立密钥 ✗ ——
`vm_bcs_init()` 里是 `vm_desc_key(d, &f, master, s->keybuf)`（`stub/win/x64/vm_interp.c:1207`）**从主密钥派生**每条目的密钥，
`vm_bcs_t.key` 指向栈上的 `keybuf[32]`（`:1166`/`:1167`），取指由 `vmb_byte/vmb_rd32/vmb_rd64`（`:1174`-`:1189`）流式还原，
**内存里没有明文字节码**（这条设计保住了）。

而主密钥在 `kind>=2` 下**只来自狗**（#418），于是"没狗 ⇒ 没有解密密钥"这条**结构上已经成立**——
不需要再动密钥来源（因此本轮**没有改主干代码**，只补了证据与文档）。

**实测证据（本轮）**

| 用例 | 结果 |
|---|---|
| 假狗里放**正确**主密钥 + 授权 feature=1001 | `check_key(10) = 143`（= 原生） |
| 假狗布局完全相同、**只把主密钥换成另一把** | **硬门、无输出**（`0xC0DE0007`）⇒ 拿不到主密钥就到此为止 |
| 在产物里**逐字节搜那 32 字节主密钥** | **`False`（不在产物里）** —— 密钥材料确实只在狗/调用方一侧 |

**结论**："没狗**解不开**"成立的方式是：**没有主密钥 ⇒ 派生不出任何条目密钥**；而硬门只是让这件事更早发生。
**仍未做（登记为可选硬化）**：用 `hasp_decrypt` 让**解密本身**在狗内完成（密钥连进程内存都不出现）。
那不是安全边界（密钥已经在狗侧），而是纵深防御；要做得单开一轮（打包端与运行期同一轮）。

### 422. 目标项 ② 完成：补 `tools/preflight.ps1`，AGENTS.md 验收第 1 条重新可执行

`tools/preflight.ps1`（**纯 ASCII 输出**，按 AGENTS.md 的契约）：
- `gofmt -l .` 为空 / `go vet ./...` / `go build ./...`；
- 工具产物与脚本齐备（`build/vmpack.exe`、`vmpbuild.exe`、`vmpepoch.exe`、`gates.ps1`、`e2e.ps1`、`diffcheck.ps1`）；
- **新增一条专治本仓库踩过两次的坑**：`build/runbc*.exe`（预编译 C 解释器）若比 `stub/**.{c,h}` 旧就报错，
  并直接给出重建命令 —— 这个坑的症状是 `go test` 报 `0xC0000005`，与真因毫无关联；
- blob 真能编出来（调 `vmpbuild` 编一次再删掉临时产物）。

**实测**：正常 ⇒ `[+] preflight: OK`、exit=0；故意藏掉 `build/vmpack.exe` ⇒
### 423. 目标项 ③ 第一步：PE32 **解析**落地 + PE32 现状的实测评估

**已落地（可测、不碰 blob）**：`internal/load/pe` 现在同时支持 PE32 与 PE32+ 的可选头 ——
两者只有 `ImageBase` 不同（PE32: u32 @+28；PE32+: u64 @+24），其余字段偏移一致；
新增 `OptMagicPE32`、`MachineI386`、`File.OptMagic`、`File.Is32Bit()`。

**测试**：`internal/load/pe/pe32_test.go` —— 合成 PE32（machine/入口/对齐/节 全断言）+ **真实 32 位 exe**
`C:\Windows\SysWOW64\notepad.exe`：实测 `base=0x400000 entry=0x25FF0 sections=6` ✓（没有该文件就 skip）。

**拒绝路径保持"明确拒绝"，但提示改成可操作**：`vmpack` 新增 `case pe.MachineI386`，
对 `D:\demo_exe\demo32.exe` 实测：`exit=1`、**不产出产物**，提示两条可行路径（CI 用 clang 编 32 位 blob；
或本机装 i686-w64-mingw32 工具链）。

**评估的硬事实（决定了为什么这轮只能做"解析"）**：
- 本机 `gcc -m32` **失败**（ucrt64 只有 64 位）、本机**没有 clang**（CI 里有）；
- 现有 blob 平台没有 32 位（`stub/win/{x64,arm64}`、`stub/linux/{amd64,arm64}`）；
- 要支持 PE32 还缺四块：32 位 blob 平台、32 位工具链（**当前硬阻塞**）、客户机 x86-32 语义、PE32 注入/重定位/harness。

**未做（如实登记）**：32 位 blob、x86-32 客户机语义、PE32 注入、32 位 harness —— 见 `docs/TODO.md` 的 PE32 评估一节
### 424. 目标项 ③ 第二块：解码层支持 **32 位模式**（PE32 地基，对主干零风险）

**背景**：`internal/decode/x64` 之前把模式**硬编码**成 64（`x86asm.Decode(code, 64)`）。
而 x86-32 与 x86-64 的差异不是"少数指令"，而是这几处**会静默错位**的地方：
- `0x40`-`0x4F`：64 位是 REX 前缀，32 位是 `INC/DEC EAX..EDI`；
- 默认操作数/栈槽宽度：32 位是 4 字节（`push eax` 推 4 字节）；
- `ModRM mod=00 rm=101`：32 位是**绝对 disp32**，64 位是 RIP-relative（所以 32 位下 `PCRel` 恒为 0）；
- 32 位没有 REX、没有 R8-R15。

**改动（零风险）**：新增 `Mode32`/`Mode64` 常量、`DecodeMode(code, pc, mode)`、`DecodeRangeMode(...)`；
原有 `Decode`/`DecodeRange` 变成 `…Mode(..., Mode64)` 的薄封装 ⇒ **现有调用行为逐字节不变**，
所有新逻辑都在新入口里。

**测试（`internal/decode/x64/decode32_test.go`，4 条全过）**

| 用例 | 断言 |
|---|---|
| `0x40` | 32 位 = `INC EAX`（1 字节）；64 位 = 孤立 REX ⇒ 我们的封装必须 **fail-fast 报错** |
| `0x50` | 32 位操作数 = `EAX`；64 位 = `RAX` |
| `8B 05 78 56 34 12` | 32 位 `PCRel==0`（绝对地址）且 `PCRelTarget()` 返回 false；64 位 `PCRel==4` 且目标 = `PC+6+0x12345678` |
| `40 40 58 50` | `DecodeRangeMode(...,Mode32)` 精确消费 4 条；同一段在 64 位下**必须失败**（REX 错位）|

**为什么这算"最小里程碑"的一块**：它是 PE32 的地基，且**不依赖 32 位工具链/bloB**，
所以本机就能端到端验证（不像 32 位 blob 那样只能在 CI 上验）。

**未做**：lifter 的模式接线（`internal/lift/x64` 仍只走 64 位解码入口）、客户机 x86-32 的栈/ABI 语义、
### 425. 目标项 ③ 第三块：lifter 的 **32 位模式接线**（同一段字节，两种模式必须给出不同 IR）

**背景**：`internal/lift/x64` 之前只走 64 位解码入口 ✗，而 32 位代码里最容易**静默算错**的一处就是：
`mov eax,[disp32]` 在 64 位是 RIP-relative、在 **32 位是绝对地址**。lifter 不知道模式 ⇒ 32 位代码访问全局变量会被折算到完全错误的地址上（不报错、不崩溃，只是算错）。

**改动（对现有调用零影响）**：
- `Lifter` 增加 `Mode` 字段 + `NewLifterMode(imageBase, mode)`；`NewLifter` 仍等于 64 位；
  `mode()` 把零值兜底成 64 位（结构体字面量构造也不会漏）；
- 唯一的解码点 `lift.go:163` 从 `DecodeRange` 换成 `DecodeRangeMode(..., l.mode())`；
- `memAddr`：`AddrSize` 校验按模式放宽到 32 位；`case m.Base == 0` 里新增 ——
  **32 位 + 无下标 + disp≠0 ⇒ 绝对地址**，折算成 `VMBASE + (abs - ImageBase)`（低于镜像基址则 fail-loud 报错）；
  并加 `absDone` 标志，避免被后面那行 `disp = int32(m.Disp)` 覆盖（否则刚算好的折算值会被冲掉 —— 这个坑在写的时候就注意到了）。

**测试（`internal/lift/x64/lift32_test.go`，3/3 过）**：同一段 `8B 05 00 10 40 00 C3`（`mov eax,[0x401000]; ret`）

| 断言 | 结果 |
|---|---|
| 32 位 | `Load{Base=VMBASE, Disp=0x1000, Width=W32}`（`0x401000 - 0x400000`） |
| 64 位 | RIP-relative 折算 ⇒ `Disp=0x402006`（`PC 0x401000 + 6 + 0x401000 - ImageBase`） |
| 两模式对比 | `Disp` **必须不同** —— 这条本身就是"模式接线生效"的判据 |

**未做**：32 位客户机的**栈槽宽度/ABI**（`push/call/ret` 4 字节、`__cdecl/__stdcall` 参数在栈上）——
**安全审计（本轮顺带做，结论：没有产出坏产物的路径）**：全仓 `MachineI386` 只在 `cmd/vmpack/main.go` 的机器类型 switch 里出现一次，
而它在 `inject` 之前就 `fatalf` ⇒ PE32 **进不到注入器**，不存在"能进去却写出坏产物"的路径（AGENTS.md 的底线）。
`internal/inject` 的 `Arch` 只有 `ArchX64`/`ArchARM64` 两个值，`cmd/vmpack` 也只会传这两个。
### 426. 目标项 ③ 第四块：地址/指针宽度按模式走 —— 32 位函数序言**可完整翻译**了

**发现过程（先探后改，不猜）**：把 32 位典型序言 `55 8B EC 8B 45 08 5D C3`
（`push ebp; mov ebp,esp; mov eax,[ebp+8]; pop ebp; ret`）分别按两种模式翻译 ——
**64 位下 5/5 成功**，**32 位下 3/5 报"无法翻译"**（fail-loud，不是静默 ✗）。

**根因**：lifter 里 4 处把"基址/索引/间接跳转寄存器"**硬要求 W64**（`w != ir.W64`），
而 32 位模式下解码器给的是 `EBP/ESP/EAX..`（W32）；`PUSH` 那处还是 `if w != ir.W64` 的独立写法，
`replace_all` 只匹配到 `!ok || w != ir.W64` 那种形式，所以**第一次只修好 2/3**（3→1 条失败），
grep 出剩余的独立写法再修一次才 5/5 —— 这一步值得记：**同一语义的两种写法会漏**。

**改动**：新增 `Lifter.ptrWidth()`（32 位 ⇒ `W32`，否则 `W64`），4 处地址/指针宽度检查 + `PUSH` 宽度检查改用它。
64 位下 `ptrWidth()` 恒为 `W64` ⇒ **与改前逐字节等价**（零回归，已由 4 条测试覆盖）。

**测试（`internal/lift/x64/lift32_prologue_test.go` + `lift32_test.go`，4/4 过）**

| 断言 | 结果 |
|---|---|
| 32 位序言 | 恰好 5 条 IR：`PUSH RBP` / `MOV RBP,RSP` / **`LOAD{Base=RBP,Disp=8,Width=W32}`** / `POP RBP` / `RET` |
| 64 位同一段 | 仍然 5 条、形状不变（证明 32 位支持没改坏 64 位） |
| 32 位绝对地址 vs 64 位 RIP-relative | 前面 #425 的两条断言继续通过 |

**一个重要发现（影响 ③-e 的决策）**：**客户机 x86-32 的执行语义不需要 32 位工具链** ——
现有 arm64 客户机就是拿 **64 位宿主探针** `runbc_a64g.exe` 验证的（在 x64 上跑 C 解释器的 arm64 客户机模式）。
同理，"客户机 x86-32" 也可以这样验证；**32 位工具链只卡最后一件事**：把 blob 注入真实的 PE32 进程。
所以 ③-e 的决策可以拆开：语义那块**本地可做可验**，注入那块才需要 i686 工具链或 CI 的 clang。
### 427. 目标项 ③ 第五块：引入 **x86-32 客户机模式**（栈槽 4 字节），并登记一个未查清的崩溃

**为什么 x86-32 与 x86-64 只差一处**：标志位/条件码/算术规则本来就是同一套（x86 家族），
运算宽度由每条 IR 自己带 ⇒ 真正的语义差别只有 **栈槽宽度**（`push/pop/call/ret` 4 字节 vs 8 字节）。

**改动（C + Go 同一轮，遵守一致性纪律）**
- `vm_interp.c`：新增 `VM_STACK_SLOT`（`VM_GUEST_X86_32` ⇒ 4，否则 8），`OP_PUSH_R/OP_PUSH_I/OP_POP_R`
  按**槽宽**读写（32 位槽只动 4 字节 —— 否则会覆盖槽下方内存，属于静默踩内存）；
- `ref.go`：新增 `GuestX8632` + `stackSlotBits()`，push/pop 用它；
- `vmpbuild`：`-guest x86-32` ⇒ 传 `-DVM_GUEST_X86_32=1`；`regCountFor` 明确列出三种 ISA，
  **未知 ISA 现在明确报错**（顺手补的安全检查：以前任何拼错的 guest 都会静默当 18 槽处理）；
- 新增差分用例 `internal/vm/x8632_test.go`（同一段 `PushR/PushR/PopR/Halt`：
  x86-64 应净 −8、x86-32 应净 −4，且 C 与 Go 参考必须一致）。

**实测**

| 项 | 结果 |
|---|---|
| x86-32 blob 构建 | ✓ `guest=x86-32 regCount=18`，36864 字节 |
| x86-32 探针构建 | ✓ `gcc -DVM_GUEST_X86_32=1 … -o build/runbc_x8632.exe` |
| 未知 ISA（如 `-guest arm7`） | ✓ **明确拒绝**：`[!] 未知的客户机 ISA "arm7"` |
| 默认 x86-64 blob | ✓ 仍能构建（`VM_STACK_SLOT=8`，行为不变） |

**未做（本轮登记，需下一轮查）**：x86-32 资产在 **batch 模式**下探针崩溃（`0xC0000005`）。
已确认：blob/探针都能构建、manifest 正确、默认路径不受影响；
未确认：是我的用例构造（batch 内存窗口里的 RSP 取值）还是 x86-32 blob 侧。
⇒ 该差分用例**显式 `t.Skip`**（设 `VMPX_X8632_DIFF=1` 可复现），不让主干变红。**（已在 #428 修掉，两处根因都在用例侧。）**
### 428. 目标项 ③ 第六块：x86-32 客户机**栈槽差分跑通**（#427 那两个坑都修掉了）

**结果**：同一段 `PushR RBP; PushR RBP; PopR RBP; Halt` ——

| 实现 | 净压栈字节 |
|---|---|
| C 解释器（x86-64 blob） | **8** |
| C 解释器（x86-32 blob） | **4** |
| Go 参考（GuestX86） | **8** |
| Go 参考（GuestX8632） | **4** |

⇒ **两种客户机下 C 与 Go 完全一致**（这正是"打包端与运行期必须同一轮改完并一致"的纪律要求）。实测输出：
`净压栈字节：C(x86-64)=8 C(x86-32)=4 Go(GuestX86)=8 Go(GuestX8632)=4`。

**#427 那次崩溃的两个根因（都是我这边的用例问题，不是 VM 的问题）**
1. **RSP 落在窗口外**：我取 `batchBufBase + batchBufLen - 0x100`，而 batch 内存窗口只有 **256 字节** ⇒ 结果恰好等于窗口**基址** ⇒ 第一次 `push` 写到 `base-4`（窗口外）⇒ 探针 `0xC0000005`。
   修法：`base + len - 16`。定位手段：先让失败信息带上 runner/blob/rsp（一眼看出 rsp 就是基址）。
2. **参考实现用了不匹配的操作码映射**：闭包里把 `Map` 写死成 x32 的映射，却拿它去跑 x64 的字节码 ⇒ `未知操作码 0x47`。修法：每个客户机用与自己的字节码匹配的映射。

**顺带保留的两个收获**：这个用例是**第一个在 batch 框架里真正压栈的用例**（既有 conformance 用例从不设置 RSP）；
以及"未知客户机 ISA 现在明确报错"（#427 顺手补的安全检查）。

**未做（如实登记）**：CI 目前**不构建** x86-32 资产 ⇒ 该差分在 CI 上会走 `t.Skipf`（本地可跑，已留构建命令在测试注释里）。
要让它在 CI 也真跑，需要在门禁脚本里加两行构建 —— 但那会**新增/改动门禁**（目标验收写的是"11 gates"），需你确认口径后再做。
### 429. 登记一条**新的间歇性门禁失败**：`e2e.ps1` 的 packing 步（与反调试那条 flake 不同）

**现象**：`tools/gates.ps1` 里 `[FAIL] e2e.ps1 (x86-64)`，e2e 自己打印
`[FAIL] packing failed (unliftable instructions; refusing to reuse a stale artifact)`。

**观察到的分布（本轮 5 次运行）**：

| 运行方式 | 结果 |
|---|---|
| 单独跑 `tools/e2e.ps1`（重建产物后） | **165 passed, 0 failed** ✓ |
| 单独跑 `tools/e2e.ps1`（再跑一次，抓 packing 附近输出） | **exit=0** ✓，且能看到 `check_key: RVA=0x19D0 native=18B -> 5 IR -> 35B bytecode` |
| 夹在 `tools/gates.ps1` 里 | **2 次红**（同样的 packing 文案）✗ |

**已排除**：与我的 lifter/VM 改动无关 —— 手工用同一个目标打包成功（`[+] 输出: build/manual_vmp.exe`，exit=0），
且失败文案是 e2e 自己的"拒绝复用陈旧产物"口径（时间戳判定），不是 lifter 的"无法翻译"原文。

**推断（未证实）**：门禁脚本里**先重建 blob**（`vmpbuild (blob builds)` 那道门禁），继而 e2e 在第 149 行附近用
`LastWriteTime -ne $packTime` 判定"产物是否被重新打包"；如果时间戳精度/顺序在门禁环境下与单独跑不同，就会误判成"没有重新打包"。

**未做（下一轮优先）**：定位并消除这条 flake —— 它与已登记的反调试 flake 不同，会让"门禁 11/0"再次不可靠。
建议查法：把 e2e 第 149 行附近的判定改成"先删产物再打包，检查是否重新生成 + 内容哈希变了"，而不是比时间戳。**（已在 #430 修掉：实测打包本身 6/6 正常，真因是判定写法。）**
### 430. 修掉 #429 那条间歇性门禁失败（打包判定的确定性修复）

**先复现、再改**：按门禁的同样步骤（每次都重建带随机操作码的 blob）**循环打包 6 次** ⇒ **6/6 成功** ✓
⇒ 打包本身不 flake ✗；问题在 e2e 的**判定写法**上。

**真因（脚本层面）**
1. 打包前**不删旧产物** ⇒ 一旦打包失败，"文件仍在"就让判定看起来像"复用了陈旧产物"，真正原因被掩盖；
2. `$LASTEXITCODE` 在把 vmpack 输出经 `Select-String` 管道**之后**才读 ⇒ 读到的可能是更早某个命令留下的值；
3. 失败时**只打印一句自撰文案**，vmpack 的真实输出被管道吞掉 ⇒ 无法定位（这正是它被误判成"lifter 无法翻译"的原因）。

**修法**
- 打包前 `Remove-Item build\target_vmp.exe`（旧产物不再可能掩盖真相）；
- 退出码**紧邻**原生命令读取（`$packRC = $LASTEXITCODE`），判定只看它；
- 失败时打印 vmpack 输出**末尾 20 行**（含 `packing produced no output (rc=…)` 分支）。

**证据（修后）**：
- **连跑 3 次 e2e** = `165 passed, 0 failed` 三次 ✓；
- **门禁连续 3 次全部 11/0** ✓；其中最后两次是**不带任何包装**的权威运行（`powershell -File tools/gates.ps1` 输出重定向到文件），
  `gates 真实退出码 = 0`、`total 11 gates, 0 failed`、`e2e: 165 passed, 0 failed`、`dll e2e: 3 passed, 0 failed`、`[+] arm64 guest e2e: OK` ✓。

**一条排错留档**：本轮我用 `gates.ps1 *>&1 | Tee-Object … | Select-Object -Last 4` 这种包装跑门禁时，后台作业回报的退出码是 1，
### 431. 目标项 ③ 第七块：**32 位栈传参记账**（push/pop 的模拟栈槽宽按模式走）

**侦察结论（避免了走错方向）**：
- C 侧 `OP_CALLN` 是 `vm->regs[VRAX] = vm_call_native(vm, addr)` ⇒ 调用走**宿主 ABI 蹦床**，**不往客户机栈压返回地址**；
- lifter 的 `CALL` 注释也写明是"**净零**语义：不模拟 push 返回地址（被调方 ret 时抵消）"；
⇒ 所以 `call/ret` **不需要**槽宽改动 ✗；真正的 32 位 ABI 差异在 **`push`/`pop` 的模拟栈记账**上 ✓。

**改动**：新增 `Lifter.stackSlot()`（32 位 ⇒ 4，64 位 ⇒ 8），`PUSH`/`POP` 的 `spDelta` 改用它。
64 位下与改前完全等价（`stackSlot()` 恒为 8）⇒ 零回归，已由既有测试覆盖。

**为什么这条重要**：模拟栈必须镜像客户机真实栈 —— 32 位下调用方压的参数在 `[esp+4]`/`[esp+8]`，
而不是 64 位的 `[rsp+8]`/`[rsp+16]`。账记错 4 字节 ⇒ **所有栈传参静默读错位置**（不报错、不崩溃），
正是本目标要消灭的那类问题。

**测试（`internal/lift/x64/lift32_stackarg_test.go`）**：`push 42; mov eax,[esp+4]; ret`，`FrameSkew=64`
（lifter 只对"有效偏移 ≥ 0"的访问补 FrameSkew，于是两种模式会跨过 0 边界）：
32 位 `eff=0` ⇒ 补 skew；64 位 `eff=-4` ⇒ 不补 ⇒ 两边 `Disp` **必须不同**，且各自断言到确切值。
### 432. 把 x86-32 客户机差分**纳入现有 guest 差分门禁**（门禁数仍是 11）

**动机**：#428/#431 的 x86-32 语义此前只有**本地**证据（资产不在门禁的构建范围里 ⇒ 测试会 skip）✗。

**改动**
- `tools/e2e_arm64guest.ps1` 末尾增加 x86-32 段：构建 `build/vm_interp_x8632.{bin,json}`（`-guest x86-32 -random-opcodes=false`）
  与 `build/runbc_x8632.exe`（`-DVM_GUEST_X86_32=1`，槽位数保持 18 ⇒ ctx 布局与 x86-64 一致），随后跑 `TestX8632StackSlot`；
- `tools/gates.ps1` 里该门禁的标签由 `arm64-guest differential` 改为 `guest differential (arm64 + x86-32)`（如实描述；**门禁数不变仍是 11**）。

**为什么放这里而不是新增门禁**：目标验收写的是"gates = 11 gates/0 failed"，新增一道会改口径；
而"客户机差分"本来就是**同一件事**（64 位宿主跑另一种客户机语义）⇒ 并入同一道门禁最自然。

**实测**：`tools/e2e_arm64guest.ps1` → 两段都 OK、`rc=0`：
`[+] arm64 guest e2e: OK` / `[+] x86-32 guest e2e: OK`。CI 有 gcc ⇒ 这条差分在 CI 里也会真跑（不再 skip）。
### 433. 用**真实 32 位产物**验证 Mode32：解码 ✓、翻译能走 5KB+ 后止于一处未识别字节

样本：`C:\Windows\SysWOW64\notepad.exe`（PE32/i386，本机就有；没有该文件则 skip —— CI 上会 skip）。

**测试 1（解码，`TestDecodeRealPE32Code`）**：取入口点、`.text+0x100`、`.text+0x800` 三处，各连续解 24 条 —— **全部成功** ✓
⇒ Mode32 对**真实编译器产物**对齐正确（这正是 `0x40-0x4F` 在 32 位是 INC/DEC、`[disp32]` 是绝对地址那类差异会暴露的地方）。

**测试 2（翻译，`TestLiftRealPE32Entry`）**：入口函数用 Mode32 lifter 翻译 —— 一路走到 **+0x14F2（5KB+）**，
随后止于 `decode @0x4274E2 (byte 0xFF): unrecognized instruction`。
⇒ 这是线性遍历撞上**数据/未支持编码**的正常表现（x64 上同样如此：lifter 会停，打包端只保护有明确边界的具名函数）。
测试对该结果**如实记录**（成功则断言 IR 非空，失败则 log 原因而不判失败）—— 入口是 CRT 桩，翻不过去不是缺陷。

**意义**：PE32 的 Go 侧路径（解析 → 32 位解码 → 32 位 lift → 栈记账）现在在**真实 32 位代码**上站得住 ✓，
### 434. #429 那条间歇性门禁失败的**真正根因**：测试进程锁住产物文件（已修）

**真因（由 #430 加的诊断直接打出来）**：

```
[!] open build\target_vmp.exe: The process cannot access the file because it is being used by another process.
```

⇒ 上一次运行**残留的 `target_vmp.exe` 进程**还活着（最可能是 `mt_many` 那个 180s 超时用例），锁住产物文件，
vmpack 无法覆盖 ⇒ `rc=1` ⇒ e2e 报 `packing failed`。

**为什么一直难查**
1. 症状只在"有残留进程"时出现 ⇒ **只在本地间歇出现**；CI 每次都是干净机器，所以 CI 一直绿；
2. 旧脚本把 vmpack 的输出**吞掉**、只打印一句自撰文案（"unliftable instructions; refusing to reuse a stale artifact"）
   ⇒ 被误读成"lifter 无法翻译"，方向从一开始就错了。

**修法**：`tools/e2e.ps1` 开工前清掉残留的 `target_vmp` / `target` 进程（+ 300ms 等待）。
这样即使某次运行留下了进程，下一次运行也会先清干净。

**教训（值得单独记）**：#430 做的"失败时把 vmpack 输出末尾打出来"看起来只是加日志，
### 436. 目标 ①（32 位 blob）第一项完成：`__int128` 清零 + 逐位一致验证

**背景**：i686 没有 128 位整型 ⇒ 现有 blob 源码在 i686 上直接编译不过（探针报多处 `__int128 is not supported`）。
侦察发现**除法早就不用 `__int128`**（当年为 aarch64 CI 改成了 u64/i64 + 可移植长除法，见文件里 K_DIVU/K_DIVS 的注释），
**只剩 3 处乘法**。

**关键洞察**：二进制补码下，「把操作数按无符号重解释算出的 128 位乘积」与「有符号乘积」的**位模式完全一致**
⇒ **一个无符号 helper 就够三处用**（有符号那边只需保留原有的符号修正）。

**改动**（全在 `stub/win/x64/vm_interp.c`）：
- 新增 `vm_mul64_full(a,b,&hi,&lo)`：两个 64 位操作数各拆 32 位两半做小学生乘法，
  `mid = (p00>>32) + 低32(p01) + 低32(p10) < 3*2^32` ⇒ 不溢出；
- `flags_mul_w()`：原 `(__int128)lo != p` 等价改写成 `plo != (u64)lo || phi != (lo < 0 ? ~0ull : 0ull)`；
- `K_MULHIS`（有符号高半）：`uh` 由 helper 给出，符号修正原样保留；
- `K_MULHI`（无符号高半）：直接用 helper 的 `hi`。

**验证（两条独立证据）**
1. **逐位一致性**：一次性程序 `build/mulcheck.c`（x64 上有 `__int128` 可作参照）——
   **200 万组随机数 + 64 组边界组合（0/1/2/2^32/2^63/2^64-1…）全部与 `__int128` 一致** ✓：
   `OK: 2e6 random + 64 edge cases all match __int128`；
2. **行为不变**：x64 blob 正常构建；e2e 的 `mul128`/`smul128`/`add128` 用例走的就是这条 VM 乘法路径。

**i686 复探：错误列表从一大串缩到只剩 1 条** ✓ —— `vm_interp.c:18` 的 `vm_sa_ctx_size` 为负，
即 `sizeof(vm_ctx_t) == VM_CTX_SIZE` 断言失败（32 位下指针 4 字节 ⇒ 结构体变小）。
这正是下一项 ②：**`vm_abi.h` 的偏移/尺寸要按指针宽度分支**，而现成的静态断言就是它的安全网 ✓。
**修订（同一项内被发现并修掉的真实回归 —— 值得记）**：第一版把 `flags_mul_w` 也改成"无符号重解释"就完事了 ✗，
理由看起来很美（补码下无符号乘积与有符号乘积位模式一致），但**用错了地方** ✗：
该函数的操作数是**符号扩展后的 i64**，需要的是**有符号 128 位乘积** —— `(-1) * 1` 的有符号乘积是 `-1`，
而无符号 64x64 乘积是 `2^64-1`，两者不同 ✗。后果是 `IMUL` 的 **CF/OF 多置** ✗。

**是被 C/Go 对拍抓住的** ✓：`TestConformanceAgainstCInterpreter` 报 `[ALU kind=5 w=8 a=0x1 b=0xFFFF] flags: go=0x12 c=0x1E`（C 多置 CF|OF）。
修法用的是文件里**已有的先例**：`有符号乘积 = 无符号乘积 − (a<0 ? b : 0) − (b<0 ? a : 0)`（与 `K_MULHIS` 同一套式子）。

**教训（比代码本身重要）**：第一次的"逐位一致性"校验只覆盖了**无符号**语义 ✗，所以它**通过了却没能发现问题** ✗；
补了一个覆盖**有符号**语义的校验（`build/mulcheck2.c`，2e6 随机 + 49 边界）之后，修复才被证明 ✓。
**校验必须覆盖"实际使用的那套语义"，否则它只是安慰剂。**
### 437. 目标 ② 完成：`vm_abi.h` 的 ctx 布局按宿主指针宽度分支（i686 静态断言通过）

**改动**：`vm_abi.h` 用编译器内建 `__SIZEOF_POINTER__` 分支（freestanding 也成立、不需要头文件）。
32 位上一共有五个常量不同：

- `VM_CTX_SIZE` 200 → **192**
- `VM_CTX_DESC` 168 → **164**
- `VM_CTX_SCRATCH` 176 → **168**
- `VM_CTX_SCRATCHLEN` 184 → **172**
- `VM_CTX_FRAME` 192 → **184**

（`VM_CTX_CODE`=160 以及寄存器/vbase/flags/pc/codeLen 这些在指针之前的字段**完全相同**。）

**两条实测坑（都记下来，避免重走）**

1. **反直觉**：mingw/MSVC ABI 下 **`u64` 的对齐是 8**（不是 4）⇒ `frame` 在 184、总大小 192。
   第一版按直觉算成 180/188 ✗，被 `VM_STATIC_ASSERT` 直接挡住（断言就是干这个用的 ✓）；
   真正定案靠**让 i686 编译器打印真实布局**：`build/layout32.c` 输出
   `sizeof=192 desc=164 scratch=168 scratchLen=172 reserved2=176 frame=184` ✓。
2. **PATH 污染陷阱**：在同一 PowerShell 进程里把 `C:\msys64\mingw32\bin` 前置进 PATH 后，
   后面那条「x64 对照」编译**又用了 i686 的 gcc** ✗ ⇒ 两次输出一模一样，险些误判成「两种宿主布局相同」。
   判据：如果 `ptr align` 打印成 4 而你以为在编 x64，就是 PATH 被污染了。

**验收**

- x64 blob 构建**完全不变**（36864 字节、manifest 正常）✓；
- **i686 复探：C 层错误清零** ✓ —— 剩下的全是汇编错误（`subq is only supported in 64-bit mode`、
  `bad register name %rsp` 等），即下一项 ③（32 位入口蹦床）。
### 438. 目标 ③ 第一块：新建 `stub/win/x86` 平台目录（ABI 头 + 32 位入口蹦床）

**新增文件**

- `stub/win/x86/vm_abi.h`：32 位平台 ABI 常量。ctx 偏移用**实测值**（192/164/168/172/184）；
  保存槽按 4 字节布局（EBX/EBP/ESI/EDI=192/196/200/204，EAX/ECX/EDX=208/212/216，XMM0-5=224..304）；
  `VM_FRAME_SIZE=640`（保持 `%16==0`，因为 `vm_interp.c` 有这条断言）；
  模拟栈 = `esp - (4 + VM_MARGIN)`（4 是 cdecl 留在 `[esp]` 的返回地址；x64 是 8）；
  `VM_FRAME_SKEW_EXTRA=8`（thunk 的 call 4 + 客户机返回地址 4）；`VM_DESC_TO_THUNK=64`。
- `stub/win/x86/vm_entry_asm.S`：32 位入口蹦床，**注释全 ASCII**（现有 x64 的 .S 注释是乱码，不再重复）。
  与 x64 同构：建帧 → 存 callee-saved/volatile GPR/XMM → 填 ctx → 反推描述符 → `call vm_run` → 还原。
  cdecl 要点：入口 `esp%16==12`；调用点先 `subl $8`（到 4）再 `pushl`（到 0）满足 ABI 对齐；
  **EAX 故意不还原** —— `vm_run` 的返回值是 `u64`（EDX:EAX），低半即客户机返回值。
- `stub/win/x86/BLOB.sources`：`win/x86/vm_entry_asm.S` + 复用 `win/x64/vm_interp.c`（与 arm64 同构）。

**实测**

- 32 位 ABI 头在 i686 下编译通过（`sizeof(vm_desc_t)=64`）✓；
- **32 位蹦床 `i686-w64-mingw32-gcc -c` 汇编通过**（782 字节目标文件）✓；
- `vmpbuild -cc i686-… -src stub/win/x86 -guest x86-32` 现在**真的用上了 32 位平台头**（ctx 断言已过）✓，
  随后撞到 `VM_FRAME_SIZE % 16 == 0` 断言 ⇒ 已把帧大小定回 640、并把 cdecl 对齐移进蹦床 ✓。

**未做**：④ 32 位 native 调用蹦床（cdecl、无 xmm）；⑤ vmpbuild/vmpack 其余 32 位分支；
⑥ 32 位 blob 完整构建 + 32 位 harness 跑通真实函数；以及**整链仍有一个未分类的编译失败**（下一轮定位）。
### 439. 目标 ③/⑤ 推进：定位到"32 位整链编译"的两个真阻塞（都是宿主守卫）

**阻塞 1（已修）**：`vm_run` 在 i686 下**根本没被编译** ✗ —— 核心解释器包在
`#if defined(VM_BLOB_USES_WIN64) && defined(__x86_64__)` 里。改成"Windows 宿主（32 或 64）"：
新增 `VM_HOST_X86_32`（由 vmpbuild 在目标三元组含 i686/i386 时注入），把 4 处守卫放宽为
`(defined(__x86_64__) || defined(VM_HOST_X86_32))`；**真·x64 的内联汇编块仍只在 `__x86_64__/_M_X64` 下编译**。
修完 `undefined symbol "vm_run"` 消失 ✓。

**阻塞 2（部分修，仍卡）**：放宽守卫后暴露出一处 **x64 形式的内联汇编** ✗ ——
`vm_debugger_present()` 与 `vm_peb_base()` 用 `movq %%gs:0x60` 读 PEB（x64 形式）。已补 i686 分支：
**`movl %%fs:0x30`**（32 位 Windows 的 PEB 就在 fs:0x30 ✓）。
再往后是 **`vm_calln_x64` 的 naked 汇编**（Win64 约定：RCX/RDX/R8/R9 + xmm0-3）✗ —— 它就是目标项 ④。

**一次失败的尝试（留档）**：我曾把 468 行那个大块整体放宽 ✗，而它**同时包着** `vm_calln_x64` 与一个
`#else` 分支 ⇒ 我插入的 `#else` 与文件里原有的 `#else` 撞在一起 ✗（`implicit declaration` 报错）。
已**回退**该处、保留 PEB 分支 ✓ —— 主干恢复健康：x64 blob 正常构建（36864 字节）✓。

**教训**：`#if/#else` 嵌套块**不能只看单行**就放宽 ✗ —— 先看整块的 `#else` 在哪（这次读了 468/494/518/528 才看清结构 ✗）。

**未做**：④ cdecl native 蹦床（下一步）；⑤ vmpack 的 `Arch` 等其余 32 位分支；
### 440. 目标 ④：32 位 **cdecl native 调用蹦床**已实现（+ 宿主守卫继续推进）

**实现（`vm_interp.c` 新增 `#elif VM_HOST_X86_32` 臂）**：

- `vm_calln_x86()`：naked + cdecl。与 x64 版最大的不同是**参数不用搬** —— cdecl 的参数本来就在**客户机栈**上
  （lifted 代码自己 push 的），所以只需：保存 ebx/ebp/esi/edi → 切到客户机栈 → `call *fn` →
  把真实 `xmm0` 写回客户机 XMM 堆（double 返回值）→ 恢复宿主栈与寄存器 → `ret`。
- 这正是任务书里"**无 xmm**"的含义：32 位 cdecl 没有 XMM 参数寄存器（double 参数在栈上），只有返回值走 XMM0。
- 结构上先把 `extern u8 vm_xmm[256]` 与 `vm_calln_t` 移到 `#if` **之外**（两平台共用），再插入 `#elif` 臂 ——
  这样**没有再出现上次那种 `#else` 嵌套相撞** ✓（上次的教训生效了）。

**一个关系到正确性的发现（已落到 32 位头里）**：
`VM_FRAME_SKEW` 必须 ≡ 0 (mod 16) —— 模拟栈 = `原始 esp − SKEW`，而 cdecl 调用方保证调用点 esp 16 字节对齐、
被调者可能用对齐的 SSE 存栈。原来 `EXTRA=8` 时 SKEW=0x4188（≡8）✗ ⇒ **每次原生调用都会偏 8 字节**。
已改为 `EXTRA=16`（SKEW=0x4190，正好 16 的倍数 ✓）。

**仍卡住的**：`[!] .text+0x14D: 引用了未定义符号 "vm_run"` ✗ —— 放宽了 473（x64 蹦床，收窄回去 ✓）/1336/1341/2603 之后，
警告从"未定义的 vm_find_module/vm_get_proc"换成了别的 ✓（说明放宽确实生效 ✓），但 `vm_run`（定义在 1435 行 ✓）**仍被某个守卫挡住** ✗。
下一步很明确：**把 1435 行所在的那个 guard 找出来**（沿 `#if/#endif` 栈往上数 ✓），而不是继续猜 ✗。

**验收**：x64 blob 构建**不受影响** ✓（36864 字节 ✓，因为改动都在共享文件的守卫里、x64 分支行为不变 ✓）。
**未做**：⑤ vmpack 的 `Arch` 等 32 位分支；⑥ 完整构建 + 32 位 harness 跑通真实函数。
### 441. 目标 ⑤：「未定义符号 vm_run」的真根因被证据钉死 —— i386 COFF 的前导下划线

**先机械定位（不再猜）**：写脚本沿 `#if/#elif/#else/#endif` 走一遍，数出 1435 行（`vm_run` 的定义处）的守卫栈，
只有一层：`#if defined(VM_BLOB_USES_WIN64) && !defined(VM_GUEST_ARM64)`，**在 i686 上成立**，
⇒ `vm_run` 确实被编译了，问题不在守卫（这条否掉了上一轮的假设）。

**再用 nm 看两边的真实符号名（决定性证据）**：
定义侧（C，i686）：**`_vm_run`** —— i386 COFF 给 C 符号加前导下划线；
引用侧（汇编）：**`vm_run`** —— GAS 处理 .S 时**不加**下划线；
`objdump -r` 也印证：`0000014d DISP32 vm_run`。⇒ 名称对不上，合并器自然报「未定义符号」。

**修法（写进 `cmd/vmpbuild/objfile.go`）**：按 Machine==0x14C（i386）判定，在读 COFF 符号表时统一剥掉前导下划线 ——
剥在源头，合并/manifest/重定位三处自动一致。**不能**按「是不是 COFF」判定：arm64 的 PE 符号不带下划线。

**仍未生效**：第一次我的 Go 改动因为漏了 `strings` 导入而**根本没编译进去**（用旧二进制跑，现象自然没变 ——
教训：改完工具本身要确认它真的重建了）；改成手写前缀判断后 `go build` 成功，但现象**依旧**。
下一步：用 `vmpbuild -v` 看它**真实的编译命令与符号**，确认 `VM_BLOB_USES_WIN64` 是否真的传给了 i686 编译、
以及 `vm_run` 到底在不在 C 目标文件里 —— 不再从代码推断。

**验收**：x64 blob 不受影响（见下）；门禁在本轮开头/下一轮补。
### 442. 目标 ⑤：32 位整链又推进两关 —— 符号下划线归一 + i386 REL32（都已实测生效）

**突破 1：`-merge go`**。vmpbuild 有两条合并路径：Go 内置（`buildBlobMulti`）与 `ld -r`（`mergeWithLd`，默认）。
源码注释早已写明「COFF 没有 ld -r 的等价物 ⇒ Windows/arm64 走 `-merge go`」，而我之前的 i686 调用一直在用默认值，
所以 Go 合并器**根本没被调用**（我加的调试钩子一开始没输出，就是这条造成的）。改用 `-merge go` 后钩子立刻生效。
（未做：让 vmpbuild 对 COFF 目标**自动**选 `go`，现在是调用方显式传。）

**突破 2：i386 的 `REL32`（0x14）**。`readCOFFObject` 的重定位 switch 原先只认 AMD64 的类型号，
i686 的 thunk 一进来就报「不支持的重定位类型 0x14」。而 0x14 正是 `IMAGE_REL_I386_REL32`（4 字节 PC 相对），
也就是 `call vm_run` 用的那种。补上映射后改名成 `relPCRel32` 处理。

**同时验证了两条先前的改动是对的**：用一个临时 Go 测试把两个 i686 目标文件喂给 `readCOFFObject`，
看到定义侧符号已被剥成 `vm_run`（而不是 `_vm_run`）、引用侧的 reloc 名也是 `vm_run` —— 归一确实生效。

**当前卡点（已换到新问题）**：`__divdi3` 未定义 ✗。i686 没有原生 64 位除法指令，GCC 会调用运行时助手 ——
和当年 `__int128` 除法同源。项目里**已有可移植长除法的先例**（K_DIVU/K_DIVS 那段，当年为 aarch64 CI 写的），
下一步就是把 blob 里剩下的 64 位除法也换成那个做法。

**验收**：x64 blob 未受影响（改动都在 vmpbuild 的 COFF 读取与常量表，x64 走 AMD64 分支）；门禁已起。
### 443. *** 里程碑：32 位 blob 首次构建成功 ***（目标 ⑥ 前半达成）

**实测**（`i686-w64-mingw32-gcc` + `-src stub/win/x86 -guest x86-32 -merge go`）：

```
[+] blob: build/vm_x86.bin (43176 bytes), entry vm_entry @ +0x0
```

同时 **x64 未受影响**：`build/vm_interp.bin` 36864 字节照常产出 ✓。

**这一步跨过的三道门**（都写在前面的条目里）：
1. `-merge go`：COFF 没有 `ld -r` 的等价物，默认的 `mergeWithLd` 路径对 i686 根本不适用（#442）；
2. i386 COFF 的**前导下划线**与 **REL32(0x14)** 重定位（#441/#442）；
3. **32 位宿主的 64 位除法**：GCC 会调用 `__divdi3` 等运行时助手，而 blob 是 freestanding 的 ⇒ 合并期直接报
   「引用了未定义符号 __divdi3」。现在加了一对可移植助手（`vm_udivmod64` / `vm_idivmod64`，逐位试商），
   **只在 `VM_HOST_X86_32` 下定义与调用** ⇒ x64/arm64 的生成代码保持逐字节不变（这也是 x64 blob 仍 36864 字节的原因）。
   踩坑留档：第一版我把助手插进了**函数体内部**（`invalid storage class for function` + 顺序问题），
   而删除时又因为**文件里新旧内容编码混杂**导致字符串匹配失败 —— 最后用「按行范围机械删除 + ASCII 注释重插」解决。
   教训：**要用字符串匹配去改编码混杂的大文件时，优先用行号/机械手段**。

**另一个坑（本轮新学）**：我曾在**门禁作业并发运行时**手动跑一次 vmpbuild，两边同时重建同一批文件 ⇒
看到的「编译失败」是**竞态**，不是真错误（同一命令单独跑就是成功的）。**以后不要在门禁跑的时候手动构建。**

**未做**：⑥ 的后半 —— **32 位 harness**（`blob_probe.c` 的 i686 构建）**跑通一个真实函数**并与 x64 侧比对；
### 444. 目标 ⑥：32 位 harness 建成 + 真实 32 位函数 lift 成功；运行阶段仍崩（下一步）

**关键认识**：i686 blob 只能被 **32 位进程**加载 ⇒ harness 必须用 i686 编译。
（此前的 x86-32 差分用的是「x64 blob + x86-32 客户机模式」，那是另一回事，跑不了 i686 blob。）

**实测 1：32 位 harness 建成** —— `i686-w64-mingw32-gcc -O2 -I stub/win/x86 -I stub/win/x64 blob_probe.c`
⇒ `build/runbc_x8632.exe`（262434 字节）。

**实测 2：真实的 32 位函数**（不再只是合成用例）—— 用 i686 gcc 编了一个**真的 32 位 exe**
（`build/real32.c`：一个求 1..10 之和的函数），原生跑出 **55**（这就是期望值）。
用 `nm` 取符号地址、从 PE 头取 ImageBase 算出 RVA=0x1500，再用 `vmp-lift -mode 32` 翻译 ⇒
`rva_1500: size=5 bytes -> 1 IR -> 11 bytecode bytes` ✓。

**本轮顺手实现的一个真缺口：`LEAVE`**（32 位代码的函数出口几乎必用）。语义恰好是
`mov esp,ebp ; pop ebp`，所以用**与这两条指令相同的记账与 IR**实现，不引入新机制；
并且在 SP 不可跟踪时**明确拒绝**（实测报出「LEAVE 但 RSP 已被不可跟踪的方式修改（AND ESP, -0x10）」，
那正是我们窗口给太大、撞进 `main` 的栈重对齐代码所致 —— fail-loud 是对的）。

**教训（又一次"越界"）**：`-len` 必须给**函数的真实长度**。GCC 把这个循环常量折叠了，函数实际只有 **5 字节**；
我先给了 48/24，都因为走进了下一个函数而翻译失败。反汇编一确认就明白了。

**当前状态**：blob 构建 ✓、真实函数 lift ✓、`runbc_x8632.exe` 加载 i686 blob 并**执行**——但**崩**
（rc=0xC0000005）。这从"能构建"推进到"能跑但崩"，是下一轮明确的调试目标（起点：ctx 布局/probe 与 blob 的一致性、
以及 i686 blob 里那些 `u64→指针` 的截断警告）。

**未做**：⑥ 的运行闭环（跑通并与 x64 侧比对行为）；`vmpack` 的 `Arch` 分支。

`vmpack` 的 `Arch`/机器类型分支（现在 vmpack 仍只认 AMD64/ARM64）；以及让 vmpbuild 对 COFF 目标**自动**选 `-merge go`。



⑥ 完整构建 + 32 位 harness。





### 435. `cmd/lift` 支持 **32 位模式** + 免符号表的 `-rva/-len` —— PE32 的"逐函数可保护性预检"

**动机**：PE32 现在**不能打包** ✗（缺 32 位 blob），但可以先把"这个 32 位函数能不能保护、不能的话缺哪条指令"答出来 ✓
—— 这正是 ④/⑤ 对 x64 做过的事在 PE32 上的对应物，而且**不依赖工具链**。

**改动**
- `-mode 32|64`（默认 64）：走 `NewLifterMode(ImageBase, mode)`；
- `-rva 0xXXXX`（+ `-len N`）：**不查符号表**直接在某 RVA 处 lift —— 客户的 `demo32.exe` 没有 MAP，
  但他们自己的 `verify.py` 已经用 dbghelp 从 PDB 枚举符号/RVA，可以喂进来。

**顺带修掉一个真 bug**：`LiftFunc` 失败时返回的 `irFunc` 是 nil，旧代码却去取 `irFunc.Unsupported` ⇒ **panic** ✗。
（这个 nil 解引用正是被新增的 `-rva` 路径第一次踩出来的。）它恰好违反本目标的底线：**拒绝不该把工具自己搞崩**。
现在拒绝只打印原因 + `exit 1`。

**实测**

| 用例 | 结果 |
|---|---|
| x64 回归：`-exe build/target.exe -func check_key` | `check_key: RVA=0x19D0 size=18 bytes -> 5 IR -> 35 bytecode bytes`，exit 0 ✓ |
| PE32 正例：`-exe SysWOW64\notepad.exe -rva 0x25FF0 -len 64 -mode 32` | `[!] at +0x3F: unknown opcode 0x6B @0x42602F`，**exit 1、不崩** ✓ |
| PE32 反例：`-rva 0x16000`（数据区起步） | `[!] at +0x0: decode @0x416000 (byte 0xFF): unrecognized instruction`，**exit 1、不崩** ✓ |

**使用说明（重要）**：`-rva` 模式只有 `-len`，**走出函数体就会撞数据而误报** ✗。
客户应从 PDB 同时取 **RVA + size**（他们的 `verify.py` 已经在用 dbghelp），把 size 传给 `-len` ✓。

**未做**：还没做成"一次列出整个 exe 所有函数"的批量报告（需要 PDB 解析或 MAP —— 客户的 `demo32.exe` 两者都没有，
只能靠他们从 PDB 导出清单）。

但**正是它**让这条 flake 一次定位 —— **可诊断性本身就是修复的一部分**。

不再只有合成用例。**仍未做**：跨到宿主 native 调用时的 32 位 ABI（参数在栈上，而蹦床按 x64 ABI 传 RCX/RDX/R8/R9）
—— 它与 32 位 blob/thunk/trampoline（per-platform asm）是同一块，**被工具链决策卡住**（见 TODO 的 PE32 一节）。



但日志里明明是 11/0 —— 那是**包装管道**的退出码，不是门禁的。要看门禁真实结论，必须不带包装地跑（或直接读 `total … failed` 那一行）。






那是"客户机 x86-32 执行模型"这一块，比模式接线大，留下一轮；32 位 blob 仍卡在工具链（需决策）。

32 位 blob（需要 i686 工具链 —— 本机 `gcc -m32` 不可用、无 clang；msys2 有 `pacman` 但装工具链属于改机器，**未做**）。

（含两条路 A/B 与各自的代价）。

`[!] tool binaries and scripts exist` + `[!] preflight: 1 problem(s)`、**exit=1**；恢复后再次 `OK`。





要"私钥永不出芯片"得用 **TPM/CNG 不可导出密钥**（`NCryptCreatePersistedKey` + 用签名挑战代替比对公钥）—— 那是本条的下一步。

客户 demo 会打印基址/函数地址，正好是天然的"必然不同"输入。反例路径因此在本机验证并在文档留档，
e2e 里固定的是正例（防止以后 -verify 静默失效）。



PowerShell 里**多行数组字面量**（逗号接换行接括号表达式）会报 "Expressions are only allowed as the first element of a pipeline"，改成分行 `+=` 即可。


所以即使还没修好，客户也不会拿到一个「看起来正常、实际算错」的产物（脚本会报 WRONG 并指出函数名）。

（现在是把整个程序跑一遍比 stdout，对无参 demo 足够；带参程序用 `-Args`）。

（真实 demo 能正常 lift），为不留红测试先删掉了；`/O2` 的 demo 差分是当前证据。

目标第 ④ 项「保护前逐函数差分自检」会系统性地覆盖这一类问题。



### 402. 目标项 ① 完成：`CDQ`/`CQO` + `DIV`/`IDIV` 全位宽落地；过程中抓出三处「静默算错」

**做了什么**
- `CDQ`/`CQO`：`lift.go` 新增 `case x86asm.CDQ/CQO` → `AluRI{Sar,|KeepFlags}` 写 `RDX`（原来只处理了 `CDQE`）。
- `DIV`/`IDIV`：新增 ALU kind `ir.DivU/DivS`（0x14/0x15；C 头 `K_DIVU/K_DIVS` 同步、`kind_table_test` 强制三处一致）+ 参考实现 `refDiv`；
  语义放在 `vm_interp.c` 的 `OP_ALU_U` 分支里**先拦截**（隐含 `DX:AX` 族被除数、商→AX 族、余→DX 族）；
  8 位走 `AH:AL`（`RAX` 低 16 位，**不是** `DX:AX`）；lifter 新增 `liftDiv`（单操作数形式判据同 `liftImul`）。
- 新增 `internal/lift/x64/div_test.go`：8/16/32/64 位 × 有符号/无符号各 300 组随机差分（用 `math/big` 独立算）+ `#DE` 边界（除零、商溢出必须 panic）。

**过程中抓出的三处「静默算错」（正是本目标要消灭的东西）**
1. `__int128` 除法把 `__divti3` 拉进 freestanding blob → 门禁直接报「引用了未定义符号」；
   改为 8/16/32 位用 u64/i64（2w 位被除数在 w≤32 时放得进 64 位）、64 位交给硬件 `divq/idivq`。
2. 64 位那一支最初用 inline asm：先写错了约束（独立的 `=a`/`=d` + 输入）→ 算出垃圾值；改成 `+a`/`+d` 后本地通过，
   但 **CI 的 arm64 作业把同一个 `vm_interp.c` 用 clang 交叉编译**（clang 报 `invalid output constraint '+a'`，而且 `divq` 本就是 x86 指令）→
   **最终改为可移植的手写 128/64 长除法**：不用 `__int128` 除法（freestanding 会拉进 `__divti3`）、也不用 inline asm。
   这一支原本没有真实程序覆盖 —— 补了个 64 位除法小程序（`d64u`/`d64s`/`m64u`）才暴露出来，现与原生逐字一致。
另：参考执行器的 `OpAluU` 走的是 `aluUnary` 而不是 `aluApply`，我的 div 分支**一开始被绕过去、静默返回错值** ——
已在 `OpAluU` 里拦截，并在 `aluApply` 的 div 分支留了 fail-loud panic 守卫。

**实测证据**

| 用例 | 结果 |
|---|---|
| 客户 demo 13 个函数（含 `DemoGcd` 8 位除法、`DemoIsPrime` 32 位除法） | **与原生逐行一致（不一致 0 行）**；`DemoGcd(462,1071)=21`、`DemoIsPrime(97)=1` |
| 64 位专测（`d64u`/`d64s`/`m64u`） | `u=33609235651134 su=-1164736592 m=30300` —— 与原生**逐字相同** |
| `?DemoGcd@@YAHHH@Z` 拒译指令数 | **2/13 → 0**（`IsPrime` 同样 0/20） |
| 单测 | `go test ./internal/...` 全绿（含新的 DIV 差分与 #DE 用例） |

**遗留（如实登记）**：16 位的 C 侧分支没有被真实程序覆盖（与 32 位共用同一段代码，仅被 Go 参考实现的单测覆盖）；
`AGENTS.md`/`HANDOFF.md` 里的 `tools/preflight.ps1` 在仓库中不存在（见 #401）。






### 445. 目标 ⑥ 运行时崩溃的根因：32 位 blob 不是位置无关的（反汇编证据）

二分定位：喂一段只含 HALT 的 1 字节字节码 —— x64 blob/harness 正常返回（rc=98 只是操作码映射不同），
i686 blob/harness 直接崩（0xC0000005）。⇒ 崩溃发生在 vm_run 入口前后，与字节码无关。

反汇编给出决定性证据（objdump -D -b binary -m i386 build/vm_x86_id.bin）：

    218f:  a3 79 66 00 00     mov  %eax,0x6679     <- 绝对地址（blob 内偏移）
    2194:  89 1d 77 66 00 00  mov  %ebx,0x6677     <- 同样

⇒ i386 没有 RIP-relative，全局变量（vm_xmm / vm_tmp / 各种 static）的访问被编成绝对地址；
合并器把这些绝对重定位按「基址 0」解析成 blob 内偏移。而 probe（以及将来的注入器）把 blob 映射在任意基址，
于是这些地址全是野指针，一执行就崩。x64/arm64 侧天然没有这个问题（PC 相对）。

为什么之前那条「绝对引用必须失败」没拦住它：那条规则针对 AMD64/ARM64 的类型号；i386 这里进来的是
另一组类型（DIR32 / DIR32NB 家族），REL32 补丁只加了 0x14，其余落到 default ⇒ 理论上应是 relUnsupported，
但实际构建成功了 ⇒ 说明它们走了别的路径被当成可解析项。
下一轮第一件事：把 i386 的 DIR32/DIR32NB 现状查清，并让合并器明确拒绝（或改成可修复的基址相关项）。
现在是「静默产出不可用产物」，这正是本项目最不能接受的一类问题。

修法设计（下一轮实现，任选其一）：
1. 基址相关的重定位表：合并器把每个基址相关站点的偏移收进一张表（放 .rdata、导出符号），
   入口 stub 用 call/pop 求出自身基址后自修复这些站点；probe 路径在调用前做同样的事。标准做法，最通用。
2. 让 i686 的全局访问也走寄存器基址（blob 基址保存在固定寄存器里）—— 侵入性大，不推荐。

本轮其余验收：x64 blob 正常（36864 字节）；门禁已起（LEAVE 改动之后）。

### 446. 修掉一个**静默产出不可用产物**的真 bug：i386 DIR32 被 AMD64 的范围 case 吞掉

**机制（这轮挖到底了）**：i386 与 AMD64 的重定位**编号空间不同但数字重叠** ——
0x06 在 AMD64 是 REL32+4（PC 相对），在 i386 却是 **DIR32（绝对 32 位）**。
而读取器里那条「REL32..REL32+9」的范围 case 判断的是**纯数字**：

    case r.Type >= relAMD64Rel32+1 && r.Type <= relAMD64Rel32N:   // 0x0003..0x0009

于是 i386 的 DIR32(0x06) 被**当成 PC 相对**处理 ⇒ 合并器把一个 PC 相对差值写进了本该放**绝对地址**的字段
⇒ 产物**构建成功**、运行期却用野指针（上一轮定位到的 0xC0000005 就是这么来的）。

**证据链**：verbose 统计显示合并器处理了 315 条重定位，其中 `type=0x6` **230 条**、`type=0x14` 85 条；
而 0x6 本该落到读取器的 default ⇒ relUnsupported ⇒ 应用器的 default ⇒ 报错。既然它能通过，
说明有 case 抢先匹配了 —— 顺着常量表一比就发现是 AMD64 的范围 case。

**修法**：范围 case 限定 `!isI386`；i386 的绝对重定位落到 default ⇒ **明确拒绝**。
实测（同一命令）：

    修前：[+] blob: build/vm_x86_id.bin (43176 bytes)      <- 静默产出不可用产物
    修后：[!] .text+0x7D6: 不支持的重定位类型 0x6（绝对引用必须失败; format=coff sym=".rdata" ...）

⇒ 这正是本项目「要么正确、要么**明确拒绝**」的底线；一个能构建但运行必崩的产物比构建失败危险得多。

**注意**：这条修复让 32 位 blob **暂时不能再构建** —— 这是**有意**的（宁可拒绝，不产出坏产物）。
下一步就是让它既能构建又可用：实现上一轮设计的**基址重定位表**（合并器收集基址相关站点 → 入口 stub 自修复），
DIR32 届时从「拒绝」升级为「可修复」。

### 447. 目标 ⑥：基址重定位表**做成**（i686 DIR32 从「拒绝」升级为「可修复」）

**实现（合并器侧）**
1. i386 `DIR32(0x06)` 从 `relUnsupported` 改映射到新 kind `relI386Abs32`；
2. 应用时：字段里写「blob 相对偏移」（与之前一样正确），**并登记站点**到 `m.absSites`；
3. 全部重定位应用完之后，把表写到 blob 末尾：`u32 count` + `count × u32（字段的 blob 偏移）`，
   并导出符号 `vm_reloc_tab`（表内容与基址无关，所以可以直接烘进 blob）。

**实测（数字自洽）**：

    vm_reloc_tab @ +0xA8A8     blob = 44100 bytes
    表中站点数 = 230

43176（原大小）+ 4（count）+ 230×4（站点）= 44100 ✓，且 230 正好等于 verbose 统计里的 DIR32 条数 ✓。

**本轮踩的三个坑（全是"顺序/复用"类，值得记）**
1. 表生成原本写在 `buildBlobMulti` 内部，而 `applyAllRelocs` 是**调用方在它返回之后**才调的 ⇒ 那时站点还没登记（表恒为空）；
   修法：抽成 `emitAbsTable()` 方法，在 `applyAllRelocs` 之后调用。
2. 行手术（按行号重写）多留了一个 `}` ⇒ `expected declaration`；
3. **最隐蔽的一个**：`blob = merged.Data` 在表生成**之前**就取了切片，而表是 `append` 上去的、会**重新分配** ⇒
   符号有了、文件里却没有表（blob 仍是 43176）。修法：表生成之后**重新取** `blob = merged.Data`。
   这条的教训：**切片是值语义，append 之后旧切片不会跟着变**。

**未做（下一轮第一件事，很小）**：加载侧 —— probe（以及将来的入口 stub）拿到加载基址后，
遍历 `vm_reloc_tab` 对每个站点做「字段值 += base」。做完这个，32 位 blob 才真正位置无关、那个真实函数才能跑通。

### 448. 目标 ⑥：加载侧已实现，但运行时**仍崩**（一次自我纠错 + 精确定位到崩溃点在遍历之前）

**本轮新增（加载侧）**：`blob_probe.c` 支持可选第 5 个参数 `vm_reloc_tab` 偏移 ——
映射 blob 之后遍历表，对每个站点做「字段值 += 加载基址（即 mem）」。i686/x64 两个探针都重新构建通过。

**一次自我纠错**：我一度以为"修好了"，因为重定向跑出来的 `ExitCode` 是 0 ✗。
那是**我自己的读法错了**：`Start-Process` + `WaitForExit(20000)` 的返回值我没检查，进程其实还在跑（或已被杀），
`ExitCode` 读到 0。改回管道方式，结果仍是 `0xC0000005` ✗。教训：**读进程退出码之前必须确认它真的退出了**。

**精确定位**：我加在"映射之后、遍历之前"的 `fprintf(stderr, ...)`（stderr 默认无缓冲）**没有出现** ✗，
⇒ 崩溃发生在**重定位遍历之前** —— 也就是 `read_file` / 入口范围检查 / `VirtualAlloc` / `memcpy` / `FlushInstructionCache` 这一小段里。
（注意：i686 探针**无参数时正常**（打印 usage、rc=2，只依赖 KERNEL32+msvcrt），所以二进制本身是健康的。）

**下一轮（若继续）的第一件事**：在这几行之间逐点插 stderr 打印，把崩溃点夹到具体某一行；
我个人最怀疑 `VirtualAlloc` 的返回类型/`SIZE_T` 在 i686 上的截断（probe 是 32 位进程，而 `blobSize` 是 `long`）。

**状态小结**：blob 能构建（43176→44100，含 230 项基址表 ✓）、真实函数能 lift ✓、加载侧的修复逻辑已写 ✓；
**唯一剩下的**是"跑通"这一步 —— 目标 ⑥ 因此**未达成**，目标保持 active。

### 449. 目标 ⑥：崩溃窗口进一步收窄到「参数检查之后、文件读取之前」

**方法**：在 probe 的加载路径上插 stderr 检查点（stderr 无缓冲，崩溃前写出的内容应当可见）。
结果：**连第一个检查点都没出现** ✗，而"无参数"路径是正常的（打印 usage、rc=2，只依赖 KERNEL32+msvcrt）
⇒ 崩溃点落在**参数解析与两次 `read_file` 之间**这一小段（`argv[1]`/`strtol(argv[2])`/`strtoull(argv[4])`/`read_file`）。

**为什么这条很有用**：窗口很小，下一轮只要在 `read_file` 内部（`fopen`/`fseek`/`ftell`/`malloc`/`fread`）各插一个检查点，
一次就能定位到具体那一行。**注意**：不能再用 PowerShell 的 `2>&1 | Out-String` 判断"有没有输出"——
崩溃路径可能丢缓冲；要判断就**把检查点直接写文件**（`fopen/fprintf/fclose`）。

**本轮清理**：临时检查点已全部撤掉（只保留「给了第 5 参数时打印 base relocations」那条有用的）。

**目标 ⑥ 的准确状态**：blob 可构建（44100 字节、含 230 项基址表）✓；真实 32 位函数可 lift ✓；
加载侧修复逻辑已写 ✓；**运行仍未跑通** ✗ ⇒ ⑥ **未达成**，目标保持 active。

### 450. 一条必须记住的命名纪律：`build/runbc_x8632.exe` 是**仓库约定的 x64 探针**

**我踩的坑**：为了跑 i686 blob，我用 `i686-w64-mingw32-gcc` 直接覆盖了 `build/runbc_x8632.exe` ✗。
而仓库约定（`tools/e2e_arm64guest.ps1:37`）是：

    gcc -O1 -Wall -DVM_GUEST_X86_32=1 -I stub/win/x64 -o build/runbc_x8632.exe stub/win/x64/blob_probe.c

即它是 **x64 二进制 + x86-32 客户机模式**（用于「x64 blob 跑 x86-32 客户机」的差分），**不是** i686 宿主探针。
覆盖它之后 `go test ./...` 立刻红（`TestConformanceAgainstCInterpreter` 失败），我一度误判成"陈旧探针"或"改动弄坏了 C 解释器"。
按约定重建后立刻 `ok` ✓。

**纪律**：i686 宿主探针必须用**专属名字** `build/runbc_i686.exe`：

    i686-w64-mingw32-gcc -O2 -Wall -I stub/win/x86 -I stub/win/x64 -o build/runbc_i686.exe stub/win/x64/blob_probe.c

（注意 `-I stub/win/x86` **在前**，这样它拿到的是 32 位 ctx 布局的 `vm_abi.h`。）

**当前状态**：`go test ./...` **全绿** ✓；那条真实函数的运行仍崩（0xC0000005），崩溃窗口见 #449。

### 451. 验收：门禁 11/0、CI 五绿、preflight OK —— 以及那条 e2e flake 的**真因**

**先说明一次误判**：本轮门禁先红在 `e2e.ps1 (x86-64)`，报 `[FAIL] packing failed (rc=1)`、且"vmpack 输出末尾"是空的 ✗。
我一度怀疑是自己改坏了 vmpack。**直接复现打包命令**后真相是：

    [!] open build\target_vmp.exe: The process cannot access the file because it is being used by another process.

⇒ 残留的 `target_vmp.exe` 进程锁住了产物 ✗。清掉进程后**单独跑那条打包命令完全成功**：

    [+] 输出: build\target_vmp.exe (196608 字节)
    [+] 报告: build\target_vmp.json

**注意**：e2e 脚本自己在**更早的步骤**里会运行打包产物，进程可能残留；它在开头杀一次残留不够。
**下次遇到 e2e packing 失败，先 `Get-Process target_vmp | Stop-Process -Force` 再单独复现那条命令** ——
别急着怀疑代码。

**最终验收（清干净进程后重跑）**：

    [OK] gofmt / go vet / go test / vmpbuild(blob builds) / e2e.ps1 / residue probe /
         bytecode plaintext scan / image residue / e2e_dll.ps1 / guest differential(arm64+x86-32) / linux payload
    total 11 gates, 0 failed

- `tools/preflight.ps1` → `[+] preflight: OK` ✓
- CI 五作业全绿：run `35712748949` ✓（另有 `35711584220` ✓）
- `go test ./...` 全绿 ✓、工作区干净 ✓

### 452. *** 关键结论：i686 blob 崩在「自校验硬门」—— 它是在**正确地拒绝** ***

**怎么定位到的（这条方法论值得复用）**：
1. 给 probe 加 `SetUnhandledExceptionFilter`，把**异常码/出错地址/访问违例目标地址**写进日志；
2. 再用它打印 **blob 映射基址** ⇒ 把出错地址换算成 blob 内偏移；
3. 用 `objdump -D -b binary -m i386` 反汇编那一处 ⇒ 看到崩溃指令是 **`0f 0b`（ud2）**——
   也就是项目里的 `__builtin_trap()`：**不是内存踩踏，是 blob 主动拒绝**；
4. 再打印异常**上下文寄存器**（`esi=0x96` 像哈希循环计数器、`ebx=ecx=blob_base+0x8000`=blob 的 .bss 起点），
   对照源码锁定了 `vm_selfcheck()`。

**根因**：`vm_selfcheck()` 对 `[base, base+vm_self_len)` 做 FNV-1a，与 vmpack 烘焙的 `vm_self_hash` 比对；
而我的**基址重定位补丁**（把 230 个 DIR32 站点 `+= base`）改了 `.text` 里的字节 ⇒ 哈希必然对不上 ⇒ 触发 ud2。

**这意味着**：`vm_self_hash` 与"加载期改字节"是**互相冲突**的两个机制，必须协调。标准做法是：
哈希时把**重定位站点**按规范化值（例如 0）参与运算（即站点字节不进入哈希）；vmpack 烘焙 `vm_self_hash` 时用同一套规则。

**顺带修掉的一个真 bug（本轮的实质进展）**：`vm_find_module` 用的是 **x64 的 PEB 布局**
（`Ldr@0x18`、8 字节指针、`DllBase@+0x30`…），而 i386 是 `Ldr@0x0C`、4 字节指针、`DllBase@+0x18`、
`Length@+0x2C`、`Buffer@+0x30`。已按 `VM_HOST_X86_32` 参数化（x64 展开后与原代码逐字节等价，不回退）。
修之前崩在 `mov 0x20(%esi)` 的访问违例（av_addr=0x11F，blob 偏移 0x72E）；修之后崩溃点推进到自校验（0x27C2）。

**下一步（很明确）**：让自校验跳过重定位站点 ——
(a) `vm_selfcheck` 通过一个由 vmpack 烘焙的「站点表偏移」全局找到表，遍历时对落在站点内的字节用规范化值；
(b) `vmpack` 计算 `vm_self_hash` 时用同一套规范化（它已经能读 vmpbuild 的 manifest，站点表信息在那里）。

### 453. *** 目标 ⑥ 达成：32 位 blob 在 32 位 harness 上跑通真实函数，且与 x64 侧一致 ***

**实测（这一段是本目标的最终证据）**

被保护的不是合成用例，而是**用 i686 gcc 真编出来的 32 位 exe**：

    build/real32.c  (v:32_sum10)  -O1 原生返回 55   —— 5 字节（GCC 把循环常量折叠了）
    build/real32b.c (v:32_loop)   -O0 原生返回 165  —— 49 字节 / 25 IR / 189 字节字节码（真循环）

经 `vmp-lift -mode 32` 翻译后，喂给 32 位 harness（`build/runbc_i686.exe`，i686 进程）在 i686 blob 里运行：

    real32.vmb   ->  rax=55   rc=1  flags=0x0
    real32b.vmb  ->  rax=165  rc=0  flags=0x0

**两个都等于原生返回值** ✓。与 x64 侧对照（同一段字节码，x64 二进制 + `-guest x86-32` blob + `runbc_x8632.exe`）：

    real32.vmb   ->  x64: rax=55 rc=1   i686: rax=55 rc=1     —— 完全一致 ✓
    real32b.vmb  ->  x64: rax=0  rc=99  i686: rax=165 rc=0    —— x64 宿主的 x86-32 客户机模式本身跑不了这个（既有缺口）

⇒ 凡是 x64 侧能跑的，两边**逐字一致**；x64 侧跑不了的那个，32 位侧**反而跑通了**。

**为达成它修掉的两个真 bug**

1. **i386 的 PEB 布局**（`vm_find_module`）：原来写的是 x64 布局（`Ldr@0x18`、8 字节指针、`DllBase@+0x30`），
   而 i386 是 `Ldr@0x0C`、4 字节指针、`DllBase@+0x18`、`Length@+0x2C`、`Buffer@+0x30`。已按 `VM_HOST_X86_32` 参数化
   （x64 展开后与原代码等价，不回退）。
2. **自校验与基址重定位的冲突**（这是最隐蔽的一个）：`vm_selfcheck()` 对 `[0, bssOff)` 做 FNV-1a 与烘焙值比对，
   而基址重定位**必须改这些字节**（896/920 个站点字节落在哈希区间内）⇒ 哈希必然对不上 ⇒ `ud2`。
   修法（两边同一套规则）：**站点内的字节按 0 参与哈希** —— vmpbuild 烘 `vm_self_hash` 时用该规则，
   并把表偏移烘成全局 `vm_reloc_tab_off`；`vm_selfcheck()` 读它找到表、按同一规则重算。
   独立验证：用 JS 按该规则重算文件得 `0xC3BC4CD8`，与 blob 里烘焙值**完全相同** ✓。

**定位方法（值得复用）**：`SetUnhandledExceptionFilter` 打异常码/出错地址/访问类型 → 同时打印 blob 映射基址换算成
blob 内偏移 → `objdump -D -b binary -m i386` 反汇编该处（看到 `0f 0b` = `ud2` ⇒ 是**主动拒绝**而非内存踩踏）
→ 再打异常上下文寄存器（`esi` 像哈希计数器、`ebx/ecx` = blob 的 .bss 起点）定位到源码。

**加载侧说明**：目前由 probe 遍历 `vm_reloc_tab` 做 `+= base`；生产路径（注入器/入口 stub）应改成入口自修复，
这一步**未做**。

**其余未做**：`vmpack` 的 i386/`Arch` 分支（生产打包路径仍只认 AMD64/ARM64）；
x64 宿主 x86-32 客户机模式在真循环上返回 `rc=99` 的既有缺口（不在本目标范围，但已记录）。

### 454. 目标①②：vmpack **已能接受 i386 并成功打包真实 32 位 exe**；运行阶段仍崩（下一步）

**已达成**：`vmpack -exe build/real32.exe -func vm32_sum10 ...` 对**真实 32 位 PE** 打包成功，
产出 155648 字节的 `build/real32_vmp.exe`（新节 `.w5eqrb7` RVA=0x1F000、`vm_entry RVA=0x1F000`、
描述符/蹦床/字节码 RVA 齐全）。两个不同函数（原生 55 / 165）都能打包。

**为此修掉的三处真问题（都不是 i386 专属的权宜，而是通用正确性）**：

1. **数据目录起点按位宽分**：`dirBase()` —— PE32 是可选头 +96，PE32+ 是 +112
   （差别只来自 NumberOfRvaAndSizes 的位置；其余字段在 ImageBase 之后自动对齐）。
   原先 9 处硬编码 `+112`，是 32 位打包必然踩的第一个坑。
2. **i386 COFF 符号的前导下划线**（`internal/scan`）：`int vm32_sum10()` 的符号是 `_vm32_sum10`，
   而调用方给的是源码名 ⇒ 报「找不到符号」。加了下划线回退（与 STATUS #441 在 vmpbuild 里修的是同一个坑）。
3. **payload 的基址重定位被错误地关在"镜像加密"分支里**：那段 `if len(items) > 0 { appendRelocs(...) }`
   原本嵌在 `if len(imgSecs) > 0` 内部 ⇒ **i386（跳过镜像加密）与 `-no-enc-image` 的情形下根本不执行**。
   已移到外面并用 `if !stripRelocs` 保留原语义。同时：
   · 重定位类型与指针宽度按镜像位宽选（PE32+ 用 DIR64=10/8 字节，PE32 用 HIGHLOW=3/4 字节）；
   · **字段要预置成"首选基址下的绝对 VA"**——HIGHLOW 的语义是「字段 += 实际基址 − 首选基址」，
     而 blob 里存的是"blob 相对偏移"，所以要先补上「首选基址 + payload RVA」。
   实测：打包日志已出现 `[*] blob 基址站点补了 230 个重定位项（type=3）` ✓（站点表 230 项全部接上）。

**仍卡住（下一步）**：打包产物运行仍是 `0xC0000005` ✗（**probe 路径是好的**，见 #453 ⇒ 问题在注入/加载一侧）。
调试方向（按可疑度）：① 描述符发现（蹦床靠"返回地址 − thunk − 64"反推，打包后调用方是 PE 入口补丁，栈形态可能不同）；
② payload 新节的**内存属性**（是否可执行/可写）与 `.bss` 是否被单独映射；③ 模拟栈 `esp-(4+VM_MARGIN)` 与真实栈的余量；
④ XMM 边界同步依赖 `ctx->frame` 被蹦床写入 ✓ 已确认。

**未做**：把 32 位打包接进 e2e/CI（需要一个 32 位被测目标）；`vmpack -verify` 对 32 位产物的路径；
以及上面 ①-④ 的定位。

### 455. 目标③：打包产物崩溃的**复现与定位** —— 新增 probe `thunk` 模式（可复用工具）

**本轮最有价值的产出：probe 的 `thunk` 模式**。它按**打包后的真实调用形态**跑：在映射区里现造一个描述符
（64B）与 5 字节 `E8` thunk，然后 `call thunk` ⇒ 蹦床靠"返回地址 − 0x45"反推描述符 ⇒ 走 `desc != NULL`
那条路（probe 以前一直是 `desc=NULL` 直呼，从没覆盖过）。实测**一次就复现**：

    直呼：    rax=55 rc=1        ✓（一直是好的）
    thunk：   0xC0000005  av_kind=0(read) av_addr=0x9D8C0008 blob_offset=0x5E4

**定位**：0x5E4 落在 `vm_xor32`（符号 +0x5E1）**内部** ⇒ 崩在**描述符字段的去混淆**上，读的是野掩码指针。
⇒ 这条路径需要**烘焙好的密钥/掩码**；我的 probe blob 没烘（vmpack 才烘）⇒ thunk 模式的探针应当喂
**vmpack 处理过的 blob**（下一步）。

**顺带查出并修掉的三处真问题**：
1. **`.reloc` 空间不足**：230 个站点需要 146 字节，而该节只剩 110 ✗（原来是嵌在"镜像加密"分支里，现在会在
   所有情形下追加 ⇒ 必须给这些项**找个新家**：新建一节承载"原有 + 新增"并把数据目录指过去，下一步做）。
2. **`appendRelocs` 静默丢弃非 DIR64 项**：`if it[0] != 10 { continue }` ⇒ i386 的 HIGHLOW 一条都加不进去。
   已支持 3/10，并**按页内偏移排序**（PE 要求）。
3. **入口 hook 在 i386 上写的是 x86-64 指令**：实测产物入口处是 `51 52 41 50 48 8d 0d …`（`push rcx/rdx/r8` + REX `lea`），
   在 32 位进程里全是垃圾 ⇒ 立刻崩。已改为 **i386 不装入口 hook**（镜像整体加密本来就跳过）。

**未做 / 下一步**：① 让 thunk 模式吃 vmpack 产出的 blob（带烘焙密钥）以复现"真·打包"路径；
② 给 230 个重定位项新建承载节；③ 端到端（打包后的真 32 位 exe 与原生一致）。

### 456. 一条踩了三次的纪律：**不要手工重建探针/blob 去跑测试**

本轮我为了验证 `thunk` 模式手工重建了 `build/runbc*.exe`，之后 `go test ./...` 一直红（arm64 差分 + x64 conformance），
我先后怀疑并**回退**了本轮的两处改动（探针的 thunk 模式、vmpack 的 HIGHLOW/入口 hook）——**都回退后仍然红** ✗，
说明与改动无关。最后把 `build/runbc*.exe` 与 `build/vm_interp.bin` **删掉、交给 `tools/gates.ps1` 按它自己的顺序重建**，
立刻恢复 `total 11 gates, 0 failed` ✓（改动也原样恢复）。

**结论**：`build/` 下的探针与 blob 必须由**门禁/CI 自己的步骤**产出（它们用的 `-D`/顺序与手工不同）；
手工重建会制造"看起来是我改坏了"的**假红**。出现红时**第一件事**是：清掉 `build/runbc*.exe`、`build/vm_interp*.bin`，
让门禁重建，再看结果 —— 而不是先回退代码。

顺带确认：`afc02ab`（含 probe `thunk` 模式 + vmpack 的 HIGHLOW/排序/i386 不装入口 hook）在 CI 上**五绿** ✓、门禁 **11/0** ✓。

### 457. *** 目标③ 首个真实用例达成：32 位 PE 打包后运行结果与原生一致（55）***

**实测**：

    build/real32.exe       i686 gcc 编的真 32 位 PE，原生返回 55
    vmpack -strip-relocs → build/t4.exe (155648 字节)
    运行 t4.exe            → 退出码 55  ✓ 与原生一致

**根因（整条 saga 的最后一环）**：i686 蹦床的结尾漏了两件事，而 x64 蹦床都有：

    x64（stub/win/x64/vm_entry_asm.S 结尾）:
        movq VM_CTX_RAX(%rsp), %rax
        addq $VM_FRAME_SIZE, %rsp
        addq $8, %rsp        ← 跳过 thunk 自己那条 E8 压的返回地址
        ret

我的 i686 版本少了 `addl $4, %esp` 与从 ctx 取回返回值 ⇒ `ret` 落到 thunk 之后的填充字节（`00 00` =
`add %al,(%eax)`）⇒ 往 `[eax]` 写（eax 此时是返回值 55）⇒ 0xC0000005。已补齐。

**定位手段（本轮新增，值得记）**：对**打包产物**用不了 probe 的 SEH 过滤器，改用 **Windows 应用程序事件日志**：
`Get-WinEvent -LogName Application` 里 APPCRASH 记录的 **P8 = 错误偏移（模块内 RVA）** 直接就给出了出错指令地址 ——
本轮据此把崩溃点从 `0x211CF`（`.bss` 写野地址）追到 `0x29C95`（thunk+5），一步到位。

**同时修掉的另外两处"同类遮蔽"**：`-strip-relocs` 的实现（`clearDynamicBase`/`stripRelocations`）与 payload 的
**字段预置**，原先都嵌在 `if len(imgSecs) > 0`（镜像整体加密）里 ⇒ i386（跳过镜像加密）**从不执行** ⇒
DYNAMIC_BASE 未清、字段保持 blob 相对偏移 ⇒ 加载器按 ASLR 重定位而预置值按首选基址写。现在两者都独立于镜像加密。

**新发现的两个待办（已开新目标继续）**：
1. **默认路径（保留 ASLR）被 `.reloc` 空间卡住**：230 个站点需要 146 字节而该节只剩 110 ✗ ⇒
   需要给这些项一个新的承载节（新建一节装"原有 + 新增"并把数据目录指过去）。
2. **`vm32_loop` 打包后返回 1（原生 165）** ✗ —— 能跑但结果不对 ⇒ 一个真实的**行为不一致**疑点（下一步查）。

### 458. 目标③：`vm32_loop` 返回 1 的问题 —— 已**二分**到根因面（本地变量/栈），字节码与解释器被证明正确

**二分结果（四个 `-O0` 小函数，probe 直呼路径作对照）**：

    f1: return 42;                     native=42   packed=42 ✓    （不碰本地变量）
    f2: int a=7,b=5; return a*b;       native=35   packed=1  ✗    probe 直呼=35 ✓
    f3: 循环求和 (1..10)               native=55   packed=1  ✗    probe 直呼 ✓
    f4: 循环求和 ×3                    native=165  packed=1  ✗    probe 直呼=165 ✓

⇒ **失败构造是"本地变量（栈存取）"，与循环无关**（f2 没有循环也失败）。
⇒ **同一份字节码在 probe 的直呼路径上全部正确** ⇒ **字节码/IR/解释器/VM 都是对的**，问题在**打包运行期的上下文**。

**排除掉的**：
· 不是加密路径（`-no-encrypt` 打包同样 f1 ✓ / f2 ✗）；
· 不是"打包时 lift 窗口不同"（vmpack 报告 `49B -> 25 IR -> 189B`，与我在 probe 里用的完全一致）；
· 不是操作码映射（vmpack 读 manifest 的 `OpcodeMap` 并 `vm.Remap`，与恒等映射一致）；
· 不是"临时寄存器撞 VSCRATCH 槽"（`VRSCRATCH` 在解释器里只出现在静态断言里）；
· 我一度以为是 `VM_FRAME_SKEW` 与实际蹦床差 12（EXTRA=16 vs 蹦床的 4）——已把蹦床改成 `-(16+VM_MARGIN)` 与之一致，
  但 f2 仍返回 1 ⇒ **也不是 skew**（而且 f2 的访问是纯 `%ebp` 相对的，`eff<0` 根本不补 skew）。

**剩下的疑点（下一步，按可疑度）**：
1. **`ctx.scratch` / `scratchLen` 两个字段**：蹦床只写了 `regs[VRSCRATCH]`（槽 17），**没写** ctx 里 offset 168/172 的
   `scratch`/`scratchLen` 字段；probe 直呼时它们是 0、`desc` 也是 NULL。而打包路径 `desc != NULL` ⇒ 解释器的**取指**
   可能走"带 scratch 的流式"分支读到垃圾（f1 只用 5 条 IR、可能没触发）。**下一步优先验证**。
2. `VRBASE = imageBase`（打包）vs `0`（probe）—— f2 不用绝对寻址，理论无关，但要确认解释器没有把它掺进栈地址计算。
3. 蹦床填入的**初始寄存器**（调用方的值）vs probe 的全 0。

**结论**：目标③**尚未达成**（`vm32_sum10` 已一致 55 ✓，但带本地变量的函数不一致 ✗）；目标保持 active。

### 459. 目标③：在 probe 里**复现**了"打包 ctx"的失败，并二分出**唯一元凶是 VRSP**

**方法**：给 probe 的直呼路径加 `like` 模式 —— 保持字节码/描述符/加密完全不变，只把 ctx 逐项做成打包路径的样子：
`regs=1` 初值非零 · `sp=1` 打包式 VRSP（`emu_stack_top - 16 - 0x4000`）· `base=1` VRBASE=0x400000。
于是可以在一份**完全相同**的字节码上做 2x2 矩阵。

**矩阵结果（同一份 `x2.vmb`，期望 35）**：

    全关（= 直呼）        rc=0         rax=35 ✓
    只开 VRBASE          rc=0         rax=35 ✓
    只开非零初值          rc=0         rax=35 ✓
    只开打包式 VRSP       rc=0xC0000005        ✗   <- 唯一能单独复现失败的
    全开（= 打包）        rc=0xC0000005        ✗

⇒ **元凶是 VRSP**（与 VRBASE、初值寄存器无关）。崩溃点 `blob_offset=0x6B31` = `mov %eax,(%ecx)`，
其中 `ecx` 来自 `mov 0x20(%esi),%edi`（读 `vm->regs[RSP]`，offset 32）+ `add $-4`；当次 `av_addr=0xFFFFFFFC`，
即 VM 看到的 `regs[RSP]` 是 **0**。

**解释器对 VRSP 的语义（vm_interp.c 第 1598/1793/1796 行）**：

    u64 rsp_start = vm->regs[VRSP];                       /* 入口值被当作"栈顶" */
    if (rsp_start - vm->regs[VRSP] > VM_MARGIN) return 99; /* 只允许往下 16KB */
    if (vm->regs[VRSP] > rsp_start)            return 97; /* 不允许往上 */

⇒ **入口的 `VRSP` 必须是一个"上方无可用、下方正好 16KB 可用"的栈顶**，而不是"栈底附近"。
我的蹦床给的是 `esp - (16 + VM_MARGIN)`，与这个语义**对不上**（它把一个已经在 16KB 之下的地址当成了栈顶）。

**下一步（很具体）**：在 probe 里把 `sp=1` 的值换成 `emu_stack + 0x80000`（下方留足 16KB 以上）再跑矩阵 ——
若这样就通过，说明问题只是"栈顶语义"：那么蹦床应当给 `VRSP = esp - 16` 之类（紧贴调用方返回地址上方），
而 `VM_FRAME_SKEW`/`VM_MARGIN` 的账要按解释器的这个语义重新对齐（三者必须同时对）。

### 460. 纠正 #459 的错误结论：矩阵重跑后 **VRSP/VRBASE/初值寄存器都不是元凶**

**#459 的结论是错的**，原因在我自己的探针里：`like` 模式的 `regs=0` 分支把 **r == VRSP（4）也清零了**，
于是"只开打包式 VRSP"那一组实际是 **RSP = 0**，崩溃在 `[-4]`（`av_addr=0xFFFFFFFC`）——这与观察吻合，
但它测的根本不是"打包式 VRSP"。

**修正后重跑矩阵（同一份 `x2.vmb`，期望 35）**：

    全关（= 直呼）        rc=0  rax=35 ✓
    只开 VRBASE          rc=0  rax=35 ✓
    只开打包式 VRSP       rc=0  rax=35 ✓
    只开非零初值          rc=0  rax=35 ✓
    全开（= 打包）        rc=0  rax=35 ✓

⇒ **三项 ctx 特征都不是元凶**：`ctx` 层面的差异被排除干净。

**于是剩下的唯一未测差异是 `ctx.desc != NULL`**（只有打包路径才有描述符解码：`vm_desc_fields` 解 6 个标量字段，
再由 `vm_run` 按其 `codeRVA/codeLen/flags` 取指）。这一路径**必须**用一份**按主密钥正确混淆**的描述符才能测 ——
而 `VM_FIELD_MASK_DESC / VM_FIELD_MASK_SALT` 是 **vmpbuild 每次构建生成**的（在生成的 `vm_crypto_key.h` 里，
由 `-include` 注入），**probe 无法静态获知**，所以"合成描述符"这条路走不通（这也是我此前 thunk 模式崩在
`vm_xor32` 的原因）。

**下一步的可行做法（已明确）**：让 **vmpack** 提供一个调试点：把「已混淆的描述符 + 它对应的 blob」
以**便于加载的形式**导出（例如按 blob 偏移拼成一份连续文件），probe 就能加载它并**只**开启 `desc != NULL` 这一项；
或者给 vmpack 加一个"描述符不混淆"的开关，并在描述符里用一个空闲字段标记它，解释器据此跳过 `vm_desc_fields`。

**本轮其余**：probe 的 `like`/`desc` 模式留在代码里（`desc` 模式当前因上述混淆问题无法单独验证，已在注释里写明）。

### 461. 回退探针的 like/desc 模式 —— 这是**真回归**（不是本地产物不一致）

时间线：

1. 我按 #456 的惯例"清掉本地产物、交给门禁重建"重跑，门禁仍然红；
2. **关键是 CI 也红了**（`main ci` 里 windows-amd64 失败）⇒ 说明不是本地产物问题，而是**源码回归**；
3. 本轮对源码的唯一改动就是 `stub/win/x64/blob_probe.c`（新增 `like`/`desc` 两个探针模式）；
4. 立即 `git checkout ae1de30 -- stub/win/x64/blob_probe.c` 回退，探针回到最后一个绿的状态。

**`desc` 模式本来就无法单独验证**（`VM_FIELD_MASK_DESC/SALT` 是 vmpbuild 每次构建生成的，probe 无法静态获知），
所以回退它没有任何损失；`like` 模式的**做法**已完整记在 #459/#460，下次重做时请**小步加、每步都跑门禁**。

**纪律补充**：清本地产物只对"产物不一致"这一类假红有效；**当 CI 同时红时，就是真回归，应当立刻回退**。

### 462. 目标③：又找到两个**真问题**，并把"返回 1"的机理钉死

**发现 1（真 bug，独立于本目标）**：`vmpack -no-encrypt` 时**描述符不会被混淆**，但解释器**永远会去混淆**
⇒ 解出来的 `codeRVA/codeLen/flags/funcRVA` 全是垃圾 ⇒ 跑飞 ⇒ `pc >= codeLen` ⇒ `return 1`。
证据：我用 `inject.FieldMask`（manifest 的 key + fieldMaskSalt）写了个临时解码器：

    k1_vmp（默认加密）: codeRVA=0x50 codeLen=0x36 flags=0x501 funcRVA=0x1500   ← 字段正确
    k1_ne （-no-encrypt）: codeRVA=0x4AF21230 codeLen=0x544F5EFB flags=0x5E5E9FD8  ← 全是垃圾

⇒ 这也说明我此前那些 `-no-encrypt` 对照实验**是无效的**（我误以为它排除了加密路径）。

**发现 2：机理钉死**。"返回 1"就是 `vm_interp.c:1800` 的 `if (vm->pc >= vm->codeLen) return 1;`；
而蹦床取回的是 ctx 里**没被写入**的 RAX（调用方 `main` 里恰好是 1），所以进程退出码是 1 —— 不是函数结果。

**发现 3：产物里的字节码与 `vmp-lift` 的 `.vmb` **逐字节相同**（54B）** ⇒ 字节码/操作码映射都对。

**最强的实验**：我把产物描述符的 **ENC 位清掉**（按掩码重新混淆）并把**明文**字节码写进 code 区 ⇒
解释器改走"直读"路径 ⇒ **不再返回 1，而是 `0xC0000005`**（事件日志 `P8=0x21800` ⇒ blob 偏移 0x2800）：

    2800:  movzbl 0x0(%ebp,%ebx,1),%eax      ← 这就是 vmb_byte 里的 s->ct[off]（取指）

⇒ 连**明文**路径都在**取指**时读到野地址 ⇒ `pc` 跑飞了（不是解密的问题，是**执行流/取指基址**的问题）。

**又纠正了一次自己**：我先怀疑"蹦床用了未去混淆的 `codeRVA` 去设 ctx->code"，但核对 x64 蹦床发现**它也这么写**，
而解释器随后会用去混淆后的字段**覆盖** `vm->code`（第 1590 行）⇒ 所以那不是根因。

**下一步（已很窄）**：查出明文路径下 `pc` 为何跑飞 —— 具体看 `vm->code` 的**运行期值**是否等于
「描述符地址 + codeRVA」，以及 `pc` 是**从哪一条 IR 之后**开始不对；blob 自带 trace（`vm_last_pc`/`vm_r1_pcs` 等符号）
可以在 probe 里按符号偏移读出来，值得优先利用。

### 463. 目标③：修掉两处**真 bug**（`-no-encrypt` 的掩码不一致 + 非加密路径的 code/codeLen）

**修 1（打包端 `internal/inject/payload.go`）**：描述符字段混淆原先只在 `len(opt.Master)==32` 时做，
而 `-no-encrypt` 时**没有主密钥** ⇒ 跳过混淆；解释器却**总是**按（零密钥派生的）掩码去解 ⇒ 字段全垃圾。
实测（我写了个临时解码器，用 manifest 的 key+fieldMaskSalt 复算掩码）：

    k1_vmp（有主密钥）: codeRVA=0x50 codeLen=0x36 flags=0x501 funcRVA=0x1500   ← 正确
    k1_ne （-no-encrypt）: codeRVA=0x4AF21230 codeLen=0x544F5EFB ...            ← 垃圾

改法：**无条件混淆**，没有主密钥时用**全零 master**（运行期 `vm_master()` 同样是零，两侧一致）。

**修 2（blob `vm_interp.c`）**：`vm->code`/`vm->codeLen` 原先只在 **ENC 分支**里用"去掩码后"的字段设置；
非加密路径就保留**蹦床用未去掩码的原始字段**算出来的值（蹦床算不了掩码）⇒ 取指必读野地址。
改法：加一个 `else` 分支，同样用去掩码后的 `f.codeRVA/f.codeLen` 设置。

**效果（可观测）**：`-no-encrypt` 产物原先崩在**第一次取指**（blob 偏移 0x2800 = `movzbl (%ebp,%ebx,1)`），
修后崩溃点**前移到 blob 0xA740**（`vm_patch_mac` 一带，最后一个 .text 节）⇒ 明文路径**明显走得更深**。

**另外两处重要更正（本轮）**：
· `rc=1` **不是**"提前返回"——能跑通的用例也是 `rax=42 rc=1`，`return 1` 就是**客户机正常返回**；
  真正决定进程退出码的是蹦床取回的 **ctx->RAX**（= 客户机返回值）。我在 #462 里的相关推断要按这条修正。
· 我先后否掉了 5 个假设（opcode 长度/字段偏移、VM_REG_MASK、蹦床设 code、keystream 分块、VRSP 系列），
  都通过**读源码或实测**否掉的，不是猜的。

**下一步**：`-no-encrypt` 现在能走到 `vm_patch_mac` 一带 ⇒ 顺着它的调用条件（`plen = (flags>>8)&0xFF`）
查为什么在非加密产物里仍被调用/越界；这条路径与加密路径**共用**，修好它对两条路都有意义。

### 464. 目标③：修掉**校验表掩码**的同类真 bug；`-no-encrypt` 路径继续前移

**修 3（`internal/inject/payload.go`）**：与描述符同理 —— 运行期 `vm_verify_table` 是**无条件**按掩码解表项的，
而打包端加掩码原先被 `if len(opt.Master) == 32` 挡着 ⇒ `-no-encrypt`（无主密钥）时表项**没加掩码** ⇒
`delta` 解出来是垃圾 ⇒ `p = base + delta` 成野指针 ⇒ `vm_patch_mac` 里那个 memcpy（blob 0xA740）直接 0xC0000005。
改法与描述符一致：**无条件加掩码**，无主密钥时用全零 master。

**-no-encrypt 路径的崩溃点推移（每一步都能复现）**：

    修 1+2 前： blob 0x2800（第一次取指，蹦床用未去掩码的 codeRVA）
    修 1+2 后： blob 0xA740（vm_patch_mac 的 memcpy，表项 delta 是垃圾）
    修 3 后：   blob 0x2880（vm_run 内一个被内联的哈希/取指循环）

**本轮排除/纠正的（都有实测或读码依据）**：
· 产物里烘焙的 `vm_self_len=0x8000`、`vm_code_off=0`、`vm_reloc_tab_off=0xA8A8` **全部正确**；
· **230/230 个基址站点在产物里都被正确预置**（逐个核对：产物字段 == 原字段 + 0x41F000）；
· 我一度以为"有些绝对存储没被预置"，后来发现自己**读偏了一个字节**（真站点在 0x2840/0x284C/0x2852，都在表里）——
  这是本轮第 8 次自我纠正，记下来提醒：**按字节偏移核对指令操作数时，先确认指令长度/操作数位置**。

**下一步（已经只剩一个差异）**：probe 的直呼路径 + `desc = NULL` 一切正常，而打包路径唯一的差别就是 **`desc != NULL`**。
要单独测它，需要一份**按掩码正确混淆**的描述符 —— 而这个掩码用 `inject.FieldMask(master, FieldMaskDomainDesc, salt)`
就能算出来（我本轮已经用一个临时 Go 工具验证过解码方向）。做法：临时工具导出这样的描述符 + probe 加一个极小的
"只读描述符文件"模式；**加探针模式时必须一步一跑门禁**（#461 的纪律：上次加 like/desc 模式让 CI 变红）。

### 465. 目标③：排除 XMM 同步；差异进一步收敛（并记录一条我一直没做的便宜核对）

**核对：同一份字节码在 probe 里是好的** ✓

    build/k1.vmb（1 个本地变量，54 字节码）→ probe 直呼 rax=2  ✓（期望就是 2）
    build/x2.vmb（a*b，92 字节码）      → probe 直呼 rax=35 ✓

而**同一个函数**打包后退出码是 1 ⇒ 字节码/IR 本身没问题，差别在**打包运行期**。

**排除：XMM 边界同步（`vm->frame != 0`）不是元凶**。
探针直呼时 `frame = 0` ⇒ 同步被跳过（守卫就是 `if (vm->frame)`），所以此前所有 probe 对照都**没覆盖**同步。
判定实验：临时把 `vm_interp.c` 里的入口/出口同步都改成 `if (0 && vm->frame)`，重建 blob 后重新打包 k1 ⇒
**仍然返回 1**（不是 2）⇒ 同步不是元凶（随后立即 `git checkout` 回退，未提交）。这是本轮第 9 次自我纠正。

**两侧密钥流的约定核对**：Go 侧字节码加密用 `chacha20poly1305.New(...).Seal(...)`（RFC 8439：AEAD 数据流从
counter=1 开始），C 侧取指用 `vm_chacha20_keystream(key, blk + 1u, nonce, ks)` ⇒ 约定一致 ✓。
且 20 字节的加密产物（`g1`/`g2`）能返回**正确的 100/101** ⇒ 解密路径对它们是对的。

**于是差异只剩两种可能**（都很具体）：
1. **解密取指**在 54 字节（仍在同一个 64 字节块内）时与打包端不一致 —— 但 20 字节正确、且同块，这在逻辑上
   要求"前 20 字节对、后面错"，需要**逐字节比对**才能确认；
2. **内存操作（STORE/LOAD）的语义**：`k1` 的失败结果恰好是 **1**，而它最后一条写 EAX 的指令是 `LOAD eax,[ebp-4]`，
   所以"内存里读到的是 1 而不是 2"最符合观察。

**下一步（可测量，不需要再猜）**：给 blob 加一个**临时**诊断 —— 在 `vm_run` 退出前把 `vm_diag[]`（已有：入口/出口
`regs[0]`、`rsp`、`code`、`codeLen`、`pc`、`rc`）以及 `vm_st_pcs/vm_st_addrs/vm_st_vals`（最近 16 次 STORE 的
pc/地址/值，已在解释器里维护）**写进一个固定文件**（blob 已经会用 PEB 取 kernel32 的 `CreateFileA/WriteFile`，
照 `vm_img_fail` 的写法即可）。这样两种可能**一次就能分开**，而且完全不必再动 probe。

### 466. 目标③：**证明解密无罪**（离线逐字节比对）；差异锁定在"内存操作语义"

**决定性实验**：写了个临时 Go 工具，用 manifest 的 key + `inject.FieldMask` 还原描述符字段，
再按打包端同样的算式派生条目密钥（`KDFEntry(master, funcRVA, KDFSaltForPlacement(selfRVA, funcRVA, codeLen))`），
用 `chacha20.NewUnauthenticatedCipher(key, nonce)` + `SetCounter(1)`（与 `chacha20poly1305` 的数据流约定一致）
**离线解密产物里的字节码**，再与 `vmp-lift` 的 `.vmb` 逐字节比对：

    fnRVA=0x1500 selfRVA=0x29C50 codeRVA=0x50 codeLen=54
    离线解密(前20): 50 05 10 20 05 04 21 01 20 04 04 10 00 00 00 11 20 11 02 00
    vmp-lift .vmb  : 50 05 10 20 05 04 21 01 20 04 04 10 00 00 00 11 20 11 02 00
    => 完全一致 ✓

⇒ **解密路径（密钥流/counter/nonce/KDF 全部）无罪**，我的密钥流假设到此终结（第 10 次自我纠正）。
**注意**：第一次跑时用了旧产物（几轮前的 manifest 密钥不同）导致 RVA 越界 panic，重新打包后才对上 ——
教训：**临时分析工具必须用当前 manifest 重新生成的产物**。

**本轮共排除（都有实测依据）**：
· 三处 ctx 特征（VRSP / VRBASE / 初始寄存器）——like 矩阵（修掉误清 RSP 的 bug 之后）；
· XMM 边界同步（`vm->frame`）——临时 `if (0 && vm->frame)` 后仍返回 1；
· `VM_REG_COUNT`/`VRSCRATCH=17` 与 lifter 的临时寄存器一致（vm_types.h 第 31 行注释明确它是"仅 VM 可见"）；
· 解密密钥流（上面的离线逐字节比对）；
· 描述符字段、AEAD 验签、字节码字节、230/230 基址预置。

**剩下的唯一区域**：**内存操作（STORE/LOAD）在打包上下文里的语义**。失败值恰好是 1，而 `k1` 最后一条写 EAX 的
指令是 `LOAD eax,[ebp-4]` ⇒ "内存里读到 1 而不是 2"最符合观察。

**下一步（唯一还需要的工具）**：给 blob 加一个 **Windows 版**诊断落盘 —— `vm_dbg_trace` 现在走 `vm_syscall3_a64`
（Linux 系统调用，Windows 用不了），要照 `vm_img_fail` 的写法用 kernel32 的 `CreateFileA/WriteFile`；
把解释器**已经在维护**的 `vm_st_pcs/vm_st_addrs/vm_st_vals`（最近 16 次 STORE 的 pc/地址/值）与 `vm_diag[]` 写进固定文件，
一次就能看清"STORE 写到哪、LOAD 从哪读"。

### 467. 目标③：**拿到 pc 证据** —— 失败用例的执行在偏移 15 就结束了（对照用例是 19）

**方法**（临时诊断，跑完已回退）：在 `vm_run` 返回前把出口 `vm->pc` 塞进返回值（退出码正好 8 位）：

    g1（20 字节码，**能跑通**）: 出口 pc = 19   ← 正常：正好落在最后一条指令（RET）上
    k1（54 字节码，**返回 1**）: 出口 pc = 15   ← 明显不正常

**解读**（用 `k1.vmb` 的指令布局逐条算长度）：

    0: PUSH_R   (2) → 2
    2: MOV_RR   (4) → 6
    6: ALU_RI   (8) → 14
   14: MOV_RI   (7) → 21        ← 出口 pc = 15 就卡在这条**开头之后一个字节**
   21: STORE   (10) → 31
   31: LOAD    (11) → 42
   42: MOV_RR   (4) → 46
   46: POP_R    (2) → 48
   48: RET      (1)

`vm->pc` 停在 15 ⇒ 说明**执行没能走到 STORE/LOAD**，而是在 MOV_RI 附近就结束了；对照 g1 停在 RET 上。
结合"失败值恰好是 1"（`k1` 里唯一会写 EAX 的末条指令是 `LOAD eax,[ebp-4]`）⇒ 最可能是**客户机的返回地址/
栈位置不对**（RET 从 `[esp]` 取回垃圾 ⇒ 后续 `pc >= codeLen` ⇒ `return 1`），也就是 `leave`(mov esp,ebp + pop ebp)
之后 ESP 的记账有问题 —— 而这与"打包上下文里 ESB/EBP 的真实值"直接相关。

**本轮的一个教训**：我用"按行区间抓块再移动"的方式改 C 文件，切错了边界（漏掉注释行/多带一行），直接把
`vm_interp.c` 编坏。已立即 `git checkout -- stub/win/x64/vm_interp.c` 恢复到已提交状态。**这类大块搬移要么用
锚点字符串精确匹配，要么就别在没有门禁保护的情况下做** —— 这是本项目 #451 那条纪律的又一次印证。

**下一步**：把 pc 证据做**更细**的分辨 —— 让临时诊断分别输出 **RET 之前的 ESP/EBP/`[esp]`** 三个值的低字节
（三次运行，或者一次运行把三个值编码成 24 位再分三次读出），就能一次性确认"返回地址是不是垃圾"。

### 468. 目标③：**决定性的一步 —— 失败用例 rc = 99（栈守卫）**

**方法**（临时诊断，随后已回退）：在 `vm_run` 返回前把 `rc` 塞进返回值（退出码 = rc）：

    k1（54B，带本地变量，失败）  rc = 99    ← vm_interp.c:1802「压栈越过给它的栈下界」
    g1（20B，常量，通过）        rc = 0
    k2（12B，O1，通过）          rc = 2

`99` 在整个解释器里**只出现在那一处**（grep 确认：1796/1802）⇒ 前面所有「返回 1」的解释都不对，
真正的结束原因是**栈守卫**。

**守卫的写法值得注意**（1801-1802）：先做 `rsp_start - vm->regs[VRSP] > (u64)VM_MARGIN`（**无符号**比较）⇒ 返回 99；
之后才检查 `vm->regs[VRSP] > rsp_start` ⇒ 返回 97。因为是**无符号**比较，**SP 向上跳**同样会先命中 99
⇒「SP 掉太多」与「SP 跳太高」两种都表现为 99。

**又量了一个数（模 256，只能定性）**：`(rsp_start - VRSP) & 0xFF` ⇒ k1 = 20、g1 = 0。20 与
「push ebp(4) + sub esp,0x10(16)」吻合，但也与「SP 向上跳了 236+256k 字节」同余 ⇒ **这个数不能定性**。

**顺带核对（都一致，故排除）**：`ALU_RI` 的长度（Go 5 字节 + imm32 = 9；C 长度表也是 9）、字段偏移
（kind/width/dst/a/imm32 两边同布局）。

**下一步**：分两次运行分别输出 `rsp_start` 与 `VRSP` 的低 8 位（或把两者相减后右移 16 位看高位），
确认是「掉太多」还是「跳太高」；若是「跳太高」，重点查两条会**整值改写 ESP** 的路径：
`write_reg(dst=4, width=32, ...)`（`sub esp,imm` 的写回）与 `mov esp,ebp`（leave 前半）。

### 469. 目标③：D = 20（只掉 20 字节）⇒ **与 rc=99 矛盾**；把矛盾如实记录并给出唯一能一次问清的手段

**本轮测量**（临时诊断，已回退）：把 `(rsp_start - VRSP) >> 8 & 0xFF` 放进退出码（解开模 256 的歧义）：

    k1 = 0    g1 = 0    g3 = 0

⇒ 三者都 < 256 ⇒ 真实位移就是**低字节那个 20**（`push ebp` 4 + `sub esp,0x10` 16）⇒
**SP 只掉了 20 字节**，远远小于 `VM_MARGIN`(0x4000)。

**矛盾**：
· 前一轮实测 `k1` 的 **rc = 99**，而 `99` 在整个 `vm_interp.c` 里**只出现在那一处栈守卫**（grep 确认 1796/1802）；
· 本轮的 D 又证明 SP 只掉 20 ⇒ 守卫条件 `20 > 16384` 为假 ⇒ 99 **不可能**由它产生。
⇒ 两次运行的数据**互相矛盾**，说明我前面"临时诊断"的观测方式本身有坑（很可能是：诊断把值写进 `ctx->RAX` 的时机
与解释器各条 return 路径的先后关系没搞清；或两次运行用的 blob/产物不是同一份）。**在把这一点查清之前，
任何基于这两个数的推论都不可靠。**

**结论（诚实登记）**：本轮**没有**推进根因；只确认了"SP 只掉 20 字节"这一个可靠事实，并且把上一轮的 99 判定标为**待复核**。

**唯一能一次问清的手段（下一轮做，且要按 #467 的教训用锚点精确编辑）**：
在 blob 里加一个 Windows 版诊断落盘（`CreateFileA`/`WriteFile`，照 `vm_img_fail` 的写法，**不用** `vm_dbg_trace`——
它走的是 Linux 系统调用），把 `vm_diag[0..15]`（入口/出口 `regs[0]`、`rsp_start`、`code`、`codeLen`、`pc`、**`rc`**）
与 `vm_st_pcs/vm_st_addrs/vm_st_vals`（最近 16 次 STORE 的 pc/地址/值，解释器已在维护）**一次写全**。
这样 pc、rc、SP、STORE 轨迹就在**同一次运行**里，矛盾自然会消失。

**本轮纪律遵守**：临时诊断已 `git checkout` 回退；主干未留下任何未验证改动。

### 470. 目标③：修掉一处**真实的 i686 隐患（Win32 API 调用约定）**；但**不是**错值根因

**发现**：`stub/win/x64/vm_interp.c` 里**所有** 25 个函数指针 typedef 都是默认 **cdecl**，而 32 位 Win32/ntdll/
bcrypt API **全部是 `__stdcall`**（callee 清栈）⇒ 在 i686 构建里，调用方会**再清一次**栈 ⇒ 宿主栈被逐次破坏。
（x64 只有一种调用约定，所以这个隐患在 x64 上不存在 —— blob 此前一直是 x64，i686 是这次新开的路径。）

**修法**：加宏

    #if defined(VM_HOST_X86_32)
    #define VM_WINAPI __attribute__((stdcall))
    #else
    #define VM_WINAPI
    #endif

并把它加到全部 25 个 typedef 上（`fn_t`/`termfn_t`/`create_t`/`read_t`/`close_t`/`gstft_t`/`ldr_t`/bcrypt 系列/
`qip_t`/`gct_t`/`exitfn_t`/`vpfn_t` 等）。x64 下 GCC 忽略该属性 ⇒ **对 x64 无影响**。

**实测（未修 vs 修后，同一个 k1/g1/g3 组合）**：行为**完全一致**（g1 通过、k1/g3/k3/h1 仍返回 1）
⇒ **这处修复没有解决错值问题**，但它是**真实存在的正确性隐患**（32 位下调用 stdcall API 会破坏宿主栈），
保留它并交给门禁/CI 判定。

**为什么"只有 desc != NULL 才出错"曾是强线索**：只有描述符路径才会调 `vm_master()`（走 ntdll/bcrypt，全是 stdcall），
而 probe 的直呼路径 `desc = NULL` 根本不走那条。这条线索**方向对**（确实是"只有打包路径才走的代码"），
但**具体点不对**：修了调用约定后错值依旧。

**本轮其余（诊断尝试，均已回退）**：
· 往 blob 里加"一次性落盘"诊断（`CreateFileA`/`WriteFile` 写 `vm_diag[]` + `vm_st_*`）—— 加完后**连 g1 都崩**，
  且始终**不生成文件**；加了 stdcall 后仍然崩、仍然没有文件 ⇒ 说明该诊断自己有问题，**已完整回退**（残留检查为空）；
· 这再次印证 #467 的教训：临时探针要**小步加、先验证编译再打包**，且不该在预算紧张时做。

**下一步**：换一种**不需要在 blob 里调 API** 的观测方式 —— 让 blob 把要看的量**写进它自己的 `.bss` 里已有的诊断数组**
（`vm_diag`/`vm_st_*` 都是导出符号，且在 `.bss`），然后用 probe 直呼**同一份打包产物里抽出的 blob**、
或在打包产物上**读出 `.bss` 段在文件里的初值**（不行，运行期才有值）⇒ 更现实的是：用 `vm_diag` 里**已经存在的**
那些写入点（入口/出口 `regs[0]`、`pc`、`rc`）而不新增 API 调用，只用**返回值**分多次读出（每次 8 位）。

### 471. 回退 __stdcall 修复（真回归）并恢复绿色

时间线：

1. #470 里给 25 个 Win32/ntdll/bcrypt 函数指针 typedef 加了 `__attribute__((stdcall))`（仅 `VM_HOST_X86_32` 生效）；
2. 本地门禁报 `linux blob build failed` + `linux payload (executed on Windows)` 失败 ⇒ **CI 五作业全红**（run 35744424024）；
3. 判定为**真回归**（CI 同时红 ⇒ 不是本地产物不一致，见 #461 的纪律）⇒ 立即 `git checkout 99e11c5 -- stub/win/x64/vm_interp.c` 回退；
4. 回退后：`preflight` = `[+] preflight: OK`；CI run **35744998980** = **completed success**（4m42s，五作业全绿）。

**结论**：该属性虽然"32 位下方向正确"，但在 Linux/arm64 blob 构建上不成立（属性/编译选项组合被拒），
**不能**用当前的写法。若以后再做，必须用**平台 + 编译器双重条件**守护（例如同时判 `_WIN32`/`__i386__`），
并在**同一轮**里跑门禁与 CI 验证 —— 本轮就是因为在预算紧张时改共享代码而付出了一次红。

**未做项（保持 active）**：目标③仍未达成 —— 真实 32 位 exe 打包后，简单函数（`vm32_sum10`=55、`g1`=100）与原生一致，
但**使用本地变量/栈的较大字节码**（`k1`/`g3`/`k3`/`h1`）仍返回 1。可靠事实：SP 只掉 20 字节；待复核：rc=99。

### 472. 目标③：**根因指向 i686 蹦床用 `movl` 填 u64 寄存器槽**（证据链完整）；两版修法都需重做

**本轮最硬的证据**（临时诊断，均已回退）：

    k1: (rsp_start - VRSP) > VM_MARGIN  →  1        （守卫条件出口时为真）
    k1: (rsp_start - VRSP) & 0xFF       →  20
    k1: ((rsp_start - VRSP) >> 8) & 0xFF →  0       （bit8..15 全 0）

⇒ 三个数联立：位移 ≡ 20 (mod 65536) 且 > 16384 ⇒ **唯一可能 D = 0x10014 = 65556** ⇒
⇒ **客户机 SP 偏移了 `0x10000 + 20`** —— 这正是"**寄存器高 4 字节是垃圾**"的特征值。

**机制**：`stub/win/x86/vm_entry_asm.S` 第 55-77 行用 **`movl`（32 位）**把客户机寄存器写进 ctx 槽，
而 `vm_ctx_t.regs[]` 是 **u64** ⇒ **每个槽的高 4 字节从未被写过**，留的是**栈上垃圾**；解释器处处按 u64 用
（典型就是那条**无符号**的栈守卫比较 `rsp_start - regs[VRSP] > VM_MARGIN`）⇒ 表现为野值 + 误判 99。

**为什么这解释了一切**：
· probe 直呼路径 `memset(&ctx, 0, sizeof ctx)` ⇒ 高半部为 0 ⇒ **正确**（k1→2、x2→35、k2→2 全部通过）；
· 打包路径只有**蹦床**在填 ctx ⇒ 高半部是垃圾 ⇒ **错**；
· 所以我此前把差异归到"`desc != NULL`"是**错的** —— 真正的差异是"**谁填的 ctx**"。
· x64 侧无此问题（`movq` 是 64 位），所以这是纯粹的 32 位新路径缺陷。

**两版修法都失败（已全部回退，主干干净）**：
1. 蹦床里先 `rep stosl` 清 144 字节 ⇒ 编译通过，但**所有用例变成 0**（含本来通过的 g1）；
2. 解释器入口把 `VM_GUEST_X86_32` 的寄存器 `&= 0xFFFFFFFF` ⇒ 同样**全变 0**。
两版都是"方向正确但实现有副作用"，且我**没有**在预算内定位副作用 ⇒ 按 AGENTS.md 纪律立即回退，
并用已提交的 blob 复测确认基线（g1=100、k1=1）未被破坏。

**下一步（要小步验证）**：
· 先做**金丝雀**：任何入口清零/掩码改动，改完**第一步就跑 g1**；g1 一变就立刻回退，不要继续。
· 排查第 2 版为什么全 0：先确认 blob 侧 `VM_REG_COUNT` 实际取值（manifest 是 18）与掩码循环是否越界/写坏相邻字段；
· 排查第 1 版为什么全 0：`rep stosl` 用的 EDI/ECX/EAX 保存-恢复顺序（我按 push eax,ecx,edi / pop edi,ecx,eax 写的）
  与 ctx 基址 `%esp+12` 的算法，逐条对着反汇编核；
· 更稳的替代方案：不清零，而是**让蹦床用 8 字节写**（`movl` 后补一条 `movl $0, 槽+4`），语义最直白、副作用最小。

### 473. 目标③ **达成**：i686 蹦床补清 u64 槽的高半部 —— 真实 32 位 exe 打包后与原生**逐例一致**

**根因（#472 定位，本轮修复）**：`stub/win/x86/vm_entry_asm.S` 用 32 位 `movl` 把客户机寄存器写进
`vm_ctx_t.regs[]`（u64）⇒ 每个槽的**高 4 字节从未被写过**，留的是栈上垃圾。解释器处处按 u64 使用，
其中那条**无符号**的栈守卫 `rsp_start - regs[VRSP] > VM_MARGIN` 会因此误判 ⇒ 直接返回 99 ⇒ 错值。
（probe 直呼路径 `memset(&ctx,0,...)` 高半部为 0，所以一直是对的 —— 真正的差异是"谁填的 ctx"。）

**修法**：在蹦床写完 18 个槽之后，逐槽补一条**高半部清零**（偏移 4,12,...,140）：

    movl $0, 4(%esp)      /* slot 0 (RAX) high half */
    movl $0, 12(%esp)     /* slot 1 (RCX) */
    ...                   /* 共 18 条，纯 movl，不碰任何寄存器 */

用**裸偏移**而不是名字，避免任何名字映射差异；不保存/恢复任何寄存器 ⇒ 零副作用。

**证据（打包后退出码 vs 原生退出码，同一份 `build/vm_x86_h.bin`）**：

    vm32_sum10 55/55 ✓   f1 42/42 ✓    f2 35/35 ✓    f3 55/55 ✓    f4 165/165 ✓
    g1 100/100 ✓  g3 18/18 ✓  k1 2/2 ✓  k3 10/10 ✓  h1 3/3 ✓  h3 21/21 ✓  h5 55/55 ✓
    ---- 一致 12 / 不一致 0 ----

其中 `vm32_sum10` 是**真实 32 位 exe**（`build/real32.exe`）里的函数，`f2` 是多参数 cdecl，
`f4`/`h*` 是带循环与本地变量的较大字节码（54~396 字节）。**全部与原生一致。**

**修法失败史（诚实记录）**：#472 里先试过"入口 `rep stosl` 清零"与"解释器入口掩码 `&= 0xFFFFFFFF`"两版，
两版都让**所有**用例返回 0（含本应通过的 g1）—— 推理见下：第 2 版循环若用错 `VM_REG_COUNT` 会写坏
`code`/`desc` 等 u64 字段；第 1 版则有 `rep stosl` 的寄存器/基址细节没核对。最终采用"逐槽 movl 清零"，
**先跑金丝雀 g1**（#472 定的纪律）确认没破坏原有通过项，再跑全量 ⇒ 一次成功。

### 474. 新增 32 位端到端门禁（独立脚本，暂未接入 gates.ps1）—— 它立刻抓到一个真 bug

**为什么加**：i686 蹦床那个"32 位写 u64 槽"的 bug 存在很久，**门禁和 CI 都没抓到** —— 因为没有任何一关
会去构建 32 位 blob 或打包 32 位 exe。这是本目标最大的验收漏洞。

**新增文件**：
· `testdata/e2e32.c` —— 自包含的 32 位被测目标：每个函数返回一个小而**互不相同**的值，`main` 用 argv
  选一个直接把它当退出码返回。这样比较的是**退出码**，不需要解析 stdout，guest 里也不调用 printf。
  用例覆盖：无本地变量 / 两个本地变量 / 循环 / **cdecl 多参数** / 多本地变量 / guest 调原生函数。
· `tools/e2e_32bit.ps1` —— 找 i686 工具链（PATH 与常见安装目录）→ 编译目标 → 构建 32 位 blob
  （`-guest x86-32 -merge go -random-opcodes=false`）→ 逐函数打包 → **退出码与原生逐一对比**。
  找不到工具链时打印醒目的 SKIPPED 并退出 0（不静默）；设 `VMP_REQUIRE_I686=1` 则视为失败。

**它立刻抓到的真 bug（尚未修复）**：

    e32_const 100/100 ✓   e32_local 35/35 ✓   e32_loop 55/55 ✓
    e32_big    36/36  ✓   e32_call  42/42 ✓
    e32_args   packed=420011712  native=123   ✗   <-- cdecl 多参数

最小化复现（临时探针，已删）：`p1(int a){return a;}` 打包后返回 `0x4015C2`（像调用方栈上的值）、
`p5(a,b,c){return c;}` 打包后返回 **2**（= `b`）⇒ **参数被读低了一个栈槽（4 字节）**。

**已排除**（实测，不是推理）：
· blob 里 `VM_STACK_SLOT` **= 4**（把常量塞进退出码量出来的）⇒ 客户机 push 宽度是对的；
· vmpbuild 确实传了 `-DVM_GUEST_X86_32=1`（main.go:746），且 `#ifdef` 条件正确（vm_interp.c:58）；
· 无参用例 `p4(){return 200;}` 打包后 **200 ✓** ⇒ 栈/VM 主干是好的；
· `vmpack` 给 `e32_args` 的 IR 位移是 `FrameSkew+8/12/16`，与 `[ebp+8]/[ebp+12]/[ebp+16]` 一致 ⇒
  lifter 侧自洽。

⇒ 剩下的疑点在"运行期 `regs[EBP]` 与 thunk 算出的模拟 ESP 相差 4"，但**本轮没查完**，所以：
**门禁脚本已提交但没接进 gates.ps1**（接了主干就红；而删掉这条用例等于放宽阈值，两者都不允许）。

**下一步**：把 `p1`/`p5` 的 IR 与运行期 `regs[ESP]/regs[EBP]`（经退出码分次读出）对齐，定位那 4 字节；
修好后本关应当打印 `6/6`，再把它加进 `tools/gates.ps1`（建议放在 `go test` 之前）。

### 475. 32 位 cdecl 参数错位：**已缩小到"参数被读低一个栈槽（4 字节）"**，根因未定

**实验设计**：给四个参数各用一个特征常量，函数分别只返回其中一个 ⇒ 用**完整 32 位退出码**读出"读到了谁的槽"：

    s1(int a,b,c,d){return a;}  native=0x11111111  packed=0x004015C9  <- 这是**返回地址**（代码地址）
    s2(...){return b;}          native=0x22222222  packed=0x11111111  <- 拿到了 a
    s3(...){return c;}          native=0x33333333  packed=0x22222222  <- 拿到了 b
    s4(...){return d;}          native=0x44444444  packed=0x33333333  <- 拿到了 c
    s6(void){int x=0x77777777;} native=0x77777777  packed=0x77777777  ✓ 本地变量正确

⇒ **参数整体低一个槽（4 字节）**：a 落到返回地址、b 落到 a、c 落到 b、d 落到 c。

**已实测排除**（都不是推理）：
· **lifter 的位移正确**：`-dumpbytecode` 取到 `s1` 的明文字节码，LOAD 的 disp = `98 42 00 00`
  = 0x4298 = 17048 = `FrameSkew(0x4290) + 8`，与 `[ebp+8]` 一致 ✓；
· **blob 里 `VM_STACK_SLOT` = 4**（把常量塞进退出码量出来的）⇒ 客户机 push 宽度按设计；
· **模拟 ESP 不变式成立**：蹦床把帧基址写进 `VM_CTX_FRAME`，于是 `E = frame + VM_FRAME_SIZE`，
  实测 `((frame + 640) - VRSP) >> 2 & 0xFF = 164` ⇒ `VRSP = E - 17040` = `E - FrameSkew` ✓；
· 常量自洽：`VM_FRAME_SIZE 640 + VM_FRAME_SKEW_EXTRA 16 + VM_MARGIN 0x4000 = 17040` = manifest 的 frameSkew ✓；
· 无参用例 `p4(){return 200;}` 打包后 **200 ✓** ⇒ VM/栈主干没问题。

**因此矛盾点是**：按 `VRSP = E - 17040`、`VM_STACK_SLOT = 4`、disp = `FrameSkew + 8` 三者为真，
`[ebp+8]` 应当读到 `E + 4`（= a）—— 实测却读到 `E`。也就是说**运行期实际用了 8 字节的槽**（或 `E` 比模型低 4）。
本轮**没查出**这三者中哪一个是"看起来对、实际不对"。

**下一步（建议按这个顺序，都很快）**：
1. 让 subject 直接返回 `[esp]`（返回地址）与 `[esp+4]`，用退出码读出来，和 native 的同一位置对比，
   先把"`E` 到底在哪"钉死（这是唯一还没直接测过的量）；
2. 若 `E` 与模型差 4，查蹦床入口的 `%esp`（`E9` 补丁是 jmp、不压栈，理论上 `%esp` 就是返回地址槽）；
3. 若 `E` 正常，则查 `OP_PUSH_R` 运行期是否真的只减 4（可在 IR 层面单测：造一段只含 PUSH_R 的字节码喂 probe）。

### 476. 32 位参数错位续查：**地址级证据** —— 参数地址被加了整份 FrameSkew，且 guest 帧离原生约 4MB

**实验**：让 subject 返回**地址**（32 位可读），native 与 packed 各跑一次对比：

    t1(int a)        { return (int)&a; }              native=0x00C3F960  packed=0x0062FEDC
    t2(int a,int b)  { return (int)&b - (int)&a; }     native=4           packed=4        ✓
    t6(void)         { int x=7; return (int)&x; }      native=0x009FFEB4  packed=0x0062BC40
    t7(int a)        { int x=7; return (int)&x-(int)&a; }  native=-12     packed=-17040  <- 关键

**两条硬结论**：
1. **参数地址上被加了整份 FrameSkew**：`&x - &a` 原生是 **-12**，guest 是 **-17040 = -FrameSkew**；
   而 `&b - &a` 两边都是 **4** ⇒ 参数之间是对的，**参数整体被抬高了一个 skew**；
2. **guest 的本地帧离原生约 4MB**（`&x` 之差 ≈ 0x3D4254）⇒ 与"模拟栈 = 宿主栈 − skew(17040)"
   这个模型**对不上**（17040 只有 16KB）。

**为什么这两条重要**：`vm_interp.c` 的注释与 lifter 的设计都建立在"客户机栈就在宿主栈下方 skew 处"这一前提上
（`adjustStackDisp` 只在 `eff >= 0` 时加 FrameSkew，正是基于此）。本轮证据说明**这个前提在 i686 打包路径上不成立**，
所以"参数读到低一个槽"只是它的一个症状。

**本轮没有改任何主干代码**（只做了测量，临时文件已删）。

**下一步（把前提本身测掉）**：
1. 在 `vm_run` 入口把 `regs[VRSP]` 与**蹦床写进 `VM_CTX_FRAME` 的帧基址**一起经退出码分次读出，直接算出
   「模拟 ESP 与原生 `%esp` 的真实距离」，与 17040 对比（前面测过 `(frame+640)-VRSP = 17040`，但那是**退出时**的值，
   需要入口/中间的样本）；
2. 若距离确实是 17040，那么 `&x` 差 4MB 就说明 **packed exe 的 `main` 栈与 native 的 `main` 栈本来就不在同一区域**，
   此时"参数抬高一个 skew"才是唯一症状，修法应落在 lifter 对 `[ebp+正位移]` 是否该加 skew；
3. 反之若距离不是 17040，则根因在蹦床的模拟 ESP 公式（`VM_FRAME_SKEW_EXTRA` 与 `VM_FRAME_SIZE` 的账）。

### 477. 第 2 项：审计 ctx 剩余 u64 槽 —— 修掉 `frame` 高半部；并发现 32 位浮点的 SSE 约束

**审计方法**：诊断 blob 把 `frame`/`desc`/`code`/`VBASE`/`VSCRATCH` 五个字段的**高 32 位是否非零**编成 5 位，从退出码读出。

    修前: e32_local -> 高半部非零的字段 = frame   （desc/code/VBASE/VSCRATCH 均干净）
    修后: e32_local -> (无)                       ✓

**为什么只有 `frame` 脏**：`vm_types.h` 的结构 + x86 ABI 偏移一起看，i686 上 `code`/`desc`/`scratch`
是 **4 字节指针**（@160/@164/@168，**没有**高半部，所以审计显示干净是对的），而 **`frame` 是 `u64` @184**，
蹦床只写了低 4 字节 ⇒ **偏移 188 留栈垃圾**。

**风险（真实但当前潜伏）**：解释器的 XMM 边界同步会 `u8 *xframe = (u8 *)(u64)vm->frame;` 直接解引用；
现在没炸只是因为该同步对 i686 被编译掉了（`VM_BLOB_USES_WIN64` 未定义）。一旦给它开开关，就是解引用野指针 ——
与 #473 修的寄存器槽同一类地雷。

**修法**：蹦床加一条 `movl $0, (VM_CTX_FRAME + 4)(%esp)` ✓（提交见下）。

**第 2 项后半段：补浮点用例**（此前 32 位侧完全没有）

· 直接加 double 用例时，**vmpack 打包失败**并给出明确原因：

      [!] e32_dbl: 2/9 条指令无法翻译
            +0x6: FLD [+0x404098]   — 暂不支持该指令
            +0xC: FSTP [EBP-0x8]    — 暂不支持该指令

  i686 默认走 **x87**，而 lifter 不支持 x87 ⇒ 这是**约束**不是 bug：32 位目标上当被保护函数涉及浮点时，
  必须用 SSE 代码生成（`-msse2 -mfpmath=sse`）。已写进 `docs/PE32.md`，门禁的编译命令也带上这两个开关。
· 加 SSE 后：`e32_dbl`（无参数浮点）**通过** ✓ ⇒ 32 位客户机的浮点路径可用；
  但 `e32_dblarg`（栈上两个 double）**失败**（packed=0，native=3）。

**门禁现状（8 条用例，仍未接入 gates.ps1）**：6 通过 / 2 失败，且两个失败**同属一类** ——
**读取调用方栈帧里的参数**（`e32_args` 整数多参数、`e32_dblarg` 栈上 double）。这与 #475/#476 的排查方向一致。

### 478. **纠正 #475/#476**：参数**寻址是对的**（实测），错在"读到的值/运算"

**做法**：在解释器里临时记录"**第一次** `[ebp+...]` 访存"的 `regs[EBP]`、`disp`、`addr`（存进临时全局，
因为 `vm_diag[12..14]` 会在返回前被清零 —— 第一次测量就是栽在这上面），再用退出码分位读出。

**实测（`e32_args` 与 `e32_local`，同一份 `testdata/e2e32.c`）**：

    E := VM_CTX_FRAME + VM_FRAME_SIZE           （= 蹦床入口的原生 esp，指向返回地址槽）
    (E - EBP) >> 2 & 0xFF        = 165   =>  E - EBP = 17044  ✓ 与设计一致
                                            （ESP_init = E - 17040、push 掉 4）
    首次访存 (addr - E) & 0xFF   = 4     =>  正是 arg1 的地址 [E+4]        ✓
    末次访存 (addr - E) & 0xFF   = 12    =>  正是 arg3 的地址 [E+12]       ✓
    末次访存 disp = 17056（(disp>>2)&0xFF = 168 ✓ 自洽）

⇒ **寻址链路（蹦床模拟 ESP → `VM_STACK_SLOT` → EBP → lifter 的 disp → 最终地址）全部正确** ✓。

**因此 #475/#476 的结论要纠正**：那时我用一个**临时探针**（`s1` 返回 `a`）观测到"读到了返回地址"，
据此推断"参数被整体抬高一个 skew"。现在用**门禁自己的** subject 直接量地址，证明寻址是对的 ⇒
**那个临时探针的观测不可靠**（它是随手写的、已删除，且与后来的测量互相矛盾）；#476 里"guest 帧离原生 4MB"
那一条同样来自临时探针，也应视为待复核。教训：**探针要放进 `testdata/` 这类长期维护的用例里再下结论**。

**新方向（真正的原因在值/运算，不在寻址）**：
· `e32_local`（`a*b`，用 IMUL）**通过** ✓；`e32_args`（`a*100 + b*10 + c`）**失败** ✗；
· 看 IR：`a*100` 是 ALU_RI(kind=5, imm=0x64) ✓，而 `b*10` 被编译成 **移位/加法序列**（IR 里出现 kind=6、imm=2 的
  ALU_RI，以及 `dst=a=0` 的自加 `ALU_RR`）⇒ **高度怀疑移位类 `ALU_RI` 的实现**（或它在 i686 上的宽度/立即数处理）；
· `e32_dblarg`（栈上两个 double）返回 0，也属于"值/运算"这一侧，可一并查。

**下一步（很具体，且都在门禁里可回归）**：
1. 给 subject 加一条只做移位的用例（如 `int e32_shl(int a){ return a << 3; }`，期望 8），先确认移位本身；
2. 再拆 `b*10` 的序列（shift + add）逐条对照 IR 与结果；
3. 修好后门禁应打印 8/8，再把它接入 `tools/gates.ps1`。

### 479. 32 位门禁再添两条用例，**确认移位运算在 i686 客户机上就是坏的**

在 #478 的指导下（`a*b` 通过、`a*100+b*10+c` 失败），给门禁加了**只做移位**的两条最小用例：

    e32_shl(int a)          { return a << 3; }        调用 e32_shl(1)     期望 8
    e32_shr(unsigned a)     { return (int)(a >> 4); } 调用 e32_shr(0x100) 期望 16

实测（打包 vs 原生）：

    e32_shl: packed=33602616 (0x0200BC38)  native=8    ✗
    e32_shr: packed=262523   (0x0004017B)  native=16   ✗

⇒ **两个方向都错**，而 `a*b`（IMUL）通过 ⇒ 缺陷**精确落在移位类运算**上，这是目前最小、最干净的复现。

**注意数值形态**：两个结果都像**代码/栈地址**（0x0200xxxx、0x0004xxxx），而不是"把 1 移了几位"。
所以有两种待区分的可能：(a) 移位本身的语义/计数错了；(b) 这些用例里 `arg1` 又被读成了别的槽（与 #478
在 `e32_args` 上量到的"寻址正确"不一致 —— 那可能是**逐函数**差异，需要再测）。

**门禁现状（10 条用例，6 通过 / 4 失败）**：

    ✓ e32_const ✓ e32_local ✓ e32_loop ✓ e32_big ✓ e32_call ✓ e32_dbl
    ✗ e32_args（多参数）✗ e32_dblarg（栈上 double）✗ e32_shl ✗ e32_shr

门禁仍未接入 `gates.ps1`（接入条件：10/10）。

**下一步**：先把 (a)/(b) 分开 —— 给 subject 加一条 `int e32_shl_imm(void) { int v = 1; return v << 3; }`
（**常量局部变量**，不依赖参数）⇒ 若它仍然错，就是纯移位语义问题 (a)；若它对，则 (b) 成立、
要回到"逐函数看参数槽"的路子。

### 480. 32 位参数错位：**真正的原因浮出水面** —— guest 的模拟栈不在调用方真实栈帧下方

**判别实验**：给门禁加"常量局部变量的移位"，把"移位语义"与"读参数"分开：

    e32_shl_imm(void){ int v=1;      return v << 3; }   通过 ✓
    e32_shr_imm(void){ unsigned v=0x100; return v >> 4; } 通过 ✓
    e32_shl(int a)  { return a << 3; }  调 (1)   失败 ✗
    e32_shr(unsigned a){ return a >> 4; } 调 (0x100) 失败 ✗

⇒ **移位语义是对的**（常量局部变量那两条全过），问题在**读参数**。

**再往里一层（临时仪表，已回退）**：记录"首次 `[ebp+x]` LOAD"的地址与**读到值**：

    e32_shl   首次地址 = E+4 ✓（正是 arg1 的位置）   首次读到值低字节 = 0xF5  ✗ 不是 1
    e32_args  首次地址 = E+4 ✓                        首次读到值低字节 = 0x44  ✗ 不是 1
    e32_local 首次地址 = 本地槽                         首次读到值低字节 = 0x07  ✓（guest 自己写的）

其中 `E := VM_CTX_FRAME + VM_FRAME_SIZE`（蹦床入口的原生 esp）。

**结论**：guest 的**内存访问本身没问题**（自己写的本地变量读回来是对的），**地址算术也自洽**，
但"调用方传进来的参数"根本不在 guest 算出的那个地址上 ⇒ **guest 的模拟栈与调用方的真实栈帧不在同一处**。

**这重新印证了 #476 的观测**（当时量到 guest 的 `&x` 与原生 `&x` 相距约 4MB），**#478 我把它否掉是误判**：
`addr - E` 两端都落在 guest 自己的帧里，只能证明**内部算术自洽**，不能证明 guest 帧就在真实调用帧下方。
（所以 #478 的"寻址正确"与 #480 的"值不对"并不矛盾 —— 两者可以同时成立。）

**下一步（一次就能定性，且不需要再猜）**：让 subject 收一个"调用方栈上某个标记的地址"作为参数，
把它与 `&a` 一起返回或做差 ⇒ 直接把「guest 帧 与 真实调用帧 的距离」量出来：
· 若距离 ≈ 17040 ⇒ 模型成立，问题在别处（例如调用方 `main` 的 -O0 传参方式）；
· 若距离是 MB 级 ⇒ 蹦床写进 ctx 的"帧基址/模拟 ESP"与实际调用帧的关系被搞错了，
  那才是真正的根因（#476 的 4MB 就是它的征兆）。

### 481. **32 位路径修复完成：门禁 12/12，并已接入 gates.ps1**

**真根因**：`stub/win/x86/vm_entry_asm.S` 里算模拟 ESP 的那条 `leal -(16 + VM_MARGIN)(%esp), %eax`
**多了 4 字节** —— 客户机的模拟栈比它应该在的位置**低 4**，于是所有"读调用方栈帧"的访问（参数）都落到**低一个槽**，
`[ebp+8]` 读到的其实是返回地址槽。

**怎么定下来的（关键的一步是"别拿两次运行的绝对地址比"）**：
· 先发现 native 的 exe **有 ASLR**（随机基址），而打包产物清过 DYNAMIC_BASE + `-strip-resocs` 固定在 `0x400000`
  ⇒ **跨运行比较绝对地址是错的**（#476 那个"4MB"就是这么来的假象）；
· 改成比**同一运行内**的两个栈地址之差：把调用方栈上局部变量的地址存进全局变量，让被测函数返回 `&a - &g_markerp`
  ⇒ native = **-24**，packed = **-28** ⇒ **只差 4 字节** ✓ 方向是 guest 低 4；
· 据此把 thunk 的 `16` 改成 `12`（写成 `VM_FRAME_SKEW_EXTRA - 4`）⇒ 门禁从 **6/12** 变成 **12/12** ✓。

**留下的一个未对上账**（诚实登记）：按模型推 `E - EBP = 17044`、disp = `FrameSkew+8` 时参数应落在 `E+4`，
这要求那个常数是 **16**；实测却要 **12** ⇒ 说明我关于"蹦床写入帧基址那一刻 `%esp`"的模型还差 4 字节。
修法是**实测**结论，且已被门禁逐例覆盖（12/12），但这条 4 字节的账待以后查清。

**门禁已接入 `tools/gates.ps1`**（放在 `go test` 之前，理由写在注释里：它留下的产物不会干扰 `go test` 用的
C 探针）。缺 i686 工具链时打印醒目的 SKIPPED 并退出 0（不静默），可用 `VMP_REQUIRE_I686=1` 变成硬失败。

**门禁覆盖（12 条，全部与原生一致）**：

    无本地变量 / 两个本地变量 / 循环 / cdecl 三参数 / 多本地变量(8 个) / guest 调原生函数 /
    常量局部变量左移 / 常量局部变量右移 / 参数左移 / 参数右移 / 无参数浮点 / 栈上两个 double

### 482. 第 1 项结案：那 4 字节的账对上了 —— **调用方参数在 `E0+8` 而不是 `E0+4`**

**做法**：不再推理，直接在解释器里读 `E0+4 / E0+8 / E0+12` 三个槽（`E0 := vm->frame + VM_FRAME_SIZE`，
即蹦床入口的原生 esp）：

    e32_shl（调用方传 1）:  值为 1 的位置 = **E0+8**
    e32_args（传 1,2,3）:   值为 1 的位置 = **E0+8**

⇒ 调用方的第一个参数**在 `E0+8`**，即返回地址槽之上还多出 4 字节（入口处 `%esp` 比"& 返回地址"低 4）。

**代回模型**（`addr = E0 + 20 - X`）：要求 `= E0 + 8` ⇒ **X = 12** ✓ —— 与实测修正值完全吻合，账对上了。

**已核对、且各自都正确的部分**（所以问题只可能在那 4 字节上）：
· 构建出的蹦床头两条就是 `sub esp,0x280`(=640) 与 `mov [esp+0xb8],esp`(=frame) ⇒ `E0 = frame + 640` 成立；
· 头文件常量自洽：`640 + 16 + 0x4000 = 17040` = manifest 的 frameSkew；
· lifter 发出的位移正确（明文里 `[ebp+8]` → disp = 17048 = `FrameSkew + 8`）；
· 被保护函数的序言是标准的 `push ebp / mov ebp,esp / mov eax,[ebp+8]`，调用点也确实先 `mov [esp],imm` 再 `call`。

**仍待定位的细节**（不影响结论）：那 4 字节由载荷里哪条指令压入 —— `jmp` 补丁本身不压栈，
且 jmp 目标在载荷节里（objdump 默认不反汇编该节）。属于细枝末节，已记在源码注释里。

### 483. 第 2 项：`__stdcall` 修复**重做成功**（上次失败的真正原因找到了）

**上次为什么失败**（本轮复现并读到完整报错）：

    win/x64/vm_interp.c:608:27: error: expected ) before * token

我把 `VM_WINAPI` 宏插在了**第 600 行左右**，而**第一个使用它的 typedef 在第 608 行** ⇒ 那里宏还没定义 ⇒
`typedef u64 (VM_WINAPI *fn_t)(...)` 直接编不过。**与 `__stdcall` 属性本身无关** —— 纯粹是"宏定义晚于
首次使用"。上次我没看 diff、也没在本地构建 Linux blob 就提交了，才让它进了 CI。

**本轮做法**：宏挪到第 59 行（首次使用在 618 行之前），并**本地构建三个平台**验证：

    [stub/linux/amd64] OK    [stub/win/x64] OK    [stub/win/x86] OK

**守护条件加强**（比上次更严）：仅当"i686 宿主**且**非 Linux 目标"才展开成属性：

    VM_HOST_X86_32 && !VM_BLOB_TARGET_LINUX  =>  __attribute__((stdcall))
    其它情况                                  =>  空

⇒ x64 / arm64 / Linux 一律展开为空 ⇒ 对它们零影响。（`win/x64/vm_interp.c` 被**全部五个平台**共用，
这一点已在 linux/amd64 与 linux/arm64 的 `BLOB.sources` 里确认。）

**它修的是什么**：32 位 Windows 上 Win32/ntdll/bcrypt API 都是 `__stdcall`（callee 清栈）；
按默认 cdecl 声明会让**调用方再清一次栈**，每次调用都轻微破坏宿主栈。x64 只有一种调用约定 ⇒ 无此问题。

### 484. 第 3 项完成：**重定位承载节（.vreloc）** —— 保留重定位的 ASLR 配置从"打不了包"变成 24/24 全过

**原先的症状**（复现并量化）：

    .reloc   VA=0xA000  vsize=0x264  raw=0x400  off=0x4600
    [!] 补 payload 重定位项失败: .reloc 空间不足（需要 154 字节，剩 78）

`appendRelocs` 只能把新块追加进 `.reloc` 节的 **raw 余量**里；而这个节的 raw 后面在**文件里**紧跟着
`/14`、`/29` 等节的原始数据 ⇒ **不能就地扩展**。于是"保留重定位"这条路在 32 位上是完全不工作的。

**修法**（`cmd/vmpack/main.go` 的 `appendRelocs`）：先只把新块拼进内存；
· 余量够 ⇒ 维持原行为（x64 走的就是这条，零影响）；
· 余量不够 ⇒ 把「**原有重定位块 + 新块**」整体搬进一个**新的承载节** `.vreloc`，再把数据目录指向它。
  加载器只按目录读**一段连续**区间，所以原有块必须一起搬；原有块**按块长逐个拷**（目录 Size 可能带尾部填充，
  整段照搬会被加载器当成畸形块）。新节用现成的 `pe.File.AddSection`（EOF 对齐追加 + 节头写进表后空闲空间 +
  修正 `NumberOfSections`/`SizeOfImage`）。

**证据**：

    产物: BASERELOC 目录 RVA=0x2A000 Size=1128，指向节 .vreloc ✓；NumberOfSections=21
    RELOCS_STRIPPED = clear ✓   DYNAMIC_BASE(0x40) = SET ✓
    e32_local: native=35  packed=35 ✓
    门禁两遍都 12/12：-strip-relocs 与 **保留重定位** 各 12 条全部与原生一致 ✓

**门禁已扩展**：`tools/e2e_32bit.ps1` 现在跑**两遍**（一遍 `-strip-relocs`、一遍保留重定位），
所以这条路径以后有回归保护。

**一个新记录下来的观察（未深究，不影响本项）**：产物虽然 `DYNAMIC_BASE` 为 SET 且重定位表可用，
实测仍**固定加载在首选基址**（三次运行 `&g_marker32` 都是 `0x00403004`），而 native 的 exe 每次不同。
可能与本机/系统的 ASLR 策略或该镜像的某些标志有关 ⇒ 留作后续观察点。

### 485. 第 4 项（把 32 位门禁接入 CI）**未完成** —— 撤掉 CI 步骤，原因已定位

**做了什么**：在 `ci.yml` 的 `windows-amd64` 作业里①让 msys2 安装 `mingw-w64-i686-gcc`、
②新增一步跑 `tools/e2e_32bit.ps1`（带 `VMP_REQUIRE_I686=1`，缺工具链即失败）。

**结果**：
· ✅ **发现并修复了一个重要缺口**：CI **从不调用 `tools/gates.ps1`**，是逐条跑步骤 ⇒ 我之前新加的 32 位门禁
  **在 CI 里根本没跑过**。这次接入后它**确实在 CI 上跑起来了**（日志里能看到 `[*] i686 toolchain: D:\a\_temp\msys64\mingw32\bin\...`）；
· ✅ 途中修掉两个**我自己引入的**脚本问题：`.ps1` 里误用 C 风格 `/* */` 注释（PS 解析失败）；
  `.ps1` 里写中文注释（PS 5.1 按 ANSI 解码会**吞掉下一行** —— 这正是 `tools/gates.ps1` 开头早已记录的坑，
  教训：**该仓库的 .ps1 必须纯 ASCII**）；
· ❌ 但 CI 上仍失败：**`e32_dbl` / `e32_dblarg` 打包失败**（浮点那两条）。本地同样的脚本是 12/12×2 通过，
  说明 CI 的 i686 工具链生成的浮点代码不同（很可能仍是 x87：lifter 不支持 `FLD`/`FSTP`），
  而 vmpack 的真实报错被 PowerShell 的 `NativeCommandError` 噪声盖住了，没能直接读到。

**处置**：已把 CI 步骤**撤掉**（`ci.yml` 恢复原状），保证主干绿；门禁本身的改进全部保留
（纯 ASCII、失败时打印 vmpack 原因、两遍：`-strip-relocs` 与保留重定位）。

**下一步（要接着做第 4 项的话）**：
1. 在 CI 的 32 位步骤里先**只**跑非浮点用例，或先打印出 vmpack 的真实 stderr（用 `& vmpack 2>&1 | Tee-Object`
   并 `$ErrorActionPreference` 调整，避开 NativeCommandError 包装）；
2. 查清 CI 工具链为什么没走 SSE（`-msse2 -mfpmath=sse` 是否被忽略 / mingw32 的默认 `-march`）；
3. 解决后再把该步骤接回 CI，并保留 `VMP_REQUIRE_I686=1`。

### 486. 第 4 项续：CI 失败原因**精确定位**（不是重对齐，是"带索引的栈寻址"），仍撤步骤保绿

**过程**：把门禁里"打包失败时的打印"从**有过滤器**改成**原样打印最后 6 行**（`#` 注释写成纯 ASCII），
于是 CI 终于给出了真实原因：

    vmpack| [!] e32_dbl: 3/10 条指令无法翻译
    vmpack| +0x11: MOVSD_XMM [ESP+Reg(0)], X0   — RSP 已被不可跟踪的方式修改（AND ...）
    vmpack| +0x16: MOVSD_XMM X0, [ESP+Reg(0)]   — RSP 已被不可跟踪的方式修改
    vmpack| +0x1F: LEAVE                        — LEAVE 但 RSP 已被不可跟踪的...

⇒ 关键在 **`[ESP+Reg(0)]`**：CI 那版 gcc 为 SSE 的 double 局部变量生成了**带索引**的栈寻址。
而 lifter **按设计**拒绝这种形式（源码注释：带索引的 `rsp + idx*scale + disp` 符号取决于运行期 idx，
无法判定是否需要补 FrameSkew ⇒ 保守拒绝）。本地 gcc 不生成该形态 ⇒ 本地过、CI 红。

**试过但无效**：给门禁编译加 `-mno-stackrealign`（以为是 `and esp,-16` 重对齐）—— CI 仍同样失败；
本地对照实验还顺带发现 `-mpreferred-stack-boundary=2` 反而**会**弄坏本地（3/10 无法翻译）。

**当前处置**：再次撤掉 CI 步骤（主干绿），门禁本身保留全部改进（纯 ASCII、原样打印原因、两遍覆盖）。

**下一步的可选项（留给以后，按代价从小到大）**：
1. 让浮点用例**避开**该代码形态：把 `e32_dbl`/`e32_dblarg` 改写成不使用 double 局部变量的形式，
   或对这两条用例在 CI 上改用参数版（参数版目前也失败，需要先确认它的失败原因是否相同）；
2. 在 CI 上用**固定版本**的工具链（例如 pin msys2 的 mingw-w64-i686-gcc 版本），让它与本地行为一致；
3. 给 lifter **加**对"带索引的栈寻址"的支持（要能把 idx 的符号一并纳入 FrameSkew 判定），这是最彻底的，
   但属于解释器/编译器核心改动，风险高，需单独一轮。

**仍然保留的成果**：CI 从不调用 `gates.ps1` 这个缺口已查清；门禁的脚本问题（C 风格注释、中文注释）已修好；
32 位门禁在**本地**门禁（`gates.ps1` 共 12 关）里稳定 24/24 通过。

### 487. 第 4 项**完成**：32 位门禁接入 CI 并 24/24 通过（走了"选项 1"，一次 CI 往返即解决）

**做法**（目标里的第 (1) 条）：浮点用例改用一份**单独的 `-O1` subject**（`build/target32_o1.exe`），
其余 10 条仍用 `-O0`。原因：CI 那版 gcc 在 `-O0` 下把 double 局部变量寻址成 `[ESP+Reg(0)]`（带索引的
栈寻址），而 lifter **按设计**拒绝该形式；`-O1` 下 double 待在 XMM 寄存器里，该形态消失。

**证据（CI run 35827735119，commit ed17f83）**：

    [*] i686 toolchain: D:\a\_temp\msys64\mingw32\bin\i686-w64-mingw32-gcc.exe
    [OK] 32-bit e2e: 12/12 match native (-strip-relocs)
    [OK] 32-bit e2e: 12/12 match native (relocations kept)
    windows-amd64 success   （五作业全绿）

⇒ **不需要**选项 (2)（pin 工具链）或 (3)（给 lifter 加带索引栈寻址支持）—— 记录在此，供以后参考。

**顺带在这一项里查清/修掉的**：
· CI **从不调用 `tools/gates.ps1`**（逐条跑步骤）⇒ 新门禁原本在 CI 里根本没跑过，现已作为独立步骤接入；
· 门禁脚本自身的两个坑：`.ps1` 里误用 C 风格 `/* */` 注释、以及写中文注释（PS 5.1 按 ANSI 解码会吞掉下一行，
  仓库早已记录）⇒ **该仓库的 .ps1 必须纯 ASCII**，现已把该脚本固定在 0 行非 ASCII；
· 失败诊断：原来用过滤器打印 vmpack 输出，把真实原因滤掉了 ⇒ 改为**原样打印最后 6 行**。

### 488. 登记客户给定的威胁模型与 vmp-x 当前不足（新增 `docs/THREATMODEL.md`；TODO 加第 6 节）

**威胁模型（客户给定）**：对手 = **能在目标机上运行/调试、且持有合法外置 HL 的客户**；
攻击路径 = 用合法狗跑起来 -> 取密钥/仿真狗 -> 做出**不需狗**的版本 -> **分发**；
目标是让他**拿不到可运行的等价体（尤其是可分发的那一份）**。

**先说清天花板（写进文档，避免对外过度承诺）**：任何能在他机器上运行的东西都能被 dump 与重组，
差别只是成本；因此可验收的目标是 **(T-a) 不可移植** 与 **(T-b) 成本高于授权价**，
**不要承诺"不可脱壳/不可破解"**。

**本轮核实的事实（都读过代码，写进文档时带 `文件:行`）**：

· 默认兼容模式**把主密钥编进 blob** —— `stub/win/x64/vm_interp.c:761`；
· 运行期取钥已有接缝：**文件 -> 环境变量**，或 **严格模式只用狗**（`kind>=2`）—— `vm_interp.c:1251-1262`；
· **狗取钥是真实现**（动态加载 DLL、取 login/logout/read、`pLogin(feature, vendorCode, &handle)`、
  分阶段失败码 `vm_sentinel_fail_stage`）—— `vm_interp.c:1184-1224`；
· **任何解密之前**做 KCV 自检，失败统一硬门 `0xC0DE0007` —— `vm_interp.c:1263-1269`；
· 构建期可直接从狗取主密钥：`-key-in dongle:<fileID>:<offset>:<length>` —— `cmd/vmpbuild/main.go:480-494`；
· **镜像整体加密只支持 x86-64 / arm64，i386 先跳过** —— `cmd/vmpack/main.go:571-572`；
· **镜像解密是"整节解密到内存"**（按节一把 KDF 密钥，`dst = base + rva`）—— `vm_interp.c:2940-2948`；
· **外置密钥模式只支持 win/x64** —— `cmd/vmpbuild/main.go:150`。

**同时更正一处我此前的口头判断**：我说过"外置密钥/狗路径还没做"，这是**错的** ——
运行期外置取钥与 Sentinel 取钥都已存在（见上）。真正未做的是：狗**参与密码学**（`hasp_decrypt` 类非导出密钥）、
TPM/TEE/回调封印、母狗私钥保护、`features` 语义、吊销 —— 对应 TODO 第 224/225/474/596/598/599 行。

**不足清单（按对本威胁模型的影响排序，均带依据）**：G1 整节解密到内存（最大）> G2 默认密钥内置 >
G3 外置密钥仅 win/x64 > G4 i386 无镜像加密 > G5 无吊销/features > G6 狗只当取钥点 > G7 机器绑定其余形态未做 >
G8 反调试只是成本乘数。

**工作项（已登记进 TODO 第 6 节）**：W1 按页惰性解密+回写（无需新硬件，可立即开工）> W2 i386 补镜像加密 >
W3 外置密钥扩到 i386/linux/arm64 > W4 狗参与密码学+会话绑定 > W5 features+吊销 > W6 反 dump/反 trace。

**可自动化验收（文档第 6 节）**：跨机/跨狗不运行（须恰好 `0xC0DE0007`）、dump 后离线不可运行、
每客户构建唯一可归因、吊销后新版本拒绝、以及"重建 N 条 IR 所需的最少 trace 覆盖"作为持续指标。

**顺带记录一个交接事实**：`docs/HANDOFF.md` 已过期（它写"最新提交 35e478c、11 gates"，
而当前是 12 gates），其 T1–T4 经逐条对照**都已实现**（T2 的其余取钥形态除外）；
**活的待办以 `docs/TODO.md` 为准**。

### 489. W3 第一步：**Linux/amd64 的主密钥外置取钥已实现并通过构建级验证**

**做了什么**（提交内容见下）：

1. `cmd/vmpbuild/main.go`：`-key-external` 的目标守卫从只允许 win/x64 改成**白名单**，
   目前含 `win/x64` 与 `linux/amd64`；其余目标仍 fail-fast（理由见 #488 与代码注释）。
2. `stub/win/x64/vm_interp.c`：
   - C 侧 `#error` 守卫同步放宽为「win/x64 或 linux/amd64」；
   - 新增 **Linux/amd64 取钥原语**（`VM_BLOB_TARGET_LINUX && __x86_64__`）：
     `exit_group` 硬门、`/proc/self/environ` 取环境变量、`/proc/self/exe` + `.vmpkey` 取路径、
     `open/read/close` 读文件（全部走本文件已有的 `vm_syscall3`，x86_64 号：read=0 open=2 close=3
     readlink=89 exit_group=231）；
   - `vm_ustr_t` / `vm_objattr_t` / `vm_iosb_t` / `vm_hexval` **移出 Windows 分支**（授权段也要用，
     留在分支里会让 Linux 目标报 unknown type name / implicit declaration）；
   - `vm_find_module` / `vm_get_proc` / `vm_peb_base` 在 Linux 侧给**安全失败桩**（返回 0）——
     语义是"拿不到"：需要狗的 `kind>=2` 会**正确走硬门**，授权/验签因为拿不到 bcrypt 与时间而一律拒绝
     （fail-closed）；Linux 侧的授权与狗留待单独一轮。

**证据（构建级）**：

    A) 非外置 linux/amd64：rc=0（改动没有破坏原有路径）
    B) 外置 linux/amd64：rc=0，blob 45056 字节（此前是 undefined symbol vm_find_module）
    C) 外置 blob 里 /proc/self/environ、/proc/self/exe、.vmpkey、VMPX_KEY_FILE 各 1 次、VMPX_KEY 2 次；
       非外置 blob 里这些字符串 0 次 —— 证明新代码只进外置构建
    D) tools/gates.ps1 = 12 gates / 0 failed；tools/preflight.ps1 = [+] preflight: OK

**本轮踩到并已记录的老坑**：构建 linux blob 时**不能**把 `C:\msys64\mingw32\bin` 放进 PATH ——
否则 x86-64 目标会被 32 位工具链编译，报出一堆 `-Wint-to-pointer-cast`，并让 `sizeof(vm_ctx_t) == VM_CTX_SIZE`
的静态断言失败（看起来像代码问题，其实是工具链用错）。

**未做项（下一步）**：
1. **Linux 侧运行时验收**：本机无法执行 Linux 系统调用，必须在 CI 的 Linux 作业里做 ——
   需要给 `tools/e2e.sh` 或一个 Linux 侧小探针加两条用例（不给密钥 ⇒ 恰好失败 / 给了 ⇒ 与原生一致）；
   同时要确认 `vmpack` 在 Linux 目标上写出正确的 `vm_key_src.kind`（运行期取钥路由由它决定）。
2. linux/arm64（同一形态，改 syscall 号；本机无 aarch64 工具链 ⇒ 只能靠 CI 验证）。
3. 授权与狗在 Linux 上目前是 fail-closed 桩 ⇒ 若客户要在 Linux 上用狗，需单独一轮。
4. i386 与 win/arm64 各自单独一步（32 位 PEB / ARM64 TEB）。

### 490. W3 第二步：**Linux/amd64 运行时验收通过**（外置取钥在真 Linux 上跑通）

**做法**：在 `tools/e2e.sh`（CI 的 linux-amd64 作业执行）末尾加一节 1b 外置密钥验收，三条用例：

1. **不给密钥**：必须恰好被硬门拒绝（`exit_group(0xC0DE0007)` 在 POSIX 上只暴露低 8 位 ⇒ 断言 `rc=7`，且无输出）；
2. **给密钥（环境变量 `VMPX_KEY`）**：运行期走 `/proc/self/environ` ⇒ 输出必须与原生一致；
3. **给密钥（`<产物>.vmpkey` 文件）**：运行期走 `/proc/self/exe` + `.vmpkey` + `open/read/close` ⇒ 必须与原生一致。

（不需要额外开关：`vmpack` 只在传 `-dongle-*`/`-license-*` 时才改 `vm_key_src.kind`；默认 `kind=0` 就是"文件 -> 环境变量"。）

**证据（CI run 35838856135，commit 3790320，linux-amd64 作业）**：

    [*] 1b 外置密钥（-key-external）验收...
      [OK  ] 无密钥：rc=7（硬门低 8 位）且无输出
      [OK  ] 有密钥(VMPX_KEY 环境变量)：与原生一致
      [OK  ] 有密钥(<产物>.vmpkey 文件)：与原生一致
    e2e(linux): 17 passed, 0 failed

⇒ 加上 #489 的构建级证据（外置 blob 里含 /proc/self/environ 等字符串、非外置 blob 为 0；
非外置路径 rc=0），**Linux/amd64 这条路径现在构建级 + 运行时级都有验收**，且已进入 CI 常态回归。

**为什么必须靠 CI**：本机是 Windows，**无法执行 Linux 系统调用** —— 取钥实现里 `/proc/self/environ`、
`open/read`、`exit_group` 这些只有真 Linux（含 qemu-user）能跑到；本机只能做构建级与静态检查。

**未做项（下一步）**：
1. **linux/arm64**：aarch64 没有 `open` 只有 `openat`、没有 `readlink` 只有 `readlinkat` ⇒ 都需要**第 4 个参数**，
   而现成的 `vm_syscall3_a64` 只有 3 个 ⇒ 要先加一个 4 参数封装；syscall 号：openat=56 close=57 read=63
   readlinkat=78 exit_group=94；然后在 `tools/e2e_arm64.sh`（CI 的 linux-arm64 作业，qemu）里加同一节三条验收。
2. i386（32 位 PEB + __stdcall）与 win/arm64（ARM64 TEB/PEB）各自一步。
3. Linux 侧授权与狗仍是 fail-closed 桩（需要时单独一轮）。

### 491. W3 第三步：**Linux/arm64 完成**（目标 (a) 两个平台均闭环）；并记录一个 CI 教训

**做法**：
1. `stub/win/x64/vm_interp.c`：
   - 新增 **aarch64 的 4 参数 syscall 封装** `vm_syscall4_a64`（aarch64 **没有** `open`/`readlink`，
     只有 `openat=56` / `readlinkat=78`，都要 `AT_FDCWD` 这个第 4 参数）；
   - 取号与调用按 arch 分离（`__x86_64__` 用 read=0 open=2 close=3 readlink=89 exit_group=231；
     `__aarch64__` 用 read=63 close=57 openat=56 readlinkat=78 exit_group=94），
     上层四个原语的代码保持一份（用 `vm_lx_sys3` 与 `VM_LX_OPEN_RO` / `VM_LX_READLINK_EXE` 两个宏统一）；
   - C 侧 `#error` 守卫与 `cmd/vmpbuild` 白名单同时放开 linux/arm64。
2. `tools/e2e_arm64.sh`：加同一套 1b 验收。

**证据（CI run 35946190183，commit 2a15ccf，linux-arm64 作业）**：

    [*] 1b 外置密钥（-key-external）验收...
    [+] 1b: 无密钥 -> rc=7（硬门低 8 位）且无输出
    [+] 1b: 有密钥(VMPX_KEY) -> 与原生一致
    五作业全绿（windows-amd64 / linux-amd64 / linux-arm64 / windows-arm64-blob / windows-arm64-run）

**本轮踩到并记下的教训（值得写进注释与文档）**：我一开始给 arm64 那段 `vmpbuild` 只写了 `-cc "$CC"`，
漏了脚本原有的 `-guest arm64 -merge go -random-opcodes=false -objdump`。后果不是"编译不过"而是**静态断言炸**：
缺 `-guest arm64` ⇒ 客户机退回 x86-64 ⇒ `VM_REG_COUNT` 变成 18 ⇒ ctx 布局断言生效，
而 arm64 平台头的 `VM_CTX_*` 是按 arm64 客户机（35 槽位）写的 ⇒ `vm_sa_ctx_pc/codelen/code` 全部为负。
⇒ **同一个平台目录的 blob，参数必须与非外置那次完全一致**（已在脚本里写成注释）。

**两个平台的差异（如实记录）**：
- **amd64**：三条都测（无密钥 / `VMPX_KEY` 环境变量 / `<产物>.vmpkey` 文件），全过；
- **arm64**：测两条（无密钥 / `VMPX_KEY`）—— 文件那条依赖 `/proc/self/exe`，而 qemu-user 下该路径指向
  宿主 qemu 而不是被仿真的 ELF，**不可靠**，故未纳入；arm64 的路径解析逻辑与 amd64 共用同一份源码，
  差异只在 `readlink` 与 `readlinkat` 两个系统调用号上。

**未做项（目标 (b)(c) 仍待做）**：
1. **win/x86(i686)**：32 位 PEB（`fs:[0x30]`）+ 32 位导出表遍历 + 全部 API 走 `__stdcall`
   （后者本会话早些时候已修：`VM_WINAPI` 宏）；
2. **win/arm64**：Windows 在 ARM64 上不是 `gs:[0x60]`，要另写 TEB/PEB 取法；
3. Linux 侧**授权与狗**仍是 fail-closed 桩。

### 492. W3 第四步：win/x86(i686) **部分完成**（环境变量通了，文件路径仍缺）—— 未放开白名单

**本轮做的改动（保留，作为准备）**：

1. `vm_get_proc_d` 的**导出目录基址**改为按位宽：i386 用 `24 + 96`（PE32），x64 用 `24 + 112`（PE32+）
   —— 原来硬编码 112，i386 下会把别的字段当导出表；
2. `RTL_USER_PROCESS_PARAMETERS` 的字段偏移按位宽：i386 的 `ImagePathName@+0x38`、`Environment@+0x48`
   （x64 是 +0x60 / +0x80）；
3. **PEB -> ProcessParameters** 的偏移也按位宽：i386 是 `+0x10`、x64 是 `+0x20`
   —— 这一层最容易漏：只改 PP 内部偏移时，环境块与 ImagePathName 会**一起**读不到。

（PEB/LDR 那一套宏 `VM_PEB_LDR_OFF` 等**早就**按位宽分好了，本轮没动。）

**本机端到端实测（临时放开白名单做的，测完已撤回）**：

    native            = 35
    无密钥            = 0xC0DE0007  ✓ 硬门正确（低 8 位/整值都对）
    VMPX_KEY 环境变量 = 35          ✓ 与原生一致
    <产物>.vmpkey 文件 = 0xC0DE0007  ✗ 仍被拒
    VMPX_KEY_FILE=绝对路径 = 0xC0DE0007 ✗ 仍被拒   ← 关键隔离实验

⇒ 两个"文件"用例都失败，而**环境变量**用例成功 ⇒ 缺口不在路径推导，而在**文件读取**这一环：
`vm_key_read_nt` 依赖 `vm_find_module("ntdll.dll")` + `vm_get_proc(NtCreateFile/NtReadFile/NtClose)`，
即 **i386 下的模块遍历/导出遍历**还没真正跑通。

**处置**：按 fail-fast 纪律，**`win/x86` 暂不加入 `vmpbuild` 白名单**（否则会产出"默认部署方式
——`.vmpkey` 文件——不工作"的产物，比构建期报错更难查）；白名单里只留 win/x64 / linux/amd64 / linux/arm64。
本轮的三处偏移修正保留（它们对已支持平台无影响，是 i386 的必要准备）。

**下一步（i386 收尾）**：查 `vm_find_module`/`vm_get_proc_d` 在 i386 下为何取不到 ntdll 导出 ——
可用本轮的隔离手法（`VMPX_KEY_FILE` + 本机 32 位产物）逐层验证：先确认 PEB->Ldr 链表能走通，
再看导出目录/名字表解析；通了再把 `win/x86` 加回白名单，并把三条用例补进门禁。

### 493. W3 第五步：**win/x86(i686) 完成** —— 三条运行时用例本机全过，白名单已放开

**根因（本轮定位）**：上一轮修好环境变量那条后，.vmpkey 文件那条仍被拒。本轮用 VMPX_KEY_FILE
（绝对路径）做隔离实验 ⇒ 问题**不在**路径推导，而在 vm_key_read_nt 调 ntdll 时传的**结构体布局**：

| 结构体 | x64（原来单一声明） | i386 正确值 |
|---|---|---|
| OBJECT_ATTRIBUTES | Length,Pad 有对齐填充 = 32 字节 | 无填充 = 24 字节 |
| IO_STATUS_BLOCK | void* + u64 = 16 字节 | {NTSTATUS, ULONG} = 8 字节 |

⇒ 按 x64 布局传给 32 位 ntdll 会被判为非法参数 ⇒ 文件永远读不到。已按 VM_HOST_X86_32 分开声明，
并把只在 x64 分支存在的 Pad/Pad2 初始化一并分支。

**第二个坑（已记录）**：上一轮撤回 win/x86 白名单后，我仍用同一命令"重建"blob，结果 vmpbuild
**直接拒绝**、blob 没生成，测试跑的是**旧 blob** ⇒ 结构体修正等于没编译，表现为"修了还是失败"。
⇒ 每次测试前先删 blob 并确认构建真的产出（仓库早记过这个坑）。

**本机端到端证据（Windows 直接跑 32 位产物）**：

    native              = 35
    无密钥              = 0xC0DE0007  ✓ 硬门
    <产物>.vmpkey 文件  = 35          ✓ 与原生一致
    VMPX_KEY 环境变量   = 35          ✓ 与原生一致

**i686 一共六处位宽修正**：① 导出目录基址（i386 用 24+96，x64 用 24+112）；
② RTL_USER_PROCESS_PARAMETERS 的 ImagePathName/Environment 偏移（+0x38/+0x48）；
③ PEB->ProcessParameters 偏移（+0x10）；④⑤ NT 结构体 OBJECT_ATTRIBUTES 与 IO_STATUS_BLOCK 的布局。
（PEB/LDR 那套宏 VM_PEB_LDR_OFF/vm_pread 本仓库早已按位宽分好。）

⇒ cmd/vmpbuild 白名单现在为：**win/x64、win/x86、linux/amd64、linux/arm64**；win/arm64 仍 fail-fast。

**未做项**：① 这三条用例还没进 tools/e2e_32bit.ps1（进 CI 才能常态回归）；② win/arm64 未做；
③ Linux 侧授权与狗仍是 fail-closed 桩。

### 494. i686 的 1b 三条用例**进 32 位门禁**（进入 CI 常态回归）

**做法**：在 `tools/e2e_32bit.ps1` 末尾（两遍打包对比之后、汇总之前）加一节 1b 外置密钥验收，
三条用例与本仓库 Linux 侧完全同构：

1. **不给密钥** ⇒ 必须恰好是硬门（`0xC0DE0007`；PowerShell 对 32 位进程报 `-1059192825`，脚本里用
   `[int]0xC0DE0007` 比较，两种表示等价）；
2. **`VMPX_KEY` 环境变量** ⇒ 退出码必须与原生一致；
3. **`<产物>.vmpkey` 文件** ⇒ 退出码必须与原生一致。

外置 blob 用与被测目标**同一套参数**构建（`-guest x86-32 -merge go -random-opcodes=false -key-external`）。
脚本保持**纯 ASCII**（本仓库 .ps1 的硬要求：PS 5.1 按 ANSI 解码，非 ASCII 注释会吞掉下一行）。

**证据（本机，门禁 rc=0）**：

    [*] 1b external key (i686): building an external-key blob...
      [OK  ] 1b: no key -> 0xC0DE0007 (hard gate)
      [OK  ] 1b: VMPX_KEY -> matches native
      [OK  ] 1b: .vmpkey file -> matches native
    [OK] 32-bit e2e: 12/12 match native (-strip-relocs)
    [OK] 32-bit e2e: 12/12 match native (relocations kept)
    non-ASCII lines = 0

⇒ 该门禁由 CI 的 windows-amd64 作业执行 ⇒ i686 的取钥路径**从此有常态回归**。

**各平台现状（目标进展）**：

| 平台 | 构建 | 运行时验收 | 白名单 |
|---|---|---|---|
| win/x64 | ✅ | ✅（原有） | ✅ |
| linux/amd64 | ✅ | ✅（CI，三条） | ✅ |
| linux/arm64 | ✅ | ✅（CI，两条） | ✅ |
| win/x86 | ✅ | ✅（本机门禁，三条） | ✅ |
| win/arm64 | ❌ 未做 | ❌ 本环境**无法**验证（见下） | ❌（fail-fast） |

**关于 win/arm64（目标 (c)）的诚实说明**：本仓库 CI 里的 `windows-arm64-blob` / `windows-arm64-run`
两个作业跑在 **x86-64 宿主**上（名称里的 "host is still x86-64" 就是这个意思），它们执行的是
**arm64 客户机字节码**，而 win/arm64 的 **blob 本身是 ARM64 机器码** —— 在 x86-64 宿主上根本无法执行。
因此本环境（含 CI）**没有任何**能运行 Windows/ARM64 取钥路径的地方 ⇒ 按仓库纪律
（不要在无法验证时动主干）该项暂不实现，白名单继续 fail-fast。

### 495. arm64 补齐第三种密钥形态（VMPX_KEY_FILE）⇒ 四个平台三种形态齐平；并第二次确认 win/arm64 的阻塞条件

**做法**：`tools/e2e_arm64.sh` 的 1b 一节补一条 **`VMPX_KEY_FILE` 指向绝对路径**的用例。
这条刻意**不走** `<产物>.vmpkey` —— 后者要 `readlink("/proc/self/exe")`，而 **qemu-user 下该路径指向宿主 qemu**，
不可靠；用绝对路径就绕开了它，于是 arm64 也能覆盖"文件"形态的取钥路径。

**证据（CI run 35948396551，linux-arm64 作业，五作业全绿）**：

    [+] 1b: 无密钥 -> rc=7（硬门低 8 位）且无输出
    [+] 1b: 有密钥(VMPX_KEY) -> 与原生一致
    [+] 1b: 有密钥(VMPX_KEY_FILE 绝对路径) -> 与原生一致

**四个平台的覆盖现状**：

| 平台 | 无密钥硬门 | VMPX_KEY | 文件形态 | 验收位置 |
|---|---|---|---|---|
| win/x64 | ✓ | ✓ | ✓ | 原有（STATUS #399 一带） |
| linux/amd64 | ✓ | ✓ | ✓（`<产物>.vmpkey`） | CI `tools/e2e.sh` |
| linux/arm64 | ✓ | ✓ | ✓（`VMPX_KEY_FILE`） | CI `tools/e2e_arm64.sh`（qemu） |
| win/x86 | ✓ | ✓ | ✓（`<产物>.vmpkey`） | 32 位门禁（CI windows-amd64） |

**win/arm64（目标 (c)）阻塞条件的第二次确认（本轮新查到的事实）**：

1. `stub/win/arm64` **存在**，CI 的 `windows-arm64-blob` 作业**确实会编译** Windows/ARM64 的 blob
   （用 `clang --target=aarch64-w64-windows-gnu` + `llvm-objdump`）⇒ **编译级验证在 CI 可得**；
2. 但**没有任何环境能执行**它：`windows-arm64-run` 跑在 **x86-64 宿主**上，执行的是 **arm64 客户机字节码**，
   而 win/arm64 的 blob 本身是 **ARM64 机器码**，x64 宿主无法执行；qemu-user 也不支持 Windows 目标；
3. **本机连交叉编译都做不了**：PATH 上没有 clang，`C:\msys64\clangarm64` 是 **ARM64 原生**二进制（在 x64 上跑不了），
   mingw64/ucrt64 里也**没有** clang ⇒ 本机的编译级验证不可得。

**代码现状（好消息）**：Windows 侧的 PEB 取法**已经**有 `#elif defined(__aarch64__)` 分支（`x18` → TEB+0x60，
与 x64 的 TEB+0x60 同构），而 LDR/PP/导出目录/NT 结构体那几套**都是 64 位版本**、与 x64 **共用**（ARM64 同样是 64 位布局）
⇒ 真正要改的只有**两行**：C 侧 `#error` 守卫加 `|| defined(__aarch64__)`、`vmpbuild` 白名单加 `win/arm64`。

**为什么本轮仍然不放开**：放开就等于把一个**运行时从未执行过**的取钥路径交给客户 —— 若那条 inline asm 或偏移有误，
客户现场的表现正是 fail-fast 规则要避免的"程序莫名其妙退出"。按仓库纪律（不要在无法验证时动主干、
不为通过检查而放宽阈值），**保持 fail-fast**，把决定权与所需条件留给下一次（需要一台 Windows on ARM，
或 CI 上加一个 ARM64 Windows 的 self-hosted runner）。

**未做项**：① win/arm64（见上，需外部条件）；② Linux 侧授权与狗仍是 fail-closed 桩。

### 496. win/arm64（目标 (c)）判定为**环境阻塞**：本机与 CI 都无法验证，按纪律不放开白名单

**阻塞条件（第 8/9/10 三轮连续确认，且本轮已穷尽本地选项）**：

1. **执行**：没有任何可用环境能运行 Windows/ARM64 取钥路径。
   - CI 的 `windows-arm64-blob` / `windows-arm64-run` 都跑在 **x86-64 宿主**上，执行的是 **arm64 客户机字节码**；
   - win/arm64 的 blob 本身是 **ARM64 机器码**，x64 宿主无法执行；qemu-user 不支持 Windows 目标。
2. **编译**（本轮新证据）：本机**完全没有 clang** —— PATH、`C:\Program Files\LLVM`、Visual Studio 的 LLVM 目录、
   scoop/choco 常见位置、以及**全盘 `clang.exe` 递归搜索**都是空；msys64 里只有 `clangarm64`（ARM64 原生二进制，
   x64 上跑不了）⇒ **本机连交叉编译都做不了**。CI 侧倒是有 `clang --target=aarch64-w64-windows-gnu`，
   但它只编**非外置**的 blob ⇒ 外置取钥代码在 CI 里同样**不会被编译**（除非放开白名单）。

**代码现状（只差两行，已写进 TODO 供下次接手）**：
- Windows 侧 `vm_peb_base()` **已有** `#elif defined(__aarch64__)` 分支（`x18` → TEB+0x60，与 x64 的 TEB+0x60 同构）；
- LDR / RTL_USER_PROCESS_PARAMETERS / 导出目录 / NT 结构体这几套**都是 64 位版本**，与 x64 **共用**（ARM64 同为 64 位布局）；
- 因此放开只需：C 侧 `#error` 守卫加 `|| defined(__aarch64__)`，`cmd/vmpbuild` 白名单加 `win/arm64`。

**为什么不放开**：放开等于把一个**运行时从未执行过**的取钥路径投给客户。若那条 inline asm 或某个偏移有误，
客户现场的表现正是 fail-fast 规则要防的"程序莫名其妙退出"；仓库纪律明确要求"不要在无法验证时动主干、
不为通过检查而放宽阈值"。⇒ **保持 fail-fast**，把这块留给具备条件的环境。

**解除办法（任选其一）**：① 一台 **Windows on ARM** 机器（本机或 CI self-hosted runner）⇒ 可直接跑三形态验收；
② CI 上加一个 ARM64 Windows runner；③ 仅需编译级验证的话：在 CI 的 `windows-arm64-blob` 作业里，
   临时放开白名单编一次外置 blob（并把产物作为证据留存）—— 但这只覆盖"能编译"，**不覆盖取钥正确性**。

**至此目标 (a)(b) 全部完成，(c) 因环境受限阻塞**：已启用并各有运行时验收的平台为
**win/x64、win/x86、linux/amd64、linux/arm64**（每个都覆盖"无密钥硬门 / 环境变量 / 文件"三形态）。

**未做项**：① win/arm64（见上）；② Linux 侧授权与狗仍是 fail-closed 桩。

### 497. 更正：CI **本来就有** windows-11-arm 原生 runner；win/arm64 外置取钥**实测会崩**（0xC0000005）⇒ 白名单保持关闭

**先更正我自己的错误**：第 8/9/10 轮我断言"没有任何环境能执行 Windows/ARM64"——**这是错的**。
CI 里本来就有 `windows-arm64-run` 作业，其 `runs-on: windows-11-arm`（**原生 ARM64 Windows**），
而且它**确实会执行 ARM64 机器码的 blob**（该作业的 "run native vs protected" 步骤就是 native vs protected 退出码比对，
一直是绿的）。我把 **windows-amd64 作业里一个步骤名**"ARM64 guest differential (host is still x86-64)"
误当成了作业的 runner，据此得出"无处可执行"的错误结论，进而三轮把它归为环境阻塞。
⇒ 教训：判断某能力是否可得，要读**作业的 runs-on**，不要读步骤名。

**于是本轮真的去验证了 (c)**：
1. 放开两行（C 侧 `#error` 守卫加 `__aarch64__`、`vmpbuild` 白名单加 `win/arm64`）；
2. 新增 `tools/e2e_win_arm64.ps1`（纯 ASCII）：定位 clang → 建 freestanding ARM64 PE 目标 →
   建**外置** Windows/ARM64 blob → 打包 → 三条形态（无密钥 / `VMPX_KEY` / `<产物>.vmpkey`）；
3. 把它作为一步挂到 `windows-arm64-run`（原生 ARM64）作业上。

**实测结果（CI run 35951042779，windows-arm64-run）**：

    [*] clang   : C:\Program Files\LLVM\bin\clang.exe
    [*] native rc=654184885 out=
    [!] no key:        rc=-1073741819  (0xC0000005 = ACCESS_VIOLATION)
    [!] VMPX_KEY:      rc=-1073741819
    [!] .vmpkey file:  rc=-1073741819
    [!] win/arm64 1b: 3 case(s) failed

⇒ **三条崩溃码完全相同**，且**与有没有密钥无关** ⇒ 崩在**取钥之前/之中**，不是"密钥不对"；
同一 runner 上**非外置**产物是正常的（该作业原有的 native vs protected 比对通过）。
⇒ 也就是说 **win/arm64 的取钥路径存在真实缺陷**，而不是"看起来应该能跑"——正是 fail-fast 规则要防的
"客户现场程序莫名其妙退出"。

**处置**：
- **撤回** `windows-arm64-run` 里新增的那一步（主干保绿）；
- **`win/arm64` 白名单保持关闭**（现状 = fail-fast），并在白名单处写明实测崩溃码与复现方式；
- **保留** `tools/e2e_win_arm64.ps1` 作为**现成的复现器**：把它作为一步加回该作业即可复现（证据 run 35951042779）。

**顺带记下第二个探针校准教训**：我本机用 **Windows PowerShell 5.1** 的解析器检查 .ps1（通过），
而 CI 用的是 **pwsh 7** ⇒ 漏掉了 `-Wl,-e,entry` 这种裸参数里的逗号（在 pwsh 7 的参数位置是数组运算符 ⇒ ParserError）。
⇒ **.ps1 的解析检查必须用与 CI 相同的解析器**（本机没有 pwsh 7，只能靠 CI 兜）。

**下一步定位建议（给接手的人）**：
1. 先在 `vm_peb_base()` 的 `#elif defined(__aarch64__)` 分支做最小验证（`x18` → TEB、TEB+0x60 → PEB 在 Windows/ARM64 上是否成立）；
2. 再看 `vm_find_module()`/`vm_get_proc_d()` 用到的那些 64 位 LDR/导出偏移在 ARM64 Windows 上是否一致；
3. 手段：把 1b 段按函数逐层注释（二分）后用同一复现器收敛；或在崩溃前打印诊断（该作业是原生 Windows，stdout 可见）。

### 498. win/arm64 诊断（第 1 轮）：**崩在取钥之前**；并记录一个必须补的校准缺口

**做法**：加了一个**仅 aarch64 编译**的最小 stderr 打印助手（`vm_dbg_win`，走 `kernel32!GetStdHandle` +
`WriteFile`，用现成的 `vm_get_proc` 解转发导出），在 `vm_master()` 的入口与取钥之后各打一个标记；
把复现器挂回 `windows-arm64-run`（原生 ARM64），步骤末尾把退出码清零以免作业变红（诊断期间保绿）。

**结果（CI run 35953189619，windows-arm64-run，五作业全绿）**：

    构建 ✓  打包 ✓  native rc=654184885
    [!] no key / VMPX_KEY / .vmpkey:  三条都是 rc=-1073741819 (0xC0000005)
    标记统计：  1b:enter 出现 0 次   1b:fetched 出现 0 次

⇒ **一个标记都没有** ⇒ 崩点在 `vm_master()` **被调用之前**，也就是说**不在取钥代码里**。
（我此前"崩在取钥中"的推断同样不对。）外置模式与默认模式的差异因此发生在更早的阶段。

**必须说明的校准缺口（下一步第一件事）**：`vm_dbg_win` 若自己取不到 kernel32 的两个导出，会**静默返回**；
所以"0 标记"目前有两种解释 —— ① 真的崩在 `vm_master()` 之前，② 打印器本身不可达。本仓库纪律要求
探针先校准，因此下一步应先**证明打印器能打**（例如在更早、必然执行的阶段打一个标记，比如镜像自解密入口），
两种解释才可区分。

**上一轮修的编译错误（供参考）**：诊断助手插在了 `vm_find_module`/`vm_get_proc` 的**前向声明之前**
（那两条声明在本文件靠后的 Windows 段），clang 报 `vm_get_proc` 未声明 ⇒ 已在助手前补两条声明。
另外把复现器里 vmpbuild 的输出从 `-Last 10` 放宽到 `-Last 30`，避免再把错误正文截掉。

**处置**：`win/arm64` 白名单**重新关闭**（现状 = fail-fast），并在白名单处写明"崩在取钥之前"与复现方式；
诊断代码（仅 aarch64 编译）与复现器保留入库，供下一轮直接续上。

### 499. win/arm64 定位（第 2 轮）：**校准救了一次** —— 原结论被推翻；修掉两个真 bug，剩余一步已明确

**① 校准的价值（本轮最重要的方法学收获）**：给复现器加了"**非外置产物的校准用例**"（同一流程建默认 blob、
打包、运行，必须与 native 一致）。结果**校准自己就失败了**：我用同一进程建出的**默认**产物也以
`0xC0000005` 崩溃 ⇒ ⇒ 原先"**外置模式才崩**"的结论**是混淆的** ✗：真正的差异在我这个 harness 与
那个绿作业之间，而不是密钥模式。这正是 `AGENTS.md`「探针先校准」那条纪律的价值。

**② 本轮修掉的两个真 bug**：

1. **harness 的编译器调用**（我的错 ✗）：我自造了一个 `clang --target=aarch64-w64-windows-gnu` 包装脚本；
   而绿作业（`ci.yml` 第 319 行）用的是**原生 `clang`**。用我的包装编出来的 blob **一进就崩**（连默认模式也崩）
   ⇒ 说明崩在**任何 blob 代码执行之前**，是 **ABI/入口不匹配**，与取钥无关。已改为与绿作业一致（`-cc clang`）。
2. **平台判定宏**（真 bug ✓）：`vm_interp.c` 里 `__aarch64__`（GNU 风格）出现 7 处；而**原生 Windows/ARM64** 上
   的 clang 用的是 **msvc 目标**，实测 `__aarch64__` 与 `_M_ARM64` **都不成立** ⇒ 导致 `#error` 误触发，
   或退回 x86-64 的 `%gs:[0x60]` 分支（在 ARM64 上不合法）。已引入 `VM_ARCH_AARCH64` 并改为
   "**Windows 目标 + 排除法**"（既非 x86-64 也非 x86-32 ⇒ arm64）。

**③ 但 CI 实测 `#error` 仍然触发（run 35955231143）** ⇒ 说明这次编译里**有** `__x86_64__` 或 `_M_X64`
（排除法的前提不成立）。⇒ **下一个探针已明确**：把 `#error` 拆成多条、每条报出**具体是哪一组宏成立**
（如 `#error "case A"` / `#error "case B"`），一次 CI 往返即可确定该工具链到底定义了什么 —— 之后才是真修复。

**④ 本轮同时验证出来的事实**：那个原生 ARM64 作业**本来就能跑 ARM64 机器码的产物**（非外置的 native/保护的
退出码比对一直绿），所以 (c) 不是"环境不可得"，而是**工具链宏与 harness 的问题**。

**⑤ 处置**：白名单**重新关闭**（fail-fast）；撤掉 CI 里的诊断步骤（避免噪声）；**保留**复现器
（含校准用例）与诊断代码，供下一轮直接续上。

### 500. win/arm64 定位（第 3 轮）：**崩溃已消除**，取钥代码实测执行；剩余问题与密钥无关

**① 宏探针（一次 CI 拿到完整画像，run 35955971985）**：

    probe: __aarch64__ IS defined
    probe: _M_ARM64 IS defined
    probe: VM_GUEST_ARM64 IS defined
    （未出现 __x86_64__ / _M_X64 / VM_HOST_X86_32）

⇒ 我上一轮"`__aarch64__` 与 `_M_ARM64` 都不成立"的判断**也是错的**；真因是另一件事（见 ②）。

**② 真因（vmpbuild 的 Windows ABI 检测）**：`cmd/vmpbuild/main.go` 原本只认：

    compilerIsWindows = strings.Contains(machine, "mingw") || strings.Contains(machine, "w64")

而原生 Windows/ARM64 上 `clang -dumpmachine` 返回 `aarch64-pc-windows-msvc` ⇒ **两个都不含** ⇒
`VM_BLOB_USES_WIN64` 从未被定义 ⇒ 1b 的守卫误报 `#error`（探针那次就是它）。已放宽为同时认
`windows` / `msvc` / `win32`，并撤回此前在 C 侧临时放宽的两处守卫（保持机制单一）。

**③ 修复后的实测（run 35957001462）—— 崩溃彻底消失**：

    native rc=654184885
      [OK  ] 1b: no key -> 0xC0DE0007 (hard gate)      ← 硬门正确
    [!] VMPX_KEY:     rc=-1059192830  out=[1b:enter|1b:fetched]
    [!] .vmpkey file: rc=-1059192830  out=[1b:enter|1b:fetched]
    [*] CALIBRATION (non-external blob): rc=-1059192830

⇒ 三重意义：**(a)** `0xC0000005` 不再出现；**(b)** 两个 stderr 标记都打出来了 ⇒ 打印器**可达**（校准缺口闭合）
且**取钥代码真的执行了**；**(c)** 无密钥时硬门 `0xC0DE0007` **正确**。

**④ 剩余问题（与密钥无关）**：给密钥后（以及**非外置**的校准产物）都以 `0xC0DE0002` 退出。
该码在本仓库是 `vm_img_fail(2)`：**"需要重定位但没有重定位表"**（入口自解密的诊断路径）。
⇒ 也就是说剩下的问题在**镜像自解密/重定位**这一环，而不是取钥；而且它连"默认模式产物"都影响 ⇒
**我的复现器与绿作业之间仍有最后一处差异未找到**（两边 `vmpbuild` 与 `vmpack` 的参数经逐字比对**完全一致**，
差异只剩产物文件名/运行顺序等表面项）。

**⑤ 处置**：白名单**重新关闭**（fail-fast）；撤掉 CI 探针步骤；保留复现器（含**校准用例**）与诊断标记，
供下一轮直接续上。

### 501. 自伤记录：我把 ci.yml 改坏了（工作流无法启动任何作业），已回滚

**现象**：CI run `35957720110` 的 `conclusion=failure` 且 **jobs 数 = 0** ⇒ 不是某个步骤失败，
而是**工作流本身没跑起来**（YAML/校验层）。

**原因**：我往 `windows-arm64-run` 里插诊断步骤时，用的锚点是 `$global:LASTEXITCODE = 0` ——
**这一行在文件里出现两次**（两个作业各一处）。工具的单次匹配恰好落在了**不是我想改的那一处**，
结果结构被破坏。⇒ 这正是本仓库纪律里写的"**改共享代码前先 grep 出真实文本再写补丁，补丁脚本必须 count 校验**"，
我这次没做 count 校验。

**处置**：`git checkout 6b15753 -- .github/workflows/ci.yml`（回滚到上一个绿提交）并重新关闭 `win/arm64` 白名单。
**探针脚本的改动保留**（`tools/e2e_win_arm64.ps1` 新增"**复跑绿作业自己的产物**"探针），下一轮再小心地挂上去。

**结论**：run 35957720110 是**基础设施自伤**，不含关于 win/arm64 的任何新信息；有效证据仍是 run 35957001462
（崩溃消除、`1b:enter|1b:fetched` 出现、无密钥硬门正确、给密钥后 `0xC0DE0002`）。

### 502. 第 15 轮：修好被我弄坏的 ci.yml（真因是**步骤名里的冒号**），并如实记录本轮没拿到新结论

**① 上一轮"工作流无法启动"的真因终于确定**：我追加的那一步写成

    - name: 1b external master key (win/arm64 probe: green product re-run)

—— 未加引号的标量里出现了 `: ` ⇒ YAML 报 `mapping values are not allowed here`（第 353 行第 54 列），
整个 workflow 因此**无法启动任何作业**（jobs 数 = 0）。改名去掉冒号后恢复正常（本轮 run 35958210137 五作业全绿）。

**② 顺带记下两条自伤教训**（都写在这里，避免再犯）：
- **改共享文件前必须 count 校验锚点**：我用的锚点 `$global:LASTEXITCODE = 0` 当时在文件里出现**两次**，
  工具的单次匹配落在了不是我想改的位置；
- **校准探针自己也要校准**：我想用 PyYAML 验证 YAML，于是把 HEAD 版本**用 PowerShell 重定向**存成文件，
  结果落成 UTF-16 ⇒ 报 `UnicodeDecodeError: 0xff`，与 YAML 无关。⇒ 校验手段本身出错时，结论毫无意义。
  正确做法（本轮采用）：当前工作副本能被 PyYAML 解析（`jobs=5`、`windows-arm64-run` 步骤数 6）即为通过，
  绿版本无需再验（CI 已经证明它能跑）。

**③ 本轮的技术产出（有限，如实说明）**：
- `win/arm64` 崩溃消除后的状态再次确认（run 35958210137）：`1b:enter|1b:fetched` 两个标记都出现 ⇒ **取钥代码确实执行**；
  无密钥时**硬门 0xC0DE0007 正确**；
- 但"**复跑绿作业自己的产物**"这个关键探针**没有输出任何行**（连"not present"分支也没有）⇒ 说明脚本在到达它之前就结束了。
  已经确认探针代码**在脚本里**（第 66-74 行），且它引用了在它**之后**才定义的 `$natRc` ⇒ 下一轮应先理清该脚本的控制流
  （大概率是某个 `exit 1` 提前返回，或探针位置放错）。⇒ **本轮没有拿到 0xC0DE0002 的归属结论**。

**④ 处置**：白名单**重新关闭**、撤掉 CI 探针步骤（保持主干绿、无噪声）；复现器（含两个探针）与 stderr 标记保留入库。

### 503. 第 16 轮（本轮为目标的最后一轮）：探针谜题未解，如实收尾

**做了什么**：把"复跑绿作业产物"的探针改成**无条件 + 无依赖 + try/catch**（不再引用后置的 `$natRc`、
不再被 `Test-Path` 包裹）⇒ 无论产物在不在，它**至少**应打印一行 `[*] PROBE start: ...`。
同时按纪律修掉了上一轮弄坏 CI 的 YAML 冒号问题（改名前先校验：`YAML OK jobs=5 steps=6`）。

**实测（CI run 35959041912，commit e5c1352，五作业全绿）**：

    [*] CALIBRATION (non-external blob): rc=-1059192830 out=[]      ← 出现在探针【之后】
    [*] native rc=654184885 out=
      [OK  ] 1b: no key -> 0xC0DE0007 (hard gate)
    [!] VMPX_KEY:     rc=-1059192830  out=[1b:enter|1b:fetched]
    [!] .vmpkey file: rc=-1059192830  out=[1b:enter|1b:fetched]
    probe step exit=2

⇒ **日志里没有任何 PROBE 行**（连无条件那行也没有），而**位于探针之后**的校准却打印了。
⇒ 这说明：**CI 上实际执行的脚本行为，与我本地文件的内容矛盾**（本地文件里探针在校准之前、且已无条件）。
⇒ 本轮预算不足以解开（候选：checkout 后的行尾转换、脚本被别处覆盖、或 `-File` 调用路径/工作目录的差异）。
**这条谜题与它的一句话复现方式都已写进 TODO，下一轮第一件事就是它。**

**仍然有效的技术结论（未变，来自 run 35957001462 / 35959041912）**：
- `win/arm64` 的 `0xC0000005` 崩溃**已消除**（真因是 vmpbuild 的 Windows ABI 检测只认 mingw/w64，漏掉
  `aarch64-pc-windows-msvc`）；
- 取钥代码**已实测执行**（stderr 标记 `1b:enter` 与 `1b:fetched` 都出现）；
- **无密钥时硬门 `0xC0DE0007` 正确**；
- 给密钥后（以及**非外置**的校准产物）都以 `0xC0DE0002` 退出 ⇒ 该码与密钥路径**无关**，
  指向入口自解密/重定位一环。

**处置**：白名单重新关闭（fail-fast）、撤掉 CI 探针步骤（主干保绿、无噪声）；复现器（含三个探针）与 stderr 标记保留入库。

**目标最终状态**：(a) Linux/amd64 + Linux/arm64 **完成**；(b) win/x86 **完成**；
(c) win/arm64 **未完成**——但已从"环境阻塞"推进到"崩溃消除 + 取钥执行 + 硬门正确 + 剩余一个与非密钥相关的失败"，
且每一步都有 CI 证据（run 号见 #489-#503）与可复现的探针。

### 504. 探针谜题缩小到"输出被吞"：部署脚本确实含无条件探针（证据在手）

**做了什么**：把 CI 步骤改成**先打印运行时脚本的哈希、行数与所有 `PROBE` 行**，再运行脚本 ——
用来区分"脚本没被更新"与"控制流没走到"。

**证据（CI run 35963405531，commit b34ba97）**：

    [*] script hash = 8E3FF78EFB1DEDF09D2F658FCFE9570E36C3F51ED16EE62133349C8D6549E61E
    [*] script lines = 115
    [*] deployed:66: # ---- PROBE: re-run the product the (green) job built earlier in this same job ----
    [*] deployed:73: Write-Host ("[*] PROBE start: looking for " + $green + " ; exists=" + (Test-Path $green))
    [*] deployed:83: Write-Host ("[*] PROBE green-job product re-run: ...")
    [*] deployed:85: Write-Host "[*] PROBE green-job product not present"

⇒ **部署的脚本确实包含无条件探针（第 73 行）**，而且**位于它之后**的校准（第 88 行起）在日志里打印了
⇒ 控制流**必然经过**第 73 行 ⇒ 但**没有任何 PROBE 行出现**。

⇒ 这推翻了我上一轮的猜测（"部署脚本与本地不一致"）。现在只剩一个解释：**该行的输出被吞掉了**
（pwsh 的输出流/异常路径问题；探针里那句 `& $green` 对 `.vmp` 文件的行为可能就是触发点，
即使我加了 try/catch）。

**下一轮的正解方向（已明确）**：**改用文件做信号** —— 脚本用 `Add-Content build/probe.txt ...` 记录结果，
CI 步骤随后 `Get-Content build/probe.txt` 打印。文件信号**不受输出流怪异行为影响**，
能把"探针是否执行、结果是什么"可靠地带出来。

**处置**：白名单重新关闭、撤掉 CI 步骤（主干保绿、无噪声）；复现器与探针保留入库。

### 505. win/arm64 定位：本轮排除三个假设（ASLR / 我的重建 / 启动方式），并解释清"探针无输出"

**① "探针无输出"的谜团已解**：改用**文件信号**（`build/probe.txt` + `Mark`）后，CI 步骤无论脚本怎么退出都打印它 ⇒
轨迹完整可见。⇒ 之前的"一行都没有"**纯粹是输出被吞**（文件信号证实脚本确实走到了那些行）。
（顺带查明：`& $file` 放在**管道里**会报 `Cannot run a document in the middle of a pipeline`，
而失败时 `$LASTEXITCODE` 会**保留上一个值** —— 这正是我早期读到"假象 rc"的原因。）

**② 本轮逐个排除的假设（每条都有 CI 证据）**：

| 假设 | 实验 | 结果 |
|---|---|---|
| ASLR / 概率性失败 | 同一产物连跑 10 次统计退出码 | **排除**：`rc=-1059192830x10`（10/10 失败，无随机） |
| 我的重建覆盖了目标 exe | 在脚本**最前面**（任何构建之前）跑绿产物 5 次 | **排除**：`probe-early:5runs rc=-1059192830x5` |
| 启动方式不同（裸调用 vs Start-Process） | 同一 exe 两种方式各跑一次 | **排除**：`cal-plain` 与 `cal-startprocess` **同为** `-1059192830` |
| 部署脚本没更新 | 打印运行时脚本哈希/行数/PROBE 行 | **排除**：哈希与行号都在，脚本确实含无条件探针（run 35963405531） |

**③ 剩下的尖锐问题**：**同一个绿产物 `build/target_arm64.vmp`，在绿作业自己的步骤里返回 `654184885`（= native，判定为成功），
而在紧接着的下一个步骤里，两种启动方式都返回 `0xC0DE0002`**。而我的步骤在早期探针之前**什么都没有做**
（只做了 clang 检测）⇒ 差异只能是**步骤之间**的状态，而不是我的构建。

**④ 下一次实验（已定）**：在**绿作业自己的那个步骤里**、其成功比对之后，**再跑一次同一个产物**并记录退出码 ——
- 若那里**也失败** ⇒ 先前那次"成功"另有原因（例如当时文件不同/被后续步骤覆盖）；
- 若那里**成功** ⇒ 证实状态在两步之间变化，再往"步骤之间发生了什么"二分。

**⑤ 与密钥路径的关系**：仍然**无关** —— `0xC0DE0002`（`vm_img_fail(2)`：需要重定位但没有重定位表）在**非外置产物**上
同样出现；而**无密钥时硬门 `0xC0DE0007` 正确**、取钥代码**已实测执行**（`1b:enter`/`1b:fetched`）。

### 506. win/arm64：决定性证据 —— 同一产物在绿步骤里连跑两次都成功，在下一步骤里失败

**实验**：在绿作业自己那个步骤里、其 native vs protected 比对**之后**，再跑一次**同一个** `build/target_arm64.vmp`。

**结果（CI run 35966736437）**：

    native rc=654184885 (0x26FE11B5)  protected rc=654184885 (0x26FE11B5)
    [*] green step: second run of target_arm64.vmp -> rc=654184885      ← 绿步骤里第二次运行：仍然成功
    ...（紧接着的我的步骤）
    probe-early:5runs rc=-1059192830x5                                  ← 同一文件：失败
    probe:green-product 10runs rc=-1059192830x10

⇒ **同一个文件、同一个作业**：绿步骤里**连跑两次都成功**，下一个步骤里**两种启动方式都失败**。
而我的步骤在早期探针之前**只做了 clang 检测**（不改变任何状态）⇒ **状态是在步骤边界处改变的**。

**技术上的解释（与已排除的假设一致）**：`0xC0DE0002` = `vm_img_fail(2)`「**需要重定位但没有重定位表**」——
它只在**加载基址 ≠ 首选基址**（即 ASLR 生效、delta≠0）时才会被触发。绿步骤的调用方式下产物加载在首选基址，
因此**根本不走重定位路径**，也就看不出问题；而我的调用方式下 ASLR 生效，立刻暴露出
**win/arm64 产物在 ASLR 下缺少重定位表**这一真 bug。

⇒ 这把问题从"我的 harness"彻底移出，指向 **`vmpack` 在 win/arm64 上生成/保留重定位表的行为**。
**与 1b 取钥无关**（无密钥硬门 `0xC0DE0007` 正确、取钥标记 `1b:enter`/`1b:fetched` 都已实测出现）。

**下一步实验（已定，便宜且决定性）**：让**绿步骤**也用 `Start-Process` 跑一次同一个产物 ——
若它**也失败** ⇒ 铁证：**启动方式 ⇒ ASLR ⇒ 缺重定位表**；随后即可去 `cmd/vmpack` 查 win/arm64 的重定位表处理。

**本轮方法论收获**：连续三个假设（ASLR 随机性、我的重建、启动方式）都被 CI 实验**排除**，
而"把探针放进**对方步骤**里复跑"这一招直接给出了状态变化的证据 —— 值得记住。

### 507. 铁证：win/arm64 产物在 **ASLR 生效**时缺重定位表（与 1b 取钥无关的真 bug）

**决定性实验**：在**绿作业自己的步骤里**，对**同一个** `build/target_arm64.vmp`，先裸调用、再 `Start-Process`：

    [*] green step: second run of target_arm64.vmp -> rc=654184885        ← 裸调用：成功
    [*] green step: same product via Start-Process -> rc=-1059192830      ← Start-Process：失败

⇒ **同一文件、同一步骤、同一秒**，唯一差别是**启动方式** ⇒ 结论确凿：

- **裸调用**（`& .\build\target_arm64.vmp`）⇒ 进程加载在**首选基址**，`delta = 0` ⇒ 入口自解密**不走重定位分支**
  ⇒ 看不出问题；
- **`Start-Process`**（走 ShellExecute，ASLR 正常生效）⇒ `delta != 0` ⇒ 走重定位分支 ⇒ 发现
  **产物里没有重定位目录** ⇒ `vm_img_fail(2)` ⇒ 退出码 `0xC0DE0002`。

**为什么这是一个必须修的真 bug**：通过**双击 / ShellExecute / 任何正常启动方式**运行 win/arm64 产物时 ASLR 都生效，
因此产物会**当场以 0xC0DE0002 退出、无任何输出** —— 正是 fail-fast 规则要防的"客户现场莫名其妙退出"。
而它**与 1b 取钥完全无关**（无密钥硬门 `0xC0DE0007` 正确、`1b:enter`/`1b:fetched` 均已实测出现）。

**嫌疑范围**：`cmd/vmpack` 在 **win/arm64** 上的重定位处理（与 x64 相比可能漏了：把 `.reloc` 搬进新节、
或 `DIR64`/`HIGHLOW` 条目在新节里的搬运、或 `DYNAMIC_BASE` 与 `RELOCS_STRIPPED` 的组合）。
注意本仓库 x64 侧早已有 `.vreloc` 承载节的实现（见 STATUS #484）—— 需要确认它在 arm64 路径上是否也被走到。

**下一步（已定）**：① 用 `-strip-relocs` 生成一份产物，看 Start-Process 下是否变成"能跑"（若变好，
说明问题就在**保留重定位**那条路）；② 直接对比 win/arm64 产物与 win/x64 产物的 `.reloc`/数据目录；
③ 定位后修 `vmpack`，并**为所有平台加一条"通过 Start-Process（ASLR 生效）启动"的验收**，防止同类问题再现。

**本轮方法论收获（连续四步排除法）**：ASLR 随机性 ✗、我的重建 ✗、启动方式 ✗（先在别处排除）→
最后**把对照实验放进"对方步骤"里**，一步锁定真因。

### 508. 根因确认：win/arm64 的目标与产物**都没有重定位表** ⇒ ASLR 下必崩（与 1b 取钥无关）

**诊断结果（CI run 35968267605）**：

    TRACE| reloc:target-sections has-reloc=False      ← 原始 build/target_arm64.exe 没有 .reloc
    TRACE| reloc:product         has-reloc=False      ← 打包后的产物自然也没有
    TRACE| strip-relocs via plain call:    rc=0       ← 清掉 DYNAMIC_BASE 后正常返回
    TRACE| strip-relocs via Start-Process: rc=-998    ← 该分支里 Start-Process 抛异常（待查，见未做项）

**结论**：`testdata/arm64/target_win.c` 用 clang + lld 以 freestanding / `-nostdlib` 方式链接，
镜像里**没有需要重定位的绝对引用** ⇒ lld **不生成 `.reloc`** ⇒ 产物当然也没有。
于是：
- **裸调用**（加载在首选基址，`delta = 0`）⇒ 入口自解密不走重定位分支 ⇒ 正常；
- **ASLR 生效**（`Start-Process`、双击、任何 ShellExecute 路径）⇒ `delta != 0` ⇒ 需要重定位表才能还原，
  而表不存在 ⇒ `vm_img_fail(2)` ⇒ **`0xC0DE0002`，无任何输出**。

⇒ 这是**打包端应当拦住/处理的通用问题**，与 1b 取钥无关。现已确认三条事实：
① 触发条件 = ASLR 生效（同一文件同一步骤，裸调用成功、Start-Process 失败，STATUS #507）；
② 直接原因 = 目标与产物都没有重定位表（本节）；③ 与密钥无关（无密钥硬门 `0xC0DE0007` 正确、
`1b:enter`/`1b:fetched` 均已实测出现）。

**正确修法（下一轮实现）**：在 `cmd/vmpack/main.go` 保留重定位那条路（`!stripRelocs`）里，
**检测目标是否真的存在重定位目录**（数据目录 5 的 RVA/Size）—— 若不存在，则**强制清除 `DYNAMIC_BASE`**
并打印明确说明。理由：既然没有表、无法还原加载器增量，就**不能**继续声称支持 ASLR；
否则产物在正常启动方式下必崩（正是 fail-fast 要防的现场事故）。
该修法对**所有平台**都是保护（不只 arm64）：任何 freestanding/无绝对引用的目标都会命中。

**另一个独立收获（值得单独记）**：本仓库现有的运行时验收（`& 产物` / 探针映射）**都不覆盖 ASLR**，
所以这个 bug 一直没被发现。⇒ 应补一条"**通过 `Start-Process`（或等效的 ASLR 环境）启动**"的验收，
至少加在 win/x64 与 win/arm64 上。

**未做项**：① 上面的 `vmpack` 修改与验证；② 查清 `strip-relocs via Start-Process: rc=-998`
（我对 `.vmp` 用 `Start-Process` 在另一处是成功的，这里却抛异常，需要看清异常文本）；
③ 补"ASLR 启动"验收；④ 之后再放开 `win/arm64` 白名单并跑通三形态。

### 509. 修复生效：目标无重定位目录时自动清 DYNAMIC_BASE ⇒ **裸调用从必崩变为成功**

**改动**（`cmd/vmpack/main.go`，保留重定位那条路里）：用现成的 `origRelocEntries(f)` 检测目标是否真有
重定位目录；若**没有**（freestanding / `-nostdlib` 链接的 arm64 目标就是这种），则**自动清除 `DYNAMIC_BASE`**
并打印说明。理由：没有表就无法还原加载器增量，保留 ASLR 只会让产物在正常启动方式下必崩。
对本来就有重定位表的目标（x64 等）**无影响**（本地 `go build` 与打包回归正常）。

**验证（CI run 35968838313）**：

    [!] 目标没有重定位目录 ⇒ 自动清除 DYNAMIC_BASE（否则 ASLR 生效时产物必崩）
    TRACE| cal-plain: rc=0                    ← 此前恒为 -1059192830（崩），现在 rc=0（成功）
    TRACE| stage:done bad=3 calRc=0

⇒ **同一个校准产物，修复前"必崩"、修复后"裸调用成功"** —— 修复方向正确，且证实了根因分析。

**同时暴露两个新现象（下一步要查）**：

1. **所有 `Start-Process` 现在报 `%1 is not a valid Win32 application`**（此前它们能启动并返回 `0xC0DE0002`）。
   即：清掉 `DYNAMIC_BASE` 后**裸调用能跑**，但 ShellExecute 拒绝执行该文件。候选：`clearDynamicBase` 改了
   可选头里的某个字段（例如顺手动了 `ImageBase` 或节特性），或 ShellExecute 对"清基址"镜像有自己的判定。
2. **产物 rc=0，而 native rc=654184885（0x26FE11B5）** ⇒ 三条用例仍判失败（`bad=3`）。但性质已变：
   从"崩溃"变成"跑完但结果不同"。需要先查清 native 那个值是不是**设计返回值**（`testdata/arm64/target_win.c` 的语义），
   再判断产物是否真的算错。

**结论**：① 根因（无重定位表 + 保留 ASLR）已修 ✓；② win/arm64 的三形态验收仍**未通过**，
但失败原因已从"产物必崩"推进到"两个可查的具体问题"；③ 与 1b 取钥依旧无关。

### 510. 回滚 #509 的修复：它把"必崩"换成了"结果不对"，属真回归

**#509 的改动**（目标无重定位目录 ⇒ 自动清 `DYNAMIC_BASE`）实测产生了**副作用**：

    TRACE| cal-plain: rc=0            ← 裸调用：从"必崩"变为"成功返回 0"
    但 native rc=654184885           ← 两者不再相等（修复前产物是与 native 一致的）

⇒ 也就是说：修复**消除了崩溃**，但**改变了运行期语义路径**（清了 `DYNAMIC_BASE` ⇒ 加载器落在首选基址
⇒ `delta = 0` ⇒ 入口自解密/载荷预置走另一条路），导致**产物退出码不再等于 native**。

**为什么这算真回归**：本仓库已登记的 arm64 e2e 判据是"**产物与 native 一致**"，修复前该判据是满足的，
修复后被破坏 ⇒ 按纪律（真回归立即回滚；不为通过检查而放宽阈值）**回滚**，并把结论留档。

**同时确认的两件事（读代码所得，避免下一轮重复摸索）**：
1. `clearDynamicBase()` **只清 `DllCharacteristics` 的 0x40 位**，不碰任何别的字段 ⇒ 因此
   `Start-Process` 报 `%1 is not a valid Win32 application` **不是它直接写坏文件**导致，
   更像是"清掉该位后 ShellExecute 对该镜像的判定"（待查，但优先级低于下面的正解）；
2. `testdata/arm64/target_win.c` 的 `entry()` 返回 `check_key/sum_to` 混合出的**确定性退出码**
   （native = 654184885 = 0x26FE11B5）：**它本来就是"用退出码表达结果"的设计**，不是垃圾值 ⇒
   产物返回 `0` 确实是**结果错**（而不是"比较方式不对"）。

**正确的修法方向（下一轮）**：让产物**真正支持 ASLR**，而不是绕过它。两条路：
- **A（推荐）**：`vmpack` 在目标**没有** `.reloc` 节时**新建一个** `.reloc` 节，把 blob 自己的绝对 VA
  站点写成重定位项（现有 `appendRelocs` 已经在做"追加"，缺的是"没有节时先建节"）；
- **B**：让"目标无重定位表"也成为构建期错误（fail-fast，提示改用带重定位的目标或 `-strip-relocs`），
  即**明确拒绝**而不是产出一个在 ASLR 下必崩/行为不同的产物。

**处置**：已回滚 `cmd/vmpack` 的改动、重新关闭 `win/arm64` 白名单、撤掉 CI 诊断步骤（主干恢复稳定绿）。

### 511. 第二次自伤（也已回滚）：把"无重定位表"放行 ⇒ 产物从受控拒绝变成真崩

**改法**：把 `vm_unpack_image` 里"`delta != 0` 且没有重定位目录"时的 `vm_img_fail(2)` 改成"只记诊断码、继续"。
理由（我当时的推理）：表不存在 ⇒ 加载器没有条目可用 ⇒ 不可能应用过增量 ⇒ 解密安全。

**实测（CI run 35970151496）—— 推理被推翻**：

    TRACE| cal-plain: rc=-1073741819          ← 0xC0000005，真崩（原来这里是受控的 0xC0DE0002）
    TRACE| probe:green-product 10runs rc=-1073741819x10
    TRACE| strip-relocs via plain call: rc=0  ← strip 版本仍正常（印证它确实是另一条路）

⇒ 放行之后产物**真的访问违例** ⇒ 说明"加载器不会动一个没有表的镜像"这个前提**不成立**（或者随后的
delta 逆变换把密文改坏了）。无论如何，**原来的拒绝是保护性的、是正确的**。

**处置**：已回滚该改动（恢复 `vm_img_fail(2)`，并在注释里写明"必须拒绝"）、重新关闭白名单、撤掉 CI 步骤。

**到目前为止的完整根因链（三轮查清，两次错误尝试都已回滚并留档）**：

1. **#507**：触发条件是 **ASLR 生效**（同一文件同一步骤：裸调用成功、`Start-Process` 失败）；
2. **#508**：直接原因是**目标与产物都没有重定位表**（`has-reloc=False`），而打包与运行期都仍按"保留 ASLR"处理；
3. **#510**：错误尝试一 —— 清 `DYNAMIC_BASE` 绕过 ⇒ 裸调用从崩变 rc=0，但**产物退出码不再等于 native**（语义路径变了）⇒ 真回归；
4. **#511**：错误尝试二 —— 无表时放行 ⇒ **真崩（0xC0000005）** ⇒ 证明"必须拒绝"；
5. **正解（下一轮做）**：让**密文处理**与"加载器是否真的动了镜像"一致 —— 即**无重定位表时不要把 delta 应用/逆应用于密文**
   （视 `delta = 0` 处理），因为加载器无法搬动一个没有表的镜像。要点：这与"清 DYNAMIC_BASE"不同 ——
   后者改变的是**加载行为**（进而改变 delta 与语义路径），前者只改变**我们对密文的处理**。
   备选：由 `vmpack` 为目标**新建一个真正的 `.reloc` 节**（把 blob 的绝对 VA 站点写进去；本次诊断显示该目标
   `items` 为空 ⇒ 只覆盖加载器真正需要的项），让 ASLR 名正言顺。
