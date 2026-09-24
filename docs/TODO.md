# TODO —— 已登记待办

> 纪律：每条都要有「为什么 / 验收标准 / 证据落点」三件套。做完就把这条从这里删掉，
> 过程与证据写进 `docs/STATUS.md`（编号追加，不覆盖历史）。
> 本文件是**待办清单**；任务书（授权范围、验收口径）仍以 `docs/HANDOFF.md` 为准。
>
> **状态汇总（2026-xx 重评后）**：必做 **4** 项、建议做 **3** 项、按需/待决策 **6** 项、可砍 **1** 项；已完成 **4** 项。
>
> **重评结论（关键）**：清单里最要紧的一条原本**不在清单上** —— 我们缺一道**"保护前逐函数差分自检"**。
> 证据：`/Od` 构建下 `DemoFormatReport` 被**成功保护**却算错（`score=8` vs 原生 42）✗ ——
> 也就是说现在的工具会**静默产出错误的受保护程序**。对客户来说这是最危险的一类缺陷（比"拒绝保护"危险得多），
> 所以它被提到必做第 ④ 条：**保护前先跑一遍"原生 vs VM"对比，不一致就拒绝保护并点名那个函数**。
>
> | 分类 | 项 | 判断依据 |
> |---|---|---|
> | **必做（技术正确性）** | ① `CDQ/CQO/IDIV/DIV` lift　② `/Od` 栈传参/varargs　③ `CVTDQ2PD`/double　④ **保护前逐函数差分自检（fail-closed）** | ①②③ 直接卡住客户 demo 里的 `Gcd`/`IsPrime`/`FormatReport`/`Mean`；④ 把"静默算错"变成"明确拒绝" |
> | **建议做（产品化）** | ⑤ 母狗/工具私钥保护（DPAPI/TPM）+ `--key-from-dongle`　⑥ 接客户自己的 `verify.py`/`ground_truth`，产出**逐函数可保护性清单**　⑦ `export` 发版包 + CI 核对 `epochs.json` | ⑤ 现在私钥是明文文件，复制即绕过工具授权；⑥ 是给客户看的"自证材料"；⑦ 交付与防发错纪元 |
> | **按需/待决策** | ⑧ Sentinel 接口层（要上狗才做）　⑨ 吊销/黑名单（离线怎么定义要先定）　⑩ `features`（并发/功能点/机器绑定 —— 客户模型里只有"产品+到期"，默认**不做**）　⑪ ELF `.rela` + Linux 反调试　⑫ 外置密钥+DLL / Linux/arm64 取钥　⑬ `vmpepoch which` 支持 ELF　⑭ **PE32（32 位）支持**（客户 `demo32.exe` 被拒：`不支持的 PE 机器类型 0x14C`，这是平台移植不是开关） | 取决于客户实际交付形态；PE32 若客户还有 32 位产品则是**硬门槛** |
> | **可砍** | ⑮ 1b 的"授权回调"形态（与 ⑤ 的 DPAPI/TPM 路线重复，TPM 那半边并入 ⑤） | 避免两条并行路线 |
>
> **已完成**：工具授权（构建凭据）✅、委派签发（canIssue）✅、运行期强制 ✅、商业化闭环可复跑脚本 `tools/acceptance_demo.ps1`（23/23）✅
> **已经过时/删掉**：授权层设计基线里"路线 B 未实现"的描述、运行期强制 WIP 段、Ed25519 描述（已换 ECDSA P-256）、密钥纪元分发策略（已落地）。
>
## PE32（32 位 x86 客户机）评估 —— 硬事实与两条路（本轮实测）

**今天的行为（保持"明确拒绝"）**：`vmpack` 对 PE32 直接拒绝，且提示已改成可操作的两条路径。
拒绝点：`cmd/vmpack/main.go` 的机器类型 switch（新增 `case pe.MachineI386`）。

**本轮已落地（不碰 blob，可测）**：`internal/load/pe` 支持 **PE32 解析** ——
可选头走 0x10B/0x20B 双分支（两格式只有 `ImageBase` 不同：PE32 是 u32 @+28，PE32+ 是 u64 @+24），
新增 `OptMagicPE32`、`MachineI386`、`File.OptMagic`、`File.Is32Bit()`；
回归测试 `internal/load/pe/pe32_test.go`：合成 PE32 用例 + **真实 `C:\Windows\SysWOW64\notepad.exe`**
（实测 `base=0x400000 entry=0x25FF0 sections=6`）。

**硬事实（本轮实测，决定了"最小里程碑"的边界）**

| 事实 | 证据 |
|---|---|
| 本机 **gcc 没有 32 位能力** | `gcc -m32` 失败（`ld` 跳过不兼容的 `libmingw32.a`，ucrt64 只有 64 位） |
| 本机 **没有 clang** | `clang --version` → 命令不存在（CI 里有，arm64 那条路在用） |
| PE32 样本齐备 | `C:\Windows\SysWOW64\notepad.exe`、`D:\demo_exe\demo32.exe`（43 KB） |
| blob 有两条合并路径 | `vmpbuild -merge ld`（x86-64 默认）/ `-merge go`（内置直拼，COFF 用） |
| 现有 blob 平台 | `stub/win/x64`、`stub/win/arm64`、`stub/linux/{amd64,arm64}` —— **没有 32 位** |

**要真正支持 PE32，缺的是四块（按依赖顺序）**
1. **32 位 blob 平台** `stub/win/x86`：VM 解释器 + 入口蹦床（AT&T 内联汇编 ⇒ 需要 GCC/Clang **不能**用 MSVC）；
2. **32 位工具链**：这是当前的**硬阻塞** —— 本机没有 ⇒ 只能在 CI 用 clang
   （`--target=i686-pc-windows-msvc -c`，freestanding 不需要 32 位 libc/头文件）+ `-merge go` 合并；
3. **客户机 x86-32 语义**：解码要切 32 位模式（`golang.org/x/arch/x86/x86asm` 的 `Decode(..., 32)` 支持），
   lift 与栈/ABI 语义（`__cdecl`/`__stdcall`、4 字节指针）要新增一条客户机 ISA —— 参考现有 `-guest arm64` 的结构；
4. **PE32 注入 + 重定位 + 32 位宿主 harness**（`internal/inject` 现在只按 AMD64/ARM64 布局写）。

**两条路（需要你定）**
- **A（推荐，若 PE32 是真实需求）**：在 CI 里把 32 位 blob 编出来（clang + `-merge go`），本地只做 1/3/4；
  代价：本地无法端到端验证 32 位产物 ⇒ 验证只能在 CI 上做（本目标的验收本来就含"CI 五作业全绿"）。
- **B（若 32 位只是"客户顺手提到"）**：保持"明确拒绝 + 可操作提示"，把预算投在 PE64 的深度上。

**更新（目标第 10 轮）—— 已完成 vs 卡点**

**已完成（全部有 `docs/STATUS.md` 证据）**
- ③-a `internal/load/pe` 支持 **PE32 解析**（#423，含真实 `SysWOW64\notepad.exe` 用例）
- ③-b 解码层 **32 位模式**（#424：`0x40-0x4F` 是 INC/DEC 而非 REX、push 宽度、`[disp32]` 是绝对地址而非 RIP-relative）
- ③-c **lifter 32 位模式接线**（#425）
- ③-d 地址/指针宽度按模式（#426）+ **栈槽与栈传参记账**（#431：`push`/`pop` 按模式记 4/8 字节）
- ③-e **客户机 x86-32 模式**：C 与 Go 双端栈槽语义一致，差分**已进 CI 门禁**（#428/#432，覆盖 `PUSH_R` 与 `PUSH_I` 两条路径）
- 真实 32 位代码验证（#433：notepad 解码全对齐；入口翻译走到 5KB+ 后止于数据）

**卡点（需要拍板）**：把 blob 注入**真实 PE32 进程**需要 **32 位 blob**（thunk/trampoline 是 per-platform asm），
而本机**没有 32 位 C 工具链**（`gcc -m32` 失败、无 clang；msys2 的 `pacman` 在）。三条路：

| 路 | 做法 | 代价 |
|---|---|---|
| **A** | `pacman -S mingw-w64-i686-gcc`（可能还要 i686 头文件） | 联网装工具链、**改机器**；换来本地可反复端到端验证 |
| **B** | 只在 CI 用 clang（`--target=i686-pc-windows-msvc -c` + `-merge go`） | 不改本机；本地无法验证，只能靠 CI 迭代（每轮约 5 分钟） |
| **C** | PE32 到此为止，剩余预算回 PE64 深度 | 客户的 `demo32.exe` 继续被明确拒绝 |

**建议**：32 位是**真实客户需求** ⇒ **A**（一次装好，之后每轮本地可验证）；只是"顺手提到" ⇒ **C**。
在拍板之前不擅自改机器（装工具链）。

> **评审请直接看 [`docs/PE32.md`](PE32.md)** —— 收口页：已完成逐项证据、卡点的确切原因、三条路的确切命令与代价与建议。

> 下面第 0–5 节保留**设计基线与历史记录**（很多文字描述的东西已经实现，看上面的表即可知道哪些还没做）。

## 0. 密钥纪元管理工具（客户反馈；工具已交付，剩下可选增强）

状态：**已实现** `cmd/vmpepoch`（见 STATUS #396）—— `new` / `list` / `which` / `keyid`，
登记表 `epochs.json` **不存密钥本身**，只存路径与指纹（sha256 前 8 字节）。

可选增强（按需）：
- [ ] `which` 支持 **ELF** 产物（现在只解析 PE 节表；PE 侧已验证：payload 会被拆成
      代码段 / `.bss` 段 / 表段，所以按"段前缀 vs blob 同长前缀"比对，而不是要求整段装得下整个 blob）。
- [ ] `export`：把一个纪元打成"发版包"（blob + manifest + key + 一页用法说明），便于交付客户。
- [ ] CI 集成：构建时顺带写/核对 `epochs.json`，产物自动断言"用的是预期纪元"（`which` 退出码可直接用）。

## 1. 补 `CDQ` / `CQO` / `IDIV` / `DIV` 的 lift —— 收益/成本比最好

**为什么**：用户自己的 `D:\demo_exe\demo64.exe` 里 `Demo::Math::Gcd`、`Math::IsPrime`
（release 版的 free 函数版本同样）就因为这几条指令无法翻译而被**拒绝保护**；补齐后两个构建都受益。

**现状（实测，lifter 原话）**
- `?DemoGcd@@YAHHH@Z` → `2/13 条指令无法翻译: +0x15 CDQ / +0x16 IDIV R8L`
- `?IsPrime@Math@Demo@@QEAA_NH@Z` → `+0x44 CDQ / +0x45 IDIV [RSP+Reg(0)]`

**进展（本轮）**：`CDQ`/`CQO` **已补**（`internal/lift/x64/lift.go`：`case x86asm.CDQ/CQO` →
`AluRI{Sar, |KeepFlags}` 写到 `RDX`；注意 Go 的 x86asm 里 CDQ/CQO 与 CDQE 是**不同助记符**，原来只处理了 `CDQE`）。
实测：`?DemoGcd@@YAHHH@Z` 的拒译从 **2/13 降到 1/13**（只剩 `IDIV R8L`）✓。

**`IDIV`/`DIV` 的最小改法（已摸清，照这个做）** —— 关键是**不需要新增操作码**：
1. **复用 `OP_ALU_U`**（编码 `[op][kind][width][dst][a]`，5 字节）：`dst` 留空不用（商/余的寄存器由 width 隐含），
   `a` = 除数。这样**不必动** `internal/vm/opcodes.go` / `vm_opcode_values.h` / `vm_opcodes.h` 的 `OP_*` 表 / `disasm.go` / `codegen.go`；
2. 新增两个 ALU kind（接在 `MulHiS` 之后 ⇒ 值 **0x14 / 0x15**）：`ir.DivU`/`ir.DivS`（`internal/ir/ir.go`）；
3. 同步三处（`kind_table_test.go` 会强制三者一致）：
   `stub/win/x64/vm_opcodes.h` 的 `K_DIVU = 0x14, K_DIVS = 0x15`、`internal/vm/ref.go` 的 `KDivU/KDivS`（放最后）+ 映射表、`kind_table_test.go` 的 checks；
4. **语义**（`stub/win/x64/vm_interp.c` 的 `OP_ALU_U` 分支里**先拦截**，别走到 `alu_unary`）：
   被除数 = 隐含的 `DX:AX` 族（按 width 取 `AH:AL` / `DX:AX` / `EDX:EAX` / `RDX:RAX`），商→AX 族、余→DX 族；
5. **除零/商溢出**：**直接 trap**（绝不静默算错；后果与原生未处理 #DE 一致）；
6. **lifter**：`case x86asm.DIV/IDIV` —— 单操作数形式的判据与 `liftImul` 相同（`args[1] == nil`），
   寄存器除数直接进 `A`，内存除数先 `Load` 到 `VMSCR`；**8 位形式（`IDIV R8L`，商 AL/余 AH）最容易写错**，
   客户 demo 两个函数正是 8 位与 32 位各一；
7. **参考实现**（`internal/vm/ref.go` 的 switch）也要补：它被 arm64 差分门禁用到，漏了会红；
8. **验收**：`Gcd`/`IsPrime` 变为"可保护"且进 VM 后与原生逐行一致；`tools/gates.ps1` 11/0。

**验收**：`tools/gates.ps1` 11/0；对 `D:\demo_exe` 的 exe 逐个函数试，`Gcd`/`IsPrime` 变成"可保护"，
且进 VM 后输出与原生逐行一致。

**边界**：除零异常（客户机 #DE）语义暂不模拟 —— 遇到就拒绝翻译并报明确错误，不要静默算错。

## 2. ~~调试版的栈传参 / varargs~~ → **已完成**（真根因是三操作数 IMUL + VM→native 栈参数，见 STATUS #404/#405）

> 结论：原假设「栈传参/varargs」被实测否掉。实际是两个独立的静默算错：
> ① 三操作数 IMUL（内存源+立即数）丢立即数（已修 #404）；
> ② VM 调 native 只传寄存器、native 的栈参数落在宿主栈上（已修：Win64 ABI 蹦床 #405）。
> 验收：客户 demo 的 `/Od` 与 `/O2` 两种构建各自 13 行**逐行一致（不一致 0 行）**。
> 下面是排查过程留档。

**现象（实测，单函数二分确认）**：`/Od /RTC1` 构建下把 `?DemoFormatReport@@YAHPEADHPEBDH@Z` 单独进 VM，
输出 `score=8`（原生 **42**）；**同一个函数在 `/O2` 下是正确的**。

**嫌疑**：该函数形如 `sprintf(buf, n, fmt, score)`，那个 `%d` 参数走**栈**（第 5 个及以后的参数 / varargs），
`/Od` 与 `/O2` 对参数的物化方式不同。

**为什么优先**：任何用 `sprintf`/varargs/参数超过 4 个的函数都会踩 —— 覆盖面最广。

**已复现并定位到指令序列（目标第 3 轮）**
- 复现：`build/demo64/demo64_dbg.exe`（`/Od /Zi /RTC1 /MDd`）只把 `?DemoFormatReport@@YAHPEADHPEBDH@Z` 进 VM →
  输出 `[DEMO_MARKER_ALPHA] score=8`，原生是 `score=42`（**静默算错**）。
- `dumpbin /disasm` 出来的函数体就是经典的 **varargs「home + 转发」** 序列（`/Od` 特有）：
  ```asm
  mov dword ptr [rsp+20h],r9d      ; 把入参 4 存进「调用者给的 shadow space」
  mov qword ptr [rsp+18h],r8
  mov dword ptr [rsp+10h],edx
  mov qword ptr [rsp+8],rcx
  push rdi
  sub  rsp,30h
  mov  eax,dword ptr [rsp+58h]     ; 读回第 5 个参数（= 上面自己 home 的那格）
  mov  dword ptr [rsp+20h],eax     ; 转发给被调用者
  mov  r9,[rsp+50h] / mov r8d,[rsp+48h] / mov rdx,[rsp+40h] / lea rcx,[...]
  call @ILT+70(?FormatReport@Math@Demo@@QEAAHPEADHPEBDH@Z)
  add  rsp,30h / pop rdi / ret
  ```
  关键点：home 写的是 `rsp_entry+8..+0x20`（调用者的 shadow space），`push rdi`+`sub rsp,30h` 之后
  再用 `[rsp+0x40..0x58]` **原样读回** —— 也就是**同一批绝对地址**，与调用者是否真的压了栈无关（自洽）。
  所以问题出在 **VM 对这段「push/sub + 以当前 rsp 为基准的 4/8 字节存读」的建模**上，
  而不是「VM 拿不到调用者的栈参数」。

**真根因（目标第 3 轮，用合成函数隔离后确定；原「栈传参/varargs」假设已被实测否掉）**

隔离实验结果（`/Od`，逐个函数单独进 VM）：

| 函数 | 原生 | 受保护 |
|---|---|---|
| `five(a,b,c,d,e) = e`（读第 5 个栈参数） | 42 | **42** ✓ |
| `sum5`（5 个参数全用） | 52 | **52** ✓ |
| `va_sum` / `va_last`（varargs） | 52 / 42 | **52 / 42** ✓ |
| `four(a,b,c,d) = a + b*2 + c*3 + d*4` | 30 | **27** ✗ |

**根因 1（已修，STATUS #404）**：`liftImul` 的**内存操作数分支丢立即数 + 被乘数写错**。
`imul ecx, dword ptr [rsp+18h], 3` 被翻译成 `ecx = ecx × mem`（应为 `mem × 3`）——
代入 `four` 得 `(1+4)+6 = 11`、`+16 = 27`，与实测完全吻合。已修 + 加 IR 级回归测试
（`internal/lift/x64/imul_mem_test.go`）。

**根因 2（已定位，未修 —— 下一轮的主任务）**：**VM 调用 native 函数时只传寄存器参数**。
`stub/win/x64/vm_interp.c` 的 `OP_CALLN` 直接 `fn(rcx,rdx,r8,r9,r10,r11,r12,r13)`，
于是 native 被调者读自己的**栈参数**时落在宿主 C 栈上（实测 `caller5(x){return five(1,2,3,4,x);}`
→ native 42、受保护 **1**）。客户 demo 的 `/Od` 症状（`score=8` 应为 42）就剩这一处：
`DemoFormatReport` 把 `score` 当**第 5 个参数**转发给 native 的 `Math::FormatReport`。

**修法（下一轮）**：给 `OP_CALLN` 加 ABI 蹦床 —— 切到 guest 栈、压一个返回地址、装载寄存器参数后再 call，
返回后恢复宿主 rsp；并处理 `FrameSkew`（guest 栈相对原生栈的偏移）。

**已知 flaky（要修）**：`tools/e2e.ps1` 的反调试用例（`antidebug: a single BeingDebugged signal flipped the verdict`）
本会话已偶发三次（每次重跑就好）。时间差路径已降级为只诊断，但仍有第二条路径在某些运行环境下同时命中，
使"只注入一个信号"的断言失败。要把它做成确定性用例（或明确哪些路径在该环境下不该参与定性）。

**验收**：`DemoFormatReport` 在 `/Od` 与 `/O2` 两种构建下都逐行一致；
`caller5`/`caller5b` 合成用例与原生一致；并把它加成 `tools/e2e.ps1` 的用例。

## 3. `CVTDQ2PD` / double 路径

**现象**：`?DemoMean@@YANPEBNH@Z` 进 VM 后输出 `0.000`（原生 3.500）；lifter 报
`+0x66: CVTDQ2PD X1, X1 — 暂不支持该指令`。

**要做**：至少补齐 `CVTDQ2PD`（int32→double）与其配套的 SSE2 双精度路径，并单测。

## 4. 修完 1、2 后，用 `D:\demo_exe` 复跑全量验收

> **已完成（目标第 10 轮）**：①-⑤ 全部收口 —— 详见 `docs/STATUS.md` #402/#404/#405/#406/#407/#409/#410。
> 验收口径：以客户自己的 `run_demo64.exe.txt` 为期望值，`/O2` 与 `/Od` 各 14 个函数 = 可保护 14 / 静默算错 0 / 被拒 0；
> `tools/diffcheck.ps1` 已挂进 `tools/e2e.ps1` 做永久自检；gates 11/0；CI 五作业全绿。
>
> 留档：早先的进展说明 —— 已交付 `tools/diffcheck.ps1` —— 逐函数「原生 vs 受保护」自动比对，
> 输出 `OK / WRONG（点名+首处差异）/ REFUSED（附缺哪条指令）` 与 `report.csv`（即可保护性清单）。
> 实测客户 demo：`/O2` = 14 可保护 / 0 算错；`/Od` = 13 可保护 / 1 算错（点名 `?Mean@...`）。
> 待做：接进 `tools/e2e.ps1`；把客户自带的 `verify.py`/`ground_truth_exe.txt` 作为期望值来源（而不只是比自身输出）。

把用户自带的 `verify.py` 流程接进来：`demo32.exe` / `demo64.exe` 两个构建都跑，
连 `ground_truth_exe.txt`、`run_demo32.exe.txt`、`run_demo64.exe.txt` 一起逐行比；
产出一份"哪些函数可保护 / 哪些被拒绝（附缺哪条指令）"的清单。

## 其他已登记（来源见括号，优先级低于上面 1–3）

- [ ] ELF 侧 `.rela.dyn/.rela.plt` 的"先减后加"应用器（现状：ELF PIE 能用是因为测试目标落在加密节里的重定位项恰好没有）。(`STATUS #390`)
- [ ] Linux 侧反调试：`/proc/self/status` 的 `TracerPid`（现在四条路径都是 Windows 目标）。(`STATUS #389`)
- [ ] 外置密钥 + DLL 组合；Linux/arm64 的取钥路径。(`STATUS #385`)
- [ ] 1b 的其余取钥形态：授权回调、TPM/TEE 封印（接缝已是 `vm_key_from_file()` 一个函数）；本次对话拟定的过渡方案是 **DPAPI 包装的密钥文件**。(`STATUS #385/#393`)
- [x] `-key-in` 的"密钥纪元"策略：`vmpepoch new` 建纪元、`which` 认领产物、按 `<产物>.vmpkey` 分发 —— 已在 `tools/acceptance_demo.ps1` 里端到端演示（`STATUS #395/#400`）。

## 5. 授权层（License Layer）—— 设计基线与**剩余未做项**
### 417. Sentinel 接进 blob 的设计与执行清单（本轮完成设计，实现留下一轮）

**先回答客户的问题：以后不用 Sentinel，改动麻烦吗？—— 不麻烦，前提是别"编译进产物"，而是做成数据驱动的可选后端。**

| 做法 | 以后不用 Sentinel 的代价 |
|---|---|
| 编进产物 + 链接导入库 + 无条件走狗 | 改代码、去链接、重测 —— 麻烦 |
| **动态加载**（`ntdll!LdrLoadDll` 取 `hasp_*.dll`，无导入表）+ **按烘进产物的 `kind` 路由** + 复用**已有的取密钥接缝** | 不写那个 `kind`（或删掉带标记的那一段）即可；不带 kind 的产物行为与今天完全一致 |

**已就绪（Go 侧，STATUS #416）**：`internal/sentinel`（抽象 + 假后端 + Windows 真后端）+ `vmpepoch dongle-probe` +
`vmpbuild -key-in dongle:<fileID>:<offset>:<length>`（构建期主密钥直接从狗里读、不落地）。

**blob 侧的执行清单（下一轮照做）**
1. 在 `stub/win/x64/vm_interp.c` 的 `VM_KEY_EXTERNAL` 分支里、`vm_key_from_file()` **之前**插入一段带标记的代码
   （`/* ---- Sentinel 后端（可选） ---- */`，约 120 行，删掉这一段即可移除该能力）：
   - `vm_key_src_t vm_key_src`（`kind/feature/fileID/offset/length/vendorCode[64]/dllName[64]/fakePath[128]`，
     与 `vm_license_meta` 同款：`.data` + `used` + vmpack 打开开关并填字段）；默认全零 ⇒ 不启用；
   - `kind=2`（真狗）：`vm_find_module(dllName 或 "hasp_windows.dll")` → 没有就 `vm_load_lib(...)`（文件里已有）→
     `hasp_login(feature, vendorCode, &h)` / `hasp_read(h, fileID, offset, 32, buf)` / `hasp_logout(h)`；
   - `kind=3`（假狗文件，**让没有真狗也能测正例**）：路径用 `\??\...` 形式，直接复用已有的 `vm_key_read_nt()`；
   - 失败按阶段记 `vm_sentinel_fail_stage`（0x5x/0x6x），统一走 `vm_key_reject()`（同一个硬门）。
2. 把 `vm_key_from_file()` 的开头改成：`if (vm_key_src.kind >= 2) { 取到就 copy 进 vm_master_buf 并 return 1; }`
   —— 只碰这一个接缝，文件/环境变量那两条路原样保留。
3. `vmpack` 新增：`-key-dongle <fileID>:<offset>`、`-dongle-vendor-code <vc>`、`-dongle-feature <n>`、
   `-dongle-dll <name>`、`-dongle-fake-file <path>`（kind=3，测试用）；照 `vm_license_meta` 的做法在补丁后**重算自哈希**
   （自哈希覆盖 `[0, bssOff)` 含 `.data` —— 这一点在 #399 已踩过）。
4. 验收：① kind=3 正例（假狗文件里放 32 字节主密钥）→ blob 构出来、产物能跑；
   ② kind=2 但没有狗/DLL → **明确拒绝**（0xC0DE0007，无输出）而不是静默退回文件；
   ③ 不写 kind → 行为与今天逐字节一致（现有 gates/e2e 不受影响）。

**仍未做（另一条线）**：真狗的**授权查询**（`hasp_get_info`/`hasp_get_size`）与 blob 侧"问狗要授权"
### 420. 「狗参与解密」的设计与执行清单（本轮只登记，未动主干）

**为什么这一轮没做**：本仓库 AGENTS.md 明确要求「不要在上下文/预算不足时动主干 —— 宁可只做零风险登记」，
而这一条恰好属于**打包端与运行期必须同一轮改完并端到端验证**的改动（字节码密钥来源，见下）。
当前会话预算已见底 ⇒ 只登记，不动代码。

**现状（已经查清，含行号）**
- 字节码用 ChaCha20 加密，密钥是 **32 字节、来自 blob manifest** ⇒ **就在产物里** ✗；
- 运行期：`vm_bcs_init(vm_bcs_t *s, const vm_ctx_t *vm)`（`vm_interp.c:1193`）把密钥填进 `vm_bcs_t.keybuf[32]`（`:1167`），
  取指走 `vmb_byte/vmb_rd32/vmb_rd64`（`:1174`-`:1189`）流式还原，**内存里没有明文字节码**（这条设计要保住）；
- 主密钥那条路已经通了（#418/#419）：`vm_key_src.kind=2` 真狗 / `kind=3` 假狗文件，严格模式不回退。

**要做的改动（下一轮，一轮做完并端到端验证）**
1. `vm_key_src` **末尾追加** `u32 bcFileID, bcOffset`（已有偏移不变）；
2. 运行期：`vm_bcs_init` 处 —— 若 `kind>=2` **不再用 manifest 里那把**，改成从狗读 32 字节当字节码密钥
   （真狗 `hasp_read(bcFileID, bcOffset, 32)`；`kind=3` 走 `vm_key_read_nt` 读假狗文件的对应偏移）；
   读不到 ⇒ **直接硬门，不回退**（保持严格模式）；
3. 打包端（**必须同一轮**）：`vmpack -dongle-bc-key <fileID>:<offset>` —— 用 Go 侧 `internal/sentinel`（真狗或假后端）
   把同一把密钥读出来，作为**字节码加密密钥**（替换现在烘在 manifest 里的那把），并把 `bcFileID/bcOffset` 写进元数据；
4. 验收三条：①）假狗里放**正确**的字节码密钥 ⇒ 产物正常跑；②）假狗里放**错误**密钥 ⇒ **解不开**（不是"拒绝"而是"取不出明文"）；
   ③）`kind=0` ⇒ 行为与今天逐字节一致（现有 11 道门禁不受影响）。

**做完这一条之后**：强度从「没狗**拒绝**」变成「没狗**解不开**」—— 到那时"有没有把 Sentinel 编译进去"就彻底不是安全问题了。
**可拆性**仍然成立：删掉带标记的 Sentinel 段 + 不烘 kind ⇒ 回到今天。

（替换/补充现在的 `<产物>.vmplic.bin` + ECDSA 验签）。


> **现状**：路线 B（纯软件）的授权工具链 + 两级 PKI + 委派签发 + **运行期强制**都**已实现**（STATUS #397–#400）。
> 本节余下的未做项只有：**Sentinel 接口层（路线 A）**、`features` 语义、**吊销/黑名单**、母狗私钥在构建机的保护。
> 其余文字是设计基线与事实核对记录（含 Thales 官方文档口径），保留备查。

**客户的实际产品模型**（照抄客户原话整理）：
- 客户（我们记为**厂商**）卖的是加密工具（vmpbuild/vmpack）；
- 厂商给**每个一级客户**一把主密钥：客户A→key-A、客户B→key-B；
- 一级客户用 `vmpbuild -key-in key-A` 保护自己的**多套软件**；
- 一级客户又有自己的**下游客户**（A-A、A-B…），各拿到针对自己的一把密钥（key-A-A、key-A-B…），
  通常放在 **HL（硬件锁/加密狗）** 里；
- **需求 R1**：一级客户的产品**升级/更新**后，下游客户（A-A、A-B）**不需要换密钥**就能用新版；
- **需求 R2**：A-A 后来又买了 A 的**另一个软件产品 B**，需要"更新授权"——
  但 `key-A-A` 在 HL 里**改不了**，所以**要能单独更新"授权"而不动锁里的密钥**。

**现状对照（务必如实告知客户）**
- **R1 已经满足**：产物自带解释器，密钥是"身份"，所以**同一把密钥 + 复用同一套 blob（或用 `-key-in` 重建）**
  就能覆盖该产品线的所有版本 —— 下游不需要任何操作。见 `STATUS #394/#395` 的实测。
- **R2 部分满足，"授权可单独更新"这条不满足**：
  - 现在"授权"就等于"你手里有那把密钥"——**谁拿到密钥，谁就能跑所有用它打的产物**；
  - 因此"给 A-A 增加产品 B"目前的做法是：**给 A-A 的密钥打一份 B 的产物发过去**（锁不用动 ✓）。
    这能实现"授权扩展"，但**没有到期、吊销、机器绑定、按产品限缩**这些能力 ✗。
  - 真正的"授权文件"（许可证）**尚未实现** ✗。

**设计基线：对齐 Sentinel HASP 的"Vendor Code + 母狗/子狗"模型**（客户点名要这个模式，已核对事实口径）

*角色与持有物*

| 角色 | 持有 | 作用 |
|---|---|---|
| **母狗**（一级客户/开发商） | `vendorID`、`vendorMasterKey`（构建期加密）、`licenseSigningKey`（签发子狗授权）、`vendorPublicKey` | 用它保护自己的软件、给下游签发授权 |
| **子狗**（下游客户） | `dongleID`（下游身份）、`vendorID`（防串用）、`products[{productID, expiry, 可选 feature/计数}]` + **母狗签名** | 决定"这台机器能跑哪些产品、到什么时候" |
| **受保护产物** | 用 `vendorMasterKey` 加密；烘进 `vendorID` + `productID` + `vendorPublicKey` | 同一份产物发给**所有**下游 |

*为什么"一份产物发所有下游"成立（这是与现状最大的差异）*：授权数据在**狗**里（可改），
产物只负责判定三条：`vendorID` 是否匹配、`productID` 是否在授权列表里、是否未过期。
于是"下游增购产品"= **在狗里增删 productID 与到期时间** ✓，**不用重新打包、不用换狗** ✓✓。

*与现状的对账*

| 能力 | 现状 |
|---|---|
| 构建期用母狗的密钥 | ✅ `vmpbuild -key-in`（将来换成"直接从狗里取"） |
| 按产品分密钥材料 | ⚠️ 现在按 `funcRVA` 派生；把 `productID` 纳入 KDF 域只是加一层（小改） |
| 产物烘 `vendorID/productID/publicKey` | ❌ 未做（描述符 64 字节已排满，应像 verify table 那样另立一张表） |
| 运行期验签 + 比对授权 | ❌ 未做 |
| **"一份产物发所有下游"** | ❌ **现状做不到**（现在是"一把密钥一版产物"，按授权方分别打包） |
| 到期 / 机器绑定 / 吊销 | ❌ 未做 |

*两条实现路线（建议先抽出接口，再选实现）*

- **A. 接硬件狗厂商 SDK**（Sentinel LDK / Virbox / 深思等）：安全存储、签名、甚至"狗内 AES 加解密"
  都由狗完成，blob 只需调厂商 API ✓ 工作量小；代价：依赖厂商 DLL/驱动 + 采购与物流。
  **这是客户的最终形态，推荐作为目标。**
- **B. 自研软件授权层（纯文件，过渡形态）**：产物侧加 `-license-vendor/-license-product/-license-pubkey`，
  授权文件 `<产物>.vmplic` = `{vendorID, dongleID, products[], expiry}` + **Ed25519 签名**；
  运行期在 `vm_master()` 之后加 `vm_license_check()`，不通过走同一个硬门。
  成本：打包端用 Go 标准库 `crypto/ed25519`（几行）；**blob 侧要写 Ed25519 验签（约 600–900 行 C，含两侧 KAT）**。
  已知短板（必须如实告知）：文件可复制（无硬件绑定就挡不住拷贝 ✗）、到期可被改系统时间绕过 ✗（需配合机器绑定/联网校验）。

**接口抽象（无论走 A 还是 B 都该先做）**：把"**从哪里拿授权 + 谁来验签**"收成一个接缝
（与现有 `vm_key_from_file()` 同一思路）：`vm_license_fetch()` + `vm_license_verify()`。
B 用文件 + blob 内 Ed25519；A 换成狗 API。将来换形态不动加密层与 VM 层。

**验收标准（动手前必须先和客户确认边界）**
- 最低：覆盖"一份产物发所有下游 + 下游授权可单独增删 productID/到期，且不动软件、不动狗里的密钥"；
- 逐条确认并按条写 e2e：到期、机器绑定、并发/次数、功能点（feature）、吊销（黑名单随新版产物下发？还是联机？）；
- 安全验收：下游**无法自行伪造/篡改**授权（改签名、加 productID 都要失败）；
  以及**串用**必须被拒（客户B 的狗跑客户A 的软件 → 拒绝）。

**客户已确认的 4 个问题（2026-09 访谈）**
1. **最终不一定上硬件狗** —— 取决于 vmp-x 自身够不够硬（见 `docs/STRENGTH.md`：够用就纯软件授权，不够就上狗）；
   **若上狗优先 Sentinel，而且客户本身就是 Sentinel 的一级客户（已有母狗 + 子狗）** ✓
   => 路线 A **不需要自研签名**：直接用 Sentinel 的 feature/写狗工具管理授权，blob 侧调 Sentinel API 即可。
2. **授权粒度要细、并留接口** —— 授权结构里预留了 `features`（并发数/功能点/机器指纹…）；
   当前先用 `products[{productID, expiry}]`，加字段不破坏签名（结构体字段序固定）。
3. **母狗形态两者都可能（USB 硬狗 / 软狗绑构建机），且必须支持离线** —— 两条路线都满足离线；
   软狗形态下私钥在构建机上，必须有导入/托管约束（建议 DPAPI/TPM 包一层，别裸放）。
4. **子狗授权由一级客户自己签** —— 签发工具必须在**客户自己的机器**上跑、私钥不经过我们；
   `vmpepoch keygen/lic-new/lic-edit` 已按这个前提实现（我们只提供工具，不持有私钥）。

**本轮已交付（路线 B 的授权工具链，Go 侧）**

```
vmpepoch keygen   --out <prefix>                                  # 母狗侧生成 Ed25519 签发密钥对
vmpepoch lic-new  --vendor <id> --dongle <id> --key <priv> --out <lic> [--product ID[@到期]]...
vmpepoch lic-edit --lic <lic> --key <priv> [--add ID[@到期]]... [--del ID]...   # 增删授权后重签
vmpepoch lic-show --lic <lic> [--pub <pub>] [--product <id>]                    # 验签 + 授权判定
```

实测（本机）：签发 A-A 的 PROD-A（2027-12-31）→ `lic-edit --add PROD-B` **重签**（软件不动、狗不动 ✓）；
`lic-show --pub` 验签通过；**篡改授权（偷偷加 PROD-C）→ 验签失败 rc=1** ✓；**过期授权 → 判定 false** ✓。

**谁运行什么（密钥归属与职责边界）**

`vmpepoch keygen` 生成的是「签发下游授权的 Ed25519 密钥对」——它属于**谁的授权树**，就该谁运行：

| 角色 | 运行什么 | 持有的密钥 | 用途 | 边界 |
|---|---|---|---|---|
| **厂商（你们）** | `keygen --out vmp-x`（可选） | 你们自己的 Ed25519 私钥 | ① 你们自己若也卖受保护软件：签你们自己的下游；② 给一级客户签「构建授权」（谁可用工具、可用哪个 vendorID、到期）；③ 签发你们的更新/授权文件 | 私钥只在你们手里，**不下发** |
| **一级客户（客户A）** | `keygen --out vendorACME` | 客户A 自己的 Ed25519 私钥（= 他的母狗侧） | 给**他的下游**（A-A/A-B）签发/更新授权 | **你们不该持有** ✗（否则等于你们能伪造他家授权） |
| **下游（A-A）** | 不运行 keygen | 只持有**被签名的授权**（路线 B）或**子狗**（路线 A） | 运行软件 | 私自改授权 ⇒ 验签失败 |

**路线 A（Sentinel）时的差别**：一级客户的签发动作由 **Sentinel 写狗工具 + 他的母狗**完成 ——
此时 `vmpepoch keygen` 对他**根本不需要**（Sentinel 体系自洽）。我们的授权工具主要用于路线 B，
或用于生成「给 Sentinel 导入的素材」。你们厂商在路线 A 里对应的是**你们自己的 Sentinel Vendor Code**。

**流程闭环（路线 B）**：客户A 在自己机器上 `keygen` → 把**公钥**交给打包流程
（`vmpbuild --license-pubkey`，**待实现**，烘进产物供运行期验签）→ 用**私钥**给每个下游 `lic-new/lic-edit` 签授权。
公钥随产物走、私钥只留在客户A 的签名机（建议 DPAPI / 软狗包住，别放 CI 明文变量 ✗）。

**可选的一层管控**：如果你们要防「工具被客户复制给第三方」，就用**你们自己的签发密钥**给一级客户发一份
「构建授权」（含 vendorID / 到期）。这是路线 B 下**唯一**需要你们签发的东西，要不要做取决于商业模式。

**两级 PKI（解决「客户能无限生成密钥 / 自立门户」）**

`keygen` 只是生成一对 Ed25519 密钥 —— **任何人本来就能自己做**（`openssl genpkey` 一行），
所以「客户能生成无限对密钥」这件事**堵不住也不该堵** ✗。真正的分界线是两条：

1. **谁的公钥被烘进产物** —— 产物只接受用那把公钥签出的授权；
2. **谁能签发「身份」** —— 没有这一层，一级客户可以随便编一个 vendorID 自立门户 ✗。

于是加一层（已实现）：

```
厂商（唯一持有根私钥）:  vmpepoch keygen     --out vendor-root
                        vmpepoch cert-issue --root vendor-root.priv --subject custA.pub \
                                             --vendor ACME-0001 --until 2028-12-31 --out custA.cert.json
一级客户 A（自己保管私钥）: vmpepoch lic-new --vendor ACME-0001 --dongle A-A --key custA.priv \
                                             --cert custA.cert.json --out A-A.vmplic --product PROD-A@2027-12-31
下游/运行期验链（只需根公钥）: vmpepoch lic-show --lic A-A.vmplic --root vendor-root.pub --product PROD-A
```

运行期判定 = 「授权签名 by 证书里的客户公钥」∧「客户公钥 by 厂商根」∧「cert.vendorID == 产物里的 vendorID」。
效果：客户**仍可自由生成/轮换自己的密钥**（业务不受影响 ✓），但**身份只能由厂商签发** ✓，
且证书可设**有效期/吊销** ✓ —— 这就是「不乱套」的那道闸。

实测（本机）：整链通过 ✓；**自立门户**（自签一张 FAKE 证书）→ 验链失败 rc=1 ✓；
**身份与签名者脱钩**（拿别的私钥签）→ 签发时就被拒 ✓；**证书被篡改** → 验签失败 ✓。

**密钥由谁生成（标准流程，回答「custA.priv/pub 谁生成」）**

| 密钥 | 谁生成 | 私钥去哪 | 公钥去哪 |
|---|---|---|---|
| **厂商根密钥对** | **厂商自己**（`keygen --out vendor-root`） | 永不外发，只在本机/根签名机 | **公开分发**：客户打包时要烘进产物（运行期验链用） |
| **一级客户密钥对** | **一级客户自己**（`keygen --out custA`） | 留在客户手里（建议 DPAPI/软狗包住） | **只把公钥交给厂商**（用证书申请文件） |
| 下游 | 不生成 | —— | 只持有被签名的授权（路线 B）或子狗（路线 A） |

**推荐交付方式：带「持有证明」的证书申请**（防止厂商签错人/被顶替）

```
客户A: vmpepoch cert-req   --key custA.priv --vendor ACME-0001 --out custA.req.json
       （请求里含用 custA.priv 签的自签名，证明申请者确实持有与公钥配对的私钥）
厂商:  vmpepoch cert-issue --root vendor-root.priv --req custA.req.json --vendor ACME-0001 \
                            --until 2028-12-31 --out custA.cert.json
       （先验持有证明，再签发；也支持旧写法 --subject custA.pub，跳过证明）
厂商  ->  把 custA.cert.json 回给客户A
客户A: vmpepoch lic-new ... --key custA.priv --cert custA.cert.json ...   # 签下游授权
客户A: vmpbuild ... --license-pubkey vendor-root.pub                      # 烘进产物（待实现）
```

**为什么不能反过来（厂商替客户生成私钥）**：谁持有私钥，谁就能签该 vendorID 下的**所有**授权 ——
厂商持有时就等于「厂商能伪造客户给下游的授权」 ✗，商业上讲不清，也违背「密钥不出客户」的信任模型。
客户若要**轮换密钥**（丢失/泄露），重新 `keygen` 再申请一张新证书即可，vendorID 不变 ✓。

实测（本机）：根生成 → 客户端生成 → `cert-req`（含持有证明）→ `cert-issue` 验证明后签发 →
`lic-new --cert` → `lic-show --root` **整链通过** ✓；**把请求改成别人的公钥 → 持有证明验不过、拒签** ✓。

**Sentinel 对应关系（2026-09 核对 Thales 官方文档，链接见文末）**

- **Starter Kit 里有「两把」Vendor key**（这是很多人的误解点）：
  - **Developer key**：配合 **Envelope** 保护软件/数据文件，通常接在开发机（也可网络共享）；
  - **Master key**：配合 **EMS / License Generation API** 创建与更新授权、向狗写数据，通常接在 EMS 机器；
    **Thales 托管的 EMS 甚至不需要这把母狗在本地。**
- **Vendor Code（.v2c）** 由「引入 Vendor key」（Master Wizard）生成 —— 即**从狗导出**；
  它**不是公钥** ✗，而是厂商的**机密凭证**（既能保护软件、也能签授权），必须妥善保管。
- **一个 Batch Code 下可以有多把 Master key**（官方原文：EMS 的 Master 页面在指定 Batch Code 后，
  若存在多把会在左栏列出）→ 「多母狗对应同一个 vendor 身份」就是这么实现的（多部门 / 灾备）。
- **隔离**要用**不同的 vendor 身份**（不同 Batch Code / 不同 Vendor Code）：一个 vendor 身份 = 一个信任域，
  跨域串用会被拒。
- **销售部门不该拿母狗/VendorCode** ✗ → 用 **EMS 的用户与角色**（只给「生成授权」权限）。
  对应到我们：**缺一个「受限签发角色」**，见下面「要补的对应物」。
- **备份**：母狗可有多把/可备份；**若全部丢失**，该 vendor 身份就无法再签发/更新授权
  （只能重建新 vendor 身份并重新保护产品）→ 必须有**备份母狗 + 保险柜**。

**我们要补的对应物（TODO 子项）**
- [x] **委派签发（canIssue）**：已实现（见下）。等价于 EMS 角色 —— 销售能发授权，但拿不到根密钥。
- [ ] 吊销/黑名单（现在只有有效期这一条杠杆；在线吊销未做）。
- [ ] 若最终走 Sentinel：以上全部由 Sentinel 体系承担，我们只需做 **`vm_license_fetch/verify` 接口层**
      （`hasp_login`/`hasp_get_info`/`hasp_decrypt`），**不做自研 PKI**。

官方文档（引用原文口径）：
- Vendor Keys: https://docs.sentinel.thalesgroup.com/ldk/LDKdocs/SPNL/LDK_SLnP_Guide/GettingStarted/Vendor%20Keys.htm
- Maintaining Master Keys: https://docs.sentinel.thalesgroup.com/ldk/LDKdocs/WebHelp/MaintainMasterKeys.htm
- EMS User Types and Roles: https://docs.sentinel.thalesgroup.com/softwareandservices/ldk/LDKdocs/SPNL/LDK_SLnP_Guide/Licensing/Users_and_Roles.htm

**澄清：不存在「自己加密自己」（三个根各管各的）**

| 谁的什么东西 | 用哪个根 | 谁签授权 | 说明 |
|---|---|---|---|
| **一级客户的软件**（你们的主业务） | **客户自己的根**（= 他的母狗 / VendorCode 对应物） | 客户自己（给他的下游） | 客户**本来就是他自己那棵树的厂商** —— 这正是 Sentinel 的模型（每家一个 Vendor ID） |
| **你们的工具 vmpbuild/vmpack**（可选） | **你们的根** | 你们 | 这只是「工具启动时校验一份许可证文件」（读文件 → ECDSA 验签 → 查到期 → 不通过就退出），**与加密功能无关**；不是拿 vmp-x 去加密 vmp-x ✗ |
| **你们自己的软件产品**（如果有） | **你们的根** | 你们 | 同客户的场景，只是树根换成你们 |

**要不要给工具本身加壳**：那是**另一个可选动作**（用 vmp-x 保护 vmpbuild/vmpack 自己），与授权链无关；
真要做要注意**自举顺序** —— 用一份**冻结的旧 blob** 去保护新工具（链式，不循环 ✓），而不是「新工具保护新工具」 ✗。

**「工具授权」可做可不做**：不做也能卖（只是客户可以把工具转手 ✗）；做的话就是普通的软件许可校验，
防得住顺手转手，防不住铁了心 patch 的人（与所有软件许可同一边界）。

**文件形态 vs Sentinel：能模拟什么、模拟不了什么**

| Sentinel 概念 | 文件形态对应物 | 我们的状态 |
|---|---|---|
| Developer key（Envelope 保护软件） | 构建密钥 `vmpbuild -key-in` | ✅ 已有 |
| Master key / Vendor Code（签授权） | 厂商根密钥 + 客户身份证书 | ✅ 已有（`cert-req`/`cert-issue`） |
| Vendor ID / Batch Code（身份=信任域） | `vendorID` + 证书链 | ✅ 已有 |
| 多把母狗（部门/灾备） | 根密钥多份副本（保险柜/HSM） | ✅ 流程问题 |
| 子狗（被授权的下游） | `<产物>.vmplic` 签名授权文件 | ✅ 签发/验签已有；**运行期强制未做** |
| 子狗 ID（哪个下游） | `dongleID` | ✅ |
| 软件 ID / 功能点 | `productID` + `items[]`（+ 预留 `features`） | ✅ |
| 到期时间 | `items[].expiry` | ✅（判定已实现） |
| 增删授权（改狗内容） | `lic-edit` 重签 | ✅ |
| EMS 角色（销售只发授权、不碰根） | **委派签发 `canIssue`** | ✅ 已实现（本节末） |
| 防拷贝（一机一授权） | 机器指纹写进签名授权 | ⚠️ 可做，但文件可复制 |
| 到期抗回拨（独立时钟/计数器） | 需要可信时间 | ❌ 离线文件形态挡不住 |

**三条硬差异（文件形态做不到的）**
1. **防拷贝**：授权就是个文件，可以复制到任意机器 ✗。缓解=把**机器指纹**写进签名授权（换机器即失效 ✓），
   但指纹可虚拟化/可伪造，且硬件变更会误伤，需要多因子 + 容错策略。
2. **到期抗回拨**：文件形态只能看系统时钟 → 改时间就绕过 ✗（狗里有独立时钟/计数器，这是硬件能力）。
   离线场景下只能抬高绕过成本（DPAPI + 注册表 + 多副本交叉校验 + 记录最后可信时间），挡不住有心人。
3. **签发凭证不可复制**：VendorCode / 根私钥在文件形态下就是磁盘上的密钥文件 ✗。
   缓解（**性价比最高的一步**）：把签名私钥放进 **TPM / Windows CNG 不可导出密钥** ≈ 软件狗，
   拿到「私钥不出芯片」，成本≈0、不需要买狗、离线可用 ✓✓。

**落地阶段建议**
- 阶段 1（现在）：文件形态把流程跑通（谁签、给谁、什么产品、何时到期、怎么增删）→ 已完成大半，补 `canIssue` 即等价 EMS 角色；
- 阶段 2（推荐）：签名私钥进 **TPM/CNG**（软狗）→ 密钥不可导出；
- 阶段 3（可选）：真上 **Sentinel**（你们已有母狗/子狗）→ 密钥不出狗 + 防拷贝 + 独立时钟。
  由于已把「取密钥 / 取授权 / 验签」收成接缝（`vm_key_from_file` / `vm_license_fetch/verify`），
  **阶段 1→2→3 是换实现，不是重写** ✓。

> 别忘了：以上全是「签发侧」。**运行期强制**（产物不认授权就拒绝运行）尚未实现 ——
> 没有它，这套现在只是管理流程，还不具备 Sentinel 那种「没授权就跑不起来」的体感。


**委派签发（canIssue）已实现 —— 等价于 Sentinel EMS 的「角色」**

```
# 1) 厂商根（自己生成，私钥不外发）
vmpepoch keygen     --out root
# 2) 销售部自己生成密钥，申请；厂商签一张带 canIssue 的证书
vmpepoch cert-req   --key sales.priv --vendor ACME-0001 --out sales.req.json
vmpepoch cert-issue --root root.priv --req sales.req.json --vendor ACME-0001 \
                    --until 2030-01-01 --can-issue --out sales.cert.json
# 3) 客户A 自己生成密钥，申请；**由销售部**签发（链深 1）
vmpepoch cert-issue --issuer sales.cert.json --issuer-key sales.priv --root-pub root.pub \
                    --req custA.req.json --vendor ACME-0001 --until 2028-12-31 --out custA.cert.json
# 4) 客户A 给下游签授权；5) 下游只需厂商根公钥即可验整链
vmpepoch lic-new  ... --key custA.priv --cert custA.cert.json --root-pub root.pub --out A-A.vmplic --product PROD-A@2027-12-31
vmpepoch lic-show --lic A-A.vmplic --root root.pub --product PROD-A
```

验链规则：本级签名由「Issuer 的公钥」验 → 逐级回溯 → 顶层由厂商根验；
并且**中间证书必须带 canIssue**，否则它签出来的下级一律不认。

实测（本机）：三层链 `整链通过：授权 <- ACME-0001（链深 1） <- 厂商根` ✓；
负例1 用**没有 canIssue** 的证书签下级 → 拒（“没有 canIssue 权限，不能签发下级”）✓；
负例2 伪造一张自我签名的“销售部”证书再去签下级 → 在**签发时**就被拒（链回溯不到厂商根）✓；
负例3 授权里塞伪造证书 → `lic-show --root` 报“证书链：不是由上一级签的”✓。

**还没做（下一步，按需选择）**
- [x] **运行期强制**：已打通（见 STATUS #399）。无授权 → `0xC0DE0007`；合法授权 → 与原生逐行一致；
  篡改/过期/productID 不符/vendorID 不符/伪造签名 → 全部 `0xC0DE0007`；门禁失败对外统一，内部阶段记在 `vm_license_fail_stage`。
- [x] **⑦ 全流程可复跑脚本**：`tools/acceptance_demo.ps1`（23 项检查全通过）。
  用法：`powershell -NoProfile -File tools/acceptance_demo.ps1 -BuildDemo`（现场用 MSVC 重编客户的 demo，带 /MAP），
  或 `-DemoExe X.exe -DemoMap X.map`（客户自己提供带 MAP 的产物）。
  覆盖：① 工具授权（无凭据 exit 8 / 有凭据可用）② 密钥纪元 + `which` 归属 ③ 外置密钥保护客户软件
  ④ 授权链（根→销售 canIssue→客户→下游；无 canIssue 的证书签下级被拒）⑤ 运行期强制（无授权/篡改/过期/伪造 → 0xC0DE0007；
  合法授权 → 与原生**逐行一致**）⑥ 授权更新（产物哈希不变、输出一致）。
  注意：**vmpack 靠 MAP 文件按名字定位函数（不读 PDB）** —— 客户自带的 demo64.exe 没有 .map，
  所以要么 `-BuildDemo` 重编一份带 /MAP 的，要么 `-DemoMap` 指定。

  **已做**：
  - `vmpbuild`：blob 里新增占位全局 `vm_license_meta`（强制 `.data`、默认 `kind=0` = 不启用）+ manifest 暴露符号偏移与 `keyExternal`；
  - `vmpack`：`-license-vendor / -license-product / -license-pub`；**非外置密钥的 blob 直接拒绝**（避免出现「以为有门禁其实没有」）；
    把 vendorID/productID 的 `SHA-256[0:4]` 与签发者公钥写进产物里那份 blob；
  - `vmpepoch lic-export`：JSON 授权 → 运行期二进制授权 `<产物>.vmplic.bin`（hdr+items+签名，与 C 侧逐字节对齐）；
  - blob 侧 `vm_license_check()`：读授权（复用 1b 的 PEB 路径 + ntdll 读文件）→ 校验 magic/版本/vendorHash/长度 →
    CNG（bcrypt）验 ECDSA P-256 → 查 productHash 与到期 → 不通过走同一个硬门 `0xC0DE0007`；调用点在**入口蹦床**（入口点、main 之前）；
  - **实测**：不带授权文件 → **恰好 `0xC0DE0007`、无输出** ✓（「没授权跑不起来」这条已成立）。
  **未打通**：带合法授权运行时仍 **ud2 崩**（`0xC000001D`，地址在 payload 内、稳定复现）。
  已用固定分支码（0x21..0x3E）逐段定位并排除：路径拼接、读文件、magic/版本/vendorHash/长度、
  bcrypt 懒加载（已改用 `ntdll!LdrLoadDll` 自己加载）、TLS/loader-lock 时序（关掉镜像加密、无 TLS 回调现象相同）。
  下一步：用调试器（或继续压细分支码）定位到具体调用；也可考虑在 blob 里自带 SHA-256、只在 CNG 里做验签。
  **风险控制**：整条路径默认关闭（`kind=0`）；门禁只在外置密钥模式下编入；`vmpack` 拒绝非外置 blob；
  现有产物/门禁/CI 不受影响（本机 gates 11/0 复验）。
**注：以下方案已实现完毕**（见 STATUS #399/#400）—— 保留在这里只作设计记录：
`vmpbuild` 的占位全局 `vm_license_meta`（默认 kind=0）→ `vmpack -license-vendor/-license-product/-license-pub`
打进产物里那份 blob → `vmpepoch lic-export` 导出二进制授权 `<产物>.vmplic.bin` → blob 侧 `vm_license_check()`
用 CNG 验 ECDSA P-256 并查 productID/到期 → 不通过走 `0xC0DE0007`。
**踩到的两个坑**（都留存档）：① 授权校验**不能**放在 `vm_master()`（那条路径会被 TLS 回调走到，回调里不能加载 DLL/调 CNG）；
② **自哈希区间是 [0, bssOff) 且包含 .data** —— 打包端改了 `.data` 里的元数据后必须**重算自哈希**，否则 `vm_selfcheck()` 直接 trap。

**注（工具演进）**：签名原语已从 Ed25519 全部换成 **ECDSA P-256**（`cmd/vmpepoch/crypto.go`、`internal/cred`）——
因为运行期要在产物里验签，而 Windows CNG 只提供 ECDSA/RSA。私钥 = 32 字节标量（hex）；公钥 = 64 字节 X||Y（hex）；
签名 = 64 字节 r||s（base64），与 CNG 的 `BCRYPT_ECCKEY_BLOB` 格式一致。

- [ ] **路线 A（Sentinel）**：blob 侧调 Sentinel API（`hasp_login`/`hasp_get_info`/`hasp_decrypt`）——
      **推荐让密钥由狗派生**，这样“同一份产物发所有下游”天然成立，且密钥不出狗。
- [ ] `features` 的具体语义（并发/功能点/机器绑定）与判定实现。
- [ ] 母狗私钥在构建机上的保护（DPAPI/TPM/软狗），以及“从狗直接取密钥”（`vmpbuild --key-from-dongle`）。


**验收标准（做之前先和客户确认边界）**：至少覆盖 R2 的"不动锁、单独更新授权"；
若还要到期/吊销/机器绑定，需明确列出并逐条验收（每条都要有 e2e）。


## 6. 抗"有狗客户脱壳再分发"（威胁模型与不足清单见 `docs/THREATMODEL.md`）

本轮把客户给定的威胁模型（对手=**持有合法 HL 的客户**，目标=**做出不需狗的可分发版本**）与
vmp-x 当前不足逐条落档，每条都带 `文件:行` 依据。要点：**做不到绝对不可脱壳**，
可验收的目标是"**不可移植**（T-a）+ **成本高于授权价**（T-b）"。

工作项（按影响排序，详见该文档第 5 节）：
- [ ] **W1**：镜像/字节码**按页惰性解密 + 执行后回写**（不依赖新硬件，可立即开工；当前是整节解密到内存）
- [ ] **W2**：i386 补镜像整体加密（现在 `vmpack` 明写 i386 先跳过）
- [ ] **W3**：外置密钥模式扩到 i386 / linux / arm64（现在只 win/x64）
- [ ] **W4**：狗参与密码学（`hasp_decrypt` 类**非导出密钥**）+ 会话/狗绑定（现有 `vm_key_from_sentinel` 只是取主密钥）
- [ ] **W5**：`features` 语义 + 吊销/黑名单（与第 5 节授权层同批）
- [ ] **W6**：反 dump / 反 trace 加固（成本乘数）

## 7. 稳定性观察（记录用，非功能项）

- [ ] `E2E x86-64` 里的 **`refill`（`tools/patch_refill.py`）出现过一次 flaky**：
      run `35833541996`（纯文档提交 `7dff5ac`）首次失败 `E2EFAIL refill: tools/patch_refill.py failed`
      （`e2e: 164 passed, 1 failed`），**重跑同一作业即全绿** ⇒ 判定为偶发而非回归。
      建议：查该子用例是否有时间/路径依赖（它做的是"按函数尾声把被覆盖的 5 字节推回来"的对抗测试）。

### W3 落地设计（1b 外置密钥多平台）—— 已完成调研，待实现

**接缝已完全看清**（`stub/win/x64/vm_interp.c`，全部在 `#ifdef VM_KEY_EXTERNAL` 内）：

```
774  #ifdef VM_KEY_EXTERNAL
776  #if !(defined(VM_BLOB_USES_WIN64) && (defined(__x86_64__) || defined(VM_HOST_X86_32)))
777  #error "VM_KEY_EXTERNAL 目前只有 Windows/x64 的取钥实现（vmpbuild 会先拦住别的目标）"
778  #endif
```

⇒ 要加 Linux，需要动 **两处守卫 + 四个平台专用原语**：

| # | 位置 | Windows 现状 | Linux 需要 |
|---|---|---|---|
| 1 | `vm_key_reject_code()`（790） | `ntdll!NtTerminateProcess(-1, 0xC0DE0000\|code)` | `exit_group(code)` 系统调用（注意：POSIX 只暴露低 8 位 ⇒ Linux 侧可观测的是 `0x07`） |
| 2 | `vm_env_block()`/`vm_env_get()`（799/808） | PEB → ProcessParameters(+0x20) → Environment(+0x80)，UTF-16 大小写不敏感 | 扫 `/proc/self/environ`（ASCII、NUL 分隔）；为不改上层，填进一个 static u16 缓冲再返回 |
| 3 | `vm_key_path()`（863） | PEB → ImagePathName 拼 `<产物全路径>.vmpkey`，`VMPX_KEY_FILE` 可覆盖 | `VMPX_KEY_FILE` 优先；否则 `readlink(/proc/self/exe)` + `.vmpkey`（同样转 u16） |
| 4 | `vm_key_read_nt()`（891） | ntdll `NtCreateFile/NtReadFile/NtClose` | `open(2)/read(0)/close(3)`（x86_64 用现成的 `vm_syscall3`，2601） |

**另外两处（本步不做，但要记下）**：
- `vm_key_from_sentinel()`（1184）是 `LoadLibrary` 式狗接口 ⇒ Linux 下应返回 0（= 不可用）⇒ `kind>=2` 严格模式会正确走硬门 ✓；
- 授权 fake-file 路径用 `vm_now_unix()`（Windows 时间源）⇒ Linux 侧要另做（`clock_gettime`）⇒ 若在 Linux 上用授权需一并处理 ✗。

**要改的外部守卫**：`cmd/vmpbuild/main.go:150` 的 `if *keyExternal && targetRel != "win/x64"` ⇒ 改成"允许已实现的平台白名单"，其余仍 fail-fast ✓。

**验证的现实约束（重要）**：本机可以**构建** linux/amd64 blob ✓，并用 `payload_probe.exe` 在 Windows 上执行其中**位置无关的 x86-64 机器码** ✓；
但**系统调用不能在 Windows 上执行** ✗ ⇒ 取钥路径的**真跑**必须在 CI 的 Linux 作业里做 ⇒
**必须同时给 `tools/e2e.sh`（或一个 Linux 侧小探针）加一条"给了/没给密钥"的用例**，否则这条路径等于没有验收 ✗。

**分步计划（建议）**：
1. 加 Linux/amd64 的四个原语（守卫 `VM_BLOB_TARGET_LINUX && __x86_64__`），**先不放宽 vmpbuild 守卫** ⇒ 本机可验证"linux blob 仍能构建 + linux payload 关仍绿"；
2. 加 arm64 分支（`vm_syscall3_a64`，2502；syscall 号：read=63/open=56/close=57/readlink=78/exit_group=94）—— 本机无 aarch64 工具链 ⇒ 只能靠 CI 的 linux-arm64 作业验证；
3. 放宽两处守卫 + 在 `tools/e2e.sh` 加验收用例（不给密钥 ⇒ 恰好失败；给了 ⇒ 与原生一致）；
4. i386 与 win/arm64 各自单独一步（32 位 PEB / ARM64 TEB）。

### W3 范围修正（调研后：比首版估计大）

首版估计的接缝等于 4 个原语，过于乐观。真实情况（都读过代码）：

1) 1b 与授权/验签在同一段（774 起，VM_KEY_EXTERNAL），里面大量依赖 Windows 专有符号：
   - vm_key_reject_code（790）走 ntdll 的 NtTerminateProcess；
   - vm_key_read_nt（891）走 ntdll 的 NtCreateFile/NtReadFile/NtClose；
   - vm_key_from_sentinel（1184/1199）走 LdrLoadDll 与 hasp_login/hasp_read；
   - 授权与验签（1020 起）走 bcrypt 的 SHA-256 与 ECDSA P-256；
   - vm_key_path（863）与时间取法（968 起）走 PEB 与 GetSystemTimeAsFileTime。
2) 这些符号对 Linux 目标是未声明的；vm_interp.c 的 1403/1408 守卫模式即为：
   Windows 目标且非 VM_BLOB_TARGET_LINUX 才声明 vm_find_module / vm_get_proc。
   第 1400-1402 行注释写明：曾经就是这样把 linux blob 编成非自包含的，CI 报过
   undefined symbol vm_find_module。

所以加 Linux 不能只补密钥原语，必须同时把不参与 Linux 编译的那部分（ntdll/bcrypt/
LoadLibrary/PEB）整段守卫掉，并给出 Linux 版或桩（桩要能正确触发硬门）。

修正后的 Linux/amd64 工作量：
（i）  密钥路径的 Linux 原语：exit_group / proc-self-environ / proc-self-exe 加 .vmpkey /
      open+read+close；
（ii） 守卫：把 vm_key_reject_code、vm_key_path、vm_key_read_nt、vm_key_from_sentinel，
      以及授权与验签整段，按 Windows 目标才编译包起来；Linux 侧 vm_key_from_sentinel 返回 0，
      于是 kind 大于等于 2 的严格模式正确走硬门；授权与验签在 Linux 侧暂不支持（或单独一轮做）；
（iii）cmd/vmpbuild/main.go:150 的白名单按平台逐个放开；
（iv） 验收：tools/e2e.sh（CI 的 Linux 作业）加不给密钥必须恰好失败、给了必须与原生一致两条用例；
      本机无法验证（Linux 系统调用不能在 Windows 上执行），必须靠 CI。

为什么本轮没有直接动手：这是跨 vm_interp.c 大段守卫重构加构建器白名单加 CI 用例的改动，
按仓库纪律（AGENTS.md：不要在预算不足时动主干）必须整轮做完并验证；本轮预算已验证不足以
安全完成，故先把这个修正后的范围钉死，下一轮按（i）到（iv）一次做完。

#### W3 进展（本轮）：Linux/amd64 构建级完成

- [x] **Linux/amd64**：外置取钥已实现（syscall 版：/proc/self/environ、/proc/self/exe + .vmpkey、
      open/read/close、exit_group 硬门），`vmpbuild` 白名单已放开该目标；构建级验证通过（STATUS #489）。
- [ ] Linux/amd64 **运行时**验收：必须加进 `tools/e2e.sh`（CI 的 Linux 作业），本机跑不了 Linux syscall。
- [ ] linux/arm64：同一形态换 syscall 号（read=63 openat=56 close=57 readlinkat=78 exit_group=94）。
- [ ] Linux 侧授权与狗：目前是 fail-closed 桩。

- [x] **Linux/amd64 运行时验收**：已在 `tools/e2e.sh` 里加三条（无密钥 rc=7 无输出 / VMPX_KEY / .vmpkey 文件），
      CI run 35838856135 全过（STATUS #490）。**Linux/amd64 至此构建级 + 运行时级双验收完成。**

- [x] **linux/arm64**：已实现（aarch64 用 openat/readlinkat + 新增 4 参数 syscall 封装），
      `tools/e2e_arm64.sh` 加了同一套验收，CI run 35946190183 全绿（STATUS #491）。
      ⇒ **目标 (a) Linux/amd64 + Linux/arm64 完成。**
- [ ] win/x86(i686)：32 位 PEB + 导出表遍历 + __stdcall（VM_WINAPI 宏已就位）
- [ ] win/arm64：ARM64 TEB/PEB 取法

- [ ] win/x86(i686)：**部分完成**（#492）—— PEB/LDR 宏早已按位宽分好；本轮又修了「导出目录基址」
      「RTL_USER_PROCESS_PARAMETERS 的 ImagePathName/Environment 偏移」「PEB->ProcessParameters 偏移」三处；
      本机实测 **VMPX_KEY 环境变量那条已与原生一致**，但 **<产物>.vmpkey 文件那条仍读不到**
      （卡在 32 位模块/导出遍历）⇒ 按 fail-fast 纪律**白名单暂不放开**。

- [x] **win/x86(i686)**：完成（#493）—— 六处位宽修正（导出目录基址 / PP 字段偏移 / PEB-PP 偏移 /
      两个 NT 结构体布局），本机三条用例全过（无密钥 0xC0DE0007、.vmpkey 与 VMPX_KEY 均与原生一致），
      白名单已放开。
- [ ] 把 i686 这三条用例补进 32 位门禁脚本（进 CI 常态回归）
- [ ] win/arm64：ARM64 TEB/PEB 取法

- [x] **把 i686 这三条用例补进 32 位门禁**：已进 `tools/e2e_32bit.ps1`（三条全过、脚本纯 ASCII），
      该门禁由 CI 的 windows-amd64 作业执行 ⇒ i686 取钥路径有常态回归（STATUS #494）。
- [ ] win/arm64：**本环境无法验证**（CI 的两个 arm64 作业都在 x86-64 宿主上跑客户机字节码，
      跑不了 ARM64 机器码的 blob）⇒ 按纪律暂不实现，白名单继续 fail-fast。
