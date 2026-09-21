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

**验收**：`DemoFormatReport` 在 `/Od` 与 `/O2` 两种构建下都逐行一致；
`caller5`/`caller5b` 合成用例与原生一致；并把它加成 `tools/e2e.ps1` 的用例。

## 3. `CVTDQ2PD` / double 路径

**现象**：`?DemoMean@@YANPEBNH@Z` 进 VM 后输出 `0.000`（原生 3.500）；lifter 报
`+0x66: CVTDQ2PD X1, X1 — 暂不支持该指令`。

**要做**：至少补齐 `CVTDQ2PD`（int32→double）与其配套的 SSE2 双精度路径，并单测。

## 4. 修完 1、2 后，用 `D:\demo_exe` 复跑全量验收

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

