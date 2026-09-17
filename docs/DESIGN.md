# vmp-x 设计文档（PoC → 跨平台）

> 路线：**B（二进制重写，不要求源码）**；**不 fork VMPacker**（其 AGPL-3.0 会污染闭源分发）。
> 首发平台：**Windows / amd64**（本机可真实运行验证）。其余平台：Linux/amd64、Linux/arm64、Windows/arm64。

---

## 1. 目标与非目标

**目标**
1. 对已编译的 PE(x64) 二进制做**函数级虚拟化**：原函数体 → 自定义 VM 字节码，入口改为跳板。
2. 语义等价必须是**可验证**的：字节码级单测 + 端到端"原生结果 == VM 结果"。
3. 不能等价翻译的输入**必须拒绝打包并列出清单**（fail-fast），绝不静默产出错误产物。
4. 架构上为四平台/双格式预留，不靠"再写一遍"。

**非目标（PoC 阶段明确不做）**
- 不承诺 x86-64 全指令覆盖（那是 DynamoRIO/QEMU 量级的长期工作）。
- 不做 macOS（代码签名 + hardened runtime 成本极高）。
- 不承诺"不可破解"——见 §2。

---

## 2. 安全模型：分级，而不是口号

业界常见错误是把"混淆 + 加密字节码"讲成"密码学级保护"。必须先把话说清楚：

> **在"攻击者完全控制运行环境 + 可无限次离线运行"的前提下，不存在密码学级的软件保护。**
> 这是不可能性结论，不是工程量问题：
> - Barak–Goldreich–Impagliazzo–Rudich–Sahai–Vadhan–Yang (CRYPTO 2001 / JACM 2012)：一般电路的 **VBB 混淆不存在**（存在不可混淆的函数族）。
> - Garg–Gentry–Halevi–Raykova–Sahai–Waters (FOCS 2013) 的 iO 是**候选构造**，且只给不可区分性，不阻止"黑盒使用"（攻击者本来就能观察输入输出）。
> - 白盒密码学（Chow et al. 2002）是这条路上的实证：所有公开的白盒 AES 都被攻破（BGE attack 2004 等）。
>
> 因此密码学级保护**只在能引入攻击者无法控制的信任根时才存在**。

### 保护等级（可定义、可验收）

| 等级 | 手段 | 门槛（攻击者成本） | 是否密码学级 |
|---|---|---|---|
| **L0** | 静态混淆、固定密钥、明文 opcode 映射 | 分钟–小时 | 否（≈ VMPacker） |
| **L1** | per-build 随机 ISA + AEAD 加密字节码 + 按需解密 + 完整性校验 | 人日 | 否（白盒：密钥必然在进程内） |
| **L2** | L1 + 每个样本唯一 + 反调试/反 DBI/反 dump + 自校验 | 人周 | 否 |
| **L3** | L2 + **密钥由 TPM 2.0 封印 / TEE 内解密执行 + 远程证明** | 需攻破硬件隔离或伪造 quote | **是**（归约到 TPM 不可伪造性 / TEE 隔离性） |
| **L4** | **关键逻辑不在客户端**：服务端执行 + 短时令牌 + 服务端风控/吊销 | 客户端本地无秘密 | **是**（不依赖客户端逆向难度） |
| **L5** | 受限交互模型（self-guarding circuits / bounded-query obfuscation） | 有可证明的安全定义 | **是**，但工程上 ≈ 每次运行都联网 |

### 结论与本项目的取舍
- **PoC 做 L1，架构预留 L3/L4**：解释器只依赖一个 `KeyProvider` 接口：
  `LocalDerived`（L1，per-build seed + HKDF）/ `TpmSealed`（L3，Windows CNG + TPM 2.0 + PCR 封印）/ `RemoteAttestation`（L4，challenge-response + 短时密钥）/ `Enclave`（L3，TEE 内解密执行）。
  换 KeyProvider 不改任何 VM/注入代码。
- **加密用真家伙，不用 XOR**：字节码用 **XChaCha20-Poly1305**（或 AES-256-GCM），密钥 `HKDF(seed, func_rva, build_id)`；seed 本身分级存放（L1：拆分+混淆；L3：TPM 封印）。
- **诚实标注**：产品文档里必须写"L1 是提高门槛的 anti-tamper；要达到密码学级必须启用 L3/L4 组件"。
- 另外必须承认：即使 L4，也只是让**复制/滥用**变难（服务端可风控），并不隐藏"算法思想"——攻击者仍可观察接口行为重写实现。密码学保护的是**秘密与完整性**，不是**行为**。

---

## 3. 架构

```
cmd/vmpack/             CLI：分析 / 打包 / 校验
cmd/vmpbuild/           stub 构建器（跨平台、替代 Makefile/PowerShell，避免双份实现漂移）
internal/load/{pe,elf}/ 容器读写（本阶段只做 PE）
internal/scan/          函数发现（导出表 / RVA 范围 / 启发式），给出候选清单
internal/decode/x64/    x86-64 解码（golang.org/x/arch/x86/x86asm）
internal/lift/x64/      解码 → IR（子集 + 不支持清单）
internal/ir/            ISA 无关中间表示（显式 flags/内存/控制流）
internal/vm/            VM ISA 定义 + 构建期随机映射生成
internal/codegen/       IR → VM 字节码（含重定位修正、AEAD 封装）
internal/inject/pe/     新增 .vmp 段、SizeOfImage/节表修正、跳板写入
internal/crypto/        HKDF / AEAD / KeyProvider 接口与实现
stub/{win,linux}/{x64,arm64}/   C 解释器（单段、零重定位、threaded dispatch）
docs/ testdata/ tools/
```

**打包数据流**
```
PE → 发现候选函数 → 提取机器码 → 解码 x86-64 → lift 到 IR
   → 校验（失败则拒绝并输出清单）→ IR → VM 字节码 → AEAD 加密（per-func key）
   → 新增 .vmp 段（解释器 + 描述符表 + 密文）
   → 原函数入口写：ENDBR64 + jmp [thunk]（5B rel32）
   → thunk: mov r11d, token ; jmp vm_entry      ← 只在函数入口覆盖 9 字节
   → 输出 + manifest（函数/RVA/校验和/被拒清单）
```

**关键设计决定（逐条对应 VMPacker 的教训）**
1. **不用私有栈**：VM 上下文里的 RSP 就是**真实 RSP**（进入时捕获、退出时回写）。
   → 彻底消除 VMPacker"SP 指向私有 16KB 栈"带来的指针语义漂移、栈帧上限、越界写坏 ctx。
2. **不销毁函数体**：入口只覆盖 9 字节；其余原字节保留（可选后续做校验和/加密占位）。
   → 异常展开（.pdata/.xdata）、backtrace、调试器不会踩到随机垃圾。
3. **标志位显式建模**：IR 层有 N/Z/C/V 四个真实标志，ADC/SBC/条件码按 ISA 语义生成，配 carry=1 的针对性单测。
   → 直接消掉 VMPacker 里"FL_CARRY 三种含义互斥"的 bug。
4. **RIP-relative 统一处理**：所有 `[RIP+disp]` 在 lift 时折算为 `模块基址 + 目标 RVA`，运行期用基址寄存器加回。
   → 天然支持 ASLR/重定位，不存在"链接期绝对地址"问题。
5. **密钥体系**：per-build seed + per-function HKDF + AEAD；opcode 映射随构建随机（seed 决定）。
6. **验证纪律**：`objdump -r` 必须为空（stub 单段零重定位）；解码器必须满足"消耗字节数 == 指令长度"的硬断言。

---

## 4. IR（最小可用子集）

- 值：虚拟寄存器 v0..vN（对应宿主寄存器映射）+ 内存操作（load/store，宽度/符号扩展显式）。
- 指令：`Assign / Binop / Unop / Load / Store / Cmp(carry-aware) / Jcc / Jmp / Call / Ret / NativeCall`。
- **flags 是一等公民**：`Cmp` 产出 `(N,Z,C,V)`；`Adc/Sbb` 消费 `C`；`Jcc` 消费对应的标志组合。
- 每个 IR 结点带 `srcRVA`，便于生成 debug 映射与"哪条 x86 指令无法翻译"的报告。

---

## 5. VM ISA 与密钥

- 栈机 + 寄存器缓存的混合模型（纯栈机在实测中通常慢 3–10 倍）。
- 指令编码：1 字节 opcode（**构建期随机映射**）+ 操作数；指令长度表在 Go 与 C 两侧**由同一份规格生成**（避免 VMPacker 那种双份手写表）。
- 字节码封装：`[header][ciphertext(AEAD)][tag]`，AAD 绑定函数 RVA/长度/构建 ID。
- 完整性：段落校验和 + 解释器自校验；校验失败走安全降级（返回失败而非崩溃）。

---

## 6. 平台落地要点

**Windows / PE（首发）**
- 新增段 `.vmp`：修正 `NumberOfSections`、`SizeOfImage`、节表剩余空间检查；段属性 `RX`。
- **CFG/CET**：跳板以 `ENDBR64` 开头（CET IBT）；VM 内部的原生调用使用**直接调用**（CFG 不检查直接调用）；如需间接调用，需在 CFG 位图中登记目标。
- 不修改原节内容 → **不需要重写重定位表**；payload 全部位置无关（RIP-relative）。
- 修改 PE 会使 **Authenticode 签名失效**：manifest 记录该事实，后续提供"打包后重签"流程。
- 若目标为 DLL，需注意 TLS 回调/延迟导入等不参与虚拟化。

**Linux / ELF（第二阶段）**
- 优先"新增 PT_LOAD"而非劫持 `PT_NOTE`（更干净）；保留 `.eh_frame`/`.ARM.exidx` 语义。
- PIE/ASLR：基址在运行期从辅助向量或 `AT_PHDR`/`_DYNAMIC` 获取，VM 统一用它加 `RVA`。

**arm64（第三阶段）**
- 解码器表驱动（按 ARM ARM 手册），但要修掉 VMPacker 的四类问题：标志位、literal pool、PIE、SIMD。
- FP/SIMD：要么实现 V/D 寄存器文件，要么**明确拒绝**并输出清单（不允许"半支持"）。

---

## 7. 构建与验证纪律

1. `cmd/vmpbuild` 负责一切 C 编译：把源码 stage 到 **ASCII 临时目录**（见 §8），调用 gcc/objdump/objcopy，解析符号得到入口偏移，输出 `vm_interp.bin` + `manifest.json`。
2. **硬断言**：抽取出的 stub 段 `objdump -r` 必须为空；否则构建失败。
3. **硬断言**：x86-64 线性扫描中 `sum(inst.Len) == 函数长度`；任何"只消费了前缀"的情况（如 ENDBR64）必须显式处理或直接拒绝。
4. **端到端**：`testdata` 下的目标程序，打包前后各跑一遍，比对 stdout/返回值/内存快照；随机输入批量比对（差分测试）。
5. **CI**：每平台 构建 + 单测 + 端到端；**未通过验证的目标函数禁止打包成功**。

---

## 8. 已验证事实与已知约束（2026-xx 本机实测）

| 结论 | 证据 |
|---|---|
| 单段零重定位 blob 可行 | `gcc -c -O2 -ffreestanding -nostdlib -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident -mno-red-zone` 编译 `.vmtext` → `objdump -r` 为空，`objcopy -O binary --only-section=.vmtext` 得到 80B blob，符号偏移可解析（vm_entry@0x40） |
| **msys2 工具链不支持非 ASCII 路径** | 在 `D:\\其它\\...` 下 gcc 报 `Fatal error: can't create ...: No such file or directory`；换 ASCII 路径后正常。**故项目根目录为 `D:\\vmp-x`** |
| x86-64 解码可用纯 Go | `golang.org/x/arch v0.20.0`（BSD-3，兼容 go1.24.5）给出完整操作数结构：`Reg/Mem/Rel/Imm`，含 RIP-relative、LOCK 前缀、3 操作数 IMUL |
| **ENDBR64 解码陷阱** | `F3 0F 1E FA` 被 x86asm 解成 1 字节的 `REP`，线性扫描会错位 → 必须特判，并加"消费字节数 == 指令长度"断言 |

**本机不具备**：clang/zig/qemu、WSL 发行版、aarch64 交叉 gcc。→ 除 Windows/amd64 外的平台只能靠 CI 验证（不会把"没跑过"写成"已完成"）。

---

## 8b. 平台路线图（横向扩展）

| 平台 | 容器 | 客户机 ISA | 状态 | 还差什么 |
|---|---|---|---|---|
| Windows / amd64 | PE | x86-64 | **已打通并实测** | — |
| Linux / amd64 | ELF | x86-64 | **注入已实现并结构化验证**，运行时待 CI | System V 入口 stub；vmpbuild 的 ELF 重定位解析；`tools/e2e.sh` |
| Linux / arm64 | ELF | **arm64** | 未实现 | 以上全部 + **arm64 解码器/lifter** + **arm64 语义解释器**（ctx 需要 X0-X30 + SP + NZCV，而不是现在的 x86 形状） |
| Windows / arm64 | PE | **arm64** | 未实现 | PE(arm64) 注入 + arm64 后端（同上） |

要点：
- **"支持 arm64" 不是"把解释器编译到 arm64"**——被保护的二进制里是 arm64 原生代码，
  所以必须新增 arm64 解码/lift + arm64 语义的 VM。宿主入口 stub 才是按平台编译的部分。
- 因此 `stub/<os>/<arch>/` 的划分是"宿主语义"边界：
  - `vm_abi.h` / `vm_entry_asm.S` 与宿主 ABI 强相关，必须每平台一份；
  - 解释器主体（`vm_interp.c`）与客户机 ISA 相关、与宿主无关，理想情况下可以在
    "客户机 ISA × 宿主 ISA" 之间复用（当前只支持 x86-64 客户机）。
- 验证策略：
  1. Windows/amd64：本地 + CI 都跑完整端到端（差分 + 基准）；
  2. Linux/amd64：CI 上原生跑（同一套差分思路，`tools/e2e.sh`）；
  3. Linux/arm64：CI 上用 `gcc-aarch64-linux-gnu` 构建 + `qemu-user-static` 运行
     （arm64 后端的差分测试可以在 x86 主机上通过 qemu 完成）；
  4. Windows/arm64：CI 上先只做构建验证。

## 8c. ARM64 客户机设计（定稿，2026 本轮）

### 客户机寄存器上下文
同一个 `vm_ctx_t` 结构，寄存器个数由**客户机 ISA** 决定（构建期选择，与宿主 ABI 选择相互独立）：

| 槽位 | x86-64 客户机 | ARM64 客户机 |
|---|---|---|
| 0..15 / 0..30 | RAX..R15 | X0..X30 |
| 16 | VBASE（模块基址） | — |
| 17 | VSCRATCH | — |
| 31 | — | SP |
| 32 / 33 | — | VBASE / VSCRATCH |
| 34 | — | ZR（恒为 0，**只读**） |

- `VBASE` 仍然是"模块基址 + guest 侧相对地址"的实现手段：ADR/ADRP 与 RIP-relative 统一
  翻译成 `LEA dst, [VBASE + rva]`。
- `ZR` 槽位由 lifter 使用（XZR）；**codegen 拒绝生成对它的写**（emit 期检查，fail-fast），
  避免"零点被悄悄写脏"这类静默错误。
- SP 作为基址寄存器与作为普通寄存器由 lifter 按指令语义区分（X31 的含义随指令而定）。

### 标志位与条件码
- flags 仍是一个 32 位字段：bit0..3 = N/Z/C/V，**含义按客户机 ISA 解释**；
  bit4 = PF 只属于 x86-64 客户机（ARM64 无此位）。
- **ARM64 的 C 与 x86 相反**：ARM64 里 C=1 表示"无借位 / 无符号大于等于"，
  x86 的 CF=1 表示借位。两者共用同一个字段，但各自有独立的求值函数。
- 移位类旗标规则也不同：ARM64 中移位量非 0 时 C = 最后移出的位，移位量为 0 时 C **保持不变**，
  且 V **永远不变**（x86 会清 V）。
- 条件码同为 16 个（EQ/NE/CS-CC/MI-PL/VS-VC/HI-LS/GE-LT/GT-LE/AL-NV），共用 `OP_JCC` 的 cond 字段，
  但求值表按客户机选择。

语义实现放在两个小模块里，并**各自与独立参考实现对拍**：
`stub/arm64/guest_semantics_arm64.c`（进 blob）对 `internal/guest/arm64/semantics.go`（Go 参考），
外加从 ARM ARM 伪码手算的锚点用例（防止两份实现同时犯同一个概念错误）。

### 调用与返回（ARM64）
- `BL`：把**返回地址写入 X30**（客户机语义），同时沿用"净零栈"调用模型：
  被调方的 `RET`（= `BR X30`）由 VM 直接返回到 `OP_CALLN` 之后。
- 入口 stub 保存/还原宿主 X0-X30 与 V0-V31（保守做法：调用方的 IPA 优化可能依赖任意寄存器
  不被破坏——x86-64 侧已经因此踩过一次 RDX/R11 的坑）。

### v1 明确不支持（一律 fail-fast，不猜）
SIMD/FP 数据运算、原子/独占访问、系统指令、指针认证（PAC）、SVE。
解码层已把它们归入 `ClassFPVec`/`ClassUnknown`，lifter 遇到即拒绝翻译并记录原因。

## 9. 里程碑

- **M1（本阶段）**：Windows/amd64 端到端可运行 PoC
  - M1.1 PE 读写 + `.vmp` 段注入（含节表/SizeOfImage 修正）
  - M1.2 x86-64 子集 lifter（整数 ALU/内存/控制流，约 60 条），带 fail-fast 清单
  - M1.3 C 解释器（单段零重定位、threaded dispatch、AEAD 解密）
  - M1.4 跳板 + thunk + token 描述符表
  - M1.5 差分测试 + 性能基准（给出真实数字，不吹"零开销"）
- **M2**：加固与横向
  - M2.1 **构建期随机操作码映射**（已完成：vmpbuild 为每个 blob 随机生成 vm_opcode_values.h，
    解释器编译期常量分发，运行时零开销；manifest 带 opcodeMap，vmpack 按指令长度表 Remap）
  - M2.2 字节码 **AEAD 加密已端到端跑通**（ChaCha20-Poly1305：Rust 无、C 实现 + x/crypto 对拍；
    每函数随机 nonce，主密钥每 blob 随机并由 vmpbuild 写进 manifest；帧内缓冲解密，验签失败即拒绝执行）
  - M2.3 字节码完整性校验（防改一条指令）
  - M2.4 Linux/amd64 + ELF 注入（已完成）+ CI 矩阵
  - 尚未实现：共享库/PIE、CET/Authenticode
- **M3**：arm64（Win/Linux）；FP/SIMD 覆盖或明确拒绝
- **M4**：KeyProvider 的 TPM/TEE/远程证明实现（L3/L4），把"密码学级"落地
