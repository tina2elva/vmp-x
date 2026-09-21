# TODO —— 已登记待办

> 纪律：每条都要有「为什么 / 验收标准 / 证据落点」三件套。做完就把这条从这里删掉，
> 过程与证据写进 `docs/STATUS.md`（编号追加，不覆盖历史）。
> 本文件是**待办清单**；任务书（授权范围、验收口径）仍以 `docs/HANDOFF.md` 为准。

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

**要做**：`CDQ`(0x99) / `CQO`(0x48 0x99)、`IDIV`(F7 /7，r/m8/16/32/64)、`DIV`(F7 /6) 的 lift + 语义 + 单测。

**验收**：`tools/gates.ps1` 11/0；对 `D:\demo_exe` 的 exe 逐个函数试，`Gcd`/`IsPrime` 变成"可保护"，
且进 VM 后输出与原生逐行一致。

**边界**：除零异常（客户机 #DE）语义暂不模拟 —— 遇到就拒绝翻译并报明确错误，不要静默算错。

## 2. 调试版的**栈传参 / varargs**（影响面最大）

**现象（实测，单函数二分确认）**：`/Od /RTC1` 构建下把 `?DemoFormatReport@@YAHPEADHPEBDH@Z` 单独进 VM，
输出 `score=8`（原生 **42**）；**同一个函数在 `/O2` 下是正确的**。

**嫌疑**：该函数形如 `sprintf(buf, n, fmt, score)`，那个 `%d` 参数走**栈**（第 5 个及以后的参数 / varargs），
`/Od` 与 `/O2` 对参数的物化方式不同。

**为什么优先**：任何用 `sprintf`/varargs/参数超过 4 个的函数都会踩 —— 覆盖面最广。

**验收**：`DemoFormatReport` 在 `/Od` 与 `/O2` 两种构建下都逐行一致；并补一条 e2e 覆盖"栈参数 + varargs"。

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
- [ ] `-key-in` 的"密钥纪元"策略落地：每客户（或客户+产品线）一个纪元，交付时按 `<产物>.vmpkey` 命名分发。(`STATUS #395`)
