# HANDOFF —— vmp-x 加固收尾任务书（给另一个会话）

> 这份文件是**自足**的：不需要上一段对话的上下文。请先通读，再动手。

## 0. 一句话任务
在 `D:\vmp-x`（route-B VMP PoC：把函数体提升为自定义 IR → VM 字节码 → 由自带 freestanding 解释器解释执行）
里，按已排好的顺序完成**密钥依赖加固**与后续几项，**每步保持门禁全绿、CI 全绿、并如实登记未做项**。

## 1. 环境与工具
- 工作区 `D:\vmp-x`；Go 1.24；Windows 10/11；本机有 msys2 gcc（`gcc`）与 Go 交叉编译（`GOOS=linux GOARCH=arm64` 可用）。
- CI：GitHub Actions，仓库 `tina2elva/vmp-x`（public）。作业：`windows-amd64` / `linux-amd64` / `linux-arm64`(qemu) / `windows-arm64-blob` / `windows-arm64-run`。
- `gh` CLI 在 `"C:\Program Files\GitHub CLI\gh.exe"`（已登录 tina2elva，但不在 PATH，用绝对路径调）。
- 本机没有 aarch64 工具链、没有 Linux/qemu：aarch64 与 Linux 侧的运行期验证**只能交给 CI**。

## 2. 当前状态（起点）
- `main` 最新提交 `35e478c`（文档），此前 `1877c7b`/`382166c` 也是文档；功能提交最近的几条：
  `df6ebba`(vm_kdf.c 进 blob)、`ed10ce6`(salt 派生+用例)、`0ee2fda`(salt 跨语言 KAT)。
- 已完成且有三重确认（本机门禁 + 产品级回归 + CI）：**目标项 (1) 的全部前置**。
- 已评估登记：#381 里 (5) 判"不做"、(6) 给出可实现方案排后；#382 定了 (2) 的选型。
- **仍未做**：**无** —— (1)(1b)(2)(3)(4)(6) 已**全部落地**（逐项证据见下与 `docs/STATUS.md`）。
  剩下的是**已登记的边界项**（据实更新）：取钥形态里 `.dpapi`（`#590`）与 `.ncrypt`（CNG/TPM 封印，`#591`）**已落地**，
  **授权回调形态已于 2026-09-30 拍板「不做」**（决定与三条回头条件见 `docs/TODO.md` 专节）；**TEE/远程证明那一档仍未做**
  （"私钥物理上不出芯片"的硬件保证/attestation 未验）。ELF 的 `.rela.dyn/.rela.plt` 应用器**已落地**（`#592`，
  提交 `0aac4a3`/`098bd98`/`d5d038c`/`411b764`；语义不是「先减后加」而是「验签前还原成 `r_addend ^ 密码流`」）。
  其余未做项（含"数字自我美化"类问题）逐条登记在 `docs/TODO.md`。「外部文件源之外的取钥形态（授权回调 / TPM-TEE）、ELF 的 .rela 应用器」
  这条原始措辞至此已全部结清，见 `docs/TODO.md`。
  **已由后续会话补齐的几项**：Linux 侧反调试 `TracerPid`（`STATUS #587`）、DLL + 外置密钥（`#589`）、
  payload 主密钥的 DPAPI 受保护形态 `<产物>.vmpkey.dpapi`（`#590`）、CNG/TPM 封印形态 `<产物>.vmpkey.ncrypt`（`#591`）；
  另外还补齐了 ELF PIE（ET_DYN）的镜像加密与运行期重定位应用器（`#592`，CI 覆盖由 `411b764` 补上）。
  **⚠️ 交接提醒**：`docs/STATUS.md #582` 的"未做项"一栏仍写着 T3/T4/T5 未做，那是**沿用旧任务书的过期说法**；
  以本节与 `#583` 为准。
- **已由后续会话完成（本条原为"未做"，据实更新；证据见 docs/STATUS.md）**：
  - **T1（目标项 (1) 接线：每条目派生密钥）** ✅：运行期 `vm_kdf_entry(master, rva, salt, key)` 已**逐节**现推；
    打包端 `inject.KDFSaltForPlacement` 与之同式；KAT 三重对齐（`TestKDFEntryMatchesC` / `TestKDFSaltDistinctAndStable` /
    `TestPatchMACMatchesC` + 门禁里的 **blob 级 KAT**：`vm_kdf_salt x5 + vm_kdf_entry x3 + patch_mac x1 match`）。
  - **T2（目标项 1b：主密钥外置 + 硬门）** ✅：三种形态（`VMPX_KEY` 环境变量 / `<产物>.vmpkey` 文件 / 无密钥）；
    无密钥时 **恰好 `0xC0DE0007` 且无输出**（CI 实测，见门禁 `[OK] 1b: no key -> 0xC0DE0007 (hard gate)`）；
    密钥校验 tag 由主密钥派生；`linux/amd64`、`linux/arm64`、`win/x64`、`win/x86` 四平台各含三形态回归。
  - **T3（目标项 (2)：完整性校验改带密钥 MAC）** ✅（`#386`，提交 `4eda829`）：入口补丁校验从**无盐 FNV**
    换成 `PatchMAC = Poly1305(KDFEntry(master, funcRVA, salt ^ 0x9E3779B9), patch || selfRVA || funcRVA || codeLen)`
    —— 按 `#382` 的选型**复用已有 Poly1305，没有新写 SHA/HMAC**；运行期只有 `vm_kdf.c:vm_patch_mac()` **一份**实现
    （原来两处各自内联 FNV，正是"两侧各改一半"的温床）。三处 KAT 把公式钉死（C 主机端 `kdf_kat.c`、Go `patchmac_test.go`、
    **blob 级** `kdf_blob_kat.c`），e2e 增加"把入口前 N 字节改回原生"的**回填**用例（必须拒绝执行，实测 `0xC000001D`）。
    **"校验开销占比"数字**：`bench check_key` 50 万次 —— 不带校验 15361 ticks vs 带 MAC 15274 ticks
    ⇒ **差异 <1%（在噪声内）** ⇒ 按实测**不做抽样**（这是评估结论，不是漏做；将来校验变重再加计数器即可）。
  - **T4（目标项 (3)：容器/记录明文收口）** ✅（`#387`，提交 `aa71dae` + `664eccc`）：描述符魔数**默认每次构建随机**
    （原来非 release 固定 `"VMPK"`，是可被签名/扫描的 4 字节特征）；描述符偏移 8..32 的 6 个 u32、
    原镜像解密表的**表头 12..24 与每条目 0..12**、加载期校验表**每条 24 字节**，分别与 `KDFEntry(master, 域常量, FieldMaskSalt)`
    逐字节异或；掩码种子每构建随机、**无主密钥推不出**；门禁 `tools/field_mask_check.py` 且**已校准**（把掩码改成空操作 ⇒ 5 处失败）。
    踩坑：aarch64 入口汇编里**写死**了魔数 `"VMPK"` 并据此判断"thunk 前有没有描述符" ⇒ 已改用 `VM_DESC_MAGIC_LO/HI` 宏。
  - **T5（目标项 (4)：反调试多路径 + 失败静默延后）** ✅（`#389`，提交 `eff45b1`）：四条路径 ——
    `PEB.BeingDebugged` / `ntdll!NtQueryInformationProcess`（DebugPort + DebugObjectHandle）/
    `ntdll!NtGetContextThread` 的 `Dr0..Dr3/Dr7`（**刻意不读 Dr6**，它复位时非 0，读了必误报）/ 一次性宽松 `rdtsc` 时间差。
    判定按**路径位掩码** ⇒ **≥2 条不同路径**才算定性（按计数会因两个调用点把同一路径算两次 ⇒ 实测 flagged 输出 782→824）；
    定性后**不 trap**，而是静默延后 `VM_DBG_DEFER_CALLS`(=3) 次调用返回错值 ⇒ 没有"一眼可定位的崩点"。
    时间差路径的阈值被实机噪声顶到过 1e7 cycles（会误报），提到 **1e9 cycles**；校准用例 `tools/antidebug_flag_test.py`。
  - **T6（目标项 (6)：保留重定位 + ASLR）** ✅（`#390`，提交 `942ce55`，**默认行为**）：`vmpack` 不再拆重定位表/清 `DYNAMIC_BASE`
    （旧行为留在应急开关 `-strip-relocs` 后）；运行期四步"**按 DIR64 减回 delta → AEAD 验签 → 解密 → 把 delta 加回去**"，
    打包端往 `.reloc` 追加 7 个 DIR64（TLS 回调数组的 3 个非零项 + TLS 目录副本的 4 个 VA 字段）。
    静态证据 `tools/pe_reloc_info.py`、动态证据 `tools/aslr_probe.py`（产物确实被加载器搬到 `0x7FF6…`）。
  - **另（本轮收尾技术债，不属于 T1–T6）** ✅：
    ① 诊断脚手架改为**默认不编进 blob**（`-diag` 显式打开；外置 blob 实测省 **~8 KB**，且不再与 `-release` 的语义矛盾）；
    ② 诊断落盘从 kernel32 的**转发导出高风险区**（`CreateFileA/WriteFile/GetStdHandle/CloseHandle`）改走 **ntdll**
    （`NtCreateFile/NtWriteFile/NtClose`，ntdll 的导出从不转发 —— 与取钥/硬门/VEH 一致）；
    ③ 门禁从 **12 道加到 14 道**：新增"产物节映射 ↔ blob 偏移一致性 / payload 逐字节一致 / `.reloc` 覆盖 / `SizeOfImage`"
    （`tools/check_symmap.py`，**自校准**）与"诊断是否 opt-in、是否只走 ntdll"两道。
  - **另**：win/arm64 一度推进后被**暂缓（fail-fast，白名单关闭）**，详见 `docs/STATUS.md #537-#581`；
    该平台与本任务书 T1–T6 无关，不影响其它平台。

## 3. 任务（按顺序做，做完一项再做下一项）

> **状态：T1–T6 与下面的收尾技术债已全部完成**（证据见 §2 与 `docs/STATUS.md`）。
> 本节保留**当时的原始任务描述**，作为**验收口径的留档**（行号可能已经漂移，动手前先 `grep` 真实文本）。
**T1（最高优先）目标项 (1) 接线：每条目派生密钥**
1. 打包端 `cmd/vmpack/main.go`：
   - 三处把"单个 `aead`"换成"每条目 `aead_f = AEAD(KDFEntry(master, rva, salt))`"：
     约 142 行（字节码 Seal）、893 行（PE 整体加密 Seal）、937 行（ELF 整体加密）；
   - 字节码条目的 salt 用 `inject.KDFSaltForPlacement(selfRVA, codeRVA, codeLen)`；
     镜像表条目用**表头里的 salt**；
   - `patchKey`（约 147 行 `copy(patchKey[:], key[:8])`）改成由该条目的 `K_f` 派生。
2. 运行期 `stub/win/x64/vm_interp.c`：七处 `u8 key[32] = VM_KEY_BYTES;`（约 558/659/679/1344/1454/1544/1695 行）
   改成"按该条目的 rva/salt 现推 `K_f`"。C 侧 salt 必须与 Go 的 `KDFSaltForPlacement` 一致
   （`vm_kdf_salt()` 已实现，KAT 已对齐，直接调用即可）。
3. 验证顺序：重建 blob → `tools/gates.ps1`（要求 **15 gates / 0 failed**）→ 本机产品级回归
   （见第 5 节 demo64 命令）→ push → 等 CI **五个作业全绿**。
4. 补一条单测："不同 RVA ⇒ 不同 salt ⇒ 不同 key"（`internal/inject/kdf_test.go` 已有 salt 用例，可扩展）。

**T2 目标项 1b：主密钥外置 + 硬门**
- `vmpbuild` 支持"占位密钥"模式（blob 里编译零密钥/占位，不含真主密钥）；
- 真主密钥来源可切：env / 外部文件 / 授权回调；payload 里放**密钥校验 tag**（由主密钥派生）；
- 缺失或不匹配 ⇒ **硬门拒绝执行**（专用退出码 `0xC0DE0007`、无输出）；默认 file 源保持兼容；
- CI 加两次运行：不给密钥必须**恰好**以该码失败、给了必须与原生输出逐字节一致。

**T3 目标项 (2)**：按 `docs/STATUS.md #382` 的选型做（复用 Poly1305，不新写 SHA/HMAC），
改造前后各测同一组被保护函数调用，给出"校验开销占比"数字。

**T4 目标项 (3)**：加密/混淆解密表与描述符本身、魔数默认随机、RVA/长度/标志混淆。

**T5 目标项 (4)**：反调试从仅 `PEB.BeingDebugged` 扩到 DR 寄存器/时间差/多路径 + 失败静默延后。

**T6（可选）目标项 (6)**：按 #381 的方案实现"先减回去 → 解密 → 再加回来"，保留重定位与 ASLR。

## 4. 硬性纪律（违反过的都写在 #374–#382 里）
1. **先读原文再改**：改共享代码前先 `grep` 出真实文本，别凭记忆写锚点；补丁脚本要 **count 校验**（恰好命中一次才动手）。
2. **判定标准是产物，不是测试**：新增源文件要"blob 真编出来"才算完成。`vm_crypto.c`/`vm_kdf.c` 进 blob 的方式是
   `cmd/vmpbuild/main.go` 里的 `appendUnique`，**不是** `BLOB.sources`（那是相对 `stub/` 的路径表，
   写错会让 blob 构建直接失败——踩过一次）。
3. **探针必须先校准**：任何"搜/采/对比"类检查，先用一个**已知存在**的对象试一次；否则空结果无意义
   （曾用"blob 里搜符号名"验证，连 `vm_entry` 都搜不到——blob 不带符号名，名字在 manifest 里）。
4. **两侧一致性改动一次做完**：KDF/密钥/格式类改动，打包端与运行期必须同一轮改完并端到端验证；错一字节 = 全量 trap。
5. 工具输出**只用 ASCII**（Windows runner 的 python stdout 是 cp1252，中文会 `UnicodeEncodeError` 被误判成其它失败）。
6. PowerShell 里**不要用 bash 的 heredoc**（`<<'MSG'`），提交信息写文件再 `git commit -F`；多行 `argparse`/`flag` 调用插入参数要插在**整个调用之后**。
7. CI 日志：`gh run view <id> --job <jobid> --log`；有些步骤的输出被脚本重定向进 `build/ci_step.log`，job 日志只回显尾部，
   必要时看注解 `::error title=...::` 里带的内容。注意 `windows-arm64-run` 在 `ci.yml` 里是 `continue-on-error: true`。
8. **不要在余量不足时动主干**：宁可只做零风险登记（这正是本次阻塞的原因）。
9. 每轮把"做了什么、证据、未做项"写进 `docs/STATUS.md`（追加编号，不覆盖历史）。

## 5. 关键入口与现成工具
| 用途 | 位置/命令 |
|---|---|
| 接线步骤与行号（起点） | `docs/STATUS.md #378` |
| 前置的三重确认状态 | `docs/STATUS.md #379`、`#380` |
| (5)/(6) 评估结论 | `docs/STATUS.md #381` |
| (2) 选型 | `docs/STATUS.md #382` |
| KDF / salt 两侧实现与 KAT | `internal/inject/kdf.go`、`stub/win/x64/vm_kdf.c`、`kdf_kat.c` |
| 本机门禁（必须 11/0） | `powershell -NoProfile -ExecutionPolicy Bypass -File tools/gates.ps1` |
| 暴露面/语义门禁 | `python tools/expose_report.py --img A --compare B --sections .text,.rdata,.data --max-ratio 0.05` |
| 文件级残留 | `python tools/image_residue.py --src A --packed B --section .text,.rdata,.data` |
| demo64 打包（无 COFF 符号，用合成 MAP） | `build/demo64.map`（若无则按 `ground_truth_exe.txt` 的 RVA 生成 MSVC MAP） |
| demo64 端到端回归 | `build\\vmpack.exe -exe D:\\demo_exe\\demo64.exe -map build\\demo64.map -func DemoAdd -func DemoFibonacci -func DemoFactorial -func DemoGcd -blob build\\vm_interp.bin -manifest build\\vm_interp.json -out build\\demo64_new.exe`，再比对 native/protected 输出（**只应差打印 base/地址的两行**） |

## 6. 明确不要做
- **不用**去迎合第三方报告里那两条**误读**（"解密后原生执行"、"离线解密即得原函数体"）——那两条由报告作者验证。
  本项目的真实结构：函数体 → IR → VM 字节码 → 解释器解释执行，原字节在打包时被 `-wipe` 抹除。
- **不要**在 aarch64 上打开 ELF 只读数据节加密（`-enc-image-elf-data`）：CI 实测必然 SIGSEGV，两个假设已被否（#376）。
- **不要**为了让检查通过而放宽阈值或只保某一个平台。

## 7. 验收标准（每项都要给证据）
1. `tools/gates.ps1` = **15 gates / 0 failed**；e2e **165 passed / 0 failed**；dll 3/3；arm64 客户机 OK；
2. 本机产品级回归：demo64 三节全加密、`.rdata` 熵 ≈7.99、**≥12 字节可读串 ≈0**、native/protected 输出除 base 两行外一致；
3. CI **五个作业全绿**（run 号写进 STATUS）；
4. `docs/STATUS.md` 追加一条：做了什么、证据（含 run 号与命令）、**未做项**。


---

## 附录 A：T1 精确改动点（动手前先按这里 `grep` 出原文）
- 打包端 `cmd/vmpack/main.go`：单个 `aead` 的三处使用（字节码 Seal ≈142 行、PE 整体加密 Seal ≈893 行、ELF 整体加密 ≈937 行）；`patchKey` 赋值 ≈147 行；`inject.Options` 传递处 ≈491/661 行。
- 运行期 `stub/win/x64/vm_interp.c`：七处 `u8 key[32] = VM_KEY_BYTES;`（≈558/659/679/1344/1454/1544/1695）。
- 派生函数已就位：`internal/inject/kdf.go` 的 `KDFEntry`/`KDFSaltForPlacement`；C 侧 `stub/win/x64/vm_kdf.c` 的 `vm_kdf_entry`/`vm_kdf_salt`（KAT 已对齐，5 组向量见 `docs/STATUS.md #378`）。
- 注意：另一会话已在 `vm_interp.c` 里用 `d->reserved1` 作条目 salt 调用 `vm_kdf_entry` —— **先确认它与打包端写入的字段含义一致**，不一致就是全量 trap。

## 附录 B：验收证据清单（缺一不可）
1. `tools/preflight.ps1` → `[+] preflight: OK`；
2. `tools/gates.ps1` → `total 15 gates, 0 failed`（e2e 165/0、dll 3/3、arm64 客户机 OK）；
3. demo64：三节全加密、`.rdata` 熵 ≈7.99、**≥12 字节可读串 ≈0**、native/protected 仅 base/地址两行不同、退出码 0=0；
4. CI 五个作业全绿，run 号写进 STATUS。

## 附录 C：并发协作约定
- 工作区可能有两个会话同时改：**提交只用明确路径**（如 `git add cmd/vmpack/main.go`），**不要 `git add -A`**；动手前 `git status`/`git log` 看清现状。
- 若发现别人未提交的改动：**不要覆盖**，先确认边界或停下来问。
