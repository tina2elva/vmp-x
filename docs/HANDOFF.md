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
- 仍未做：**(1) 的接线**、1b（主密钥外置 + 硬门）、(2) 的实现、(3) 容器加密与混淆、(4) 反调试多路径。

## 3. 任务（按顺序做，做完一项再做下一项）
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
3. 验证顺序：重建 blob → `tools/gates.ps1`（要求 **11 gates / 0 failed**）→ 本机产品级回归
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
1. `tools/gates.ps1` = **11 gates / 0 failed**；e2e **147 passed / 0 failed**；dll 3/3；arm64 客户机 OK；
2. 本机产品级回归：demo64 三节全加密、`.rdata` 熵 ≈7.99、**≥12 字节可读串 ≈0**、native/protected 输出除 base 两行外一致；
3. CI **五个作业全绿**（run 号写进 STATUS）；
4. `docs/STATUS.md` 追加一条：做了什么、证据（含 run 号与命令）、**未做项**。
