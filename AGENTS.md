# AGENTS.md —— 在这个仓库里工作前必读

**当前任务**：vmp-x 的加固收尾。**唯一权威任务书**是 `docs/HANDOFF.md`，请先完整读它，
再读 `docs/STATUS.md` 的 `#378`（接线步骤与行号）、`#379`/`#380`（前置三重确认）、`#381`（(5)(6) 评估）、`#382`（(2) 选型）。

## 动手前
1. `git log --oneline -5` 与 `git status --short`：**这个工作区可能有另一个会话同时在改**。
   看到不是自己写的未提交改动，**不要覆盖、不要 `git add -A`**，先问清楚或只提交自己改的路径。
2. 改共享代码前先 `grep` 出**真实文本**再写补丁；补丁脚本必须 count 校验（恰好一次才动手）。

## 硬性纪律（本仓库踩过的坑）
- 判定标准是**产物**：新增源文件要"blob 真编出来"才算完成。进 blob 的方式是 `cmd/vmpbuild` 里的
  `appendUnique`，**不是** `BLOB.sources`（那里是相对 `stub/` 的路径表，写错会让 blob 构建失败）。
- 任何"搜/采/对比"类探针**先校准**（用已知存在的对象试一次），否则空结果无意义。
- 打包端与运行期的一致性改动（密钥/格式/KDF）**必须同一轮改完并端到端验证**，错一字节 = 全量 trap。
- 工具输出**只用 ASCII**（Windows runner 的 python stdout 是 cp1252）。
- PowerShell 里**别用 bash 的 heredoc**（`<<'MSG'`）；提交信息写文件再 `git commit -F`。
- **不要在上下文/预算不足时动主干**——宁可只做零风险登记。

## 完成一项的验收（缺一不可，全部要有证据）
1. `powershell -NoProfile -ExecutionPolicy Bypass -File tools/preflight.ps1` → `[+] preflight: OK`；
2. `tools/gates.ps1` → `total 11 gates, 0 failed`（e2e 147/0、dll 3/3、arm64 客户机 OK）；
3. CI **五个作业全绿**（`gh run list` 取 run 号）；
4. `docs/STATUS.md` 追加一条：做了什么、证据（含 run 号与命令）、**未做项**。

## 明确不要做
- 不要去迎合第三方报告里那两条**误读**（"解密后原生执行"、"离线解密即得原函数体"）。
- **不要**在 aarch64 上打开 ELF 只读数据节加密（`-enc-image-elf-data`）：CI 实测必然 SIGSEGV（`docs/STATUS.md #376`）。
- 不要为了让检查通过而放宽阈值，也不要只保某一个平台。
