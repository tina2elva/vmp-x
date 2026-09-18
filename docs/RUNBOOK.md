# RUNBOOK：四平台可复制执行清单

本文件是「照着敲就能跑」的清单。**哪些已在本机验证、哪些只能在 CI/真机跑**，每条都写明。

## 0. 前置条件

| 平台 | 需要 |
|---|---|
| 通用 | Go 1.22+（本项目 `go.mod` 的版本） |
| Windows/amd64 | **Windows PowerShell 5.1 或 PowerShell 7**（本机只有 5.1，所有脚本都兼容两者）+ msys2 UCRT64 的 `gcc``objdump``ld`（或等价的 MinGW-w64 工具链）+ PowerShell 7 |
| Linux/amd64 | `gcc``binutils``readelf` |
| Linux/arm64 | `aarch64-linux-gnu-gcc``aarch64-linux-gnu-objdump``qemu-user` |
| Windows/arm64 | **已全绿**：CI 用 clang 的 `aarch64-w64-windows-gnu` 目标产出 arm64 COFF blob 并在 `windows-11-arm` 原生 arm64 Windows 上**真跑**（native 与打包后退出码一致）。本机只需 Go + clang（可选） |

## 1. Windows / amd64（本机已验证）

```powershell
go build ./...
go test ./...                              # 期望：11 个包全绿
gofmt -l .                                 # 期望：无输出
go vet ./...                               # 期望：无输出

# 全量真机 E2E（会自动重建 blob 与目标程序，并在构建失败时立刻退出）
powershell -NoProfile -File tools/e2e.ps1                   # 期望：146 passed, 0 failed
powershell -NoProfile -File tools/e2e_dll.ps1               # 期望：3 passed, 0 failed

# 覆盖率实测
go build -o build/coverage.exe ./cmd/coverage
./build/coverage.exe build/target.exe <某个 dll> build/linux_target
```

## 2. Linux / amd64

```bash
bash tools/e2e.sh
```

脚本自己会：构建工具 → `CGO_ENABLED=0 GOOS=linux` 编出真实 ELF 目标（符号完整）→ 构建 linux/amd64 blob
（优先用**宿主 gcc 产出的 ELF 可重定位目标**，失败才回退 mingw）→ 保护 `main.checkKey`/`main.sumTo` →
原生 vs 被保护逐项比对 → 用 `readelf` 断言**不存在 W+X 段**。
**这一条尚未在本机跑过**（本机是 Windows）：需要 Linux 主机或 CI。

## 3. Linux / arm64（qemu，尚未在本机跑过）

```bash
CC=aarch64-linux-gnu-gcc OBJDUMP=aarch64-linux-gnu-objdump QEMU=qemu-aarch64 \
  bash tools/e2e_arm64.sh
```

脚本会：交叉编译 aarch64 目标（只使用可翻译指令）→ 用 **内置合并器**（`-merge go`）构建 linux/arm64 blob
→ 用 AArch64 的 4 字节 `BL` 跳板 + 4 字节 `B` 入口改写打包 → 在 qemu 下比对原生与被保护输出。
qemu-user 走的是正常 `execve` 装载路径，所以**内核/加载器把控制权交给改写后入口**这件事也被覆盖。

## 4. Windows / arm64（CI 上已完成构建 + 真跑）

本机没有 aarch64 的 Windows 工具链，所以这一段完全交给 CI（两个作业）：

- `windows-arm64-blob`（ubuntu-latest）：`sudo apt-get install -y llvm lld` 后，用
  `clang --target=aarch64-w64-windows-gnu` 编 blob（合并走内置合并器 `-merge go`，不需要 ld），
  再用同一个 clang 编一个 **freestanding 的 arm64 PE 目标**并打包，校验入口补丁是 8 字节
  `mov x16,x30 ; b thunk`（报告 JSON 里 `F0 03 1E AA`）。
- `windows-arm64-run`（`windows-11-arm`，GitHub 的原生 arm64 Windows）：编 blob → 编 PE 目标 → 打包 →
  **native 与打包后各跑一次**，比对退出码（目标把被保护函数的返回值混合成一个 30 位退出码，
  任一项算错都会变）。最近一次结果：`native=654184885 protected=654184885`。

被保护函数在 arm64 上用 clang 编时注意两点（都踩过）：`sum_to` 会被折成闭式 `n*(n+1)/2`
（生成 UMULH/EXTR，不在 lifter 子集内），需要 `__attribute__((optnone))` 逼出真正的循环；
pwsh 包装器结尾 `exit $LASTEXITCODE`，跑完被保护程序后要把 `$LASTEXITCODE` 清零。

```powershell
go build -o build/vmpbuild.exe ./cmd/vmpbuild
./build/vmpbuild.exe -src stub/win/arm64 -out build/vm_interp_win_arm64.bin \
    -manifest build/vm_interp_win_arm64.json -entry vm_entry -guest arm64 \
    -cc <aarch64-w64-mingw32-gcc> -objdump <aarch64-w64-mingw32-objdump>
```

期望：打印 blob 大小与 `.text/.rdata/.bss` 布局，且**没有未定义符号**。
本机没有 aarch64 工具链，所以这一步也没跑过。


## 4.5 ARM64 **客户机**语义差分（本机可跑，已通过）

```powershell
./build/vmpbuild.exe -src stub/win/x64 -out build/vm_interp_a64g.bin `
    -manifest build/vm_interp_a64g.json -entry vm_entry -guest arm64 -random-opcodes=false
gcc -O1 -Wall -DVM_GUEST_ARM64=1 -DVM_REG_COUNT=35 -I stub/win/x64 -o build/runbc_a64g.exe stub/win/x64/blob_probe.c
go test ./internal/lift/arm64/ -run TestArm64GuestInCInterpreter -v
go test ./internal/vm/ -run TestGuestSemantics -v
```

注意：**必须**用 `-random-opcodes=false` 构建这个 blob（差分测试直接喂 Go 侧生成的默认操作码）。
这两条测试在缺产物时会 `t.Skip`，所以它们显示为通过并不代表跑过。
注意：harness **必须**与 blob 用同一套 ctx 布局（`-DVM_GUEST_ARM64=1 -DVM_REG_COUNT=35`），否则 ctx 结构大小不一致，症状是解释器 `rc=1`。
当前状态：**两条都通过**（第 76 轮修复：`VRBASE/VRSCRATCH` 对 ARM64 客户机改为 32/33，与 X0-X30/SP/ZR 不再冲突；harness 补上 `-DVM_REG_COUNT=35`）。

## 4.6 ELF 共享库（.so）—— 定位逻辑已实现，运行时验证待 CI

已实现并有单测覆盖：`.symtab` → `.dynsym` 回退（`internal/scan/elf_dynsym_test.go` 用合成的 stripped ELF 验证），
以及把目标函数当导出符号定位。**运行时 `dlopen` 验证需要 Linux**，建议步骤：

```bash
# 在 Linux 上：把共享库里的导出函数保护起来，再由宿主程序 dlopen 后调用它
gcc -O2 -shared -fPIC -o build/libtarget.so testdata/dll.c       # 复用 DLL 用例的源码
gcc -O2 -o build/dlhost build/dlhost.c -ldl                       # 宿主（dlopen + dlsym）
./build/vmpack -exe build/libtarget.so -func protected_helper -out build/libtarget.vmp.so
LD_LIBRARY_PATH=build ./build/dlhost build/libtarget.vmp.so      # 原生 vs 被保护，输出应一致
```

注意：`.so` 的注入走「覆盖段」路径（不新增 W+X），细节见 `docs/DESIGN.md`；
本机（Windows）无法执行这一步，所以它属于「需要 CI」一栏。
## 4.5 Python 扩展（.pyd）—— 已实测通过

`.pyd` 就是标准 PE DLL，python 侧没有额外格式要求；难点在**发布形态**：

- wheel 装出来的扩展没有 COFF 符号表（`该 PE 有 0 个符号`）；
- 唯一的导出常常是一枚几字节的 CFG 跳转桩（`jmp [rip+...]`，末尾不是 RET，我们会保守拒绝），
  真正干活的是 `.text` 里的内部函数。

所以这条路的做法是：**用构建时留下的 `.map` 按名字定位内部函数**，边界用 `.pdata` 的
`RUNTIME_FUNCTION`（精确）。一条命令即可（脚本会顺手做行为验证）：

```powershell
powershell -NoProfile -File tools/e2e_pyd.ps1 `
  -Pyd <dir>\example.cp313-win_amd64.pyd `
  -Map <dir>\example.map `
  -Func __pyx_pf_7example_2fibonacci `
  -Python C:\TaijiControl\WinPy313\python\python.exe `
  -Expr "print('fib(10)=', example.fibonacci(10))"
```

脚本做三件事：`vmpack -map ... -func <名字>` 打包 → 打印结构（描述符/ thunk / 入口补丁）→
把原生与打包后的 pyd 分别放进两个临时目录，用**同一个 Python 3.13 片段**各跑一遍并比对输出。

实测（2026-09，`example.cp313-win_amd64.pyd` 47616 字节）：

```
coverage: 函数 131，整段可翻译 98 (74.8%)；指令 7088，可翻译 7027 (99.1%)
__pyx_pf_7example_2fibonacci: RVA=0x13A0 native=851B -> 310 IR -> 2223B bytecode
入口补丁 E9 9B 3C 02 00（jmp 0x180025040，正好是报告里的 thunk）
原生  fib(10)=55  fib(15)=610  greet=Hello, vmp!
打包后 fib(10)=55  fib(15)=610  greet=Hello, vmp!   → 一致
```

也就是说：**Python 层的 `fibonacci()` 调用现在走 VM 执行，结果不变**。

### 多函数保护（第 8 轮实测）

一次保护多个函数：把 `-func` 重复即可（一个函数一份描述符/thunk/字节码槽，独立加密、独立校验）：

```powershell
powershell -NoProfile -File tools/e2e_pyd.ps1 -Pyd <pyd> -Map <map> \
  -Func __pyx_pf_7example_n -Func __pyx_pf_7example_2fibonacci \
  -Func __pyx_pymod_create -Func __pyx_bisect_code_objects \
  -Expr "print('fib(10)=', example.fibonacci(10)); print('n.shape=', example.n().shape)"
```

`example.cp313-win_amd64.pyd` 里 `.map` 能命名的 14 个函数实测：

| 结果 | 数量 | 说明 |
|---|---|---|
| 能翻译且**运行正确** | **4** | `__pyx_pf_7example_n` / `__pyx_pf_7example_2fibonacci` / `__pyx_pymod_create` / `__pyx_bisect_code_objects` |
| 能翻译但**运行崩溃** | **2** | `__pyx_pf_7example_6current_time_str`、`__pyx_pw_7example_9add_dly`（单独打包、单独调用同样崩，不是多函数相互影响） |
| 翻译阶段就拒绝 | 8 | 6 个「函数末尾不是 RET」（尾声是间接尾调用/跳转桩）、1 个「1/125 条指令无法翻译」、1 个「+0x0 是 JMP」 |

多函数产物的结构复测（4 个函数）：补丁 4 条全部落在我们的新节（`0x1010/0x13A0/0x2BC0/0x6450`），
`.pdata` 里 4 条记录全部清除，回填尝试（一次补回 4 处原始字节）被加载期校验拒绝，行为与原生完全一致。

**结论（重要）**：能翻译不等于能跑对。扩大保护面会立刻暴露解释器在个别函数上的运行时缺陷 ——
这也是 (f) 这一条的价值：把覆盖口径从「翻译成功率」改成「翻译 + 运行都成功」。

注意事项：

- `.map` 的 `Publics by Value` 一节里第三列是 VA（含 Preferred load address），减去它即 RVA；
- 打包后 `.pyd` 会多出 `.vmp` / `.vmpb` / `.vmpc` 三个节（stub、blob 的 .bss、描述符与字节码），体积会明显变大；
- 只保护 `-func` 点名的函数，其余（含那个 CFG 桩）保持原样；
- 目标机器上的 Python 版本必须匹配 pyd 的 ABI 标签（`cp313` → 3.13）。
## 5. 排错（三条"沉默的坑"，都是踩过的）

1. **构建失败被吞掉**：`vmpbuild` 或 `gcc` 失败时，脚本若继续就会拿**旧产物**去测，
   表现成"功能全错"。所以 `tools/e2e.ps1` 现在对 `vmpbuild` 与 `gcc` 都检查退出码并立刻退出。
2. **解释器必须用 `-O1`**：-O2 下只要浮点函数含整数↔浮点转换，**整个解释器**会被 gcc 编译错
   （`check_key` 都会算错）。这是解释器里既有 UB 被优化决策改变后暴露，见 `docs/STATUS.md` 第 71/72 轮。
3. **路径必须是纯 ASCII**：msys2 的 gcc 在非 ASCII 路径下会失败；本项目放在 `D:\\vmp-x`。


### 5.1 一条命令跑完全部本机门禁

```powershell
powershell -NoProfile -File tools/gates.ps1     # gofmt / vet / test / x86 E2E / DLL E2E
```

### 5.2 本机为什么跑不了 Linux 侧（已实测，不是猜测）

- `wsl.exe` 存在但**没有安装任何发行版**（`wsl --status` 明确提示未安装）；
- 没有 docker / podman / qemu-aarch64（都已用 `Get-Command` 确认）；
- 因此 Linux/amd64 与 Linux/arm64 的执行验证**只能**在 CI 或真机上完成。

## 7. 推送前最小改动清单（为了跑 CI）

本目录**不是 git 仓库**，也从未推送到远端。要跑 ci.yml，最少做这些：

```bash
cd /d/vmp-x
git init -b main
git add -A            # .gitignore 已忽略 build/ 与中间产物
git commit -m "vmp-x: route-B VMP PoC (x86-64/arm64, PE/ELF)"
git remote add origin <你的仓库>
git push -u origin main
```

注意两点：

1. `build/` 里既有产物也有 **AEAD 主密钥**（`build/vm_interp.json` 的 `key` 字段）——`.gitignore` 已把 `build/` 排除，
   推之前请再确认一次 `git status` 里没有 `build/`；
2. CI 首次运行最可能在 `linux-amd64`（`tools/e2e.sh`）与 `linux-arm64`（qemu）两个作业上暴露问题 ——
   这两个脚本从未在 Linux 上跑过；`windows-arm64-blob` 若镜像里没有 aarch64 COFF 编译器会**明确失败**（不会静默跳过）。
## 6. 本机 vs CI 的边界（收尾报告要用的两栏）

| 项目 | 状态 |
|---|---|
| Windows/amd64 真机 E2E（146 用例）、DLL E2E（3 用例）、Go 单测、差分测试 | **本机已验证** |
| ELF 去 RWX 断言、PIE（两个加载地址）、明文缓存线程安全（多线程原子计数 80000） | **本机已验证** |
| Linux/amd64 **注入载荷**在 Windows 上执行（`tools/verify_linux_payload.ps1`：ET_EXEC 6/6、PIE 两个装载地址一致） | **本机已验证** |
| Linux/amd64 的 `tools/e2e.sh`（打包 + readelf 断言 + 差分） | **CI 已跑到运行期**：打包成功、**无 W+X 段**、差分用例尚未全绿（根因见下一行） |
| └ Linux/amd64 运行期问题的定位 | 模拟栈位于宿主 RSP 之下约 12.7KB（FRAME 4544 + EXTRA 16 + MARGIN 8192），而 Go 程序的 **goroutine 栈初始只有 8KB** → `runtime: split stack overflow`。单纯的『把客户机栈搬走』已试过并回退（见 docs/STATUS.md 第 92 轮） |
| Linux/arm64 的 `tools/e2e_arm64.sh`（交叉编译 + qemu） | **CI 已跑到执行**：blob 构建 ✓、AArch64 打包 ✓（补丁是 8 字节 `mov x16,x30 ; b thunk`）、qemu 首次执行 → **段错误**（尚未定位） |
| └ Linux/arm64 的已知缺口 | 该目标 ELF 只有 3 个 phdr，NOTE 槽位要留给覆盖段，缺少第二个空槽 → payload 段**退回 RWX**（代码里明确 `[warn]`，不是静默降级） |
| （第 96/97 轮更新）`windows-amd64` | **runner 上无失败步骤**：帧 640 + margin 3KB + 16 个缓存槽的配置下，146 例 E2E 全部通过。此前 runner 上失败的是 `mt(0)`（多线程），真因是「兜底缓冲池」在 4 线程 × 嵌套下被耗尽 —— 已删除该池（见 STATUS 289/290） |
| （第 103 轮）`linux-amd64` | **全绿**（CI `failedSteps=[]`）：打包 ✓、无 W+X ✓、payload 探针 ✓、差分 E2E ✓。此前失败的根因是**重叠 PT_LOAD 的映射顺序**（可写覆盖段被 payload 的 RX 映射盖回去），见 §5 踩坑 |
| （第 120 轮后更新）`linux-arm64` | **全绿**：blob 构建 ✓、打包 ✓、qemu 端到端输出与 native 一致。主要修复：arm64 适配器不再吞掉 Unsupported（fail-fast）；寄存器形式 ADD/SUB 的 Rd/Rn=31 按 XZR 处理（cmp 由此可译）；入口 stub 返回值不再被还原循环冲掉 |
| Windows/arm64 blob 构建 | **需要外部工具链**：runner 镜像里没有能产出 aarch64 COFF 的编译器（作业按设计显式失败，`continue-on-error`） |