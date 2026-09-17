# RUNBOOK：四平台可复制执行清单

本文件是「照着敲就能跑」的清单。**哪些已在本机验证、哪些只能在 CI/真机跑**，每条都写明。

## 0. 前置条件

| 平台 | 需要 |
|---|---|
| 通用 | Go 1.22+（本项目 `go.mod` 的版本） |
| Windows/amd64 | **Windows PowerShell 5.1 或 PowerShell 7**（本机只有 5.1，所有脚本都兼容两者）+ msys2 UCRT64 的 `gcc``objdump``ld`（或等价的 MinGW-w64 工具链）+ PowerShell 7 |
| Linux/amd64 | `gcc``binutils``readelf` |
| Linux/arm64 | `aarch64-linux-gnu-gcc``aarch64-linux-gnu-objdump``qemu-user` |
| Windows/arm64 | 只有 **blob 构建**这一步（用 aarch64 交叉工具链产出 COFF 目标文件） |

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

## 4. Windows / arm64（只验证 blob 构建）

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
| Linux 加载器映射并跳转、`tools/e2e.sh`、Linux/arm64 qemu E2E、Windows/arm64 blob 构建 | **需要 CI/真机** |