# vmp-x：路线 B 的 VMP PoC（x86-64 / ARM64，PE + ELF）

把**已经编译好的**原生函数搬进自建虚拟机的保护方案。不需要源码、不需要重编译目标程序：
读 PE/ELF 映像 → 反汇编目标函数 → 翻译成自建 VM 的字节码 → 注入解释器 blob → 把函数入口改成跳板。

- 目标平台：Windows/amd64、Linux/amd64、Windows/arm64、Linux/arm64
- 载入格式：PE（新增 RX/RW/RX 三节）与 ELF（不引入 W+X 段，见 docs/DESIGN.md）
- 解释器是**自包含**的 freestanding blob：无 libc 依赖、无导入表、无动态符号
- **原镜像整体原地加密**（`.text`/`.rdata`/`.data`，默认对 x86-64 的 EXE 与 DLL 都开，
  `-no-enc-image` / `-no-enc-image-dll` 关闭）：文件里读不到任何原始代码；
  入口自解密（PEB→kernel32→VirtualProtect，不留 RWX；基址由"解密表地址 − 表自身 RVA"反推），
  TLS 回调会被插到数组最前（回调在入口点之前跑）。打包端会拆掉重定位表，因此镜像必须落在首选基址。
  门禁第 11 条盯着"文件里 0 残留"。
- **原镜像 `.text` 整体原地加密**（同上，本行仅保留历史说明）：
  文件里读不到任何原始代码；入口自解密（PEB→kernel32→VirtualProtect，不留 RWX），
  TLS 回调会被插到数组最前（回调在入口点之前跑）。门禁第 11 条盯着"文件里 0 残留"。
- **入口补丁之外的原生机器码在打包时被抹成伪随机字节**（`-wipe`，默认开）：产物里不再留下
  可被「同源另一份构建按 RVA 差分」拼回来的函数体，见 docs/STATUS.md 第 328–331 条

## 快速开始（Windows / amd64）

```powershell
# 1) 构建工具
go build -o build/vmpbuild.exe ./cmd/vmpbuild
go build -o build/vmpack.exe   ./cmd/vmpack
go build -o build/coverage.exe ./cmd/coverage

# 2) 编译解释器 blob（会同时写出 build/vm_interp.json 清单）
./build/vmpbuild.exe -src stub/win/x64 -out build/vm_interp.bin -manifest build/vm_interp.json -entry vm_entry

# 3) 准备一个目标程序，并保护其中一个函数（可多次 -func）
gcc -O2 -o build/target.exe testdata/target.c
./build/vmpack.exe -exe build/target.exe -func check_key -out build/target_vmp.exe

# 4) 跑起来（输出应与原生完全一致）
./build/target.exe     check_key 12345
./build/target_vmp.exe check_key 12345
```


## 一条命令跑完全部门禁（本机 Windows/amd64）

```powershell
powershell -NoProfile -File tools/gates.ps1
```

它依次跑 gofmt / go vet / go test / x86-64 E2E / DLL E2E，并在最后打印一张通过表；任何一步失败都会以非零退出码结束。
## 全量验证（真机 E2E）

| 命令 | 覆盖 | 本机实测 |
|---|---|---|
| `powershell -NoProfile -File tools/e2e.ps1` | Windows/amd64 x86-64：24 个被保护函数 × 多组取值，逐字节比对原生 | **146 passed, 0 failed**（第 79 轮复测） |
| `powershell -NoProfile -File tools/e2e_dll.ps1` | 把 DLL 里的导出函数也保护起来（含 LoadLibrary/GetProcAddress 调用链） | **3 passed, 0 failed** |
| `powershell -NoProfile -File tools/verify_linux_payload.ps1` | Linux ELF 载荷：ET_EXEC 与 PIE（两个加载地址） | 6/6 与 6/6 |
| `bash tools/e2e.sh` | Linux/amd64：ELF 打包 + readelf 断言（不得出现 W+X 段） | 需在 Linux 上跑 |
| `bash tools/e2e_arm64.sh` | Linux/arm64：qemu 端到端（**只能在 CI/真机跑**） | 见 docs/RUNBOOK.md |
| `go test ./...` | 11 个包：解码、lifter、参考 VM、注入、扫描、覆盖率 | 全绿 |
| `powershell -NoProfile -File tools/difftest.ps1` | 与独立参考实现（x86asm/arm64asm/Go 参考 VM）的差分测试 | 全绿 |

## 加固分层与四平台证据

这一版把"保护"拆成三层，每层都有**可复跑的门禁**或**真机 CI 证据**（不靠叙述）：

| 层 | 做什么 | 证据 |
|---|---|---|
| ① 原生机器码抹除（`-wipe`，默认开） | 入口跳板之外的原生函数体在打包时被抹成**伪随机**字节（不是 `E9..CC` 那种一眼可辨的填充） | 门禁第 9 条 `residue probe`：文件与**运行期内存**里 `native:check_key/sum_to` 双 absent |
| ② 字节码执行期不常驻明文（流式取指） | AEAD 只用于**验签**（Poly1305 认的是密文），取指时按 64 字节块取 ChaCha20 密钥流、逐字节异或还原；没有整份明文缓冲 | 门禁第 10 条 `bytecode plaintext scan`：打包进程里 `bytecode:check_key` **absent**；blob 544,768 → **32,768 字节** |
| ③ 原镜像整体加密（默认对 x86-64 EXE/DLL 与 ET_EXEC x86-64 ELF 开） | `.text`/`.rdata`/`.data`（PE）与可执行段（ELF）**原地**加密；入口自解密：PE 自己从 PEB 找 kernel32 取 `VirtualProtect`（arm64 走 `x18`→TEB→PEB），ELF 走 `mprotect` 系统调用（aarch64 为 `svc #226`）；TLS 目录搬进 payload 并重指；拆重定位表 | 门禁第 11 条 `image residue`：三节非零 64B 块 **0 命中**（`.text` 熵 5.99→7.99、`.rdata` 4.88→7.96、`.data` 0.75→7.59） |

四平台的真机证据（都是本仓库 GitHub Actions 跑出来的，`.github/workflows/ci.yml`）：

| 平台 | 验证内容 | 结果 |
|---|---|---|
| windows-amd64 | gofmt/vet/test + E2E 147 例 + DLL 3 例 + arm64 客户机差分 | 绿（每次 push 都跑） |
| linux-amd64 | **ELF 整体加密默认开**：打包 → 结构断言 → 文件级 0 残留 → 真跑与原生逐字节一致（`tools/e2e_elf_image.sh --strict`） | run **35482334570** 绿：`[OK  ] ELF 整体加密：输出一致` |
| linux-arm64（qemu-user） | aarch64 的 ELF 整体加密 + 入口自解密（含补上的 `ORR Xd, XZR, #imm` 形式，两个被保护函数） | run **35481622554** 绿：`chunks=9217 NON-ZERO FOUND=0` + 运行期一致 |
| windows-arm64（原生 arm64 Windows） | PE/arm64 三段：结构（补丁 `F0 03 1E AA …`）+ 文件级（`.text` 2.87→7.55、`.rdata` 0.20→7.62，0 命中）+ 运行期退出码一致 | run **35483191384** 绿：`native=… protected=…` |

> 注意：`windows-arm64-run` 在 `ci.yml` 里标了 `continue-on-error: true`（runner 标签可用性所限），
> 所以它**红不会让整个 run 变红**——看结论时要单独看这个作业。

### 仍未做（如实）

1. **镜像必须落在首选基址**：整体加密是在文件字节上做的，所以打包端会拆掉重定位表（`IMAGE_FILE_RELOCS_STRIPPED`）；基址被占则**明确失败**，不静默跑飞。代价是该模块失去 ASLR。
2. **ELF 只支持 ET_EXEC**：PIE/ET_DYN 会被 `ld.so` 的重定位写进密文，当前明确跳过（要做得先解决重定位与加密的交互）。
3. **ELF 侧只加密可执行段**：`.rodata`/`.data` 等其它段仍是明文（PE 侧已覆盖 `.rdata`/`.data`）。
4. **arm64 的两个宿主 blob 只能由 CI 构建**：本机没有 `aarch64-w64-mingw32` / `aarch64-linux-gnu` 工具链，Windows/arm64 与 Linux/arm64 的 blob 由 CI 的 clang / 交叉 gcc 作业产出并验证。
5. **解释器仍是 `-O1`**：`-O2` 下只要浮点函数里含整数↔浮点转换，整个解释器会被 gcc 编译错（见 `docs/STATUS.md` 第 71/72 轮）。
6. **指令子集未覆盖** x87、AVX/VEX、AES-NI、REP 字符串、`SYSCALL`。
7. **没有反调试/反 dump 纵深**（除入口补丁校验与自校验外），也没有 JIT。

## 覆盖到的指令子集

在**真实编译产物**上的实测（`build/coverage.exe <目标>`，函数级 = 整段可翻译的比例）：

| 目标 | 函数级 | 指令级 |
|---|---|---|
| Go 1.22 编译的 Linux 二进制（`build/linux_target`，1797 函数） | **86.8%** | **99.3%** |
| libstdc++-6.dll（5441 函数） | **91.4%** | **99.5%** |
| testdata/target.c（80 函数） | **87.5%** | **99.4%** |

子集包含（x86-64）：通用整数 ALU 全宽（含 ADC/SBB/乘法高低半/位扫描）、条件与控制流、
调用（直接/间接、含 thunk 回宿主）、栈与内存、跳转表（含 gcc 的分裂形态）、
SIMD 位运算与打包整数算术/洗牌/标量搬移、浮点标量（ADDSD/MULSD/DIVSD/CVTSI2SD/CVTTSD2SI/UCOMISD）、
以及**真正的原子读改写**（XCHG/LOCK 系列，用宿主 `__atomic_*` 实现，多线程语义与原生一致）。

## 已知限制（如实清单）

1. **调用约定只覆盖整数参数/返回值**（x86-64 SysV/Win64 的整数寄存器），浮点/向量参数不进出宿主；
   浮点只在函数**内部**可用（testdata 的 `fp_mix` 是这种用法）。
2. **解释器用 `-O1` 编译**：-O2 下只要浮点函数里含整数↔浮点转换，**整个解释器**会被 gcc 编译错
   （已二分到触发点，根因疑为解释器里既有的 UB）。代价约 1.3–1.7×（见 docs/STATUS.md 第 71/72 轮）。
3. `fp_mix` 的**两个大参数**取值仍与原生不符（未定位），因此这两个参数没有进 E2E 用例清单。
4. 未支持：x87、AES-NI、AVX/VEX、REP 字符串指令、`SYSCALL`、冷块（switch 默认目标在符号范围外）的部分形态。
5. 跨进程/跨模块仍建议视为同机可信环境（主密钥在 blob 里，见 `stub/win/x64/vm_crypto.h` 的定位说明）。
   曾经的"明文缓存 + 锁"已随**流式取指**移除：现在字节码在内存里也始终是密文，代价是解释器慢 ~1.7–1.9×。
6. 没有 JIT、没有反调试、没有 CET/Authenticode 兼容处理。
7. ARM64 侧：lifter/解码/ABI 已就绪（含 Linux/arm64 与 Windows/arm64 的 blob 构建），
   但**尚未在本机真机执行过**（本机无 aarch64 工具链/qemu），需要 CI 或真机确认。
8. 抹除只解决「函数体还躺在镜像里」这一条。**在拿到同源另一份构建的前提下，任何只做变换、不引入密钥的
   保护都能无损还原**（最省事的做法：把同源版本的原生函数搬进同一个槽位，这个槽位对调用方本来就是
   「一次调用」的语义）。跨过这个类别需要 per-build 密钥依赖（被保护函数读到的数据也加密），
   见 docs/STATUS.md 第 328–331 条。

## 性能（Windows/amd64）

数字来自 `tools/e2e.ps1` 的 bench 步骤（同一口径，改动前后对照）：

| 函数 | 原生 | 改动前（明文缓存） | 改动后（流式取指） | 代价 |
|---|---|---|---|---|
| check_key | 0.4 ns/iter | 15.3 µs/iter | 29.0 µs/iter | ×1.9 |
| sum_to | 15 ns/iter | 17.2 µs/iter | 28.7 µs/iter | ×1.7 |

开销来自解释器的取指/分发循环（这是"用可移植性换性能"的路线 B 固有代价），
流式取指再叠加 ~1.7–1.9×：每次取指多了按块取密钥流 + 逐字节异或。
> 早期 README 里那张 125×/88× 的表用的是另一套计时口径，与上表不可比（未核对，见 docs/STATUS.md）。

## 文档

- `docs/DESIGN.md`：设计（VM ISA、字节码、PE/ELF 注入、去 RWX、PIE/共享库、缓存与线程安全）
- `docs/STATUS.md`：逐轮进展与**逐条证据**（每一轮做了什么、验到了什么、哪些没验证）
- `docs/RUNBOOK.md`：四平台的可复制执行清单（含 CI 未闭环项的说明）