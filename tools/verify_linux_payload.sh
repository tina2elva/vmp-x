#!/usr/bin/env bash
# verify_linux_payload.sh - 在 Linux 本机验证"被保护 ELF 的 payload 能否执行"。
#
# 目的：把"哪一环坏"切成两半 —— payload（解释器 blob + 描述符 + thunk + SysV 入口 + 字节码）
# 与 "加载器把控制权交给被补丁的函数入口"。Windows 侧有等价脚本（tools/verify_linux_payload.ps1），
# 这里用 POSIX mmap 版本，好在 CI 的 Linux 上直接跑。
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build

echo "[*] building tools..."
go build -o build/vmpbuild ./cmd/vmpbuild
go build -o build/vmpack ./cmd/vmpack
go build -o build/extractpayload ./cmd/extractpayload
gcc -O1 -Wall -o build/payload_probe_linux stub/linux/amd64/payload_probe_linux.c

echo "[*] building linux/amd64 target + blob + packing..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o build/linux_target ./testdata/linux
./build/vmpbuild -src stub/linux/amd64 -out build/vm_interp_linux.bin -manifest build/vm_interp_linux.json -entry vm_entry >/dev/null
./build/vmpack -exe build/linux_target -func main.checkKey -func main.sumTo \
    -blob build/vm_interp_linux.bin -manifest build/vm_interp_linux.json \
    -out build/linux_target.vmp -report build/linux_vmp.json >/dev/null

echo "[*] extracting the injected payload..."
python3 - <<'PY' > build/payload_args.txt
import json
d = json.load(open('build/linux_vmp.json'))
p = [x for x in d['placements'] if x['name'] == 'main.checkKey'][0]
print(d['sectionRVA'], d['sectionSize'], p['thunkRVA'])
PY
read -r sec_rva sec_size thunk_rva < build/payload_args.txt
./build/extractpayload -elf build/linux_target.vmp -rva "$sec_rva" -size "$sec_size" -thunk "$thunk_rva" -out build/linux_payload.bin -patchout build/linux_payload_patch.txt | tee build/payload_meta.txt
echo "[*] running the payload probe (payload mapped at its original VA)..."
thunk_off=$(printf '0x%x' $((thunk_rva - sec_rva)))
va=$(grep -o 'payloadVA=0x[0-9A-Fa-f]*' build/payload_meta.txt | head -n1 | cut -d= -f2)
# 两个关键符号在 blob 内的偏移（payload 的第 0 字节就是 blob 的第 0 字节），用于把故障 PC 映射回函数
read -r vm_run_off vm_entry_off < <(python3 - <<'PY'
import json
d = json.load(open('build/vm_interp_linux.json'))
s = d['symbols']
print(s['vm_run'], s['vm_entry'])
PY
)
echo "    vm_run=+0x$vm_run_off vm_entry=+0x$vm_entry_off"
echo "    payloadVA=$va thunkOff=$thunk_off"

pass=0; fail=0
for a in 0 1 10 255 12345 1000000; do
    want=$(./build/linux_target check-key "$a")
    prc=0
    pout=$(./build/payload_probe_linux build/linux_payload.bin "$va" "$thunk_off" "$vm_run_off" "$vm_entry_off" "$a" build/linux_payload_patch.txt) || prc=$?
    if [ "$prc" -ne 0 ]; then
        echo "  [FAIL] 探针在 check-key($a) 上异常退出：rc=$prc（139=SIGSEGV / 132=SIGILL）"
        printf '%s' "$pout" | head -n 6 | sed 's/^/         /'
        # 关键：只反汇编探针报的那个故障偏移附近（±0x40），否则会被无关代码淹掉
        foff=$(printf '%s' "$pout" | grep -o 'FAULTOFF=0x[0-9A-Fa-f]*' | head -n1 | cut -d= -f2)
        if [ -n "$foff" ] && command -v objdump >/dev/null 2>&1 && [ "$fail" -eq 0 ]; then
            lo=$(printf '0x%X' $((foff - 0x40)))
            hi=$(printf '0x%X' $((foff + 0x40)))
            echo "         --- blob 反汇编 $lo .. $hi （故障偏移 $foff）---"
            objdump -D -b binary -m i386:x86-64 --adjust-vma=0 --start-address=$lo --stop-address=$hi build/vm_interp_linux.bin 2>/dev/null | sed 's/^/         /'
        fi
        fail=$((fail+1))
        continue
    fi
    got=$(printf '%s' "$pout" | grep -o '= [0-9]*' | head -n1 | cut -d' ' -f2)
    if [ "$want" = "$got" ]; then
        pass=$((pass+1)); echo "  [OK  ] check-key($a) = $got"
    else
        fail=$((fail+1)); echo "  [FAIL] check-key($a): native=$want payload=$got"
    fi
done
echo ""
echo "payload probe: $pass passed, $fail failed"
[ "$fail" -eq 0 ]