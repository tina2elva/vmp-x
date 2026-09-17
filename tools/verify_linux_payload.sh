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
./build/extractpayload -elf build/linux_target.vmp -rva "$sec_rva" -size "$sec_size" -thunk "$thunk_rva" -out build/linux_payload.bin
echo "[*] running the payload probe (payload mapped at its original VA)..."
thunk_off=$(printf '0x%x' $((thunk_rva - sec_rva)))
va=$(grep -o 'payloadVA=0x[0-9A-Fa-f]*' build/payload_meta.txt | head -n1 | cut -d= -f2)
echo "    payloadVA=$va thunkOff=$thunk_off"

pass=0; fail=0
for a in 0 1 10 255 12345 1000000; do
    want=$(./build/linux_target check-key "$a")
    got=$(./build/payload_probe_linux build/linux_payload.bin "$va" "$thunk_off" "$a" | grep -o '= [0-9]*' | head -n1 | cut -d' ' -f2)
    if [ "$want" = "$got" ]; then
        pass=$((pass+1)); echo "  [OK  ] check-key($a) = $got"
    else
        fail=$((fail+1)); echo "  [FAIL] check-key($a): native=$want payload=$got"
    fi
done
echo ""
echo "payload probe: $pass passed, $fail failed"
[ "$fail" -eq 0 ]