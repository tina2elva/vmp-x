/* kdf_kat.c - 主机端 KAT：与 Go 侧 internal/inject/kdf.go 必须逐字节一致。 */
#include <stdio.h>
typedef unsigned char u8;
typedef unsigned int u32;
void vm_kdf_entry(const u8 master[32], u32 rva, u32 salt, u8 out[32]);
u32 vm_kdf_salt(u32 selfRVA, u32 codeRVA, u32 codeLen);
int main(void) {
    u8 master[32];
    for (int i = 0; i < 32; i++) master[i] = (u8)(0x10 + i);
    u32 rvas[5] = {0x1670u, 0x16A0u, 0x1700u, 0x1730u, 0x93000u};
    for (int c = 0; c < 5; c++) {
        u32 salt = vm_kdf_salt(rvas[c], 0x90u, 40u);
        u8 out[32];
        vm_kdf_entry(master, rvas[c], salt, out);
        printf("rva=0x%-6X salt=0x%08X key=", rvas[c], salt);
        for (int i = 0; i < 32; i++) printf("%02x", out[i]);
        printf("\n");
    }
    return 0;
}
