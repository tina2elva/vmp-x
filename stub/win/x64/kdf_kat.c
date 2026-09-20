/* kdf_kat.c - 主机端 KAT：与 Go 侧 internal/inject/kdf.go 必须逐字节一致。 */
#include <stdio.h>
#include <string.h>
typedef unsigned char u8;
typedef unsigned int u32;
void vm_kdf_entry(const u8 master[32], u32 rva, u32 salt, u8 out[32]);
int main(void) {
    u8 master[32];
    for (int i = 0; i < 32; i++) master[i] = (u8)(0x10 + i);
    u32 cases[3] = {0x1670u, 0x16A0u, 0x93000u};
    u32 salts[3] = {0x11223344u, 0x11223344u, 0xAABBCCDDu};
    for (int c = 0; c < 3; c++) {
        u8 out[32];
        vm_kdf_entry(master, cases[c], salts[c], out);
        printf("rva=0x%X salt=0x%X key=", cases[c], salts[c]);
        for (int i = 0; i < 32; i++) printf("%02x", out[i]);
        printf("\n");
    }
    return 0;
}
