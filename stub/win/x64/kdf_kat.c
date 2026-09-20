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
    /* 接线约定：描述符 → 条目密钥。C 侧运行期是 vm_interp.c 的 vm_desc_key，
     * Go 侧是 internal/inject/payload.go 里 KDFEntry(master, fn.RVA, KDFSaltForPlacement(descSelfRVA, fn.RVA, len(code)))。
     * 这里把"哪三个字段喂进 salt、哪个字段当 rva"钉死（改任何一处都会让这条 KAT 变）。 */
    {
        u32 selfRVA = 0x3140u, funcRVA = 0x1670u, codeLen = 40u;
        u32 salt = vm_kdf_salt(selfRVA, funcRVA, codeLen);
        u8 out[32];
        vm_kdf_entry(master, funcRVA, salt, out);
        printf("desc selfRVA=0x%X funcRVA=0x%X codeLen=%u salt=0x%08X key=", selfRVA, funcRVA, codeLen, salt);
        for (int i = 0; i < 32; i++) printf("%02x", out[i]);
        printf("\n");
    }
    /* 接线约定：镜像节 → 节密钥（KDFEntry(master, rva = 节 RVA, salt = 表头 salt)；nonce/aad 不变）。 */
    {
        u32 secRVA = 0x1000u, tblSalt = 0xDEADBEEFu;
        u8 out[32];
        vm_kdf_entry(master, secRVA, tblSalt, out);
        printf("sect rva=0x%X salt=0x%08X key=", secRVA, tblSalt);
        for (int i = 0; i < 32; i++) printf("%02x", out[i]);
        printf("\n");
    }
    return 0;
}
