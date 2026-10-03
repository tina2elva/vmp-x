/* keyname_probe_key.h - placeholder build constants for keyname_probe.c ONLY.
 *
 * WHY: vm_interp.c is a blob source: cmd/vmpbuild generates vm_crypto_key.h with
 * this build's VM_KEY_BYTES / mask seeds / KCV and passes it on the compiler
 * command line. A probe that includes vm_interp.c only to call
 * vm_ncrypt_keyname_ok() must still satisfy the compiler, and the values are
 * irrelevant to that one byte predicate. They are deliberately obvious dummies
 * (and this header is never used by the blob build: it is not on any BLOB
 * sources list and no blob compile line points at it).
 */
#ifndef VMPX_KEYNAME_PROBE_KEY_H
#define VMPX_KEYNAME_PROBE_KEY_H
#define VM_KEY_BYTES {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
#define VM_FIELD_MASK_SALT   0x12345678u
#define VM_FIELD_MASK_DESC   0x9E3779B9u
#define VM_FIELD_MASK_IMAGE  0x85EBCA6Bu
#define VM_FIELD_MASK_VERIFY 0xC2B2AE35u
#define VM_KEY_CHECK_SALT    0x00000001u
#define VM_KEY_CHECK_RVA     0x00000002u
#define VM_KEY_CHECK_LEN     16
#define VM_KEY_CHECK_BYTES {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
#define VM_SIGMA_MASK        0x00000000u
#define VM_SIGMA_OBF0        0x61707865u
#define VM_SIGMA_OBF1        0x3320646Eu
#define VM_SIGMA_OBF2        0x79622D32u
#define VM_SIGMA_OBF3        0x6B206574u
#endif
