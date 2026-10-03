/* keyname_probe.c - the C-side boundary assertion for the .ncrypt wrap key name.
 *
 * WHY THIS FILE EXISTS (the registered A1 defect): the runtime rule for the
 * bytes of the key name in <artifact>.vmpkey.ncrypt used to be "reject 0x00 and
 * >127", while the tool side (internal/cred/payloadwrap.go ValidWrapKeyName)
 * rejects "<0x20 || >0x7e". Both sides must agree, or the runtime can accept a
 * name the tool would never write. The asymmetry was invisible because it is
 * fail-closed (a name the tool cannot produce leads to the hard gate anyway).
 *
 * HOW THIS PINS IT: this probe includes the REAL stub/win/x64/vm_interp.c --
 * not a copy -- and calls its vm_ncrypt_keyname_ok() byte by byte at and just
 * past both boundaries. Change either boundary in vm_interp.c and this probe
 * prints FAIL and exits non-zero; tools/e2e.ps1 turns that into a red case.
 * The mirror assertion on the Go side is TestValidWrapKeyNameBoundaries.
 *
 * usage: keyname_probe      (exit 0 = every byte in the rule's domain decided
 *                            exactly as the Go side decides it)
 */
#include <stdio.h>

/* vm_interp.c is normally compiled with cmd/vmpbuild's generated
 * vm_crypto_key.h (this build's key bytes / mask seeds / KCV). The probe only
 * calls the one byte predicate, so placeholder constants are enough -- see the
 * header for why that is safe. */
#include "keyname_probe_key.h"
#include "vm_interp.c"

int main(void) {
    int bad = 0;
    unsigned c;
    /* calibration: the two edges of the rule must be ACCEPTED */
    if (!vm_ncrypt_keyname_ok(0x20u)) { printf("FAIL: 0x20 (space) must be accepted\n"); bad++; }
    if (!vm_ncrypt_keyname_ok(0x7eu)) { printf("FAIL: 0x7e ('~') must be accepted\n"); bad++; }
    /* one step outside each edge must be REJECTED */
    if (vm_ncrypt_keyname_ok(0x1fu)) { printf("FAIL: 0x1f must be rejected (Go side rejects <0x20)\n"); bad++; }
    if (vm_ncrypt_keyname_ok(0x7fu)) { printf("FAIL: 0x7f must be rejected (Go side rejects >0x7e)\n"); bad++; }
    /* the whole domain, byte by byte: same decision as Go's ValidWrapKeyName */
    for (c = 0; c < 256u; c++) {
        int want = (c >= 0x20u && c <= 0x7eu);
        int got = vm_ncrypt_keyname_ok((u8)c);
        if (want != got) {
            printf("FAIL: byte 0x%02x decided %d, want %d\n", c, got, want);
            bad++;
        }
    }
    if (bad) { printf("keyname_probe: FAIL (%d byte(s) off the Go rule)\n", bad); return 1; }
    printf("keyname_probe: OK (256 bytes decided exactly like Go ValidWrapKeyName: accept 0x20..0x7e only)\n");
    return 0;
}
