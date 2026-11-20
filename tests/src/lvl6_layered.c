/* Level 6 — everything combined with multi-layer gating:
 *   layer 0: exact length
 *   layer 1: fixed 4-byte prefix (byte loop)
 *   layer 2: table-lookup constraint on the middle 4 bytes
 *   layer 3: FNV-1a hash of the trailing bytes
 *   layer 4: whole-string checksum
 * Each layer is an independent reject branch, so the engine must accumulate
 * constraints across all of them before anything can be solved. */
#include "common.h"
#include "gen_constants.h"

static unsigned int fnv_tail(const char *p, int n) {
    unsigned int h = 0x811C9DC5u;
    for (int i = 0; i < n; i++) {
        h ^= (unsigned char)p[i];
        h = (h * 0x01000193u) & 0xFFFFFFFFu;
    }
    return h;
}

int check(const char *input) {
    if (strlen(input) != L6_LEN) return 0;                          /* L0 */

    for (int i = 0; i < 4; i++) {                                   /* L1 */
        if ((unsigned char)input[i] != L6_PREFIX[i]) return 0;
    }

    for (int i = 0; i < 4; i++) {                                   /* L2 */
        unsigned char idx = (unsigned char)input[L6_MID_OFF + i];
        if (L4_SBOX[idx] != L6_TARGET[i]) return 0;
    }

    if (fnv_tail(input + L6_TAIL_OFF, L6_LEN - L6_TAIL_OFF)
        != L6_HASH) return 0;                                       /* L3 */

    unsigned int sum = 0;                                           /* L4 */
    for (int i = 0; i < L6_LEN; i++) {
        sum = (sum + (unsigned char)input[i]) & 0xFFFFFFFFu;
    }
    if (sum != L6_SUM) return 0;

    return 1;
}

int main(int argc, char **argv) {
    const char *in = (argc > 1) ? argv[1] : "";
    if (check(in)) { printf(GRANT_MARK "\n"); return 0; }
    printf(DENY_MARK "\n"); return 1;
}
