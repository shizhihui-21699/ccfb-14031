/* Level 4 — table lookup inside a loop: every input byte must map through a
 * 256-byte permutation table to a prescribed target byte. */
#include "common.h"
#include "gen_constants.h"

int check(const char *input) {
    if (strlen(input) != L4_LEN) return 0;
    for (int i = 0; i < L4_LEN; i++) {
        unsigned char idx = (unsigned char)input[i];
        if (L4_SBOX[idx] != L4_TARGET[i]) return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    const char *in = (argc > 1) ? argv[1] ? argv[1] : "" : "";
    if (check(in)) { printf(GRANT_MARK "\n"); return 0; }
    printf(DENY_MARK "\n");
    return 1;
}
