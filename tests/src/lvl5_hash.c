/* Level 5 — hash fragment: a 32-bit FNV-1a hash of the whole input computed
 * in a loop, compared against a baked-in target. No individual byte is
 * directly compared, so only constraint solving recovers the input. */
#include "common.h"
#include "gen_constants.h"

int check(const char *input) {
    if (strlen(input) != L5_LEN) return 0;
    unsigned int h = 0x811C9DC5u;
    for (int i = 0; i < L5_LEN; i++) {
        h ^= (unsigned char)input[i];
        h = (h * 0x01000193u) & 0xFFFFFFFFu;
    }
    if (h != L5_HASH) return 0;
    return 1;
}

int main(int argc, char **argv) {
    const char *in = (argc > 1) ? argv[1] : "";
    if (check(in)) { printf(GRANT_MARK "\n"); return 0; }
    printf(DENY_MARK "\n");
    return 1;
}
