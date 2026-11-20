/* Level 1 — trivial direct byte comparison, one branch. */
#include "common.h"
#include "gen_constants.h"

int check(const char *input) {
    if (strlen(input) != L1_LEN) return 0;
    for (int i = 0; i < L1_LEN; i++) {
        if ((unsigned char)input[i] != L1_EXPECTED[i]) return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    const char *in = (argc > 1) ? argv[1] : "";
    if (check(in)) { printf(GRANT_MARK "\n"); return 0; }
    printf(DENY_MARK "\n");
    return 1;
}
