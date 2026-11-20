/* Level 3 — loop with accumulator (checksum) plus boundary constraints. */
#include "common.h"
#include "gen_constants.h"

int check(const char *input) {
    if (strlen(input) != L3_LEN) return 0;
    if ((unsigned char)input[0] != L3_FIRST) return 0;
    if ((unsigned char)input[L3_LEN - 1] != L3_LAST) return 0;
    unsigned int sum = 0;
    for (int i = 0; i < L3_LEN; i++) {
        sum = (sum + (unsigned char)input[i]) & 0xFFFFFFFFu;
    }
    if (sum != L3_SUM) return 0;
    return 1;
}

int main(int argc, char **argv) {
    const char *in = (argc > 1) ? argv[1] : "";
    if (check(in)) { printf(GRANT_MARK "\n"); return 0; }
    printf(DENY_MARK "\n");
    return 1;
}
