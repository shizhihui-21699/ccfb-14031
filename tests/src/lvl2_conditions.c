/* Level 2 — multi-layer conditions, no loop. Two bytes must satisfy a
 * conjunction of range and arithmetic constraints. */
#include "common.h"

int check(const char *input) {
    unsigned char a = (unsigned char)input[0];
    unsigned char b = (unsigned char)input[1];
    if (input[2] != 0) return 0;                 /* exact length 2 */
    if (a < 0x30 || a > 0x7A) return 0;          /* ASCII band */
    if (b < 0x30 || b > 0x7A) return 0;
    if (((a + b) & 0xFF) != 0xA4) return 0;      /* arithmetic join */
    if (((a ^ b) & 0xFF) != 0x14) return 0;      /* bitwise join  */
    if (a <= b) return 0;                        /* strict order  */
    return 1;
}

int main(int argc, char **argv) {
    const char *in = (argc > 1) ? argv[1] : "";
    if (check(in)) { printf(GRANT_MARK "\n"); return 0; }
    printf(DENY_MARK "\n");
    return 1;
}
