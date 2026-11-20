/* Provably unsatisfiable: same byte must equal two different constants. */
#include "../common.h"
int check(const char *input) {
    if (input[0] != 0x41) return 0;   /* 'A' */
    if (input[0] != 0x42) return 0;   /* 'B' — contradicts the first */
    if (input[1] != 0) return 0;
    return 1;
}
int main(int argc, char **argv){
    const char *in = argc>1?argv[1]:"";
    if (check(in)){ printf(GRANT_MARK"\n"); return 0; }
    printf(DENY_MARK"\n"); return 1;
}
