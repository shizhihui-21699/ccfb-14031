/* Data-independent loop repeated many times; stresses the unroll cap. */
#include "../common.h"
int check(const char *input) {
    if (input[0] == 0) return 0;
    volatile unsigned acc = 0;
    for (int i = 0; i < 200; i++) acc = (acc + 1) & 0xff;
    if (acc != 200) return 0;
    return 1;
}
int main(int argc, char **argv){
    const char *in = argc>1?argv[1]:"";
    if (check(in)){ printf(GRANT_MARK"\n"); return 0; }
    printf(DENY_MARK"\n"); return 1;
}
