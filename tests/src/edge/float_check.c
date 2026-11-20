/* Uses a floating-point comparison the integer engine does not model. */
#include "../common.h"
int check(const char *input) {
    double x = (double)input[0];
    if (x == 65.0) {            /* needs FP registers/insns */
        if (input[1] == 0) return 1;
    }
    return 0;
}
int main(int argc, char **argv){
    const char *in = argc>1?argv[1]:"";
    if (check(in)){ printf(GRANT_MARK"\n"); return 0; }
    printf(DENY_MARK"\n"); return 1;
}
