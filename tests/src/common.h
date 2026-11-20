#ifndef LICENSE_TESTS_COMMON_H
#define LICENSE_TESTS_COMMON_H

/*
 * Every test program exposes:
 *   int check(const char *input);
 * and prints GRANT_MARK when check() returns nonzero, DENY_MARK otherwise.
 * The analyzer targets check() directly and treats its input as symbolic.
 */
#define GRANT_MARK "LICENSE_OK_GRANTED"
#define DENY_MARK  "LICENSE_DENIED"

#include <stdio.h>
#include <string.h>

#endif
