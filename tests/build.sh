#!/usr/bin/env bash
# Build every level into an arm64 Mach-O test target.
# -O0 keeps code simple/stack-based; -fno-pic -no-pie gives absolute addresses;
# -fno-stack-protector drops canary machinery that would add unrelated branches.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/src"
BIN="$HERE/bin"
mkdir -p "$BIN"

python3 "$SRC/gen_constants.py"

CFLAGS=(-O0 -fno-pic -fno-stack-protector -fno-builtin
        -target arm64-apple-darwin)

for src in "$SRC"/lvl*.c; do
    name="$(basename "$src" .c)"
    clang "${CFLAGS[@]}" "$src" -o "$BIN/$name"
    echo "built $BIN/$name"
done

# Edge cases used by the test suite for blocker reporting.
for src in "$SRC"/edge/*.c; do
    [ -e "$src" ] || continue
    name="edge_$(basename "$src" .c | sed 's/_check$//')"
    clang "${CFLAGS[@]}" "$src" -o "$BIN/$name"
    echo "built $BIN/$name"
done
