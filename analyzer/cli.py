"""
cli.py — command-line driver for the license-check symbolic analyzer.

Pipeline
--------
1. Parse the arm64 Mach-O and locate the check function (default `_check`).
2. For a range of candidate input lengths, symbolically execute check() with a
   fully symbolic input buffer and look for a feasible nonzero-return path.
3. On success, hand the Z3 model back as concrete bytes and verify the result
   by re-running the real binary (when --verify is given).
4. Always report what blocked deeper analysis: unsupported opcodes, symbolic
   memory, loop-unroll / state / instruction budgets, solver timeouts.

The tool never guesses: an input is printed only when Z3 proves a feasible
success path; otherwise the blocking reason is reported instead.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time

from .macho import MachO
from .engine import Engine, Limits, Result


def _escaped(data: bytes) -> str:
    out = []
    for b in data:
        if 0x20 <= b < 0x7F:
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def _print_result(name: str, length: int, res: Result, binary: str | None,
                  verify: bool):
    print(f"\n=== input length {length} ===")
    print(f"  states={res.n_states} forks={res.n_forks} "
          f"insns={res.n_instructions} sat={res.n_sat} "
          f"unsat={res.n_unsat} time={res.elapsed_s:.2f}s")
    if res.timed_out:
        print("  [!] wall-clock timeout reached — analysis incomplete")
    if res.found:
        data = res.input_bytes
        print(f"  [+] PASSING INPUT FOUND ({len(data)} bytes)")
        print(f"      raw bytes : {data.hex()}")
        print(f"      escaped   : {_escaped(data)}")
        printable = data.decode("latin1")
        print(f"      as text   : {printable!r}")
        if verify and binary:
            _verify(binary, data)
        return True
    if res.blocked:
        # Collapse identical reasons for a readable summary.
        seen = {}
        for b in res.blocked:
            key = (b.reason, b.detail)
            seen.setdefault(key, []).append(b.addr)
        print("  [-] no passing input derived; blockers:")
        for (reason, detail), addrs in seen.items():
            sample = ", ".join(hex(a) for a in addrs[:4])
            extra = f" (+{len(addrs)-4} more)" if len(addrs) > 4 else ""
            print(f"      {reason:18s} {detail}  @ {sample}{extra}")
    else:
        print("  [-] no feasible success path at this length (all paths reject)")
    return False


def _verify(binary: str, data: bytes):
    try:
        # argv is passed to execve as bytes; pass the recovered value directly
        # so high bytes (0x80-0xFF) survive without any text re-encoding.
        proc = subprocess.run([binary.encode(), data],
                              capture_output=True, timeout=10)
        marker = proc.stdout.decode("latin1").strip()
        ok = proc.returncode == 0 and "GRANT" in marker
        print(f"      verify    : {'MATCH (real binary returns success)' if ok else 'MISMATCH'} "
              f"[exit {proc.returncode}, {marker!r}]")
    except Exception as e:
        print(f"      verify    : could not execute target ({e})")


def analyze(path: str, target: str, min_len: int, max_len: int,
            limits: Limits, verify: bool, stop_on_find: bool) -> int:
    print(f"target binary : {path}")
    macho = MachO(path)
    print(f"architecture  : arm64, {len(macho.segments)} segments, "
          f"{len(macho.function_symbols())} symbols, "
          f"{len(macho.stubs)} imported stubs")
    sym = macho.by_name.get(target)
    if sym is None:
        print(f"error: symbol {target!r} not present; "
              f"candidates: {[s.name for s in macho.function_symbols()][:12]}")
        return 2
    print(f"check function: {target} @ {sym.addr:#x}")

    t0 = time.monotonic()
    for length in range(min_len, max_len + 1):
        engine = Engine(macho, target, limits)
        res = engine.run(input_len=length)
        found = _print_result(target, length, res, path, verify)
        if found and stop_on_find:
            print(f"\ntotal wall time: {time.monotonic()-t0:.2f}s")
            return 0
    print(f"\ntotal wall time: {time.monotonic()-t0:.2f}s")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analyze",
        description="Symbolically recover inputs that reach the "
                    "authorization-passed path of an arm64 Mach-O check.")
    p.add_argument("binary", help="path to the compiled arm64 Mach-O program")
    p.add_argument("--target", default="_check",
                   help="name of the check function symbol (default: _check)")
    p.add_argument("--min-len", type=int, default=1)
    p.add_argument("--max-len", type=int, default=16,
                   help="largest symbolic input length to try")
    p.add_argument("--timeout", type=float, default=60.0,
                   help="per-length wall-clock budget in seconds")
    p.add_argument("--solver-timeout", type=int, default=20000,
                   help="per Z3 check() timeout in milliseconds")
    p.add_argument("--max-states", type=int, default=20000)
    p.add_argument("--max-insns", type=int, default=2_000_000)
    p.add_argument("--max-unroll", type=int, default=64,
                   help="loop back-edge unroll cap")
    p.add_argument("--verify", action="store_true",
                   help="re-run the real binary on any recovered input")
    p.add_argument("--all-lengths", action="store_true",
                   help="keep trying longer inputs after a find")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    limits = Limits(timeout_s=args.timeout,
                    max_states=args.max_states,
                    max_instructions=args.max_insns,
                    max_loop_unroll=args.max_unroll,
                    solver_timeout_ms=args.solver_timeout)
    return analyze(args.binary, args.target, args.min_len, args.max_len,
                   limits, args.verify, stop_on_find=not args.all_lengths)


if __name__ == "__main__":
    sys.exit(main())
