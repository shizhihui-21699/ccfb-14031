#!/usr/bin/env python3
"""
test_analyzer.py — end-to-end and unit tests for the license-check analyzer.

Run with the project venv:  .venv/bin/python -I tests/test_analyzer.py
Exits non-zero on any failure. Covers:
  * Mach-O parsing (symbols, stubs, cstrings, address translation)
  * the expression/memory layer (narrow stores, symbolic table lookups)
  * full symbolic recovery on all six difficulty levels plus edge cases
  * blocker reporting (unsatisfiable, loop cap, unsupported opcode)
"""
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from analyzer.macho import MachO
from analyzer.engine import Engine, Limits, UnsupportedError
from analyzer import expr

BIN = os.path.join(ROOT, "tests", "bin")

# level -> (binary, known input length, expected ground-truth serial or None)
LEVELS = [
    ("lvl1_compare", 7, b"PLAN-42"),
    ("lvl2_conditions", 2, None),
    ("lvl3_loop_sum", 9, b"ACME-2026"),
    ("lvl4_table", 8, b"TBL-9Z4Q"),
    ("lvl5_hash", 10, b"SN-7F2A-X9"),
    ("lvl6_layered", 11, b"ULT-8K2M-51"),
]


class TestMachO(unittest.TestCase):
    def setUp(self):
        self.m = MachO(os.path.join(BIN, "lvl3_loop_sum"))

    def test_check_symbol(self):
        self.assertIn("_check", self.m.by_name)
        self.assertNotIn("_check", {k: v for k, v in
                                    [(s.name, s) for s in self.m.symbols
                                     if s.is_import]})

    def test_stub_resolution(self):
        names = set(self.m.stubs.values())
        self.assertIn("_strlen", names)
        self.assertIn("_printf", names)

    def test_cstrings(self):
        vals = list(self.m.read_cstrings().values())
        self.assertIn("LICENSE_OK_GRANTED\n", vals)

    def test_address_roundtrip(self):
        sym = self.m.by_name["_check"]
        off = self.m.vaddr_to_off(sym.addr)
        self.assertIsNotNone(off)
        # first word at check is a real instruction (non-zero, mapped)
        self.assertTrue(any(self.m.data[off:off + 4]))


class TestMemory(unittest.TestCase):
    def _mem(self):
        import z3
        g = z3.Array("g", z3.BitVecSort(64), z3.BitVecSort(64))
        s = z3.Array("s", z3.BitVecSort(64), z3.BitVecSort(64))
        i = z3.Array("i", z3.BitVecSort(64), z3.BitVecSort(8))
        m = expr.Memory(g, s, 0x1000, 8, input_array=i)
        m.mark_globals(set())
        return m

    def test_64bit_roundtrip(self):
        m = self._mem()
        m.store(expr.bv(0x2000), expr.bv(0xDEADBEEFCAFEBABE), 64)
        self.assertEqual(expr.as_int(m.load(expr.bv(0x2000), 64)),
                         0xDEADBEEFCAFEBABE)

    def test_narrow_store_preserves_high_bits(self):
        m = self._mem()
        m.store(expr.bv(0x2000), expr.bv(0x1122334455667788), 64)
        m.store(expr.bv(0x2000), expr.bv(0xAB, 64), 8)   # overwrite low byte
        word = expr.as_int(m.load(expr.bv(0x2000), 64))
        self.assertEqual(word, 0x11223344556677AB)

    def test_unaligned_32bit_store(self):
        m = self._mem()
        m.store(expr.bv(0x2000), expr.bv(0xDEADBEEFDEADBEEF), 64)
        m.store(expr.bv(0x2004), expr.bv(0xCAFEBABE, 64), 32)
        self.assertEqual(expr.as_int(m.load(expr.bv(0x2000), 64)),
                         0xCAFEBABEDEADBEEF)

    def test_symbolic_input_byte(self):
        import z3
        m = self._mem()
        v = z3.BitVec("x", 8)
        m.store(expr.bv(0x1002), z3.ZeroExt(56, v), 8)
        out = m.load(expr.bv(0x1002), 8)
        # Should reference the symbolic byte, not fold to a constant.
        self.assertFalse(expr.is_concrete(out))


class TestRecovery(unittest.TestCase):
    def _run(self, name, length, timeout=60):
        m = MachO(os.path.join(BIN, name))
        return Engine(m, "_check", Limits(timeout_s=timeout)).run(length)

    def test_all_levels_find_feasible_input(self):
        for name, length, _truth in LEVELS:
            with self.subTest(level=name):
                res = self._run(name, length)
                self.assertTrue(res.found,
                                f"{name}: no input found; "
                                f"blocked={[(b.reason, b.detail) for b in res.blocked]}")
                self.assertEqual(len(res.input_bytes), length)
                self.assertNotIn(0, res.input_bytes,
                                 f"{name}: recovered input contains NUL")

    def test_recovered_input_passes_real_binary(self):
        for name, length, _truth in LEVELS:
            with self.subTest(level=name):
                res = self._run(name, length)
                proc = subprocess.run(
                    [os.path.join(BIN, name), res.input_bytes],
                    capture_output=True, timeout=10)
                self.assertEqual(proc.returncode, 0,
                                 f"{name}: real binary rejected {res.input_bytes.hex()}")
                self.assertIn(b"GRANT", proc.stdout)

    def test_ground_truth_match_where_unique(self):
        # L1's check pins every byte, so the recovered value must equal the
        # generator secret exactly. Other levels admit multiple preimages.
        res = self._run("lvl1_compare", 7)
        self.assertEqual(res.input_bytes, b"PLAN-42")


class TestBlockers(unittest.TestCase):
    def test_unsatisfiable_reported_not_guessed(self):
        m = MachO(os.path.join(BIN, "edge_unsat"))
        res = Engine(m, "_check", Limits(timeout_s=20)).run(1)
        self.assertFalse(res.found)
        self.assertEqual(res.blocked, [])  # clean UNSAT, not an engine failure

    def test_loop_unroll_cap_reported(self):
        m = MachO(os.path.join(BIN, "edge_longloop"))
        res = Engine(m, "_check",
                     Limits(timeout_s=20, max_loop_unroll=50)).run(1)
        self.assertFalse(res.found)
        self.assertTrue(any(b.reason == "loop-unroll-cap" for b in res.blocked))

    def test_unsupported_opcode_reported(self):
        m = MachO(os.path.join(BIN, "edge_float"))
        res = Engine(m, "_check", Limits(timeout_s=20)).run(1)
        self.assertFalse(res.found)
        reasons = {b.detail for b in res.blocked}
        self.assertTrue(any("scvtf" in r or "fcmp" in r or "fmov" in r
                            for r in reasons))


if __name__ == "__main__":
    unittest.main(verbosity=2)
