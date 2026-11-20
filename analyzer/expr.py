"""
expr.py — bit-vector expression layer over Z3 and a concrete/symbolic memory
model tuned for license-check analysis.

Design choices
--------------
* Registers hold Z3 64-bit BitVec expressions. A "concrete" value is just a
  BitVecVal, so one code path handles both.
* Memory is split into two Z3 arrays:
    - GLOBALS: initialized from the binary's mapped segments (read-mostly:
      string literals, const lookup tables such as the S-box).
    - STACK:   uninitialized scratch; every slot starts unconstrained, which
      matches an -O0 frame whose locals are all explicitly written before read.
  Reads consult GLOBALS first for mapped constant addresses, else STACK.
  The symbolic input lives in its own region (INPUT_BASE .. +max_len) on the
  STACK array, addressed via the pointer passed to check().
* Widths 8/16/32/64 are supported; loads/stores handle little-endian width
  truncation explicitly so byte/halfword/word accesses to a 64-bit slot behave
  like real hardware.
"""
from __future__ import annotations

import z3

MASK64 = (1 << 64) - 1


def bv(val, width: int = 64):
    """Wrap a Python int as a BitVecVal (masked to width)."""
    return z3.BitVecVal(val & ((1 << width) - 1), width)


def to64(e) -> z3.BitVecRef:
    """Zero-extend a narrower bitvec to 64 bits; pass through 64-bit ones."""
    w = e.size()
    if w == 64:
        return e
    return z3.ZeroExt(64 - w, e)


def is_concrete(e) -> bool:
    # Z3 does not fold constant arithmetic eagerly (e.g. val - val stays a
    # BitVecRef), so simplify before testing for a numeric literal.
    if z3.is_bv_value(e):
        return True
    s = z3.simplify(e)
    return z3.is_bv_value(s)


def as_int(e):
    if z3.is_bv_value(e):
        return e.as_long()
    s = z3.simplify(e)
    return s.as_long() if z3.is_bv_value(s) else None


class Memory:
    def __init__(self, globals_array, stack_array,
                 input_base: int, input_len: int, input_array=None,
                 global_bytes=None, const_regions=None, macho=None):
        self.globals = globals_array
        self.stack = stack_array
        self.input_base = input_base
        self.input_len = input_len
        self._global_words: set[int] = set()
        # Dedicated byte-addressed array for the symbolic input. Keeping it
        # separate avoids nesting one narrow Store per input byte inside the
        # 64-bit stack array, which would otherwise produce enormous terms.
        self.input = input_array if input_array is not None else \
            z3.Array("input", z3.BitVecSort(64), z3.BitVecSort(8))
        # Legacy whole-image byte array (unused in the compact path but kept
        # for callers that construct Memory directly).
        self.global_bytes = global_bytes
        # Named constant regions (addr_lo, addr_hi) plus a lazily-built compact
        # byte array per region, enabling symbolic-index table reads cheaply.
        self.const_regions = const_regions or []
        self._macho = macho
        self._region_arrays: dict[tuple[int, int], object] = {}

    # ----- addressing -----
    def _is_const_addr(self, addr_e):
        if not is_concrete(addr_e):
            return None
        return as_int(addr_e)

    def _in_input(self, addr: int) -> bool:
        return self.input_base <= addr <= self.input_base + self.input_len

    # ----- stores -----
    def store(self, addr_e, value_e, width: int):
        a = self._is_const_addr(addr_e)
        if a is None:
            # Symbolic-address store. With a fixed, fully-mapped input this
            # should not happen; report upward rather than silently weaken.
            raise SymbolicMemoryError(
                f"symbolic store address (width {width})")
        if self._in_input(a) and width == 8:
            self.input = z3.Store(self.input, bv(a),
                                  z3.Extract(7, 0, value_e))
            return
        if width == 64:
            # The stack array is indexed by 8-byte word base addresses, so a
            # 64-bit store must be aligned to the same base as loads use.
            if a & 0x7:
                # Unaligned 64-bit access: fold into the containing word(s).
                self._store_narrow(a, value_e, 64)
            else:
                self.stack = z3.Store(self.stack, bv(a), value_e)
        else:
            self._store_narrow(a, value_e, width)

    def _store_narrow(self, addr: int, value_e, width: int):
        # AArch64 little-endian narrow store: replace the low `width` bits of
        # the 64-bit word containing this address, preserving the rest.
        base = addr & ~0x7
        word = z3.Select(self.stack, bv(base))
        shift = (addr & 0x7) * 8
        nbits = width
        field_mask = bv(((1 << nbits) - 1) << shift, 64)
        cleared = word & ~field_mask
        value64 = to64(z3.Extract(nbits - 1, 0, value_e))
        new_word = cleared | (value64 << shift)
        self.stack = z3.Store(self.stack, bv(base), new_word)

    # ----- loads -----
    def load(self, addr_e, width: int, sign_extend: bool = False):
        a = self._is_const_addr(addr_e)
        if a is not None:
            # Byte reads inside the input region come straight from the input
            # array (covers the symbolic bytes and their concrete NUL terminator).
            if width == 8 and self._in_input(a):
                return z3.ZeroExt(56, z3.Select(self.input, bv(a)))
            word = self._load_word(a)
            shift = (a & 0x7) * 8
            raw = z3.Extract(shift + width - 1, shift, word)
            return self._extend(raw, width, sign_extend)

        # ----- symbolic address -----
        if width != 8:
            raise SymbolicMemoryError(
                f"symbolic-address load of width {width} (only byte "
                f"table lookups are modeled)")
        # A symbolic byte read of the input buffer itself.
        if self._expr_in_input(addr_e):
            return z3.ZeroExt(56, z3.Select(self.input, to64(addr_e)))
        # A symbolic byte read of a named constant table.
        region = self._region_of_expr(addr_e)
        if region is not None:
            lo, hi = region
            rel = to64(addr_e) - bv(lo)
            byte_e = self._region_lookup(region, rel)
            return z3.ZeroExt(56, byte_e)
        raise SymbolicMemoryError(
            "symbolic load addresses an unmapped/non-constant region")

    def _region_array(self, region):
        # Retained for API compatibility; the ITE-based lookup in
        # _region_lookup is the preferred representation for solving.
        arr = self._region_arrays.get(region)
        if arr is not None:
            return arr
        lo, hi = region
        data = self._macho.read_vaddr(lo, hi - lo)
        arr = z3.K(z3.BitVecSort(64), z3.BitVecVal(0, 8))
        for i, byte in enumerate(data):
            arr = z3.Store(arr, bv(i), bv(byte, 8))
        self._region_arrays[region] = arr
        return arr

    def _region_lookup(self, region, rel_expr):
        """Symbolic table read as a nested-ITE over concrete bytes.

        Pure bit-vector theory (no array select/store chain) — markedly faster
        for the 256-entry permutation tables these checks use. Bounded so an
        unexpectedly huge region falls back to the array form.
        """
        lo, hi = region
        data = self._macho.read_vaddr(lo, hi - lo)
        idx = z3.Extract(63, 0, rel_expr)
        if len(data) > 512:
            arr = self._region_array(region)
            return z3.Select(arr, idx)
        # Build from the last entry backward.
        result = z3.BitVecVal(data[-1], 8)
        for i in range(len(data) - 2, -1, -1):
            result = z3.If(idx == bv(i, 64),
                           z3.BitVecVal(data[i], 8), result)
        return result

    def _region_of_expr(self, addr_e):
        for lo, hi in self.const_regions:
            s = z3.Solver()
            s.set("timeout", 2000)
            s.add(z3.Or(to64(addr_e) < bv(lo), to64(addr_e) >= bv(hi)))
            if s.check() == z3.unsat:
                return (lo, hi)
        return None

    @staticmethod
    def _extend(raw, width, sign_extend):
        if sign_extend and width < 64:
            return z3.SignExt(64 - width, raw)
        if width < 64:
            return z3.ZeroExt(64 - width, raw)
        return raw

    def _expr_in_input(self, addr_e) -> bool:
        # input accesses are base(INPUT_BASE) + bounded index; detect the
        # common shape base+offset where offset is provably within range.
        lo = self.input_base
        hi = self.input_base + self.input_len
        s = z3.Solver()
        s.set("timeout", 2000)
        s.add(z3.Or(to64(addr_e) < bv(lo), to64(addr_e) > bv(hi)))
        return s.check() == z3.unsat

    def _load_word(self, addr: int):
        base = addr & ~0x7
        # Mapped constant (table/string) addresses read from GLOBALS; the input
        # region and frame live in STACK. Membership is keyed on the aligned
        # 8-byte word base so any byte inside a mapped constant word resolves.
        if base in self._global_words:
            return z3.Select(self.globals, bv(base))
        return z3.Select(self.stack, bv(base))

    def mark_globals(self, words: set[int]):
        self._global_words = set(words)

    def in_input(self, addr: int) -> bool:
        return self.input_base <= addr < self.input_base + self.input_len

    def clone(self):
        m = Memory.__new__(Memory)
        m.globals = self.globals
        m.stack = self.stack
        m.input = self.input
        m.global_bytes = self.global_bytes
        m.input_base = self.input_base
        m.input_len = self.input_len
        m._global_words = self._global_words
        m.const_regions = self.const_regions
        m._macho = self._macho
        # Share lazily-built region arrays (immutable once constructed).
        m._region_arrays = self._region_arrays
        return m


class SymbolicMemoryError(Exception):
    """Raised on a symbolic-address access the model cannot resolve."""
