"""
engine.py — AArch64 symbolic execution engine for license-check recovery.

Scope and method
----------------
A depth-first symbolic executor over a single target function (default
`check`). The function's pointer argument is treated as a symbolic byte buffer
of bounded length. Every branch whose condition depends on the input is forked
into two states guarded by complementary path constraints. When a state reaches
the function's success return (nonzero w0), the accumulated constraints are
given to Z3 and the satisfying bytes are reported as a concrete passing input.

Honesty about limits: when the engine cannot make progress it records *why*
(unsupported opcode, symbolic memory address, loop-unroll cap, solver timeout,
global instruction/time budget) instead of guessing. The driver surfaces these
as "blocked" reasons so the operator knows exactly what was and wasn't derived.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import capstone
import z3

from .expr import bv, to64, is_concrete, as_int, Memory, SymbolicMemoryError

CS = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
CS.detail = True

# Condition-code -> (Z3 predicate on N,Z,C,V flags) matching AArch64 cc codes.
# We materialize N/Z/C/V as fresh Bool after each flag-setting op and select.
INV_COND = {
    capstone.arm64.ARM64_CC_EQ: "eq", capstone.arm64.ARM64_CC_NE: "ne",
    capstone.arm64.ARM64_CC_HS: "hs", capstone.arm64.ARM64_CC_LO: "lo",
    capstone.arm64.ARM64_CC_MI: "mi", capstone.arm64.ARM64_CC_PL: "pl",
    capstone.arm64.ARM64_CC_VS: "vs", capstone.arm64.ARM64_CC_VC: "vc",
    capstone.arm64.ARM64_CC_HI: "hi", capstone.arm64.ARM64_CC_LS: "ls",
    capstone.arm64.ARM64_CC_GE: "ge", capstone.arm64.ARM64_CC_LT: "lt",
    capstone.arm64.ARM64_CC_GT: "gt", capstone.arm64.ARM64_CC_LE: "le",
}

# A small fixed stack window. check() frames are tiny; generous headroom.
STACK_BASE = 0x7F00_0000_0000
STACK_SIZE = 0x4000
INPUT_BASE = 0x1000_0000_0000          # symbolic input region base


@dataclass
class Limits:
    timeout_s: float = 60.0
    max_states: int = 20000
    max_instructions: int = 2_000_000
    max_loop_unroll: int = 64
    solver_timeout_ms: int = 20000
    # Per-fork feasibility pruning. ITE-based table reads keep the resulting
    # bit-vector formulas small, so pruning every fork is cheap in practice
    # and essential to prevent path explosion on multi-layer checks.
    prune_branches: bool = True
    prune_every: int = 1


@dataclass
class Blocked:
    reason: str
    addr: int
    detail: str


@dataclass
class Result:
    found: bool = False
    input_bytes: bytes | None = None
    model: dict | None = None
    n_states: int = 0
    n_instructions: int = 0
    n_forks: int = 0
    n_sat: int = 0
    n_unsat: int = 0
    blocked: list[Blocked] = field(default_factory=list)
    branches_explored: int = 0
    timed_out: bool = False
    elapsed_s: float = 0.0
    success_addr: int | None = None


def _fresh_bools(prefix, n, counter):
    return [z3.Bool(f"{prefix}_{next(counter)}") for _ in range(n)]


class State:
    def __init__(self, macho, fn_addr, input_len, id_counter,
                 const_regions=None):
        self.macho = macho
        self.pc = fn_addr
        self.fn_addr = fn_addr
        self.const_regions = const_regions or []
        self.ret_addr = 0xDEAD_BEEF_DEAD_BEEF     # sentinel return target
        self.input_len = input_len
        self.id_counter = id_counter

        # 31 general 64-bit registers (index 31 aliases sp/zr by context).
        self.regs = [bv(0) for _ in range(31)]
        self.sp = bv(STACK_BASE + STACK_SIZE)
        self.flags = {"N": z3.BoolVal(False), "Z": z3.BoolVal(False),
                      "C": z3.BoolVal(False), "V": z3.BoolVal(False)}
        self.constraints: list[z3.BoolRef] = []

        # Build global memory from mapped segments. The 64-bit word view backs
        # ordinary concrete accesses. For symbolic-index access we do NOT dump
        # whole segments into a Z3 array (huge terms); instead each named
        # constant object (lookup tables, strings) gets a compact byte array
        # built lazily on first symbolic reference.
        g = z3.Array("globals", z3.BitVecSort(64), z3.BitVecSort(64))
        global_words = set()
        for seg in macho.segments:
            if seg.filesize == 0:
                continue
            blob = macho.data[seg.fileoff:seg.fileoff + seg.filesize]
            for off in range(0, len(blob) - 7, 8):
                word = int.from_bytes(blob[off:off + 8], "little")
                addr = seg.vmaddr + off
                g = z3.Store(g, bv(addr), bv(word))
                global_words.add(addr & ~0x7)
        # Named constant regions (tables/strings) eligible for compact arrays.
        const_regions = self.const_regions
        stk = z3.Array("stack", z3.BitVecSort(64), z3.BitVecSort(64))
        inp = z3.Array("input", z3.BitVecSort(64), z3.BitVecSort(8))
        self.mem = Memory(g, stk, INPUT_BASE, input_len,
                          input_array=inp, const_regions=const_regions,
                          macho=macho)
        self.mem.mark_globals(global_words)

        # Symbolic input bytes live in the dedicated byte-addressed input
        # array, followed by a concrete NUL terminator.
        self.input_vars = []
        for i in range(input_len):
            bvar = z3.BitVec(f"in_{i}", 8)
            self.input_vars.append(bvar)
            self.mem.input = z3.Store(self.mem.input,
                                      bv(INPUT_BASE + i), bvar)
        self.mem.input = z3.Store(self.mem.input,
                                  bv(INPUT_BASE + input_len), bv(0, 8))
        # A C string of exactly input_len has no embedded NUL before the
        # terminator; constrain every input byte nonzero so length semantics
        # stay consistent and recovered values are real serial characters.
        for bvar in self.input_vars:
            self.constraints.append(bvar != z3.BitVecVal(0, 8))

        # x0 = pointer to symbolic input; link register = sentinel.
        self.regs[0] = bv(INPUT_BASE)
        self.regs[30] = bv(self.ret_addr)

        # Loop-unroll tracking: (back-edge target) -> count.
        self.loop_counts: dict[int, int] = {}
        self.call_depth = 0
        self.return_value = None

    def clone(self):
        s = State.__new__(State)
        s.macho = self.macho
        s.pc = self.pc
        s.fn_addr = self.fn_addr
        s.ret_addr = self.ret_addr
        s.input_len = self.input_len
        s.id_counter = self.id_counter
        s.regs = list(self.regs)
        s.sp = self.sp
        s.flags = dict(self.flags)
        s.constraints = list(self.constraints)
        s.mem = self.mem.clone()
        s.input_vars = self.input_vars
        s.loop_counts = dict(self.loop_counts)
        s.call_depth = self.call_depth
        s.return_value = self.return_value
        return s


class Engine:
    def __init__(self, macho, target: str = "_check", limits: Limits | None = None,
                 verbose=False):
        self.macho = macho
        self.limits = limits or Limits()
        self.verbose = verbose
        self._id = iter(range(10 ** 9))
        sym = macho.by_name.get(target)
        if sym is None or sym.is_import:
            raise KeyError(f"target symbol {target!r} not found in binary")
        self.fn_addr = sym.addr
        self.fn_end = self._function_end(sym.addr)
        self.text = macho.section("__text")
        self.result = Result()
        # Cache disassembly by address.
        self._insn_cache: dict[int, capstone.CsInsn] = {}

    # ----- disassembly helpers -----
    def _function_end(self, start):
        # Linear sweep until the first ret after start (functions are adjacent
        # and -O0 emits a single epilogue).
        end = start
        for insn in CS.disasm(self.macho.data[self.macho.vaddr_to_off(start):
                                              self.macho.vaddr_to_off(start) + 0x800],
                              start):
            end = insn.address + 4
            if insn.mnemonic == "ret":
                break
        return end

    def insn_at(self, addr):
        if addr in self._insn_cache:
            return self._insn_cache[addr]
        off = self.macho.vaddr_to_off(addr)
        it = CS.disasm(self.macho.data[off:off + 4], addr)
        insn = next(it, None)
        self._insn_cache[addr] = insn
        return insn

    def _in_text(self, addr: int) -> bool:
        t = self.text
        return t is not None and t.addr <= addr < t.addr + t.size

    def _collect_const_regions(self) -> list[tuple[int, int]]:
        """Address spans of named constant objects (tables, string literals).

        These are the only globals a symbolic index can legitimately address,
        so each becomes a compact per-object byte array rather than a full
        segment dump.
        """
        regions = []
        for sym in self.macho.function_symbols():
            # Skip code and the Mach header marker; keep data objects.
            if sym.name in ("__mh_execute_header",):
                continue
            if self._in_text(sym.addr):
                continue
            # Size is not in nlist; bound it conservatively by the distance to
            # the next data symbol or end of its section.
            size = self._region_size(sym.addr)
            regions.append((sym.addr, sym.addr + size))
        # Include __cstring spans as well.
        for addr, text in self.macho.read_cstrings().items():
            if text:
                regions.append((addr, addr + len(text) + 1))
        return regions

    def _region_size(self, addr: int, cap: int = 4096) -> int:
        candidates = [s.addr for s in self.macho.function_symbols()
                      if s.addr > addr and not self._in_text(s.addr)]
        for sec in self.macho.sections:
            if sec.addr <= addr < sec.addr + sec.size:
                candidates.append(sec.addr + sec.size)
        if candidates:
            return min(min(candidates) - addr, cap)
        return cap

    # ----- main driver -----
    def run(self, input_len: int) -> Result:
        t0 = time.monotonic()
        r = self.result
        const_regions = self._collect_const_regions()
        init = State(self.macho, self.fn_addr, input_len, self._id,
                     const_regions=const_regions)
        worklist = [init]
        r.n_states = 1

        while worklist:
            if time.monotonic() - t0 > self.limits.timeout_s:
                r.timed_out = True
                break
            if r.n_instructions > self.limits.max_instructions:
                r.blocked.append(Blocked("instruction-budget", self.fn_addr,
                                         f"hit {self.limits.max_instructions} insns"))
                break
            if r.n_states > self.limits.max_states:
                r.blocked.append(Blocked("state-budget", self.fn_addr,
                                         f"hit {self.limits.max_states} states"))
                break

            st = worklist.pop()
            pc_now = st.pc if isinstance(st.pc, int) else as_int(st.pc)
            if pc_now is None or self.macho.vaddr_to_off(pc_now) is None:
                # A state whose pc left the mapped text (e.g. ran into the
                # return sentinel without a modeled return) cannot make further
                # progress. Record why instead of crashing.
                r.blocked.append(Blocked(
                    "control-left-text", st.fn_addr,
                    f"pc={pc_now!r} depth={st.call_depth} "
                    f"lr={as_int(st.regs[30]):#x}"))
                continue
            try:
                outcome = self._exec_until_branch(st)
            except _StopState as e:
                self._record_terminal(st, e, r)
                continue
            except UnsupportedError as e:
                r.blocked.append(Blocked("unsupported", st.pc, str(e)))
                continue
            except SymbolicMemoryError as e:
                r.blocked.append(Blocked("symbolic-memory", st.pc, str(e)))
                continue

            if outcome is None:
                continue
            kind, data = outcome
            if kind == "return":
                self._handle_return(st, data, r, worklist, t0)
            elif kind == "branch":
                self._handle_branch(st, data, r, worklist)
            elif kind == "branch-plain":
                # pc already updated by the handler; keep executing same state
                worklist.append(st)
            elif kind == "call":
                self._handle_call(st, data, r, worklist)
        r.elapsed_s = time.monotonic() - t0
        return r

    # ----- terminal handling -----
    def _record_terminal(self, st, exc, r):
        if isinstance(exc, _LoopCap):
            r.blocked.append(Blocked("loop-unroll-cap", st.pc, str(exc)))

    def _handle_return(self, st, value_e, r, worklist, t0):
        # Success = return value (w0) nonzero AND feasible.
        r.branches_explored += 1
        cond = (to64(value_e) != 0)
        s = z3.Solver()
        s.set("timeout", self.limits.solver_timeout_ms)
        s.add(*st.constraints)
        s.add(cond)
        chk = s.check()
        if chk == z3.sat:
            r.n_sat += 1
            if not r.found:
                self._capture_solution(st, s, r)
                # Keep exploring briefly? No — first passing input satisfies
                # the goal; stop and report.
                worklist.clear()
                return
        elif chk == z3.unsat:
            r.n_unsat += 1
        else:
            r.blocked.append(Blocked("solver-timeout", st.pc,
                                     "could not decide success constraints"))

    def _capture_solution(self, st, solver, r):
        m = solver.model()
        out = bytearray()
        model_map = {}
        for i, var in enumerate(st.input_vars):
            v = m.eval(var, model_completion=True)
            val = v.as_long() if is_concrete(v) else 0
            out.append(val & 0xFF)
            model_map[f"in[{i}]"] = val & 0xFF
        r.found = True
        r.input_bytes = bytes(out)
        r.model = model_map
        r.success_addr = st.pc

    # ----- branching -----
    def _handle_branch(self, st, data, r, worklist):
        cond_expr, taken_addr, fall_addr = data
        r.n_forks += 1
        if is_concrete(cond_expr):
            target = taken_addr if as_int(cond_expr) != 0 else fall_addr
            st.pc = target
            worklist.append(st)
            return
        # Two symbolic children. DFS order: push fall-through first so the
        # "taken" path is explored next. Aggressive per-fork pruning is costly
        # once array/table constraints appear, so it is throttled and uses a
        # short solver timeout (unknown is kept as potentially feasible).
        children = [(z3.Not(cond_expr), fall_addr), (cond_expr, taken_addr)]
        for guard, target in children:
            child = st.clone()
            child.constraints.append(guard)
            r.n_states += 1
            if (self.limits.prune_branches and
                    r.n_forks % self.limits.prune_every == 0):
                if not self._feasible(child, quick=True):
                    r.n_unsat += 1
                    continue
            child.pc = target
            worklist.append(child)

    def _feasible(self, st, quick=False):
        s = z3.Solver()
        s.set("timeout", (min(3000, self.limits.solver_timeout_ms)
                          if quick else self.limits.solver_timeout_ms))
        s.add(*st.constraints)
        # Unknown (timeout) is treated as feasible so pruning never discards a
        # potentially valid path for lack of a decision.
        return s.check() != z3.unsat

    # ----- calls -----
    def _handle_call(self, st, data, r, worklist):
        target, ret = data
        # Library / imported stub?
        name = self.macho.stubs.get(target)
        if name is not None:
            self._apply_libc(st, name)
            st.pc = ret
            worklist.append(st)
            return
        # Known internal function: descend (bounded depth).
        if st.call_depth >= 8:
            r.blocked.append(Blocked("call-depth", st.pc,
                                     "internal call depth limit"))
            return
        st.call_depth += 1
        st.regs[30] = bv(ret)
        st.pc = target
        worklist.append(st)
    # ----- libc models -----
    def _apply_libc(self, st, name):
        if name == "_strlen":
            ptr = st.regs[0]
            st.regs[0] = self._strlen(st, ptr)
        elif name == "_strcmp" or name == "_strncmp":
            self._strcmp(st, name == "_strncmp")
        elif name == "_memcmp":
            self._memcmp(st)
        elif name in ("_memcpy", "_memmove"):
            self._memcpy(st)
        elif name == "_memset":
            self._memset(st)
        else:
            raise UnsupportedError(f"unmodeled library call {name}")

    def _strlen(self, st, ptr_e):
        base = as_int(ptr_e)
        if base is None:
            raise SymbolicMemoryError("strlen on symbolic pointer")
        # Walk any concrete prefix (global/string literals) first.
        n = 0
        while True:
            b_e = st.mem.load(bv(base + n), 8)
            if not is_concrete(b_e):
                break
            if as_int(b_e) == 0:
                return bv(n)
            n += 1
            if n > st.input_len + 16:
                raise SymbolicMemoryError("strlen ran past input window")
        # Symbolic input region. The input is modeled as exactly input_len
        # symbolic bytes followed by a concrete NUL terminator, and the
        # per-length exploration already assumes no embedded NUL is a useful
        # solution. Therefore the length is deterministically input_len:
        # returning it concretely keeps all downstream control flow on
        # enumerable paths, which is what makes these checks tractable.
        if st.mem.in_input(base):
            return bv(st.input_len)
        # Unknown symbolic region outside the input window: not enumerable.
        raise SymbolicMemoryError(
            "strlen over symbolic region outside the modeled input")

    def _strcmp(self, st, bounded):
        p0 = as_int(st.regs[0]); p1 = as_int(st.regs[1])
        n = as_int(st.regs[2]) if bounded else 1 << 30
        if p0 is None or p1 is None:
            raise SymbolicMemoryError("strcmp with symbolic pointer")
        i = 0
        result = bv(0, 64)
        while i < n:
            a = z3.ZeroExt(56, z3.Extract(7, 0, st.mem.load(bv(p0 + i), 8)))
            b = z3.ZeroExt(56, z3.Extract(7, 0, st.mem.load(bv(p1 + i), 8)))
            result = z3.If(a != b, to64(a) - to64(b), result)
            if not bounded and is_concrete(a) and as_int(a) == 0:
                break
            i += 1
            if i > st.input_len + 16:
                break
        st.regs[0] = result

    def _memcmp(self, st):
        p0 = as_int(st.regs[0]); p1 = as_int(st.regs[1]); n = as_int(st.regs[2])
        result = bv(0, 64)
        for i in range(n):
            a = st.mem.load(bv(p0 + i), 8); b = st.mem.load(bv(p1 + i), 8)
            result = z3.If(a != b, to64(a) - to64(b), result)
        st.regs[0] = result

    def _memcpy(self, st):
        dst = as_int(st.regs[0]); src = as_int(st.regs[1]); n = as_int(st.regs[2])
        for i in range(n):
            st.mem.store(bv(dst + i), st.mem.load(bv(src + i), 8), 8)
        st.regs[0] = bv(dst)

    def _memset(self, st):
        dst = as_int(st.regs[0]); val = st.regs[1]; n = as_int(st.regs[2])
        for i in range(n):
            st.mem.store(bv(dst + i), z3.Extract(7, 0, val), 8)
        st.regs[0] = bv(dst)

    # ======================================================================
    # Instruction execution: run straight-line until a branch/call/return.
    # ======================================================================
    def _exec_until_branch(self, st):
        budget = 100000
        while budget:
            budget -= 1
            self.result.n_instructions += 1
            pc_now = st.pc if isinstance(st.pc, int) else as_int(st.pc)
            if pc_now is None or not self._in_text(pc_now):
                # pc left the function's text (a truncated/sentinel target).
                raise UnsupportedError(
                    f"control flow left __text (pc={pc_now:#x}, "
                    f"depth={st.call_depth})")
            insn = self.insn_at(pc_now)
            if insn is None:
                raise UnsupportedError(f"undecodable instruction at {pc_now:#x}")
            mnem = insn.mnemonic
            # Loop unroll guard on backward unconditional/conditional edges.
            if mnem in ("b", "cbz", "cbnz", "tbz", "tbnz") or mnem.startswith("b."):
                tgt = self._branch_target(insn)
                cur = st.pc if isinstance(st.pc, int) else as_int(st.pc)
                if tgt is not None and cur is not None and tgt <= cur:
                    c = st.loop_counts.get(tgt, 0) + 1
                    if c > self.limits.max_loop_unroll:
                        raise _LoopCap(
                            f"back-edge to {tgt:#x} exceeded "
                            f"{self.limits.max_loop_unroll} unrolls")
                    st.loop_counts[tgt] = c

            handler = self._HANDLERS.get(mnem)
            if handler is None:
                raise UnsupportedError(
                    f"unsupported opcode {mnem!r} at {st.pc:#x}")
            rc = handler(self, st, insn)
            if rc is not None:
                return rc
            # Straight-line instruction: fall through to the next word.
            st.pc += 4
        raise UnsupportedError("basic block exceeded straight-line budget")
    def _branch_target(self, insn):
        for op in insn.operands:
            if op.type == capstone.arm64.ARM64_OP_IMM:
                return op.imm
        return None

    # ----- operand accessors -----
    def _reg_idx(self, insn, op_index):
        name = insn.reg_name(insn.operands[op_index].reg)
        return self._reg_num(name)

    @staticmethod
    def _reg_num(name):
        if name in ("sp",):
            return 31
        if name in ("wzr", "xzr"):
            return -1
        if name in ("fp", "x29"):
            return 29
        if name in ("lr", "x30"):
            return 30
        return int(name[1:])

    @staticmethod
    def _width_of(name: str) -> int:
        # Only the w-prefixed GPR names are 32-bit. Aliases fp (x29), lr (x30)
        # and sp are 64-bit, as are all x-prefixed registers.
        return 32 if name.startswith("w") else 64

    @staticmethod
    def _narrow(e, width: int):
        return e if e.size() == width else z3.Extract(width - 1, 0, e)

    def _read_reg(self, st, name):
        if name == "sp":
            return st.sp
        if name in ("wzr", "xzr"):
            return bv(0)
        return st.regs[self._reg_num(name)]

    def _write_reg(self, st, name, value):
        if name == "sp":
            st.sp = value
            return
        if name in ("wzr", "xzr"):
            return
        idx = self._reg_num(name)
        # Writes to w-register zero the upper 32 bits of the x-register.
        if name.startswith("w"):
            value = z3.ZeroExt(32, z3.Extract(31, 0, value))
        st.regs[idx] = value

    def _operand_reg_name(self, insn, i):
        return insn.reg_name(insn.operands[i].reg)

    # ----- flag computation -----
    def _set_flags_sub(self, st, result, a, b, width):
        # a - b, width in bits (32 or 64).
        n = z3.Bool(f"N_{next(st.id_counter)}")
        zf = z3.Bool(f"Z_{next(st.id_counter)}")
        cf = z3.Bool(f"C_{next(st.id_counter)}")
        vf = z3.Bool(f"V_{next(st.id_counter)}")
        st.flags = {"N": n, "Z": zf, "C": cf, "V": vf}
        st.constraints.append(n == (z3.Extract(width - 1, width - 1, result) == bv(1, 1)))
        st.constraints.append(zf == (result == bv(0, width)))
        # C set iff no borrow (unsigned a >= b)
        st.constraints.append(cf == (z3.UGE(a, b)))
        # V iff signed overflow: operands differ in sign and result sign != a
        sa = z3.Extract(width - 1, width - 1, a)
        sres = z3.Extract(width - 1, width - 1, result)
        st.constraints.append(vf == z3.And(sa != z3.Extract(width - 1, width - 1, b),
                                           sres != sa))

    def _cond_pred(self, st, cc):
        f = st.flags
        N, Z, C, V = f["N"], f["Z"], f["C"], f["V"]
        table = {
            "eq": Z, "ne": z3.Not(Z),
            "hs": C, "lo": z3.Not(C),
            "mi": N, "pl": z3.Not(N),
            "vs": V, "vc": z3.Not(V),
            "hi": z3.And(C, z3.Not(Z)), "ls": z3.Or(z3.Not(C), Z),
            "ge": N == V, "lt": N != V,
            "gt": z3.And(N == V, z3.Not(Z)),
            "le": z3.Or(N != V, Z),
        }
        return table[cc]

    # ======================================================================
    # Individual instruction handlers. Return None to continue, or a tuple
    # ("branch"|"call"|"return", payload) to break out of the block.
    # ======================================================================
    def _h_add(self, st, insn):
        d = self._operand_reg_name(insn, 0)
        width = self._width_of(d)
        a = self._narrow(self._read_reg(st, self._operand_reg_name(insn, 1)), width)
        b = self._src_operand(st, insn, 2, width)
        self._write_reg(st, d, a + b)

    def _h_sub(self, st, insn, set_flags=False):
        d = self._operand_reg_name(insn, 0)
        width = self._width_of(d)
        a = self._narrow(self._read_reg(st, self._operand_reg_name(insn, 1)), width)
        b = self._src_operand(st, insn, 2, width)
        res = a - b
        self._write_reg(st, d, res)
        if set_flags:
            self._set_flags_sub(st, res, a, b, width)

    def _h_subs(self, st, insn):
        self._h_sub(st, insn, set_flags=True)

    def _h_mul(self, st, insn):
        d = self._operand_reg_name(insn, 0)
        width = self._width_of(d)
        a = self._narrow(self._read_reg(st, self._operand_reg_name(insn, 1)), width)
        b = self._src_operand(st, insn, 2, width)
        self._write_reg(st, d, a * b)

    def _h_and(self, st, insn, set_flags=False):
        d = self._operand_reg_name(insn, 0)
        width = self._width_of(d)
        a = self._narrow(self._read_reg(st, self._operand_reg_name(insn, 1)), width)
        b = self._src_operand(st, insn, 2, width)
        res = a & b
        self._write_reg(st, d, res)
        if set_flags:
            n = z3.Bool(f"N_{next(st.id_counter)}")
            zf = z3.Bool(f"Z_{next(st.id_counter)}")
            st.flags = {"N": n, "Z": zf, "C": z3.BoolVal(False),
                        "V": z3.BoolVal(False)}
            st.constraints.append(zf == (res == bv(0, width)))
            st.constraints.append(n == (z3.Extract(width-1, width-1, res) == bv(1, 1)))

    def _h_ands(self, st, insn):
        self._h_and(st, insn, set_flags=True)

    def _h_eor(self, st, insn):
        d = self._operand_reg_name(insn, 0)
        width = self._width_of(d)
        a = self._narrow(self._read_reg(st, self._operand_reg_name(insn, 1)), width)
        b = self._src_operand(st, insn, 2, width)
        self._write_reg(st, d, a ^ b)

    def _h_orr(self, st, insn):
        d = self._operand_reg_name(insn, 0)
        width = self._width_of(d)
        a = self._narrow(self._read_reg(st, self._operand_reg_name(insn, 1)), width)
        b = self._src_operand(st, insn, 2, width)
        self._write_reg(st, d, a | b)

    def _h_orr_alias(self, st, insn):
        # `mov xD, xS` is ORR xD, XZR, xS in many encodings; capstone usually
        # presents mov directly, but tolerate the alias.
        self._h_orr(st, insn)

    def _h_mov(self, st, insn):
        d = self._operand_reg_name(insn, 0)
        src = insn.operands[1]
        if src.type == capstone.arm64.ARM64_OP_IMM:
            self._write_reg(st, d, bv(src.imm, 64))
        else:
            self._write_reg(st, d, self._read_reg(st, insn.reg_name(src.reg)))

    def _h_movk(self, st, insn):
        d = self._operand_reg_name(insn, 0)
        imm_op = insn.operands[1]
        imm = imm_op.imm
        shift = imm_op.shift.value if imm_op.shift.type else 0
        width = self._width_of(d)
        cur = self._narrow(self._read_reg(st, d), width)
        mask = bv((0xFFFF << shift) & ((1 << width) - 1), width)
        new = (cur & ~mask) | bv((imm & 0xFFFF) << shift, width)
        self._write_reg(st, d, new)

    def _h_movn(self, st, insn):
        d = self._operand_reg_name(insn, 0)
        imm_op = insn.operands[1]
        imm = imm_op.imm
        shift = imm_op.shift.value if imm_op.shift.type else 0
        width = self._width_of(d)
        self._write_reg(st, d, bv(~((imm & 0xFFFF) << shift), width))

    # ----- loads/stores -----
    def _addr_mode(self, st, insn, base_op=1):
        mem = insn.operands[base_op].mem
        base = self._read_reg(st, insn.reg_name(mem.base))
        disp = mem.disp
        idx = None
        if mem.index != 0:
            idx = self._read_reg(st, insn.reg_name(mem.index))
        addr = to64(base) + bv(disp)
        if idx is not None:
            addr = addr + to64(idx)
        return addr

    def _h_ldr(self, st, insn, width=None, sign=False, byte=False):
        d = self._operand_reg_name(insn, 0)
        if width is None:
            width = self._width_of(d)
        addr = self._addr_mode(st, insn, 1)
        val = st.mem.load(addr, width, sign_extend=sign)
        self._write_reg(st, d, val)

    def _h_str(self, st, insn, width=None):
        d = self._operand_reg_name(insn, 0)
        if width is None:
            width = self._width_of(d)
        val = self._read_reg(st, d)
        addr = self._addr_mode(st, insn, 1)
        st.mem.store(addr, val, width)

    def _h_adrP(self, st, insn):
        # ADRP: page of target (capstone gives absolute target in operand).
        d = self._operand_reg_name(insn, 0)
        target = insn.operands[1].imm
        self._write_reg(st, d, bv(target & ~0xFFF))

    def _h_adr(self, st, insn):
        d = self._operand_reg_name(insn, 0)
        self._write_reg(st, d, bv(insn.operands[1].imm))

    # ----- branches -----
    def _h_b(self, st, insn):
        tgt = insn.operands[0].imm
        st.pc = tgt
        return ("branch-plain", None)

    def _h_bcond(self, st, insn):
        cc = self._cc_name(insn)
        tgt = insn.operands[0].imm
        pred = self._cond_pred(st, cc)
        fall = st.pc + 4
        return ("branch", (pred, tgt, fall))

    def _h_cbz(self, st, insn, nonzero=False):
        reg = self._read_reg(st, self._operand_reg_name(insn, 0))
        tgt = insn.operands[1].imm
        test = (reg != 0) if nonzero else (reg == 0)
        return ("branch", (test, tgt, st.pc + 4))

    def _h_tbz(self, st, insn, nonzero=False):
        reg = self._read_reg(st, self._operand_reg_name(insn, 0))
        bit = insn.operands[1].imm
        bitval = z3.Extract(bit, bit, reg)
        test = (bitval == 1) if nonzero else (bitval == 0)
        return ("branch", (test, insn.operands[2].imm, st.pc + 4))

    def _h_bl(self, st, insn):
        tgt = insn.operands[0].imm
        return ("call", (tgt, st.pc + 4))

    def _h_blr(self, st, insn):
        name = self._operand_reg_name(insn, 0)
        tgt_e = self._read_reg(st, name)
        if not is_concrete(tgt_e):
            raise SymbolicMemoryError("indirect call through symbolic pointer")
        return ("call", (as_int(tgt_e), st.pc + 4))

    def _h_ret(self, st, insn):
        # If the link register still holds the sentinel, this is the top-level
        # check() returning. Otherwise it is a callee returning to its caller.
        lr = as_int(st.regs[30])
        if st.call_depth == 0 and lr == st.ret_addr:
            st.pc = st.ret_addr
            return ("return", st.regs[0])
        # Callee return: resume at the link-register address.
        st.pc = lr
        st.call_depth = max(0, st.call_depth - 1)
        return ("branch-plain", None)

    def _h_nop(self, st, insn):
        pass

    # ----- select / shifts / extension aliases -----
    def _h_csel(self, st, insn):
        d = self._operand_reg_name(insn, 0)
        a = self._read_reg(st, self._operand_reg_name(insn, 1))
        b = self._read_reg(st, self._operand_reg_name(insn, 2))
        cc = self._cc_name(insn)
        self._write_reg(st, d, z3.If(self._cond_pred(st, cc), a, b))

    def _h_lsl(self, st, insn):
        d = self._operand_reg_name(insn, 0)
        a = self._read_reg(st, self._operand_reg_name(insn, 1))
        op = insn.operands[2]
        if op.type == capstone.arm64.ARM64_OP_IMM:
            res = a << op.imm
        else:
            res = a << self._read_reg(st, insn.reg_name(op.reg))
        self._write_reg(st, d, res)

    def _h_lsr(self, st, insn):
        d = self._operand_reg_name(insn, 0)
        a = self._read_reg(st, self._operand_reg_name(insn, 1))
        op = insn.operands[2]
        amt = op.imm if op.type == capstone.arm64.ARM64_OP_IMM \
            else self._read_reg(st, insn.reg_name(op.reg))
        self._write_reg(st, d, z3.LShR(a, amt))

    def _h_neg(self, st, insn):
        d = self._operand_reg_name(insn, 0)
        a = self._read_reg(st, self._operand_reg_name(insn, 1))
        self._write_reg(st, d, -a)

    def _h_mvn(self, st, insn):
        d = self._operand_reg_name(insn, 0)
        a = self._src_operand(st, insn, 1, 64)
        self._write_reg(st, d, ~a)

    def _h_sxt(self, st, insn):
        d = self._operand_reg_name(insn, 0)
        a = self._read_reg(st, self._operand_reg_name(insn, 1))
        mnem = insn.mnemonic
        src_w = {"sxtb": 8, "sxth": 16, "sxtw": 32}[mnem]
        narrow = z3.Extract(src_w - 1, 0, a)
        self._write_reg(st, d, z3.SignExt(64 - src_w, narrow))

    def _h_uxt(self, st, insn):
        d = self._operand_reg_name(insn, 0)
        a = self._read_reg(st, self._operand_reg_name(insn, 1))
        src_w = {"uxtb": 8, "uxth": 16, "uxtw": 32}[insn.mnemonic]
        self._write_reg(st, d, z3.ZeroExt(64 - src_w, z3.Extract(src_w - 1, 0, a)))

    def _h_stp_ldp(self, st, insn, load):
        mem = insn.operands[2].mem
        base = self._read_reg(st, insn.reg_name(mem.base))
        addr = to64(base) + bv(mem.disp)
        rt = self._operand_reg_name(insn, 0)
        rt2 = self._operand_reg_name(insn, 1)
        width = self._width_of(rt)
        if load:
            self._write_reg(st, rt, st.mem.load(addr, width))
            self._write_reg(st, rt2, st.mem.load(addr + bv(width // 8), width))
        else:
            st.mem.store(addr, self._read_reg(st, rt), width)
            st.mem.store(addr + bv(width // 8), self._read_reg(st, rt2), width)

    # ----- source operand (reg or immediate, optional shift) -----
    def _src_operand(self, st, insn, i, width):
        op = insn.operands[i]
        if op.type == capstone.arm64.ARM64_OP_IMM:
            return bv(op.imm, width)
        val = self._narrow(self._read_reg(st, insn.reg_name(op.reg)), width)
        if op.shift.type:
            val = self._apply_shift(val, op.shift)
        return val

    @staticmethod
    def _apply_shift(val, shift):
        amt = shift.value
        t = shift.type
        if t == capstone.arm64.ARM64_SFT_LSL:
            return val << amt
        if t == capstone.arm64.ARM64_SFT_LSR:
            return z3.LShR(val, amt)
        if t == capstone.arm64.ARM64_SFT_ASR:
            return val >> amt
        return val

    @staticmethod
    def _cc_name(insn):
        # mnemonic like b.eq -> eq
        return insn.mnemonic.split(".")[1]


class UnsupportedError(Exception):
    pass


class _StopState(Exception):
    pass


class _LoopCap(_StopState):
    pass


# Bind mnemonics to handlers after the class is defined. Loads/stores with the
# same semantics share thin wrappers via lambdas.
def _install_handlers():
    E = Engine
    E._HANDLERS = {
        "add": E._h_add,
        "sub": lambda s, st, i: E._h_sub(s, st, i, False),
        "subs": E._h_subs,
        "mul": E._h_mul,
        "and": lambda s, st, i: E._h_and(s, st, i, False),
        "ands": E._h_ands,
        "eor": E._h_eor,
        "orr": E._h_orr,
        "mov": E._h_mov,
        "movz": E._h_mov,
        "movk": E._h_movk,
        "movn": E._h_movn,
        "adr": E._h_adr,
        "adrp": E._h_adrP,
        "ldr": E._h_ldr,
        "ldur": E._h_ldr,
        "ldrsw": lambda s, st, i: E._h_ldr(s, st, i, 32, sign=True),
        "ldursw": lambda s, st, i: E._h_ldr(s, st, i, 32, sign=True),
        "ldrh": lambda s, st, i: E._h_ldr(s, st, i, 16),
        "ldrb": lambda s, st, i: E._h_ldr(s, st, i, 8),
        "ldrsb": lambda s, st, i: E._h_ldr(s, st, i, 8, sign=True),
        "ldursh": lambda s, st, i: E._h_ldr(s, st, i, 16, sign=True),
        "ldrsh": lambda s, st, i: E._h_ldr(s, st, i, 16, sign=True),
        "str": E._h_str,
        "stur": E._h_str,
        "strh": lambda s, st, i: E._h_str(s, st, i, 16),
        "strb": lambda s, st, i: E._h_str(s, st, i, 8),
        "stp": lambda s, st, i: E._h_stp_ldp(s, st, i, False),
        "ldp": lambda s, st, i: E._h_stp_ldp(s, st, i, True),
        "b": E._h_b,
        "bl": E._h_bl,
        "blr": E._h_blr,
        "ret": E._h_ret,
        "nop": E._h_nop,
        "cbz": lambda s, st, i: E._h_cbz(s, st, i, False),
        "cbnz": lambda s, st, i: E._h_cbz(s, st, i, True),
        "tbz": lambda s, st, i: E._h_tbz(s, st, i, False),
        "tbnz": lambda s, st, i: E._h_tbz(s, st, i, True),
        "csel": E._h_csel,
        "lsl": E._h_lsl,
        "lsr": E._h_lsr,
        "asr": E._h_lsl,
        "neg": E._h_neg,
        "mvn": E._h_mvn,
        "sxtb": E._h_sxt,
        "sxth": E._h_sxt,
        "sxtw": E._h_sxt,
        "uxtb": E._h_uxt,
        "uxth": E._h_uxt,
        "uxtw": E._h_uxt,
    }
    # Conditional branches b.<cc> all route to one handler.
    for cc in INV_COND.values():
        E._HANDLERS[f"b.{cc}"] = E._h_bcond


_install_handlers()
