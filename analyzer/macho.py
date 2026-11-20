"""
macho.py — minimal Mach-O reader for arm64 (Mach-O 64-bit, little endian).

Only what the symbolic analyzer needs:
  * choose the arm64 slice of a fat binary
  * enumerate segments/sections with vmaddr<->file offset translation
  * read the local symbol table (function addresses/names)
  * resolve __stubs entries to imported symbol names via the indirect table
  * pull __cstring contents
Everything is parsed with struct from raw bytes; no third-party dependency.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

# Mach-O constants
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
N_SECT = 0xE          # section symbol mask (n_type & 0x0e)
N_EXT = 0x1
N_PEXT = 0x10
N_TYPE = 0x0E
N_UNDF = 0x0


@dataclass
class Section:
    name: str
    seg: str
    addr: int
    size: int
    offset: int
    reserved1: int
    flags: int


@dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    sections: list[Section] = field(default_factory=list)


@dataclass
class Symbol:
    name: str
    addr: int
    is_import: bool       # undefined (external) symbol
    is_local: bool


class MachO:
    def __init__(self, path: str):
        with open(path, "rb") as f:
            raw = f.read()
        self.path = path
        magic = struct.unpack_from(">I", raw, 0)[0]
        if magic in (FAT_MAGIC, FAT_CIGAM):
            raw = self._extract_arm64_slice(raw)
        self.data = raw
        if struct.unpack_from("<I", raw, 0)[0] != MH_MAGIC_64:
            raise ValueError("not a 64-bit Mach-O file")
        self.cputype, self.cpusub = struct.unpack_from("<ii", raw, 4)
        self.ncmds, self.sizeofcmds = struct.unpack_from("<II", raw, 16)
        self.segments: list[Segment] = []
        self.sections: list[Section] = []
        self._symoff = self._nsyms = self._stroff = self._strsize = 0
        self.indirect: list[int] = []
        self._parse_load_commands()
        self.symbols: list[Symbol] = self._parse_symbols()
        self.by_name = {s.name: s for s in self.symbols}
        self.stubs: dict[int, str] = self._parse_stubs()

    # ----- fat handling -----
    @staticmethod
    def _extract_arm64_slice(raw: bytes) -> bytes:
        be = ">I"
        magic, nfat = struct.unpack_from(">II", raw, 0)
        off = 8
        for _ in range(nfat):
            cputype, cpusub, offset, size, align = struct.unpack_from(">iiIII", raw, off)
            # CPU_TYPE_ARM64 == 0x0100000C
            if cputype == 0x0100000C:
                return raw[offset:offset + size]
            off += 20
        raise ValueError("fat binary contains no arm64 slice")

    # ----- load commands -----
    def _parse_load_commands(self):
        off = 32
        indirect_off = indirect_n = 0
        for _ in range(self.ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.data, off)
            if cmd == LC_SEGMENT_64:
                seg = self._parse_segment(off)
                self.segments.append(seg)
                self.sections.extend(seg.sections)
            elif cmd == LC_SYMTAB:
                (self._symoff, self._nsyms,
                 self._stroff, self._strsize) = struct.unpack_from("<IIII", self.data, off + 8)
            elif cmd == LC_DYSYMTAB:
                # dysymtab_command fields after cmd/cmdsize:
                # 0 ilocalsym,1 nlocalsym,2 iextdefsym,3 nextdefsym,
                # 4 iundefsym,5 nundefsym,6 tocoff,7 ntoc,8 modtaboff,9 nmodtab,
                # 10 extrefsymoff,11 nextrefsyms,12 indirectsymoff,13 nindirectsyms
                vals = struct.unpack_from("<" + "I" * 18, self.data, off + 8)
                indirect_off, indirect_n = vals[12], vals[13]
            off += cmdsize
        if indirect_off and indirect_n:
            self.indirect = list(struct.unpack_from(
                f"<{indirect_n}I", self.data, indirect_off))
        else:
            self.indirect = []

    def _parse_segment(self, off: int) -> Segment:
        (segname,) = struct.unpack_from("<16s", self.data, off + 8)
        segname = segname.split(b"\x00")[0].decode()
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", self.data, off + 24)
        nsects = struct.unpack_from("<I", self.data, off + 64)[0]
        seg = Segment(segname, vmaddr, vmsize, fileoff, filesize)
        soff = off + 72
        for _ in range(nsects):
            sname, sseg = struct.unpack_from("<16s16s", self.data, soff)
            sname = sname.split(b"\x00")[0].decode()
            sseg = sseg.split(b"\x00")[0].decode()
            addr, size = struct.unpack_from("<QQ", self.data, soff + 32)
            offset, align, reloff, nreloc = struct.unpack_from(
                "<IIII", self.data, soff + 48)
            flags, reserved1, reserved2, _res3 = struct.unpack_from(
                "<IIII", self.data, soff + 64)
            seg.sections.append(Section(sname, sseg, addr, size, offset,
                                        reserved1, flags))
            soff += 80
        return seg

    # ----- symbols -----
    def _cstr(self, strtab_off: int) -> str:
        base = self._stroff + strtab_off
        end = self.data.index(b"\x00", base)
        return self.data[base:end].decode("utf-8", "replace")

    def _parse_symbols(self) -> list[Symbol]:
        out = []
        for i in range(self._nsyms):
            base = self._symoff + i * 16
            n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from(
                "<IBBHQ", self.data, base)
            if n_strx == 0:
                continue
            name = self._cstr(n_strx)
            is_undef = (n_type & N_TYPE) == N_UNDF
            is_local = not (n_type & N_EXT)
            out.append(Symbol(name, n_value, is_undef, is_local))
        return out

    def _parse_stubs(self) -> dict[int, str]:
        """Map each stub entry address to its imported symbol name."""
        stubs = {}
        for sec in self.sections:
            if sec.name != "__stubs":
                continue
            # arm64 stub entries are 12 bytes (adrp/ldr/br)
            entry = 12
            count = sec.size // entry
            for k in range(count):
                idx = sec.reserved1 + k
                if idx >= len(self.indirect):
                    break
                sym_idx = self.indirect[idx]
                if sym_idx == 0x80000000 or sym_idx >= self._nsyms:
                    continue
                strx = struct.unpack_from("<I", self.data,
                                          self._symoff + sym_idx * 16)[0]
                if strx:
                    stubs[sec.addr + k * entry] = self._cstr(strx)
        return stubs

    # ----- address helpers -----
    def vaddr_to_off(self, addr: int) -> int | None:
        for seg in self.segments:
            if seg.vmaddr <= addr < seg.vmaddr + seg.vmsize:
                return seg.fileoff + (addr - seg.vmaddr)
        return None

    def read_vaddr(self, addr: int, n: int) -> bytes:
        off = self.vaddr_to_off(addr)
        if off is None:
            raise KeyError(f"address 0x{addr:x} not mapped")
        return self.data[off:off + n]

    def section(self, name: str) -> Section | None:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def read_cstrings(self) -> dict[int, str]:
        sec = self.section("__cstring")
        if not sec:
            return {}
        blob = self.data[sec.offset:sec.offset + sec.size]
        out, start = {}, 0
        for i, b in enumerate(blob):
            if b == 0:
                out[sec.addr + start] = blob[start:i].decode("utf-8", "replace")
                start = i + 1
        return out

    def function_symbols(self) -> list[Symbol]:
        """Defined local/global text symbols (candidate analysis targets)."""
        return [s for s in self.symbols
                if not s.is_import and s.addr and s.name not in ("",)]
