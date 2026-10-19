"""Every SQL table malcatsql exposes. Addresses are virtual addresses unless a column says ``ea``."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any, Optional

import apsw

from . import TOOL_NAME, __version__
from .vtab import CachedSurface, Col, Row, Surface, numbered

if TYPE_CHECKING:
    from .engine import Engine
    from .session import Session


_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ENUM_NAMES: dict[tuple[type, int], str] = {}


def _enum_name(value: Any) -> Optional[str]:
    # pybind11 enum `.name` costs ~35 us per access; memoize per (enum type, value)
    if value is None:
        return None
    try:
        key = (type(value), int(value))
    except (TypeError, ValueError):
        return getattr(value, "name", str(value))
    name = _ENUM_NAMES.get(key)
    if name is None:
        name = _ENUM_NAMES[key] = getattr(value, "name", str(value))
    return name


def _lower_enum(value: Any) -> Optional[str]:
    name = _enum_name(value)
    return None if name is None else name.lower()


def _b(value: Any) -> int:
    return 1 if value else 0


# =============================================================================== orientation


class BinaryTable(Surface):
    name = "binary"
    skill = "connect"
    doc = "Key/value orientation facts (summary row first)."
    columns = (Col("key", "TEXT"), Col("value", "TEXT"), Col("type", "TEXT"))
    scan_rows = 30

    def rows(self, eq: dict[str, Any]) -> list[Row]:
        s, a = self.session, self.session.a
        regions = [r for r in a.map.regions if r.virt is not None]
        min_addr = min((r.virt for r in regions), default=None)
        max_addr = max((r.virt + max(r.virt_size, r.phys_size) for r in regions), default=None)
        nfns = s.cached(("binary", "nfns"), lambda: sum(1 for _ in a.fns))
        entry = s.va(a.entrypoint)
        arch = _enum_name(a.architecture)
        summary = (
            f"{a.type} {arch} {_enum_name(a.category)}, {nfns} functions, "
            f"entry {'0x%X' % entry if entry is not None else 'n/a'}, {s.source_path.name}"
        )
        ent = a.entropy
        facts: list[tuple[str, Any, str]] = [
            ("summary", summary, "string"),
            ("tool_name", TOOL_NAME, "string"),
            ("tool_version", __version__, "string"),
            ("malcat_version", _malcat_version(s), "string"),
            ("processor", arch, "string"),
            ("filetype", a.type, "string"),
            ("category", _enum_name(a.category), "string"),
            ("image_base", _hex(a.imagebase), "hex"),
            ("entry_point", _hex(entry), "hex"),
            ("min_addr", _hex(min_addr), "hex"),
            ("max_addr", _hex(max_addr), "hex"),
            ("is_64bit", "true" if s.is_64bit else "false", "bool"),
            ("bits", "64" if s.is_64bit else "32", "int"),
            ("endianness", "little" if a.is_lsb else "big", "string"),
            ("filename", str(s.source_path), "string"),
            ("file_size", str(a.file.size), "int"),
            ("md5", _safe(lambda: ent.md5), "string"),
            ("sha1", _safe(lambda: ent.sha1), "string"),
            ("sha256", _safe(lambda: ent.sha256), "string"),
            ("imphash", _safe(lambda: ent.imphash), "string"),
            ("project_path", str(s.project_path), "string"),
            ("project_loaded", "true" if s.project_loaded else "false", "bool"),
            ("unsaved_changes", "true" if s.unsaved_changes else "false", "bool"),
        ]
        return numbered([(k, None if v is None else str(v), t) for k, v, t in facts])


def _hex(v: Optional[int]) -> Optional[str]:
    return None if v is None else "0x%X" % v


def _safe(fn: Any) -> Any:
    try:
        return fn()
    except Exception:
        return None


def _malcat_version(s: Session) -> Optional[str]:
    version = getattr(s.malcat, "version", None)
    return _safe(version) if callable(version) else version


class CapabilitiesTable(Surface):
    name = "capabilities"
    skill = "connect"
    doc = "Feature/mutation matrix: gate writes on mutation.<table>.<op>."
    columns = (Col("key", "TEXT", pushdown=True), Col("value", "TEXT"), Col("description", "TEXT"))
    scan_rows = 200

    def __init__(self, session: Session, engine: Engine) -> None:
        super().__init__(session)
        self.engine = engine

    def rows(self, eq: dict[str, Any]) -> list[Row]:
        a = self.session.a
        arch = _enum_name(a.architecture)
        out: list[tuple[str, str, str]] = [
            ("feature.decompiler", _tf(arch in DECOMPILABLE), "decompile()/pseudocode for this architecture"),
            ("feature.capa", "true", "capa / capa_matches (computed on first query)"),
            ("feature.yara", "true", "signatures / signature_hits"),
            ("feature.python", _tf(self.engine.settings.get_bool("enable_python")), "malcat_python() gate"),
            ("feature.kesakode", "false", "not exposed: online lookups consume quota"),
            ("feature.persistence", "true", "SELECT save() writes a .malcat project"),
        ]
        for surf in self.engine.surfaces.values():
            for op in ("insert", "update", "delete"):
                out.append(
                    (
                        f"mutation.{surf.name}.{op}",
                        _tf(op in surf.writable),
                        surf.write_note if op in surf.writable else "",
                    )
                )
        if "key" in eq:
            out = [r for r in out if r[0] == eq["key"]]
        return numbered(out)


# Function.decompile() supports x86/x64, arm, aarch64 and mips (see Malcat's mcp_common.fn_decompile)
DECOMPILABLE = {"X86", "X64", "ARMV7", "ARMV7T", "ARMV8", "ARMV8T", "AARCH64", "MIPS32", "MIPS64"}


def _tf(v: bool) -> str:
    return "true" if v else "false"


class RuntimeSettingsTable(Surface):
    name = "runtime_settings"
    skill = "connect"
    doc = "Live runtime knobs; UPDATE value to change one."
    columns = (
        Col("key", "TEXT", pushdown=True),
        Col("value", "TEXT"),
        Col("type", "TEXT"),
        Col("scope", "TEXT"),
        Col("kind", "TEXT"),
        Col("settable", "INT"),
        Col("description", "TEXT"),
    )
    scan_rows = 10
    writable = frozenset({"update"})
    write_note = "UPDATE runtime_settings SET value=... WHERE key=..."

    def __init__(self, session: Session, engine: Engine) -> None:
        super().__init__(session)
        self.engine = engine

    def rows(self, eq: dict[str, Any]) -> list[Row]:
        out = []
        for i, spec in enumerate(self.engine.settings.specs, 1):
            if "key" in eq and spec.key != eq["key"]:
                continue
            value = self.engine.settings.get_text(spec.key)
            out.append((i, (spec.key, value, spec.type, spec.scope, "value", 1, spec.doc)))
        return out

    def update(self, rowid: int, values: dict[str, Any]) -> None:
        spec = self.engine.settings.specs[rowid - 1]
        if values["key"] != spec.key:
            raise apsw.ConstraintError("runtime_settings: only the value column is writable")
        self.engine.settings.set(spec.key, values["value"])


# =============================================================================== functions & code


class FuncsTable(CachedSurface):
    name = "funcs"
    skill = "disassembly"
    doc = "Functions. UPDATE name renames (Malcat user label)."
    columns = (
        Col("addr", "INT", pushdown=True),
        Col("name", "TEXT", pushdown=True),
        Col("fullname", "TEXT"),
        Col("size", "INT"),
        Col("end_addr", "INT"),
        Col("category", "TEXT"),
        Col("num_bb", "INT"),
        Col("num_instructions", "INT"),
        Col("num_calls", "INT"),
        Col("num_api_calls", "INT"),
        Col("num_string_refs", "INT"),
        Col("num_xor_ops", "INT"),
        Col("num_known_constants", "INT"),
        Col("num_dynamic_jumps", "INT"),
        Col("num_arith_ops", "INT"),
        Col("is_leaf", "INT"),
        Col("is_library", "INT"),
        Col("has_loop", "INT"),
        Col("ea", "INT"),
    )
    scan_rows = 20_000
    writable = frozenset({"update"})
    write_note = "UPDATE funcs SET name=... (empty/NULL removes the user label); run is deferred to the next read"

    def build(self) -> list[Row]:
        s = self.session
        out: list[Row] = []
        for i, f in enumerate(s.a.fns):
            if i % 2048 == 0:
                s.check_deadline()
            ea = f.address
            out.append(
                (
                    ea,
                    (
                        s.va(ea),
                        f.name,
                        f.fullname,
                        f.size,
                        s.va(f.end),
                        _lower_enum(f.category),
                        f.num_bb_code,
                        f.num_instructions,
                        f.num_calls,
                        f.num_api_calls,
                        f.num_string_references,
                        f.num_xor_ops,
                        f.num_known_constants_uses,
                        f.num_dynamic_jumps,
                        f.num_arithmetic_ops,
                        _b(f.is_leaf),
                        _b(f.is_library),
                        _b(f.has_back_edge),
                        ea,
                    ),
                )
            )
        return out

    def update(self, rowid: int, values: dict[str, Any]) -> None:
        _set_label(self.session, rowid, values["name"])


class FuncHashesTable(CachedSurface):
    name = "func_hashes"
    skill = "workspace"
    doc = (
        "Per-function code fingerprints for cross-sample matching: pic_hash (position-independent "
        "code hash, 16 hex digits; equal = same code) and Malcat's fuzzy_hash (64-byte blob; use hamming())."
    )
    columns = (
        Col("addr", "INT", pushdown=True),
        Col("pic_hash", "TEXT", pushdown=True),
        Col(
            "pic_count",
            "INT",
            doc="functions in THIS sample sharing the pic_hash; only pic_count = 1 matches identify a function",
        ),
        Col("fuzzy_hash", "BLOB"),
        Col("size", "INT"),
        Col("num_instructions", "INT"),
    )
    scan_rows = 20_000

    def build(self) -> list[Row]:
        s = self.session
        raw: list[tuple[int, str, bytes, int, int]] = []
        for i, f in enumerate(s.a.fns):
            if i % 2048 == 0:
                s.check_deadline()
            raw.append((f.address, "%016x" % f.pic_hash, bytes(f.fuzzy_hash()), f.size, f.num_instructions))
        counts: dict[str, int] = {}
        for _, h, *_rest in raw:
            counts[h] = counts.get(h, 0) + 1
        return [(ea, (s.va(ea), h, counts[h], fz, size, n)) for ea, h, fz, size, n in raw]


def _set_label(s: Session, ea: int, name: Optional[str]) -> None:
    if name:
        if not s.a.syms.set_label(ea, str(name)):
            raise apsw.ConstraintError(f"malcat refused label {name!r} at 0x{s.va(ea) or ea:X}")
    else:
        s.a.syms.unset_label(ea)
    s.mark_dirty()


def _function_blocks(s: Session, func_ea: int) -> list[Any]:
    """Code basic blocks of one function (live malcat objects: consume immediately)."""
    fn = s.a.fns.find(func_ea)
    if fn is None or fn.address != func_ea:
        return []
    out = []
    cur, end = fn.start, fn.end
    while cur < end:
        bb = s.a.cfg.find_forward(cur)
        if bb is None or bb.start >= end:
            break
        owner = bb.function
        if bb.code and owner is not None and owner.address == func_ea:
            out.append(bb)
        cur = bb.end if bb.end > cur else cur + 1
    return out


def _all_code_blocks(s: Session) -> Any:
    for i, bb in enumerate(s.a.cfg):
        if i % 4096 == 0:
            s.check_deadline()
        if bb.code:
            yield bb


def _func_filter_ea(s: Session, eq: dict[str, Any]) -> Optional[int]:
    """EA of the function named by an EQ func_addr constraint, or None if it isn't a function."""
    ea = s.try_ea(eq["func_addr"])
    if ea is None:
        return None
    fn = s.a.fns.find(ea)
    return ea if fn is not None and fn.address == ea else None


class BlocksTable(Surface):
    name = "blocks"
    skill = "disassembly"
    doc = "Code basic blocks; filter by func_addr."
    columns = (
        Col("start_addr", "INT"),
        Col("end_addr", "INT"),
        Col("func_addr", "INT", pushdown=True),
        Col("size", "INT"),
        Col("is_loop", "INT"),
        Col("num_in", "INT"),
        Col("num_out", "INT"),
    )
    scan_rows = 1_000_000

    def _row(self, bb: Any, func_va: Optional[int]) -> Row:
        s = self.session
        return (
            bb.address,
            (
                s.va(bb.start),
                s.va(bb.end),
                func_va,
                bb.size,
                _b(bb.is_loop),
                sum(1 for _ in bb.incoming),
                sum(1 for _ in bb.outgoing),
            ),
        )

    def rows(self, eq: dict[str, Any]) -> list[Row]:
        s = self.session
        if "func_addr" in eq:
            fea = _func_filter_ea(s, eq)
            if fea is None:
                return []
            return [self._row(bb, eq["func_addr"]) for bb in _function_blocks(s, fea)]

        def build() -> list[Row]:
            out = []
            for bb in _all_code_blocks(s):
                owner = bb.function
                out.append(self._row(bb, s.va(owner.address) if owner is not None else None))
            return out

        return s.cached((self.name, "all"), build)


class CfgEdgesTable(Surface):
    name = "cfg_edges"
    skill = "disassembly"
    doc = "Basic-block edges (jump/step/call/except); filter by func_addr."
    columns = (
        Col("func_addr", "INT", pushdown=True),
        Col("from_addr", "INT"),
        Col("to_addr", "INT"),
        Col("edge_type", "TEXT"),
    )
    scan_rows = 2_000_000

    def rows(self, eq: dict[str, Any]) -> list[Row]:
        s = self.session
        if "func_addr" in eq:
            fea = _func_filter_ea(s, eq)
            if fea is None:
                return []
            blocks = [(bb, eq["func_addr"]) for bb in _function_blocks(s, fea)]
        else:
            blocks = []
            for bb in _all_code_blocks(s):
                owner = bb.function
                blocks.append((bb, s.va(owner.address) if owner is not None else None))
        out = []
        for bb, fva in blocks:
            src = s.va(bb.start)
            for e in bb.outgoing:
                out.append((fva, src, s.va(e.address), _lower_enum(e.type)))
        return numbered(out)


class InstructionsTable(Surface):
    name = "instructions"
    skill = "disassembly"
    doc = "Instructions; filter by func_addr (or addr). Unconstrained scans are slow on big files."
    columns = (
        Col("addr", "INT", pushdown=True),
        Col("func_addr", "INT", pushdown=True),
        Col("block_addr", "INT"),
        Col("mnemonic", "TEXT"),
        Col("disasm", "TEXT"),
        Col("size", "INT"),
        Col("itype", "TEXT"),
        Col("num_refs", "INT"),
    )
    scan_rows = 5_000_000

    def _row(self, ins: Any, func_va: Optional[int], block_va: Optional[int]) -> Row:
        s = self.session
        return (
            ins.address,
            (
                s.va(ins.address),
                func_va,
                block_va,
                ins.mnemonic,
                ins.disasm(),
                ins.size,
                _lower_enum(ins.type),
                sum(1 for _ in ins.outrefs),
            ),
        )

    def rows(self, eq: dict[str, Any]) -> list[Row]:
        s = self.session
        if "addr" in eq:
            ea = s.try_ea(eq["addr"])
            ins = s.a.asm[ea] if ea is not None else None
            if ins is None or ins.address != ea:
                return []
            fn, bb = ins.function, ins.bb
            row = self._row(
                ins,
                s.va(fn.address) if fn is not None else None,
                s.va(bb.address) if bb is not None else None,
            )
            if "func_addr" in eq and row[1][1] != eq["func_addr"]:
                return []
            return [row]
        if "func_addr" in eq:
            fea = _func_filter_ea(s, eq)
            if fea is None:
                return []
            out = []
            for bb in _function_blocks(s, fea):
                bva = s.va(bb.address)
                out.extend(self._row(ins, eq["func_addr"], bva) for ins in bb)
            return out
        out = []
        for bb in _all_code_blocks(s):
            owner = bb.function
            fva = s.va(owner.address) if owner is not None else None
            bva = s.va(bb.address)
            out.extend(self._row(ins, fva, bva) for ins in bb)
        return out


class LoopsTable(CachedSurface):
    name = "loops"
    skill = "disassembly"
    doc = "Strongly connected regions (loops) found by Malcat."
    columns = (
        Col("func_addr", "INT", pushdown=True),
        Col("start_addr", "INT"),
        Col("end_addr", "INT"),
        Col("size", "INT"),
    )
    scan_rows = 50_000

    def build(self) -> list[Row]:
        s = self.session
        out = []
        for lp in s.a.loops:
            fea = s.function_ea_at(lp.start)
            out.append((s.va(fea), s.va(lp.start), s.va(lp.end), lp.size))
        return numbered(out)


class SegmentsTable(CachedSurface):
    name = "segments"
    skill = "disassembly"
    doc = "Memory map regions (PE sections etc.)."
    columns = (
        Col("name", "TEXT", pushdown=True),
        Col("start_addr", "INT"),
        Col("end_addr", "INT"),
        Col("size", "INT"),
        Col("offset", "INT"),
        Col("phys_size", "INT"),
        Col("perm", "TEXT"),
        Col("is_rsrc", "INT"),
    )
    scan_rows = 50

    def build(self) -> list[Row]:
        out = []
        for r in self.session.a.map.regions:
            start = r.virt
            end = None if start is None else start + r.virt_size
            perm = ("r" if r.read else "-") + ("w" if r.write else "-") + ("x" if r.exec else "-")
            out.append((r.name, start, end, r.virt_size, r.phys, r.phys_size, perm, _b(r.rsrc)))
        return numbered(out)


# =============================================================================== symbols


class NamesTable(CachedSurface):
    name = "names"
    skill = "annotations"
    doc = "All symbols (function/import/export/entry/label/variable/typedef). Writable labels."
    columns = (
        Col("addr", "INT", pushdown=True),
        Col("name", "TEXT", pushdown=True),
        Col("type", "TEXT", pushdown=True),
        Col("ea", "INT"),
    )
    scan_rows = 50_000
    writable = frozenset({"insert", "update", "delete"})
    write_note = "INSERT/UPDATE set a user label, DELETE removes it; run is deferred to the next read"

    def build(self) -> list[Row]:
        s = self.session
        return [(sym.address, (s.va(sym.address), sym.name, _lower_enum(sym.type), sym.address)) for sym in s.a.syms]

    def insert(self, values: dict[str, Any]) -> int:
        ea = self.session.ea(values["addr"])
        if not values.get("name"):
            raise apsw.ConstraintError("names: INSERT needs a non-empty name")
        _set_label(self.session, ea, values["name"])
        return ea

    def update(self, rowid: int, values: dict[str, Any]) -> None:
        _set_label(self.session, rowid, values["name"])

    def delete(self, rowid: int) -> None:
        _set_label(self.session, rowid, None)


def _symbol_rows(s: Session, kinds: set[str]) -> list[Any]:
    return [sym for sym in s.a.syms if _enum_name(sym.type) in kinds]


class EntriesTable(CachedSurface):
    name = "entries"
    skill = "analysis"
    doc = "Entry points and exports."
    columns = (Col("addr", "INT", pushdown=True), Col("name", "TEXT"), Col("kind", "TEXT"))
    scan_rows = 1000

    def build(self) -> list[Row]:
        s = self.session
        rows = [
            (s.va(sym.address), sym.name, _lower_enum(sym.type))
            for sym in _symbol_rows(s, {"ENTRY", "EXPORT"})
        ]
        return numbered(rows)


class ImportsTable(CachedSurface):
    name = "imports"
    skill = "xrefs"
    doc = "Imported symbols; addr is the import slot (IAT entry)."
    columns = (
        Col("addr", "INT", pushdown=True),
        Col("module", "TEXT", pushdown=True),
        Col("name", "TEXT", pushdown=True),
        Col("qualified_name", "TEXT"),
        Col("ordinal", "INT"),
    )
    scan_rows = 2000

    def build(self) -> list[Row]:
        s = self.session
        rows = []
        for sym in _symbol_rows(s, {"IMPORT"}):
            module, _, func = sym.name.partition(".")
            if not func:
                module, func = "", sym.name
            ordinal = int(func[1:]) if func.startswith("#") and func[1:].isdigit() else None
            rows.append((s.va(sym.address), module, func, sym.name, ordinal))
        return numbered(rows)


# =============================================================================== references


class XrefsTable(Surface):
    name = "xrefs"
    skill = "xrefs"
    doc = "All references (code/data/struct/symbol); filter by to_addr or from_addr."
    columns = (
        Col("from_addr", "INT", pushdown=True),
        Col("to_addr", "INT", pushdown=True),
        Col("type", "TEXT"),
        Col("is_code", "INT"),
        Col("access", "TEXT"),
        Col("from_func", "INT"),
    )
    scan_rows = 1_000_000

    def _incoming(self, target_ea: int) -> list[tuple[Any, ...]]:
        s = self.session
        rl = s.a.xrefs.find(target_ea)
        if rl is None:
            return []
        to_va = s.va(target_ea)
        out = []
        for r in rl:
            access = ("r" if r.r else "") + ("w" if r.w else "") + ("x" if r.x else "")
            out.append(
                (
                    s.va(r.address),
                    to_va,
                    _lower_enum(r.type),
                    _b(r.is_code),
                    access or None,
                    s.va(s.function_ea_at(r.address)) if r.is_code else None,
                )
            )
        return out

    def _all(self) -> list[tuple[Any, ...]]:
        s = self.session

        def build() -> list[tuple[Any, ...]]:
            out: list[tuple[Any, ...]] = []
            ea, n = 0, 0
            while True:
                rl = s.a.xrefs.find_forward(ea)
                if rl is None:
                    break
                n += 1
                if n % 2048 == 0:
                    s.check_deadline()
                out.extend(self._incoming(rl.address))
                ea = rl.address + 1
            return out

        return s.cached((self.name, "all"), build)

    def rows(self, eq: dict[str, Any]) -> list[Row]:
        s = self.session
        if "to_addr" in eq:
            ea = s.try_ea(eq["to_addr"])
            rows = self._incoming(ea) if ea is not None else []
            if "from_addr" in eq:
                rows = [r for r in rows if r[0] == eq["from_addr"]]
            return numbered(rows)
        rows = self._all()
        if "from_addr" in eq:
            index = s.cached(
                (self.name, "by_from"),
                lambda: _group(self._all(), 0),
            )
            rows = index.get(eq["from_addr"], [])
        return numbered(rows)


def _group(rows: list[tuple[Any, ...]], pos: int) -> dict[Any, list[tuple[Any, ...]]]:
    out: dict[Any, list[tuple[Any, ...]]] = {}
    for r in rows:
        out.setdefault(r[pos], []).append(r)
    return out


class CallEdgesTable(CachedSurface):
    name = "call_edges"
    skill = "xrefs"
    doc = "Function call graph edges (Malcat callers/callees). Prefer the callers/callees views."
    columns = (Col("caller_addr", "INT", pushdown=True), Col("callee_addr", "INT", pushdown=True))
    scan_rows = 200_000

    def build(self) -> list[Row]:
        s = self.session
        rows = []
        for i, f in enumerate(s.a.fns):
            if i % 2048 == 0:
                s.check_deadline()
            caller = s.va(f.address)
            for c in f.callees:
                rows.append((caller, s.va(c.address)))
        return numbered(rows)


# =============================================================================== data


class StringsTable(CachedSurface):
    name = "strings"
    skill = "data"
    doc = "Strings found by Malcat (user/meta/dynamic stack strings/scanned)."
    columns = (
        Col("addr", "INT", pushdown=True),
        Col("text", "TEXT"),
        Col("size", "INT"),
        Col("characters", "INT"),
        Col("encoding", "TEXT"),
        Col("type", "TEXT", pushdown=True),
        Col("tag", "TEXT", pushdown=True),
        Col("score", "INT"),
        Col("category", "TEXT"),
        Col("num_xrefs", "INT"),
        Col("entropy", "REAL"),
        Col("offset", "INT"),
        Col("ea", "INT"),
    )
    scan_rows = 50_000

    def build(self) -> list[Row]:
        s = self.session
        out = []
        for i, st in enumerate(s.a.strings):
            if i % 4096 == 0:
                s.check_deadline()
            ea = st.address
            out.append(
                (
                    ea,
                    (
                        s.va(ea),
                        st.text,
                        st.size,
                        st.characters,
                        _lower_enum(st.encoding),
                        _lower_enum(st.type),
                        (st.tag or "").lower() or None,
                        st.score,
                        _lower_enum(st.category),
                        st.num_xrefs,
                        _safe(lambda: float(st.entropy)),
                        s.offset(ea),
                        ea,
                    ),
                )
            )
        return out


class CommentsTable(CachedSurface):
    name = "comments"
    skill = "annotations"
    doc = "User comments. INSERT/UPDATE/DELETE write through to Malcat."
    columns = (Col("addr", "INT", pushdown=True), Col("text", "TEXT"), Col("ea", "INT"))
    scan_rows = 1000
    writable = frozenset({"insert", "update", "delete"})
    write_note = "persisted by SELECT save()"

    def build(self) -> list[Row]:
        s = self.session
        return [(c.address, (s.va(c.address), c.text, c.address)) for c in s.a.comments]

    def insert(self, values: dict[str, Any]) -> int:
        ea = self.session.ea(values["addr"])
        self._write(ea, values.get("text"))
        return ea

    def update(self, rowid: int, values: dict[str, Any]) -> None:
        self._write(rowid, values.get("text"))

    def delete(self, rowid: int) -> None:
        self._write(rowid, None)

    def _write(self, ea: int, text: Optional[str]) -> None:
        s = self.session
        if text:
            s.a.comments[ea] = str(text)
        else:
            s.a.comments.remove(ea)
        s.touch()


class ByteSearchTable(Surface):
    name = "byte_search"
    skill = "data"
    doc = "Yara-style byte pattern search: FROM byte_search('48 8B ?? 24') or WHERE pattern = ..."
    columns = (
        Col("addr", "INT"),
        Col("offset", "INT"),
        Col("size", "INT"),
        Col("matched_hex", "TEXT"),
        Col("pattern", "TEXT", pushdown=True, hidden=True, required=True),
        Col("start_addr", "INT", pushdown=True, hidden=True),
        Col("end_addr", "INT", pushdown=True, hidden=True),
        Col("max_results", "INT", pushdown=True, hidden=True),
    )
    scan_rows = 1000

    def __init__(self, session: Session, engine: Engine) -> None:
        super().__init__(session)
        self.engine = engine

    def rows(self, eq: dict[str, Any]) -> list[Row]:
        s = self.session
        f = s.a.file
        limit = eq.get("max_results") or self.engine.settings.get_int("byte_search_max_results")
        start = 0
        stop = f.size
        if eq.get("start_addr") is not None:
            start = s.offset(s.ea(eq["start_addr"])) or 0
        if eq.get("end_addr") is not None:
            stop = s.offset(s.ea(eq["end_addr"])) or f.size
        out: list[tuple[Any, ...]] = []
        off = start
        while off < stop and len(out) < limit:
            s.check_deadline()
            hit, size = f.search_bytes(str(eq["pattern"]), off, stop - off)
            if hit is None:
                break
            ea = s.ea_from_offset(hit)
            out.append((s.va(ea), hit, size, f.read(hit, size).hex().upper()))
            off = hit + max(size, 1)
        return numbered(out)


class StructuresTable(CachedSurface):
    name = "structures"
    skill = "data"
    doc = "Top-level file structures parsed by Malcat (headers, directories, resources...)."
    columns = (
        Col("name", "TEXT", pushdown=True),
        Col("category", "TEXT", pushdown=True),
        Col("addr", "INT"),
        Col("offset", "INT"),
        Col("size", "INT"),
        Col("ea", "INT"),
    )
    scan_rows = 5000

    def build(self) -> list[Row]:
        s = self.session
        rows = [
            (st.name, _lower_enum(st.type), s.va(st.address), s.offset(st.address), st.size, st.address)
            for st in s.a.struct
        ]
        return numbered(rows)


class CarvedTable(CachedSurface):
    name = "carved"
    skill = "data"
    doc = "Embedded files carved by Malcat."
    columns = (
        Col("name", "TEXT"),
        Col("type", "TEXT", pushdown=True),
        Col("category", "TEXT"),
        Col("addr", "INT"),
        Col("offset", "INT"),
        Col("size", "INT"),
        Col("ea", "INT"),
    )
    scan_rows = 500

    def build(self) -> list[Row]:
        s = self.session
        rows = [
            (c.name, c.type, _lower_enum(c.category), s.va(c.address), s.offset(c.address), c.size, c.address)
            for c in s.a.carved
        ]
        return numbered(rows)


class VfilesTable(CachedSurface):
    name = "vfiles"
    skill = "data"
    doc = "Virtual files (archive members, resources, overlays) Malcat can open."
    columns = (
        Col("path", "TEXT", pushdown=True),
        Col("type", "TEXT"),
        Col("filetype", "TEXT"),
        Col("size", "INT"),
        Col("unpack_method", "TEXT"),
    )
    scan_rows = 500

    def build(self) -> list[Row]:
        rows = [
            (v.path, v.type or None, v.filetype or None, v.size, v.unpack_method or None)
            for v in self.session.a.vfiles
        ]
        return numbered(rows)


class MetadataTable(CachedSurface):
    name = "metadata"
    skill = "analysis"
    doc = "Parsed metadata (version info, debug info, compile date...)."
    columns = (Col("category", "TEXT", pushdown=True), Col("key", "TEXT", pushdown=True), Col("value", "TEXT"))
    scan_rows = 200

    def build(self) -> list[Row]:
        rows = []
        for category, items in self.session.a.metadata or []:
            for key, value in items:
                rows.append((category or "", key, None if value is None else str(value)))
        return numbered(rows)


# =============================================================================== detections


class ConstantsTable(CachedSurface):
    name = "constants"
    skill = "detections"
    doc = "Known constants (crypto tables, hashes, magic values) in code or data."
    columns = (
        Col("addr", "INT", pushdown=True),
        Col("name", "TEXT", pushdown=True),
        Col("category", "TEXT", pushdown=True),
        Col("size", "INT"),
        Col("is_code", "INT"),
        Col("func_addr", "INT", pushdown=True),
    )
    scan_rows = 2000

    def build(self) -> list[Row]:
        s = self.session
        rows = []
        for c in s.a.constants:
            fea = s.function_ea_at(c.address) if c.is_code else None
            rows.append((s.va(c.address), c.name, c.category, c.size, _b(c.is_code), s.va(fea)))
        return numbered(rows)


class SignaturesTable(CachedSurface):
    name = "signatures"
    skill = "detections"
    doc = "Matching Yara rules (Malcat's signature set)."
    columns = (
        Col("id", "TEXT", pushdown=True),
        Col("name", "TEXT"),
        Col("type", "TEXT", pushdown=True),
        Col("category", "TEXT"),
        Col("reliability", "INT"),
        Col("description", "TEXT"),
        Col("tags", "TEXT"),
        Col("num_patterns", "INT"),
    )
    scan_rows = 200

    def build(self) -> list[Row]:
        rows = [
            (
                m.id,
                m.name,
                _lower_enum(m.type),
                m.category,
                m.reliability,
                m.description,
                ",".join(m.tags or []) or None,
                len(list(m.patterns)),
            )
            for m in self.session.a.sigs
        ]
        return numbered(rows)


class SignatureHitsTable(CachedSurface):
    name = "signature_hits"
    skill = "detections"
    doc = "Where each Yara rule's string/byte patterns matched."
    columns = (
        Col("rule_id", "TEXT", pushdown=True),
        Col("pattern", "TEXT"),
        Col("addr", "INT"),
        Col("offset", "INT"),
        Col("size", "INT"),
        Col("func_addr", "INT", pushdown=True),
    )
    scan_rows = 2000

    def build(self) -> list[Row]:
        s = self.session
        rows = []
        for m in s.a.sigs:
            for p in m.patterns:
                for off, size in p.matches:
                    ea = s.ea_from_offset(off)
                    fea = s.function_ea_at(ea) if ea is not None else None
                    rows.append((m.id, p.id, s.va(ea), off, size, s.va(fea)))
        return numbered(rows)


class AnomaliesTable(CachedSurface):
    name = "anomalies"
    skill = "detections"
    doc = "Anomalies/oddities, one row per location (addr NULL when the anomaly has none)."
    columns = (
        Col("name", "TEXT", pushdown=True),
        Col("category", "TEXT", pushdown=True),
        Col("level", "TEXT", pushdown=True),
        Col("label", "TEXT"),
        Col("comment", "TEXT"),
        Col("addr", "INT"),
        Col("size", "INT"),
    )
    scan_rows = 500

    def build(self) -> list[Row]:
        s = self.session
        rows = []
        for an in s.a.anomalies:
            base = (an.name, an.category, _lower_enum(an.level), an.label, an.comment)
            locations = list(an.locations)
            if not locations:
                rows.append(base + (None, None))
            for ea, size in locations:
                rows.append(base + (s.va(ea), size))
        return numbered(rows)


def _capa(s: Session) -> list[tuple[tuple[Any, ...], list[tuple[Any, ...]]]]:
    """Run capa once per session (rule matches don't depend on user labels)."""

    def build() -> list[tuple[tuple[Any, ...], list[tuple[Any, ...]]]]:
        out = []
        for rule in s.a.capa_run():
            if not rule.matching:
                continue
            matches = [(m.address, getattr(m, "scope", None)) for m in rule.matches]
            info = (
                rule.name,
                rule.namespace,
                rule.scope,
                json.dumps([a.value for a in rule.attack]),
                json.dumps([m.value for m in rule.mbc]),
                rule.description,
                len(matches),
            )
            out.append((info, matches))
        return out

    return s.sticky("capa", build)


class CapaTable(Surface):
    name = "capa"
    skill = "detections"
    doc = "Matching capa rules (computed on first query; can take a while on big files)."
    columns = (
        Col("rule", "TEXT", pushdown=True),
        Col("namespace", "TEXT"),
        Col("scope", "TEXT"),
        Col("attack", "TEXT", doc="JSON array"),
        Col("mbc", "TEXT", doc="JSON array"),
        Col("description", "TEXT"),
        Col("num_matches", "INT"),
    )
    scan_rows = 300

    def rows(self, eq: dict[str, Any]) -> list[Row]:
        rows = [info for info, _ in _capa(self.session)]
        if "rule" in eq:
            rows = [r for r in rows if r[0] == eq["rule"]]
        return numbered(rows)


class CapaMatchesTable(Surface):
    name = "capa_matches"
    skill = "detections"
    doc = "Addresses where each capa rule matched."
    columns = (
        Col("rule", "TEXT", pushdown=True),
        Col("addr", "INT"),
        Col("scope", "TEXT"),
        Col("func_addr", "INT", pushdown=True),
    )
    scan_rows = 3000

    def rows(self, eq: dict[str, Any]) -> list[Row]:
        s = self.session
        rows = []
        for info, matches in _capa(s):
            if "rule" in eq and info[0] != eq["rule"]:
                continue
            for ea, scope in matches:
                fea = s.function_ea_at(ea) if ea is not None else None
                row = (info[0], s.va(ea), _enum_name(scope) if scope is not None else None, s.va(fea))
                if "func_addr" in eq and row[3] != eq["func_addr"]:
                    continue
                rows.append(row)
        return numbered(rows)


# =============================================================================== decompiler


class PseudocodeTable(Surface):
    name = "pseudocode"
    skill = "decompiler"
    doc = "Decompiled text split into lines; REQUIRES func_addr = X (about 3 s per function)."
    columns = (
        Col("func_addr", "INT", pushdown=True),
        Col("line", "INT"),
        Col("text", "TEXT"),
    )
    scan_rows = 10_000_000
    scan_error = (
        "pseudocode requires a func_addr constraint (each function takes seconds to decompile): "
        "SELECT * FROM pseudocode WHERE func_addr = 0x..."
    )

    def rows(self, eq: dict[str, Any]) -> list[Row]:
        s = self.session
        fea = _func_filter_ea(s, eq)
        if fea is None:
            return []
        text = s.decompile(fea)
        return numbered([(eq["func_addr"], i, line) for i, line in enumerate(text.splitlines(), 1)])


class DecompileAliasesTable(Surface):
    name = "decompile_aliases"
    skill = "decompiler"
    doc = "Per-function variable renames shown in decompiled output. Writable."
    columns = (
        Col("func_addr", "INT", pushdown=True),
        Col("old_name", "TEXT"),
        Col("new_name", "TEXT"),
    )
    scan_rows = 100_000
    writable = frozenset({"insert", "update", "delete"})
    write_note = "persisted by SELECT save(); malcatsql applies aliases to decompile() output itself"

    def _aliases(self, fea: int) -> dict[str, str]:
        return dict(self.session.a.fns.find(fea).get_decompile_aliases() or {})

    def rows(self, eq: dict[str, Any]) -> list[Row]:
        s = self.session
        if "func_addr" in eq:
            fea = _func_filter_ea(s, eq)
            feas = [] if fea is None else [fea]
        else:
            feas = [f.address for f in s.a.fns]
        out: list[Row] = []
        rowids: dict[int, tuple[int, str]] = {}
        for fea in feas:
            fva = s.va(fea)
            for old, new in sorted(self._aliases(fea).items()):
                rowid = _alias_rowid(fea, old)
                rowids[rowid] = (fea, old)
                out.append((rowid, (fva, old, new)))
        self._rowids = rowids
        return out

    def _apply(self, fea: int, mapping: dict[str, str]) -> None:
        s = self.session
        s.a.fns.find(fea).set_decompile_aliases(mapping)
        s.touch()

    def insert(self, values: dict[str, Any]) -> int:
        s = self.session
        fea = s.function_start_ea(values["func_addr"])
        old, new = values.get("old_name"), values.get("new_name")
        if not old or not new:
            raise apsw.ConstraintError("decompile_aliases: old_name and new_name are required")
        self._validate(fea, str(old), str(new))
        mapping = self._aliases(fea)
        mapping[str(old)] = str(new)
        self._apply(fea, mapping)
        return _alias_rowid(fea, str(old))

    def update(self, rowid: int, values: dict[str, Any]) -> None:
        fea, old = self._lookup(rowid)
        if values.get("old_name") != old:
            raise apsw.ConstraintError("decompile_aliases: only new_name is writable")
        self._validate(fea, old, str(values["new_name"]))
        mapping = self._aliases(fea)
        mapping[old] = str(values["new_name"])
        self._apply(fea, mapping)

    def _validate(self, fea: int, old: str, new: str) -> None:
        """A rename is a claim about the code. If the premise is false the write must fail loudly
        (a variable that is not there means the analyst's reading of the function is wrong)."""
        if not _IDENTIFIER.match(new):
            raise apsw.ConstraintError(f"decompile_aliases: {new!r} is not a valid identifier")
        raw = self.session.decompile_raw(fea)
        words = set(re.findall(r"[A-Za-z_]\w*", raw))
        if old not in words:
            raise apsw.ConstraintError(
                f"decompile_aliases: {old!r} does not occur in the decompiled code of "
                f"0x{self.session.va(fea):X}; rename only names you saw in decompile()/pseudocode"
            )
        if new != old and new in words:
            raise apsw.ConstraintError(
                f"decompile_aliases: {new!r} already exists in 0x{self.session.va(fea):X}; "
                "renaming onto an existing name would merge two different variables"
            )

    def delete(self, rowid: int) -> None:
        fea, old = self._lookup(rowid)
        mapping = self._aliases(fea)
        mapping.pop(old, None)
        self._apply(fea, mapping)

    def _lookup(self, rowid: int) -> tuple[int, str]:
        try:
            return self._rowids[rowid]
        except (AttributeError, KeyError):
            raise apsw.ConstraintError("decompile_aliases: row not found (re-select it first)") from None


def _alias_rowid(fea: int, old: str) -> int:
    # stable 63-bit id from (function, variable) so UPDATE/DELETE can find the row again
    return (hash((fea, old)) & 0x3FFF_FFFF_FFFF_FFFF) or 1


# =============================================================================== registry

SURFACES: tuple[type[Surface], ...] = (
    BinaryTable,
    CapabilitiesTable,
    RuntimeSettingsTable,
    FuncsTable,
    FuncHashesTable,
    SegmentsTable,
    BlocksTable,
    CfgEdgesTable,
    InstructionsTable,
    LoopsTable,
    NamesTable,
    EntriesTable,
    ImportsTable,
    XrefsTable,
    CallEdgesTable,
    StringsTable,
    CommentsTable,
    ByteSearchTable,
    StructuresTable,
    CarvedTable,
    VfilesTable,
    MetadataTable,
    ConstantsTable,
    SignaturesTable,
    SignatureHitsTable,
    AnomaliesTable,
    CapaTable,
    CapaMatchesTable,
    PseudocodeTable,
    DecompileAliasesTable,
)

#: surfaces whose constructor also needs the engine (settings / registry access)
NEEDS_ENGINE = {CapabilitiesTable, RuntimeSettingsTable, ByteSearchTable}

VIEWS: dict[str, str] = {
    "callers": """
        SELECT e.callee_addr AS func_addr, e.caller_addr, f.name AS caller_name
        FROM call_edges e LEFT JOIN funcs f ON f.addr = e.caller_addr""",
    "callees": """
        SELECT e.caller_addr AS func_addr, e.callee_addr, f.name AS callee_name
        FROM call_edges e LEFT JOIN funcs f ON f.addr = e.callee_addr""",
    "string_refs": """
        SELECT s.addr AS string_addr, s.text, s.type AS string_type, x.from_addr,
               x.from_func AS func_addr, f.name AS func_name
        FROM strings s JOIN xrefs x ON x.to_addr = s.addr
        LEFT JOIN funcs f ON f.addr = x.from_func
        WHERE s.addr IS NOT NULL""",
    "import_refs": """
        SELECT i.addr AS import_addr, i.module, i.name, i.qualified_name, x.from_addr,
               x.from_func AS func_addr, f.name AS func_name
        FROM imports i JOIN xrefs x ON x.to_addr = i.addr
        LEFT JOIN funcs f ON f.addr = x.from_func""",
    "entities": """
        SELECT name, 'function' AS kind, addr, '' AS parent_name, name AS qualified_name,
               'funcs' AS source FROM funcs
        UNION ALL SELECT name, 'symbol', addr, '', name, 'names' FROM names
            WHERE type NOT IN ('function', 'import')
        UNION ALL SELECT name, 'segment', start_addr, '', name, 'segments' FROM segments
        UNION ALL SELECT name, 'import', addr, module, qualified_name, 'imports' FROM imports
        UNION ALL SELECT substr(text, 1, 256), 'string', addr, '', substr(text, 1, 256), 'strings'
            FROM strings""",
}
