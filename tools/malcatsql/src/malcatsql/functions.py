"""Scalar SQL functions. Address arguments are virtual addresses (int, or '0x..' text)."""

from __future__ import annotations

import contextlib
import io
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Optional

import apsw

if TYPE_CHECKING:
    from .engine import Engine

#: name -> (arities like "1/2", one-line doc); the source of truth for the `functions` skill
CATALOG: dict[str, tuple[str, str]] = {}
_ARITIES: dict[str, set[int]] = {}
#: functions whose first argument may legitimately be NULL (everything else maps NULL -> NULL)
NULL_ACCEPTING = {"save", "hex"}

#: decompiler bookkeeping that drowns big functions: `*(&uStack_20 + iVar9) = 0x14010bea4;` stores
#: of return addresses into an alloca'd frame, and pure local declarations
NOISE_LINE = re.compile(r"^\s*\*\(&uStack_\w+ \+ \w+\) = 0x[0-9a-fA-F]+;\s*$")
DECL_LINE = re.compile(
    r"^\s+(?:u?int\d*_t|undefined\d*|char|code|bool|float|double|int|long|void)\s*\**\s*\w+;\s*$"
)


def hex_override(x: Any) -> Optional[str]:
    """SQL ``hex()``: integers -> ``0x1400019C0``; blobs/text keep SQLite semantics (uppercase hex)."""
    if x is None:
        return None
    if isinstance(x, int):
        return ("-0x%X" % -x) if x < 0 else ("0x%X" % x)
    if isinstance(x, str):
        x = x.encode("utf-8")
    if isinstance(x, float):
        x = repr(x).encode()
    return bytes(x).hex().upper()


def hamming_bits(a: Any, b: Any) -> Optional[int]:
    """Differing bits of two equal-length byte strings (blobs, or hex text as collect() returns)."""
    x = bytes.fromhex(a) if isinstance(a, str) else bytes(a)
    y = bytes.fromhex(b) if isinstance(b, str) else bytes(b)
    if len(x) != len(y):
        return None
    return (int.from_bytes(x, "big") ^ int.from_bytes(y, "big")).bit_count()


def register_hex_and_hamming(conn: apsw.Connection) -> None:
    """The two pure helpers the multi-sample workspace connection shares with every sample."""
    conn.create_scalar_function("hex", hex_override, 1, deterministic=True)
    conn.create_scalar_function("hamming", hamming_bits, 2, deterministic=True)


def register_functions(engine: Engine) -> None:
    s = engine.session
    conn = engine.conn

    def fn(name: str, arity: int, doc: str, deterministic: bool = False) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def deco(f: Callable[..., Any]) -> Callable[..., Any]:
            impl = f
            if arity >= 1 and name not in NULL_ACCEPTING:
                # SQL semantics: NULL first argument (e.g. an unmapped addr column) -> NULL result
                def impl(*args: Any, _f: Callable[..., Any] = f) -> Any:
                    return None if args[0] is None else _f(*args)

            conn.create_scalar_function(name, impl, arity, deterministic=deterministic)
            _ARITIES.setdefault(name, set()).add(arity)
            arities = "/".join(str(n) for n in sorted(_ARITIES[name]))
            CATALOG[name] = (arities, doc or CATALOG.get(name, ("", ""))[1])
            return f

        return deco

    # ------------------------------------------------------------------ formatting / addresses

    fn("hex", 1, "hex(x): integers -> '0x1400019C0'; blobs/text keep SQLite semantics", True)(hex_override)

    @fn("ea2va", 1, "ea2va(ea): Malcat effective address -> virtual address")
    def _ea2va(ea: Any) -> Optional[int]:
        return s.va(ea)

    @fn("va2ea", 1, "va2ea(addr): virtual address -> Malcat effective address")
    def _va2ea(addr: Any) -> Optional[int]:
        return s.try_ea(addr)

    @fn("va2off", 1, "va2off(addr): virtual address -> file offset (NULL if not backed by file bytes)")
    def _va2off(addr: Any) -> Optional[int]:
        return s.offset(s.try_ea(addr))

    @fn("off2va", 1, "off2va(offset): file offset -> virtual address")
    def _off2va(off: int) -> Optional[int]:
        return s.va(s.ea_from_offset(off))

    @fn("rva", 1, "rva(addr): virtual address -> RVA")
    def _rva(addr: Any) -> Optional[int]:
        ea = s.try_ea(addr)
        return None if ea is None else s.a.a2r(ea)

    # ------------------------------------------------------------------ functions & names

    def _fn_at(addr: Any) -> Any:
        s.ensure_fresh()
        ea = s.try_ea(addr)
        return None if ea is None else s.a.fns.find(ea)

    @fn("func_start", 1, "func_start(addr): start address of the function containing addr")
    def _func_start(addr: Any) -> Optional[int]:
        f = _fn_at(addr)
        return None if f is None else s.va(f.address)

    @fn("func_end", 1, "func_end(addr): end address of the function containing addr")
    def _func_end(addr: Any) -> Optional[int]:
        f = _fn_at(addr)
        return None if f is None else s.va(f.end)

    @fn("func_at", 1, "func_at(addr): name of the function containing addr")
    def _func_at(addr: Any) -> Optional[str]:
        f = _fn_at(addr)
        return None if f is None else f.name

    @fn("name_at", 1, "name_at(addr): symbol/label at exactly addr (NULL if none)")
    def _name_at(addr: Any) -> Optional[str]:
        s.ensure_fresh()
        ea = s.try_ea(addr)
        if ea is None:
            return None
        f = s.a.fns.find(ea)
        if f is not None and f.address == ea:
            return f.name
        for sym in s.a.syms:
            if sym.address == ea:
                return sym.name
        return None

    @fn("set_name", 2, "set_name(addr, name): set a user label ('' or NULL removes it); returns 1")
    def _set_name(addr: Any, name: Optional[str]) -> int:
        ea = s.ea(addr)
        if name:
            if not s.a.syms.set_label(ea, str(name)):
                raise apsw.ConstraintError(f"malcat refused label {name!r}")
        else:
            s.a.syms.unset_label(ea)
        s.mark_dirty()
        return 1

    @fn("set_comment", 2, "set_comment(addr, text): set a user comment ('' or NULL removes it); returns 1")
    def _set_comment(addr: Any, text: Optional[str]) -> int:
        ea = s.ea(addr)
        if text:
            s.a.comments[ea] = str(text)
        else:
            s.a.comments.remove(ea)
        s.touch()
        return 1

    # ------------------------------------------------------------------ code text

    @fn("disasm", 1, "disasm(addr): one instruction as text")
    def _disasm(addr: Any) -> Optional[str]:
        s.ensure_fresh()
        ea = s.try_ea(addr)
        ins = None if ea is None else s.a.asm[ea]
        return None if ins is None else ins.disasm()

    @fn("disasm_func", 1, "disasm_func(addr): full listing of the function starting at addr")
    def _disasm_func(addr: Any) -> str:
        s.ensure_fresh()
        return s.a.fns.find(s.function_start_ea(addr)).disasm()

    def _decompile(addr: Any, refresh: Any = 0) -> str:
        s.ensure_fresh()
        return s.decompile(s.function_start_ea(addr), bool(refresh))

    fn("decompile", 1, "decompile(addr[, refresh]): pseudo-C of the function starting at addr (cached)")(
        lambda addr: _decompile(addr)
    )
    fn("decompile", 2, "")(_decompile)

    # ------------------------------------------------------------------ bytes

    @fn("bytes", 2, "bytes(addr, n): n raw bytes at addr as a blob (use hex() to print)")
    def _bytes(addr: Any, n: int) -> Optional[bytes]:
        off = s.offset(s.ea(addr))
        return None if off is None else s.a.file.read(off, int(n))

    def _read_string(addr: Any, encoding: str = "ascii", max_bytes: int = 512) -> Optional[str]:
        off = s.offset(s.ea(addr))
        if off is None:
            return None
        readers = {
            "ascii": s.a.file.read_cstring_ascii,
            "utf8": s.a.file.read_cstring_utf8,
            "utf16le": s.a.file.read_cstring_utf16le,
            "utf16be": s.a.file.read_cstring_utf16be,
        }
        reader = readers.get(str(encoding).lower().replace("-", ""))
        if reader is None:
            raise apsw.ConstraintError(f"read_string: encoding must be one of {sorted(readers)}")
        return reader(off, int(max_bytes))

    fn("read_string", 1, "read_string(addr[, encoding[, max_bytes]]): C string at addr")(
        lambda addr: _read_string(addr)
    )
    fn("read_string", 2, "")(lambda addr, enc: _read_string(addr, enc))
    fn("read_string", 3, "")(_read_string)

    @fn("search_first", 1, "search_first(pattern): VA of the first byte_search match (or NULL)")
    def _search_first(pattern: str) -> Optional[int]:
        hit, _ = s.a.file.search_bytes(str(pattern), 0, 0)
        return None if hit is None else s.va(s.ea_from_offset(hit))

    # ------------------------------------------------------------------ token-saving helpers
    # A full decompile of a big function is tens of KB of mostly noise. These return only what a
    # question needs: a structured profile, grep with context, a line window, a compact listing.

    def _decompiled_lines(addr: Any) -> list[str]:
        s.ensure_fresh()
        return s.decompile(s.function_start_ea(addr)).splitlines()

    def _numbered(lines: list[str], indices: list[int]) -> str:
        out: list[str] = []
        last = -2
        for i in indices:
            if i != last + 1 and out:
                out.append("   ...")
            out.append(f"{i + 1:5d}| {lines[i]}")
            last = i
        return "\n".join(out)

    @fn("func_profile", 1, "func_profile(addr[, limit]): JSON summary of one function: size/stats, callers, callees, imports, strings, constants, loops")
    def _func_profile(addr: Any, limit: int = 40) -> str:
        s.ensure_fresh()
        ea = s.function_start_ea(addr)
        f = s.a.fns.find(ea)
        limit = max(1, min(int(limit), 500))
        import_type = s.malcat.Symbol.Type.IMPORT
        imports = s.cached(
            ("profile", "imports"),
            lambda: {sym.address: sym.name for sym in s.a.syms if sym.type == import_type},
        )
        strings: dict[int, str] = {}
        used_imports: list[str] = []
        for ref in f.outrefs:
            st = s.a.strings.find(ref.address)
            if st is not None and st.address not in strings:
                strings[st.address] = st.text.replace("\r", "\\r").replace("\n", "\\n")[:100]
            name = imports.get(ref.address)
            if name is not None and name not in used_imports:
                used_imports.append(name)
        callees = [(s.va(c.address), c.name) for c in f.callees]
        callers = [(s.va(c.address), c.name) for c in f.callers]
        consts = [
            {"addr": s.va(c.address), "name": c.name, "category": c.category}
            for c in s.a.constants
            if f.start <= c.address < f.end
        ]
        loops = sum(1 for lp in s.a.loops if f.start <= lp.start < f.end)
        profile = {
            "addr": s.va(f.address),
            "name": f.name,
            "size": f.size,
            "category": _enum_name_lower(f.category),
            "basic_blocks": f.num_bb_code,
            "instructions": f.num_instructions,
            "loops": loops,
            "api_calls": f.num_api_calls,
            "xor_ops": f.num_xor_ops,
            "known_constant_uses": f.num_known_constants_uses,
            "dynamic_jumps": f.num_dynamic_jumps,
            "callers": {"total": len(callers), "items": callers[:limit]},
            "callees": {"total": len(callees), "items": callees[:limit]},
            "imports": {"total": len(used_imports), "items": used_imports[:limit]},
            "strings": {"total": len(strings), "items": [[s.va(a), t] for a, t in list(strings.items())[:limit]]},
            "constants": {"total": len(consts), "items": consts[:limit]},
        }
        return json.dumps(profile, ensure_ascii=False, separators=(",", ":"))

    fn("func_profile", 2, "")(_func_profile)

    def _enum_name_lower(value: Any) -> Optional[str]:
        name = getattr(value, "name", None)
        return None if name is None else name.lower()

    @fn("pseudocode_grep", 2, "pseudocode_grep(addr, regex[, context[, max_matches]]): matching lines of a function's pseudo-C with line numbers and context (case-insensitive)")
    def _pseudocode_grep(addr: Any, pattern: str, context: int = 2, max_matches: int = 40) -> str:
        try:
            rx = re.compile(str(pattern), re.IGNORECASE)
        except re.error as exc:
            raise apsw.ConstraintError(f"pseudocode_grep: bad regex {pattern!r}: {exc}") from None
        lines = _decompiled_lines(addr)
        hits = [i for i, text in enumerate(lines) if not NOISE_LINE.match(text) and rx.search(text)]
        shown = hits[: max(1, int(max_matches))]
        context = max(0, min(int(context), 20))
        wanted: set[int] = set()
        for i in shown:
            wanted.update(range(max(0, i - context), min(len(lines), i + context + 1)))
        body = _numbered(lines, sorted(j for j in wanted if not NOISE_LINE.match(lines[j])))
        return f"{body}\n-- {len(shown)} of {len(hits)} matching lines ({len(lines)} total)" if hits else f"-- no match ({len(lines)} lines)"

    fn("pseudocode_grep", 3, "")(lambda a, p, c: _pseudocode_grep(a, p, c))
    fn("pseudocode_grep", 4, "")(_pseudocode_grep)

    @fn("decompile_lines", 3, "decompile_lines(addr, start, count): a window of the pseudo-C (original 1-based line numbers, stack-bookkeeping noise dropped)")
    def _decompile_lines(addr: Any, start: int, count: int) -> str:
        lines = _decompiled_lines(addr)
        first = max(0, int(start) - 1)
        window = [i for i in range(first, min(len(lines), first + max(1, int(count)))) if not NOISE_LINE.match(lines[i])]
        return _numbered(lines, window) + f"\n-- lines {first + 1}..{first + int(count)} of {len(lines)}"

    @fn("decompile_compact", 1, "decompile_compact(addr): numbered pseudo-C without stack-return-address noise, local declarations and blank lines")
    def _decompile_compact(addr: Any) -> str:
        lines = _decompiled_lines(addr)
        keep = [i for i, text in enumerate(lines) if text.strip() and not NOISE_LINE.match(text) and not DECL_LINE.match(text)]
        return _numbered(lines, keep) + f"\n-- {len(keep)} of {len(lines)} lines kept"

    def _xor(data: Any, key: Any, skip: Any = None) -> bytes:
        raw = data.encode("latin-1", "replace") if isinstance(data, str) else bytes(data)
        if isinstance(key, int):
            keys = bytes([key & 0xFF])
        else:
            keys = key.encode("latin-1", "replace") if isinstance(key, str) else bytes(key)
        if not keys:
            raise apsw.ConstraintError("xor: empty key")
        keep = set(bytes(skip)) if isinstance(skip, (bytes, bytearray, memoryview)) else set()
        return bytes(b if b in keep else b ^ keys[i % len(keys)] for i, b in enumerate(raw))

    fn("hamming", 2, "hamming(a, b): differing bits of two equal-length blobs or hex strings (NULL if lengths differ); use on func_hashes.fuzzy_hash", True)(hamming_bits)

    @fn("xor_bytes", 2,"xor_bytes(data, key[, skip]): XOR a blob/text with an int or repeating key; bytes listed in skip (blob) are left unchanged. Returns a blob")
    def _xor_bytes(data: Any, key: Any, skip: Any = None) -> bytes:
        return _xor(data, key, skip)

    fn("xor_bytes", 3, "")(_xor_bytes)

    @fn("read_xor_string", 3, "read_xor_string(addr, n, key[, skip]): n bytes at addr XOR-decoded (text, undecodable bytes shown as ?)")
    def _read_xor_string(addr: Any, n: int, key: Any, skip: Any = None) -> Optional[str]:
        off = s.offset(s.ea(addr))
        if off is None:
            return None
        return _xor(s.a.file.read(off, int(n)), key, skip).decode("utf-8", "replace")

    fn("read_xor_string", 4, "")(_read_xor_string)

    # ------------------------------------------------------------------ discovery

    def _entities_search(pattern: str, limit: int = 50, offset: int = 0) -> str:
        limit = max(1, min(int(limit), 500))
        needle = f"%{pattern}%"
        rows = conn.execute(
            "SELECT name, kind, addr, parent_name, qualified_name, source FROM entities "
            "WHERE name LIKE ?1 OR parent_name LIKE ?1 OR qualified_name LIKE ?1 "
            "LIMIT ?2 OFFSET ?3",
            (needle, limit, int(offset)),
        )
        keys = ("name", "kind", "addr", "parent_name", "qualified_name", "source")
        return json.dumps([dict(zip(keys, r)) for r in rows])

    fn("entities_search", 1, "entities_search(pattern[, limit[, offset]]): JSON array of matching entities")(
        lambda p: _entities_search(p)
    )
    fn("entities_search", 2, "")(lambda p, n: _entities_search(p, n))
    fn("entities_search", 3, "")(_entities_search)

    # ------------------------------------------------------------------ session

    def _save(path: Optional[str] = None) -> str:
        return s.save(path)

    fn("save", 0, "save([path]): write annotations to the .malcat project; returns its path")(lambda: _save())
    fn("save", 1, "")(_save)

    @fn("refresh", 0, "refresh(): force Malcat's deferred re-analysis now; returns 1")
    def _refresh() -> int:
        s.rerun()
        return 1

    # ------------------------------------------------------------------ python

    def _python(code: str, origin: str) -> str:
        if not engine.settings.get_bool("enable_python"):
            raise apsw.AuthError(
                "python is disabled: UPDATE runtime_settings SET value='1' WHERE key='enable_python'"
            )
        s.ensure_fresh()
        buf = io.StringIO()
        namespace: dict[str, Any] = {
            "malcat": s.malcat,
            "analysis": s.a,
            "a": s.a,
            "session": s,
            "va": s.va,
            "ea": s.ea,
            "sql": lambda q, *args: list(conn.execute(q, args)),
            "__name__": "__malcatsql__",
        }
        with contextlib.redirect_stdout(buf):
            exec(compile(code, origin, "exec"), namespace)
        # user code may have relabeled/commented anything: refresh before the next read
        s.mark_dirty()
        out = buf.getvalue()
        cap = engine.settings.get_int("python_output_max")
        if cap and len(out) > cap:
            out = out[:cap] + f"\n... [truncated {len(out) - cap} chars]"
        return out

    @fn("malcat_python", 1, "malcat_python(code): exec Python with `analysis`/`malcat` bound; returns stdout")
    def _malcat_python(code: str) -> str:
        return _python(str(code), "<malcat_python>")

    @fn("malcat_python_file", 1, "malcat_python_file(path): like malcat_python() for a .py file")
    def _malcat_python_file(path: str) -> str:
        p = Path(str(path)).expanduser()
        return _python(p.read_text(encoding="utf-8"), str(p))
