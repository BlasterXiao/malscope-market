"""Owns one malcat analysis and the invariants every SQL surface relies on.

Invariants (learned the hard way, see README "Engine notes"):

* Malcat objects (Function, BasicBlock, Instruction, Reference, ...) are only valid until the next
  ``Analysis.run()`` / ``Analysis.load()``. Reusing one afterwards returns silently wrong data or
  crashes the process. Surfaces therefore copy plain ints/strs out of malcat inside ``Filter`` and
  never keep malcat objects around; everything cached here is plain Python data keyed by ``gen``.
* Label edits only become visible after ``run()``, which costs ~1.5 s on a large DLL no matter how
  many labels changed. Writes only call :meth:`mark_dirty`; the single ``run()`` happens lazily in
  :meth:`ensure_fresh` right before the next read.
* SQL addresses are virtual addresses (what Malcat prints in disassembly/decompilation). Malcat's
  API speaks "effective addresses" (EA); conversion happens only at this boundary.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar

import apsw

T = TypeVar("T")

PROJECT_SUFFIX = ".malcat"
_malcat_ready = False


def _import_malcat() -> Any:
    global _malcat_ready
    try:
        import malcat  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - environment problem
        raise RuntimeError(
            "cannot import the 'malcat' module. Run Malcat's install_api.py with the Python 3.13 "
            "interpreter that runs malcatsql (malcat.pyd is built for CPython 3.13 only)."
        ) from exc
    if not _malcat_ready:
        malcat.setup()
        _malcat_ready = True
    return malcat


def parse_option_value(raw: str) -> Any:
    """Turn a ``--option key=value`` string into bool/int/str for ``malcat.analyse``."""
    low = raw.strip().lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    try:
        return int(raw, 0)
    except ValueError:
        return raw


def resolve_input(path: str | os.PathLike[str]) -> tuple[Path, Optional[Path]]:
    """Return ``(source_binary, project_file_or_None)`` for a binary or a ``.malcat`` project."""
    p = Path(path).expanduser().resolve()
    if p.suffix.lower() == PROJECT_SUFFIX:
        source = p.with_suffix("")
        if not source.is_file():
            raise FileNotFoundError(
                f"project {p} needs its source binary next to it ({source} not found)"
            )
        return source, p
    if not p.is_file():
        raise FileNotFoundError(f"input file not found: {p}")
    return p, None


class Session:
    """A malcat analysis plus generation-scoped caches of plain Python rows."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        options: Optional[dict[str, Any]] = None,
        project: Optional[str | os.PathLike[str]] = None,
        use_project: bool = True,
    ) -> None:
        self.malcat = _import_malcat()
        self.source_path, given_project = resolve_input(path)
        if project is not None:
            self.project_path = Path(project).expanduser().resolve()
        elif given_project is not None:
            self.project_path = given_project
        else:
            self.project_path = Path(str(self.source_path) + PROJECT_SUFFIX)
        self.options: dict[str, Any] = dict(options or {})

        started = time.perf_counter()
        self.a = self.malcat.analyse(str(self.source_path), self.options)
        self.analysis_seconds = time.perf_counter() - started
        if self.a.failed:
            errors = "; ".join(str(e) for e in self.a.log)
            raise RuntimeError(f"malcat analysis failed for {self.source_path}: {errors}")

        self.project_loaded = False
        if use_project and self.project_path.is_file():
            if not self.a.load(str(self.project_path)):
                raise RuntimeError(f"malcat refused to load project {self.project_path}")
            self.a.run()
            self.project_loaded = True
        self.gen = 0
        self.dirty = False
        self.unsaved_changes = False
        self.deadline: Optional[float] = None
        self._cache: dict[Any, Any] = {}
        self._sticky: dict[Any, Any] = {}  # survives generations (e.g. capa results)
        self._decompiled: dict[int, str] = {}  # raw decompiler text, dropped only by rerun()

    # ------------------------------------------------------------------ freshness

    def ensure_fresh(self) -> None:
        """Run the deferred ``Analysis.run()`` if a write made the analysis dirty."""
        if self.dirty:
            self.rerun()

    def rerun(self) -> None:
        """Re-analyse now; drops every cached row and decompilation (names may have changed)."""
        self.a.run()
        self.dirty = False
        self._decompiled.clear()
        self._bump()

    def mark_dirty(self) -> None:
        """Record a write that needs ``run()`` (labels, python) before the next read."""
        self.dirty = True
        self.unsaved_changes = True
        self._bump()

    def touch(self) -> None:
        """Record a write that is visible immediately (comments) but invalidates cached rows."""
        self.unsaved_changes = True
        self._bump()

    def _bump(self) -> None:
        self.gen += 1
        self._cache.clear()

    def cached(self, key: Any, build: Callable[[], T]) -> T:
        """Memoize ``build()`` for the current generation."""
        if key not in self._cache:
            self._cache[key] = build()
        return self._cache[key]

    def sticky(self, key: Any, build: Callable[[], T]) -> T:
        """Memoize ``build()`` for the session lifetime (only for results labels cannot change)."""
        if key not in self._sticky:
            self._sticky[key] = build()
        return self._sticky[key]

    def check_deadline(self) -> None:
        """Cooperative timeout for long Python-side scans (SQLite's progress handler can't see them)."""
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise apsw.InterruptError("query timeout (query_timeout_ms) exceeded")

    # ------------------------------------------------------------------ addresses

    def va(self, ea: Optional[int]) -> Optional[int]:
        """Malcat EA -> virtual address, ``None`` when the location has no VA (e.g. overlay)."""
        if ea is None:
            return None
        try:
            return self.a.a2v(ea)
        except Exception:
            return None

    def ea(self, addr: Any) -> int:
        """Virtual address (int or '0x..' text) -> Malcat EA. Raises ``ValueError`` if unmapped."""
        if isinstance(addr, str):
            addr = int(addr, 0)
        if not isinstance(addr, int):
            raise ValueError(f"address must be an integer, got {addr!r}")
        try:
            ea = self.a.v2a(addr)
        except Exception:
            ea = None
        if ea is None:
            raise ValueError(f"address 0x{addr:X} is not mapped in this file")
        return ea

    def try_ea(self, addr: Any) -> Optional[int]:
        try:
            return self.ea(addr)
        except ValueError:
            return None

    def offset(self, ea: Optional[int]) -> Optional[int]:
        """Malcat EA -> file offset, ``None`` for virtual-only memory (e.g. .bss)."""
        if ea is None:
            return None
        try:
            return self.a.a2p(ea)
        except Exception:
            return None

    def ea_from_offset(self, offset: int) -> Optional[int]:
        try:
            return self.a.p2a(offset)
        except Exception:
            return None

    # ------------------------------------------------------------------ helpers

    def function_ea_at(self, ea: int) -> Optional[int]:
        fn = self.a.fns.find(ea)
        return None if fn is None else fn.address

    def function_start_ea(self, addr: Any) -> int:
        """EA of the function that *starts* at ``addr`` (VA). Raises ``ValueError`` otherwise."""
        ea = self.ea(addr)
        fn = self.a.fns.find(ea)
        if fn is None or fn.address != ea:
            raise ValueError(f"no function starts at 0x{int(addr):X}")
        return ea

    def decompile_raw(self, func_ea: int, refresh: bool = False) -> str:
        """Decompiler text exactly as Malcat produced it (no aliases applied), cached until rerun()."""
        raw = None if refresh else self._decompiled.get(func_ea)
        if raw is None:
            raw = self._decompiled[func_ea] = self.a.fns.find(func_ea).decompile()
        return raw

    def decompile(self, func_ea: int, refresh: bool = False) -> str:
        """Pseudo-C for one function, with its decompile aliases applied.

        Malcat stores aliases (``Function.set_decompile_aliases``) but headless ``decompile()``
        ignores them (only Malcat's own decompiler view applies them), so we apply them as whole-word renames.
        The raw text is cached separately: alias edits never trigger a re-decompile.
        """
        raw = self.decompile_raw(func_ea, refresh)
        aliases = self.a.fns.find(func_ea).get_decompile_aliases() or {}
        if not aliases:
            return raw
        pattern = re.compile(r"\b(" + "|".join(re.escape(k) for k in sorted(aliases, key=len, reverse=True)) + r")\b")
        return pattern.sub(lambda m: aliases[m.group(1)], raw)

    def save(self, path: Optional[str | os.PathLike[str]] = None) -> str:
        """Persist user annotations to a ``.malcat`` project (Malcat's .bndb equivalent)."""
        self.ensure_fresh()
        target = Path(path).expanduser().resolve() if path else self.project_path
        if not self.a.save(str(target)):
            raise RuntimeError(f"malcat failed to save project {target}")
        self.project_path = target
        self.unsaved_changes = False
        return str(target)

    @property
    def is_64bit(self) -> bool:
        return self.a.architecture.name in ("X64", "AARCH64", "ARMV8", "ARMV8T", "MIPS64")
