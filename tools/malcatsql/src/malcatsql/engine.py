"""SQL engine: one apsw connection with every malcatsql surface, view and function registered."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Optional

import apsw
import apsw.ext

from . import TOOL_NAME, __version__
from .functions import register_functions
from .session import Session
from .tables import NEEDS_ENGINE, SURFACES, VIEWS
from .vtab import Surface


@dataclass(frozen=True)
class SettingSpec:
    key: str
    type: str  # "int" | "bool"
    default: Any
    scope: str
    doc: str


SETTING_SPECS: tuple[SettingSpec, ...] = (
    SettingSpec("query_timeout_ms", "int", 120_000, "common", "Abort a statement after N ms (0 = no limit)"),
    SettingSpec("enable_python", "bool", False, "malcatsql", "Allow malcat_python()/malcat_python_file()"),
    SettingSpec("python_output_max", "int", 65_536, "malcatsql", "Truncate captured Python stdout to N chars"),
    SettingSpec("byte_search_max_results", "int", 1000, "malcatsql", "Default cap for byte_search rows"),
    SettingSpec("max_result_rows", "int", 100_000, "common", "Rows returned per statement over HTTP/MCP"),
    SettingSpec("collect_max_rows", "int", 1_000_000, "workspace", "Workspace collect(): max rows per sample before it refuses (never truncates silently)"),
)


class Settings:
    def __init__(self, overrides: Optional[dict[str, Any]] = None) -> None:
        self.specs = SETTING_SPECS
        self._spec = {s.key: s for s in SETTING_SPECS}
        self._values = {s.key: s.default for s in SETTING_SPECS}
        for k, v in (overrides or {}).items():
            self.set(k, v)

    def set(self, key: str, value: Any) -> None:
        spec = self._spec.get(key)
        if spec is None:
            raise apsw.ConstraintError(f"unknown runtime setting {key!r}")
        try:
            if spec.type == "bool":
                parsed = _parse_bool(value)
            else:
                parsed = int(value, 0) if isinstance(value, str) else int(value)
                if parsed < 0:
                    raise ValueError
        except (TypeError, ValueError):
            raise apsw.ConstraintError(f"invalid {spec.type} value {value!r} for {key}") from None
        self._values[key] = parsed

    def get_int(self, key: str) -> int:
        return int(self._values[key])

    def get_bool(self, key: str) -> bool:
        return bool(self._values[key])

    def get_text(self, key: str) -> str:
        v = self._values[key]
        if isinstance(v, bool):
            return "1" if v else "0"
        return str(v)


def _parse_bool(value: Any) -> bool:
    if isinstance(value, (int, bool)):
        return bool(value)
    low = str(value).strip().lower()
    if low in ("1", "true", "yes", "on"):
        return True
    if low in ("0", "false", "no", "off"):
        return False
    raise ValueError(value)


class Engine:
    """Executes SQL against one :class:`Session`. Not thread-safe: use from a single thread."""

    def __init__(self, session: Session, settings: Optional[dict[str, Any]] = None) -> None:
        self.session = session
        self.settings = Settings(settings)
        self.conn = apsw.Connection(":memory:")
        self.surfaces: dict[str, Surface] = {}
        for cls in SURFACES:
            surf = cls(session, self) if cls in NEEDS_ENGINE else cls(session)  # type: ignore[call-arg]
            self.surfaces[surf.name] = surf
            self.conn.create_module(surf.name, surf, use_bestindex_object=True, eponymous=True)
        for name, body in VIEWS.items():
            self.conn.execute(f"CREATE TEMP VIEW {name} AS {body}")
        register_functions(self)
        self.conn.set_progress_handler(self._progress, 10_000)

    # ------------------------------------------------------------------ execution

    def _progress(self) -> bool:
        deadline = self.session.deadline
        return deadline is not None and time.monotonic() > deadline

    def run(self, sql: str, max_rows: Optional[int] = None, sample: Optional[str] = None) -> dict[str, Any]:
        """Execute one or more statements; return the bnsql-style JSON envelope.

        ``sample`` only means something for a multi-sample :class:`~malcatsql.workspace.Workspace`.
        """
        started = time.perf_counter()
        results: list[dict[str, Any]] = []
        if sample:
            return _envelope(
                False, results, started,
                f"this server holds a single sample; drop the sample selector ({sample!r})",
            )
        try:
            for stmt in split_statements(sql):
                results.append(self._run_one(stmt, max_rows))
        except apsw.Error as exc:
            return _envelope(False, results, started, f"{type(exc).__name__}: {exc}")
        except Exception as exc:  # malcat/python errors raised from inside surfaces
            return _envelope(False, results, started, f"{type(exc).__name__}: {exc}")
        return _envelope(True, results, started, None)

    def _run_one(self, stmt: str, max_rows: Optional[int]) -> dict[str, Any]:
        timeout = self.settings.get_int("query_timeout_ms")
        self.session.deadline = time.monotonic() + timeout / 1000 if timeout else None
        before = self.conn.total_changes()
        try:
            cursor = self.conn.execute(stmt)
            columns: list[str] = []
            rows: list[list[Any]] = []
            truncated = False
            try:
                columns = [d[0] for d in cursor.get_description()]
            except apsw.ExecutionCompleteError:
                columns = []
            for row in cursor:
                if max_rows is not None and len(rows) >= max_rows:
                    truncated = True
                    break
                rows.append([_jsonable(v) for v in row])
            if not columns:
                columns = _describe(self.conn, stmt)
        finally:
            self.session.deadline = None
        return {
            "statement": stmt,
            "columns": columns,
            "rows": rows,
            "row_count": len(rows),
            "truncated": truncated,
            "changes": self.conn.total_changes() - before,
        }

    def status(self) -> dict[str, Any]:
        s = self.session
        return {
            "tool": TOOL_NAME,
            "version": __version__,
            "file": str(s.source_path),
            "project": str(s.project_path),
            "project_loaded": s.project_loaded,
            "unsaved_changes": s.unsaved_changes,
            "filetype": s.a.type,
            "architecture": s.a.architecture.name,
            "analysis_seconds": round(s.analysis_seconds, 2),
            "mode": "headless",
            "python_available": True,
            "enable_python": self.settings.get_bool("enable_python"),
            "tables": sorted(self.surfaces),
            "views": sorted(VIEWS),
        }

    def table_names(self) -> list[str]:
        return sorted(self.surfaces) + sorted(VIEWS)

    def schema_of(self, name: str) -> list[tuple[Any, ...]]:
        return list(self.conn.execute(f'SELECT * FROM pragma_table_xinfo("{name}")'))


def split_statements(sql: str) -> list[str]:
    """Split a script into complete SQL statements (handles ';' inside strings/comments)."""
    out: list[str] = []
    buf = ""
    pieces = sql.split(";")
    for i, piece in enumerate(pieces):
        buf += piece
        if i == len(pieces) - 1:
            break
        buf += ";"
        if apsw.complete(buf):
            if buf.strip(" \t\r\n;"):
                out.append(buf.strip())
            buf = ""
    if buf.strip():
        out.append(buf.strip())
    return out


def _describe(conn: apsw.Connection, stmt: str) -> list[str]:
    try:
        info = apsw.ext.query_info(conn, stmt)
        return [d[0] for d in (info.description or ())]
    except Exception:
        return []


def _jsonable(v: Any) -> Any:
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).hex().upper()
    if isinstance(v, str):
        try:
            v.encode("utf-8")
        except UnicodeEncodeError:  # lone surrogates from broken UTF-16 would break JSON/stdout
            return v.encode("utf-8", "replace").decode("utf-8")
    return v


def _envelope(success: bool, results: list[dict[str, Any]], started: float, error: Optional[str]) -> dict[str, Any]:
    return {
        "success": success,
        "results": results,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
        "error": error,
    }
