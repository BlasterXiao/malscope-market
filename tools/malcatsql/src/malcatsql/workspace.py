"""Multi-sample workspace: several Malcat analyses behind one SQL endpoint.

Each sample keeps its own :class:`Engine` (so every table, view and function works unchanged inside
it). The workspace connection adds what a single sample cannot do:

* ``samples``                      one row per loaded sample
* ``collect(name, sql[, aliases])``  run ``sql`` on every sample, gather the rows into a TEMP table
                                   ``name`` with a leading ``sample`` column (full SQLite from there:
                                   joins, GROUP BY, window functions, recursive CTEs)
* ``on_sample(alias, sql)``         run one statement on one sample (reads: JSON rows; writes: change
                                   count). Errors abort the statement, so a wrong premise in a bulk
                                   write is reported instead of silently skipped
* ``save_all()``                    persist every sample's ``.malcat`` project

Typical use is cross-sample reasoning in plain SQL, e.g. code reuse by ``func_hashes.pic_hash``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import apsw

from . import TOOL_NAME, __version__
from .engine import Engine, Settings, _jsonable
from .functions import register_hex_and_hamming
from .session import Session

_ALIAS_SPEC = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.+)$")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

#: name -> (arities, doc); mirrored into the generated function catalog
WORKSPACE_FUNCTIONS: dict[str, tuple[str, str]] = {
    "collect": ("2/3", "collect(name, sql[, aliases]): run sql on every sample (or the comma-separated aliases) and store all rows in TEMP table `name` with a leading `sample` column; returns the row count; errors if a result would be truncated"),
    "on_sample": ("2", "on_sample(alias, sql): run sql on one sample; SELECT -> JSON {columns, rows}, other statements -> number of changed rows; failures abort the calling statement"),
    "save_all": ("0", "save_all(): save every sample's .malcat project; returns the number saved"),
}


@dataclass(frozen=True)
class SampleSpec:
    alias: str
    path: str


def parse_targets(targets: list[str]) -> list[SampleSpec]:
    """``[alias=]path`` items -> unique SQL-safe aliases (file stem when no alias is given)."""
    specs: list[SampleSpec] = []
    used: set[str] = set()
    for item in targets:
        m = _ALIAS_SPEC.match(item)
        alias, path = (m.group(1), m.group(2)) if m else (None, item)
        if alias is None:
            stem = re.sub(r"[^A-Za-z0-9_]", "_", Path(path).stem) or "sample"
            alias = stem if not stem[0].isdigit() else f"s_{stem}"
        base, n = alias, 1
        while alias.lower() in used:
            n += 1
            alias = f"{base}_{n}"
        used.add(alias.lower())
        specs.append(SampleSpec(alias, path))
    return specs


class _WorkspaceSession:
    """The slice of Session that Engine's statement runner touches."""

    def __init__(self, ws: Workspace) -> None:
        self.ws = ws
        self.deadline: Optional[float] = None

    @property
    def unsaved_changes(self) -> bool:
        return any(e.session.unsaved_changes for e in self.ws.engines.values())


class Workspace(Engine):
    def __init__(
        self,
        targets: list[str],
        *,
        options: Optional[dict[str, Any]] = None,
        use_project: bool = True,
        settings: Optional[dict[str, Any]] = None,
    ) -> None:
        # deliberately not Engine.__init__: no single analysis, no surfaces
        specs = parse_targets(targets)
        if len(specs) < 2:
            raise ValueError("a workspace needs at least two samples")
        self.engines: dict[str, Engine] = {}
        for spec in specs:
            self.engines[spec.alias] = Engine(
                Session(spec.path, options=options, use_project=use_project), settings
            )
        self.session = _WorkspaceSession(self)  # type: ignore[assignment]
        self.settings = Settings(settings)
        self.surfaces = {}
        self.conn = apsw.Connection(":memory:")
        register_hex_and_hamming(self.conn)
        self.conn.create_scalar_function("collect", self._collect, 2)
        self.conn.create_scalar_function("collect", self._collect, 3)
        self.conn.create_scalar_function("on_sample", self._on_sample, 2)
        self.conn.create_scalar_function("save_all", self._save_all, 0)
        self.conn.execute(
            "CREATE TEMP TABLE samples(alias TEXT PRIMARY KEY, path TEXT, filetype TEXT, processor TEXT, "
            "size INT, md5 TEXT, sha256 TEXT, imphash TEXT, functions INT, strings INT, unsaved INT)"
        )
        self.conn.set_progress_handler(self._progress, 10_000)

    # ------------------------------------------------------------------ catalogue

    def _refresh_samples(self) -> None:
        rows = []
        for alias, e in self.engines.items():
            env = e.run(
                "SELECT (SELECT value FROM binary WHERE key='filename'), (SELECT value FROM binary WHERE key='filetype'),"
                "(SELECT value FROM binary WHERE key='processor'), (SELECT value FROM binary WHERE key='file_size'),"
                "(SELECT value FROM binary WHERE key='md5'), (SELECT value FROM binary WHERE key='sha256'),"
                "(SELECT value FROM binary WHERE key='imphash'), (SELECT count(*) FROM funcs), (SELECT count(*) FROM strings)"
            )
            r = env["results"][0]["rows"][0]
            rows.append((alias, r[0], r[1], r[2], int(r[3]), r[4], r[5], r[6], r[7], r[8], int(e.session.unsaved_changes)))
        with self.conn:
            self.conn.execute("DELETE FROM samples")
            self.conn.executemany("INSERT INTO samples VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)

    def run(self, sql: str, max_rows: Optional[int] = None, sample: Optional[str] = None) -> dict[str, Any]:  # type: ignore[override]
        if sample:
            engine = self.engines.get(sample)
            if engine is None:
                return _error(f"no sample {sample!r}; loaded: {', '.join(self.engines)}")
            return engine.run(sql, max_rows=max_rows)
        self._refresh_samples()
        return super().run(sql, max_rows=max_rows)

    def status(self) -> dict[str, Any]:
        samples = [dict(e.status(), alias=a) for a, e in self.engines.items()]
        return {
            "tool": TOOL_NAME,
            "version": __version__,
            "mode": "workspace",
            "file": ", ".join(self.engines),
            "filetype": "workspace",
            "architecture": f"{len(samples)} samples",
            "analysis_seconds": round(sum(s["analysis_seconds"] for s in samples), 2),
            "project": "",
            "project_loaded": False,
            "unsaved_changes": self.session.unsaved_changes,
            "samples": samples,
            "tables": ["samples"],
            "views": [],
            "workspace_functions": sorted(WORKSPACE_FUNCTIONS),
        }

    def table_names(self) -> list[str]:
        temp = [r[0] for r in self.conn.execute("SELECT name FROM sqlite_temp_master WHERE type IN ('table','view')")]
        return sorted(set(temp))

    def schema_of(self, name: str) -> list[tuple[Any, ...]]:
        rows = list(self.conn.execute(f'SELECT * FROM pragma_table_xinfo("{name}")'))
        return rows or next(iter(self.engines.values())).schema_of(name)

    # ------------------------------------------------------------------ SQL functions

    def _pick(self, aliases: Optional[str]) -> list[str]:
        if not aliases:
            return list(self.engines)
        names = [a.strip() for a in str(aliases).split(",") if a.strip()]
        for a in names:
            if a not in self.engines:
                raise apsw.ConstraintError(f"no sample {a!r}; loaded: {', '.join(self.engines)}")
        return names

    def _collect(self, name: str, sql: str, aliases: Optional[str] = None) -> int:
        if not _IDENT.match(str(name)):
            raise apsw.ConstraintError(f"collect: {name!r} is not a valid table name")
        cap = self.settings.get_int("collect_max_rows")
        columns: Optional[list[str]] = None
        batches: list[tuple[str, list[list[Any]]]] = []
        for alias in self._pick(aliases):
            env = self.engines[alias].run(str(sql), max_rows=cap)
            if not env["success"]:
                raise apsw.ConstraintError(f"collect on {alias}: {env['error']}")
            result = env["results"][-1]
            if not result["columns"]:
                raise apsw.ConstraintError("collect: the statement returns no columns")
            if result["truncated"]:
                raise apsw.ConstraintError(
                    f"collect on {alias}: more than {cap} rows; narrow the query or raise collect_max_rows"
                )
            if columns is None:
                columns = _unique_columns(result["columns"])
            elif len(result["columns"]) != len(columns):
                raise apsw.ConstraintError(f"collect on {alias}: column count differs from the first sample")
            batches.append((alias, result["rows"]))
        assert columns is not None
        quoted = ", ".join(f'"{c}"' for c in ["sample"] + columns)
        marks = ", ".join("?" for _ in range(len(columns) + 1))
        total = 0
        # nested DDL/DML while the outer statement runs: use a separate cursor on the same connection
        self.conn.execute(f'DROP TABLE IF EXISTS temp."{name}"')
        self.conn.execute(f'CREATE TEMP TABLE "{name}"({quoted})')
        for alias, rows in batches:
            self.conn.executemany(f'INSERT INTO temp."{name}" VALUES ({marks})', [(alias, *r) for r in rows])
            total += len(rows)
        return total

    def _on_sample(self, alias: str, sql: str) -> Any:
        engine = self.engines.get(str(alias))
        if engine is None:
            raise apsw.ConstraintError(f"no sample {alias!r}; loaded: {', '.join(self.engines)}")
        env = engine.run(str(sql))
        if not env["success"]:
            raise apsw.ConstraintError(f"on_sample {alias}: {env['error']}")
        result = env["results"][-1]
        if not result["columns"]:
            return result["changes"]
        return json.dumps({"columns": result["columns"], "rows": [[_jsonable(v) for v in r] for r in result["rows"]]}, ensure_ascii=False)

    def _save_all(self) -> int:
        for e in self.engines.values():
            e.session.save()
        return len(self.engines)


def _unique_columns(names: list[str]) -> list[str]:
    out: list[str] = []
    for raw in names:
        base = (raw or "col").replace('"', "") or "col"
        if base.lower() == "sample":
            base = "sample_"
        name, n = base, 1
        while name.lower() in {o.lower() for o in out}:
            n += 1
            name = f"{base}_{n}"
        out.append(name)
    return out


def _error(message: str) -> dict[str, Any]:
    return {"success": False, "results": [], "elapsed_ms": 0, "error": message}
