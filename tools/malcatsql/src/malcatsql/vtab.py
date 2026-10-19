"""apsw virtual-table plumbing shared by every malcatsql surface.

A :class:`Surface` declares columns and implements ``rows(eq)``; ``eq`` holds the EQ constraints
SQLite pushed down (only for columns flagged ``pushdown``). ``rows`` must return plain tuples
``(rowid, values)`` where ``values`` covers the visible columns in declaration order. Cursors only
ever iterate those tuples, so no malcat object outlives the ``Filter`` call that produced it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, Optional

import apsw

if TYPE_CHECKING:
    from .session import Session

EQ = apsw.SQLITE_INDEX_CONSTRAINT_EQ

Row = tuple[int, tuple[Any, ...]]


@dataclass(frozen=True)
class Col:
    name: str
    type: str = ""
    pushdown: bool = False
    hidden: bool = False
    required: bool = False
    doc: str = ""


class Surface:
    """One eponymous virtual table backed by the live malcat analysis."""

    name: ClassVar[str]
    doc: ClassVar[str] = ""
    skill: ClassVar[str] = "connect"
    columns: ClassVar[tuple[Col, ...]]
    #: estimated rows for an unconstrained scan; keeps the planner driving joins from small tables
    scan_rows: ClassVar[int] = 100_000
    #: refuse unconstrained scans (with this hint) instead of running them
    scan_error: ClassVar[Optional[str]] = None
    writable: ClassVar[frozenset[str]] = frozenset()  # subset of {"insert", "update", "delete"}
    write_note: ClassVar[str] = ""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.visible = [c for c in self.columns if not c.hidden]
        self._layout: list[tuple[bool, Any]] = []
        vis_index = 0
        for c in self.columns:
            if c.hidden:
                self._layout.append((True, c.name))
            else:
                self._layout.append((False, vis_index))
                vis_index += 1

    # ---------------------------------------------------------------- provider API

    def rows(self, eq: dict[str, Any]) -> list[Row]:
        raise NotImplementedError

    def insert(self, values: dict[str, Any]) -> int:
        raise self._denied("insert")

    def update(self, rowid: int, values: dict[str, Any]) -> None:
        raise self._denied("update")

    def delete(self, rowid: int) -> None:
        raise self._denied("delete")

    def _denied(self, op: str) -> apsw.Error:
        note = f" {self.write_note}" if self.write_note else ""
        return apsw.ReadOnlyError(f"mutation.{self.name}.{op} = false (not supported).{note}")

    # ---------------------------------------------------------------- schema helpers

    def create_sql(self) -> str:
        cols = ", ".join(
            f'"{c.name}" {c.type}{" HIDDEN" if c.hidden else ""}'.rstrip() for c in self.columns
        )
        return f"CREATE TABLE x({cols})"

    # ---------------------------------------------------------------- apsw VTModule

    def Create(self, db: apsw.Connection, modulename: str, dbname: str, tablename: str, *args: str):  # noqa: N802
        return self.create_sql(), _Table(self)

    Connect = Create  # noqa: N815


class _Table:
    def __init__(self, surface: Surface) -> None:
        self.s = surface

    def BestIndexObject(self, iio: apsw.IndexInfo) -> bool:  # noqa: N802
        used: list[str] = []
        cols = self.s.columns
        for i in range(iio.nConstraint):
            icol = iio.get_aConstraint_iColumn(i)
            if icol < 0 or not iio.get_aConstraint_usable(i):
                continue
            col = cols[icol]
            if col.pushdown and iio.get_aConstraint_op(i) == EQ and col.name not in used:
                used.append(col.name)
                iio.set_aConstraintUsage_argvIndex(i, len(used))
                # hidden inputs are consumed by us; visible ones are re-checked by SQLite
                iio.set_aConstraintUsage_omit(i, col.hidden)
        required = {c.name for c in cols if c.required}
        if not required <= set(used):
            return False  # -> "no query solution" unless another plan supplies the input
        iio.idxStr = ",".join(used)
        if used:
            iio.estimatedCost = 10.0
            iio.estimatedRows = 10
        else:
            iio.estimatedCost = float(self.s.scan_rows) * 10.0
            iio.estimatedRows = self.s.scan_rows
        return True

    def Open(self) -> _Cursor:  # noqa: N802
        return _Cursor(self.s)

    def UpdateInsertRow(self, rowid: Optional[int], fields: tuple[Any, ...]) -> int:  # noqa: N802
        return self.s.insert(dict(zip((c.name for c in self.s.columns), fields)))

    def UpdateChangeRow(self, rowid: int, newrowid: int, fields: tuple[Any, ...]) -> None:  # noqa: N802
        if newrowid != rowid:
            raise apsw.ConstraintError(f"{self.s.name}: changing the address/rowid is not supported")
        self.s.update(rowid, dict(zip((c.name for c in self.s.columns), fields)))

    def UpdateDeleteRow(self, rowid: int) -> None:  # noqa: N802
        self.s.delete(rowid)

    def Disconnect(self) -> None:  # noqa: N802
        pass

    Destroy = Disconnect  # noqa: N815


class _Cursor:
    def __init__(self, surface: Surface) -> None:
        self.s = surface
        self.data: list[Row] = []
        self.eq: dict[str, Any] = {}
        self.i = 0

    def Filter(self, indexnum: int, indexname: Optional[str], constraintargs: tuple[Any, ...]) -> None:  # noqa: N802
        self.eq = dict(zip(indexname.split(","), constraintargs)) if indexname else {}
        if not self.eq and self.s.scan_error:
            raise apsw.ConstraintError(self.s.scan_error)
        self.s.session.ensure_fresh()
        self.data = self.s.rows(self.eq)
        self.i = 0

    def Eof(self) -> bool:  # noqa: N802
        return self.i >= len(self.data)

    def Next(self) -> None:  # noqa: N802
        self.i += 1

    def Rowid(self) -> int:  # noqa: N802
        return self.data[self.i][0]

    def Column(self, n: int) -> Any:  # noqa: N802
        if n == -1:
            return self.data[self.i][0]
        hidden, key = self.s._layout[n]
        if hidden:
            return self.eq.get(key)
        return self.data[self.i][1][key]

    def Close(self) -> None:  # noqa: N802
        self.data = []


class CachedSurface(Surface):
    """Surface whose full row set is cheap enough to build once per generation.

    EQ pushdown on any ``pushdown`` column is answered from a lazily built hash index.
    """

    def build(self) -> list[Row]:
        raise NotImplementedError

    def all_rows(self) -> list[Row]:
        return self.session.cached((self.name, "rows"), self.build)

    def _index(self, column: str) -> dict[Any, list[Row]]:
        def make() -> dict[Any, list[Row]]:
            pos = next(i for i, c in enumerate(self.visible) if c.name == column)
            index: dict[Any, list[Row]] = {}
            for row in self.all_rows():
                index.setdefault(row[1][pos], []).append(row)
            return index

        return self.session.cached((self.name, "index", column), make)

    def rows(self, eq: dict[str, Any]) -> list[Row]:
        if not eq:
            return self.all_rows()
        result: Optional[list[Row]] = None
        for column, value in eq.items():
            hits = self._index(column).get(value, [])
            if result is None:
                result = hits
            else:
                ids = {id(r) for r in hits}
                result = [r for r in result if id(r) in ids]
        return result or []


def numbered(rows: list[tuple[Any, ...]]) -> list[Row]:
    """Attach 1-based synthetic rowids to read-only rows."""
    return [(i, r) for i, r in enumerate(rows, 1)]
