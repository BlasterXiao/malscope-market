"""Every ```sql block in the plugin's skills must run against a real session (guards doc rot)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

import pytest

from malcatsql.engine import Engine, split_statements

SKILLS = Path(__file__).resolve().parents[3] / "plugins" / "malcatsql" / "skills"
BLOCK = re.compile(r"```sql\n(.*?)```", re.S)
# statements that touch the analyst's filesystem or need inputs that only exist on their machine
SKIP_MARKERS = ("C:/cases", "<table>", "<surface>")

DOCS = sorted(p for p in SKILLS.rglob("*.md"))


def sql_blocks(path: Path) -> list[str]:
    statements: list[str] = []
    for block in BLOCK.findall(path.read_text(encoding="utf-8")):
        statements.extend(s for s in split_statements(block) if not any(m in s for m in SKIP_MARKERS))
    return statements


def _workspace(tmp_path: Path) -> Engine:
    """Two byte-identical copies aliased `old` and `new`, the names the workspace skill uses."""
    import shutil

    from conftest import NOTEPAD
    from malcatsql.workspace import Workspace

    paths = []
    for alias in ("old", "new"):
        p = tmp_path / f"{alias}_sample.exe"
        shutil.copyfile(NOTEPAD, p)
        paths.append(f"{alias}={p}")
    ws = Workspace(paths, use_project=False)
    # give `old` a solved function so the name-propagation recipe has something to carry over
    ws.run("SELECT on_sample('old', 'UPDATE funcs SET name = ''solved_fn'' WHERE addr = (SELECT addr FROM funcs ORDER BY size DESC LIMIT 1)')")
    return ws  # type: ignore[return-value]


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: str(p.relative_to(SKILLS)))
def test_skill_sql_examples_run(doc: Path, fresh: Callable[..., Engine], tmp_path: Path) -> None:
    statements = sql_blocks(doc)
    if not statements:
        pytest.skip("no sql blocks")
    e = fresh(use_project=False, settings={"enable_python": True})
    if doc.parent.name == "workspace":
        e = _workspace(tmp_path)
    failures = []
    for stmt in statements:
        env = e.run(stmt)
        if not env["success"]:
            failures.append(f"{stmt}\n  -> {env['error']}")
    assert not failures, "\n\n".join(failures)
