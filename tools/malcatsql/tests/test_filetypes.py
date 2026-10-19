"""Non-x64 inputs: x86 PE, .NET assembly, Office document, ZIP archive (+ optional extra samples).

Extra samples (e.g. real malware, opened read-only/static): set MALCATSQL_EXTRA_SAMPLES to a
';'-separated list of paths. They are copied to a temp dir first, so no project file is written
next to the originals.
"""

from __future__ import annotations

import os
import shutil
import zipfile
from pathlib import Path
from typing import Optional

import pytest

from conftest import NOTEPAD, q
from malcatsql.engine import Engine
from malcatsql.session import Session

NEEDS_INPUT = {"byte_search", "pseudocode"}


def _first_existing(*candidates: str) -> Optional[Path]:
    for c in candidates:
        p = Path(c)
        if p.is_file():
            return p
    return None


def _dotnet_assembly() -> Optional[Path]:
    base = Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319")
    return _first_existing(str(base / "RegAsm.exe"), str(base / "InstallUtil.exe"), str(base / "MSBuild.exe"))


def _office_doc() -> Optional[Path]:
    for root in (Path.home() / "Documents", Path.home() / "Desktop"):
        if root.is_dir():
            for p in root.glob("*.docx"):
                return p
    return None


SAMPLES: dict[str, Optional[Path]] = {
    "x86_pe": _first_existing(r"C:\Windows\SysWOW64\notepad.exe"),
    "dotnet": _dotnet_assembly(),
    "docx": _office_doc(),
    "zip": None,  # built in the fixture
}
EXTRA = [Path(p) for p in os.environ.get("MALCATSQL_EXTRA_SAMPLES", "").split(";") if p.strip()]


@pytest.fixture(params=list(SAMPLES) + [f"extra{i}" for i in range(len(EXTRA))])
def any_engine(request: pytest.FixtureRequest, tmp_path: Path) -> Engine:
    key = request.param
    if key == "zip":
        src = tmp_path / "bundle.zip"
        with zipfile.ZipFile(src, "w") as z:
            z.write(NOTEPAD, "notepad.exe")
            z.writestr("readme.txt", "hello from malcatsql tests")
    else:
        src = SAMPLES.get(key) if key in SAMPLES else EXTRA[int(key[5:])]
        if src is None or not src.is_file():
            pytest.skip(f"no {key} sample on this machine")
        copy = tmp_path / src.name
        shutil.copyfile(src, copy)
        src = copy
    return Engine(Session(src, use_project=False))


def test_every_surface_answers_on_any_filetype(any_engine: Engine) -> None:
    e = any_engine
    failures = []
    for name in e.table_names():
        if name in NEEDS_INPUT:
            continue
        env = e.run(f"SELECT * FROM {name} LIMIT 1")
        if not env["success"]:
            failures.append(f"{name}: {env['error']}")
    assert not failures, "\n".join(failures)
    facts = dict((k, v) for k, v, _ in q(e, "SELECT * FROM binary"))
    assert facts["filetype"] and facts["processor"]


def test_decompile_follows_capability(any_engine: Engine) -> None:
    e = any_engine
    can = q(e, "SELECT value FROM capabilities WHERE key = 'feature.decompiler'") == [["true"]]
    funcs = q(e, "SELECT addr FROM funcs WHERE addr IS NOT NULL ORDER BY size LIMIT 1 OFFSET 3")
    if not funcs:
        pytest.skip("no functions in this file type")
    env = e.run(f"SELECT decompile({funcs[0][0]})")
    if can:
        assert env["success"], env["error"]
        assert env["results"][0]["rows"][0][0]
    else:
        # must fail cleanly (SQL error), never crash the process
        assert env["success"] or env["error"]
