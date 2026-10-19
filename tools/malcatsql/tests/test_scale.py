"""Large-binary behaviour (shell32.dll, ~31k functions / 1.5M instructions). Run with -m slow."""

from __future__ import annotations

import shutil
import time
from pathlib import Path

import pytest

from conftest import err, q
from malcatsql.engine import Engine
from malcatsql.session import Session

SHELL32 = Path(r"C:\Windows\System32\shell32.dll")
pytestmark = [pytest.mark.slow, pytest.mark.skipif(not SHELL32.is_file(), reason="no shell32.dll")]


@pytest.fixture(scope="module")
def big(tmp_path_factory: pytest.TempPathFactory) -> Engine:
    copy = tmp_path_factory.mktemp("big") / "shell32.dll"
    shutil.copyfile(SHELL32, copy)
    return Engine(Session(copy, use_project=False))


def timed(engine: Engine, sql: str) -> tuple[list[list[object]], float]:
    t = time.perf_counter()
    rows = q(engine, sql)
    return rows, time.perf_counter() - t


def test_cheap_surfaces_stay_interactive(big: Engine) -> None:
    for sql in (
        "SELECT count(*) FROM funcs",
        "SELECT count(*) FROM names",
        "SELECT count(*) FROM strings",
        "SELECT count(*) FROM imports",
    ):
        _, dt = timed(big, sql)
        assert dt < 5, (sql, dt)


def test_per_function_pushdown_is_fast(big: Engine) -> None:
    addr, n = q(big, "SELECT addr, num_instructions FROM funcs ORDER BY num_instructions DESC LIMIT 1")[0]
    rows, dt = timed(big, f"SELECT count(*) FROM instructions WHERE func_addr = {addr}")
    assert rows == [[n]] and dt < 5, dt


def test_xref_lookups(big: Engine) -> None:
    target = q(big, "SELECT addr FROM imports LIMIT 1")[0][0]
    _, dt = timed(big, f"SELECT * FROM xrefs WHERE to_addr = {target}")
    assert dt < 1, dt
    _, dt = timed(big, "SELECT count(*) FROM xrefs")
    assert dt < 60, dt


def test_unconstrained_instruction_scan_hits_timeout(big: Engine) -> None:
    q(big, "UPDATE runtime_settings SET value = '2000' WHERE key = 'query_timeout_ms'")
    try:
        t = time.perf_counter()
        message = err(big, "SELECT count(*) FROM instructions")
        assert "timeout" in message or "nterrupt" in message
        assert time.perf_counter() - t < 10
    finally:
        q(big, "UPDATE runtime_settings SET value = '120000' WHERE key = 'query_timeout_ms'")
