from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path
from typing import Any, Callable

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")

if importlib.util.find_spec("malcat") is None or not NOTEPAD.is_file():
    pytest.skip("needs the malcat Python module and notepad.exe", allow_module_level=True)

from malcatsql.engine import Engine  # noqa: E402
from malcatsql.session import Session  # noqa: E402


@pytest.fixture(scope="session")
def sample_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("samples")


@pytest.fixture(scope="session")
def sample(sample_dir: Path) -> Path:
    """Read-only copy of notepad.exe (no project file ever written next to it)."""
    dst = sample_dir / "notepad_ro.exe"
    shutil.copyfile(NOTEPAD, dst)
    return dst


@pytest.fixture(scope="session")
def engine(sample: Path) -> Engine:
    """Shared engine for read-only tests. Never write through it."""
    return Engine(Session(sample, use_project=False))


@pytest.fixture
def fresh(tmp_path: Path) -> Callable[..., Engine]:
    """Factory for a private engine on a private copy (for write/persistence tests)."""
    copy = tmp_path / "notepad.exe"
    shutil.copyfile(NOTEPAD, copy)

    def make(**kwargs: Any) -> Engine:
        settings = kwargs.pop("settings", None)
        return Engine(Session(copy, **kwargs), settings)

    return make


def q(engine: Engine, sql: str) -> list[list[Any]]:
    """Run SQL and return the last statement's rows; fail loudly on errors."""
    env = engine.run(sql)
    assert env["success"], env["error"]
    return env["results"][-1]["rows"]


def err(engine: Engine, sql: str) -> str:
    env = engine.run(sql)
    assert not env["success"], f"expected failure: {sql}"
    return env["error"]
