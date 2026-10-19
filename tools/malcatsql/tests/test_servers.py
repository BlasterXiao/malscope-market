from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterator

import anyio
import pytest
from fastapi.testclient import TestClient

from malcatsql.http_server import create_app
from malcatsql.mcp_server import build_mcp
from malcatsql.worker import EngineWorker, open_engine_factory

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def worker(sample: Path) -> Iterator[EngineWorker]:
    w = EngineWorker(open_engine_factory(str(sample), use_project=False))
    yield w
    w.close()


def test_worker_owns_engine_on_one_thread(worker: EngineWorker) -> None:
    import threading

    names = {worker.submit(lambda e: threading.current_thread().name) for _ in range(5)}
    assert names == {"malcatsql-engine"}


def test_http_query_raw_and_json(worker: EngineWorker) -> None:
    client = TestClient(create_app(worker))
    assert client.get("/health").json()["ok"] is True
    r = client.post("/query", content="SELECT key FROM binary LIMIT 1")
    body = r.json()
    assert r.status_code == 200 and body["success"] and body["results"][0]["rows"] == [["summary"]]
    r = client.post("/query", json={"sql": "SELECT addr FROM funcs; SELECT 1", "max_rows": 2})
    body = r.json()
    assert body["results"][0]["row_count"] == 2 and body["results"][0]["truncated"] is True
    r = client.post("/query", content="SELECT * FROM nope")
    assert r.json()["success"] is False and "no such table" in r.json()["error"]
    assert client.get("/status").json()["filetype"] == "PE"


def test_http_token(worker: EngineWorker) -> None:
    client = TestClient(create_app(worker, token="s3cret"))
    assert client.post("/query", content="SELECT 1").status_code == 401
    assert client.post("/query", content="SELECT 1", headers={"Authorization": "Bearer nope"}).status_code == 401
    ok = client.post("/query", content="SELECT 1", headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 200 and ok.json()["success"]
    ok = client.post("/query", content="SELECT 1", headers={"X-XSQL-Token": "s3cret"})
    assert ok.status_code == 200
    assert client.get("/health").status_code == 200


def test_http_concurrent_requests(worker: EngineWorker) -> None:
    from concurrent.futures import ThreadPoolExecutor

    client = TestClient(create_app(worker))
    sqls = ["SELECT count(*) FROM funcs", "SELECT count(*) FROM strings", "SELECT count(*) FROM names"] * 8
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda s: client.post("/query", content=s).json(), sqls))
    assert all(r["success"] for r in results)
    assert len({json.dumps(r["results"][0]["rows"]) for r in results}) == 3


def test_mcp_tools(worker: EngineWorker) -> None:
    mcp = build_mcp(worker, "127.0.0.1", 0)

    async def go() -> tuple[Any, Any]:
        tools = {t.name for t in await mcp.list_tools()}
        res = await mcp.call_tool("query", {"sql": "SELECT value FROM binary WHERE key = 'filetype'"})
        return tools, res

    tools, res = anyio.run(go)
    assert {"query", "status"} <= tools
    payload = res[1] if isinstance(res, tuple) else res
    text = json.dumps(payload, default=lambda o: getattr(o, "text", str(o)))
    assert '"PE"' in text or "PE" in text


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    # no PYTHONIOENCODING on purpose: the CLI must survive a legacy-codepage pipe (cp936/cp1252)
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONIOENCODING", "PYTHONUTF8")}
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "malcatsql", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        timeout=300,
    )


def test_cli_command_and_formats(sample: Path) -> None:
    r = _cli(str(sample), "--no-project", "-c", "SELECT key, value FROM binary WHERE key IN ('filetype','processor')")
    assert r.returncode == 0, r.stderr
    assert "PE" in r.stdout and "X64" in r.stdout and "2 row(s)" in r.stdout
    r = _cli(str(sample), "--no-project", "--format", "json", "-c", "SELECT hex(addr) AS a FROM funcs LIMIT 1")
    env = json.loads(r.stdout)
    assert env["success"] and env["results"][0]["rows"][0][0].startswith("0x")
    r = _cli(str(sample), "--no-project", "-c", "SELECT * FROM pseudocode")
    assert r.returncode == 1 and "func_addr" in r.stderr


def test_cli_sql_file_and_options(sample: Path, tmp_path: Path) -> None:
    script = tmp_path / "q.sql"
    script.write_text("SELECT count(*) AS n FROM funcs;\nSELECT 'done';\n", encoding="utf-8")
    r = _cli(str(sample), "--no-project", "-o", "flirt_disable=true", "-f", str(script), "--format", "csv")
    assert r.returncode == 0, r.stderr
    assert r.stdout.splitlines()[0] == "n" and "done" in r.stdout


def test_cli_prints_non_ascii_through_a_pipe(sample: Path) -> None:
    # notepad's VersionInfo contains '©', which crashed print() on a cp936 pipe before the fix
    for fmt in ("table", "json", "csv"):
        r = _cli(str(sample), "--no-project", "--format", fmt, "-c", "SELECT value FROM metadata")
        assert r.returncode == 0, (fmt, r.stderr)
        assert "©" in r.stdout


def test_cli_missing_file() -> None:
    r = _cli("Z:\\nope\\missing.exe", "-c", "SELECT 1")
    assert r.returncode == 1 and "not found" in r.stderr
