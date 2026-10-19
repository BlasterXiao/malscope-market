"""Multi-sample workspace: collect(), on_sample(), cross-sample SQL, write validation."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from conftest import NOTEPAD
from malcatsql.http_server import create_app
from malcatsql.worker import EngineWorker, open_engine_factory
from malcatsql.workspace import Workspace, parse_targets

X86 = Path(r"C:\Windows\SysWOW64\notepad.exe")


def rows(ws: Workspace, sql: str, sample: str | None = None) -> list[list[Any]]:
    env = ws.run(sql, sample=sample)
    assert env["success"], env["error"]
    return env["results"][-1]["rows"]


def fail(ws: Workspace, sql: str, sample: str | None = None) -> str:
    env = ws.run(sql, sample=sample)
    assert not env["success"], f"expected failure: {sql}"
    return env["error"]


@pytest.fixture(scope="module")
def ws_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("ws")
    shutil.copyfile(NOTEPAD, d / "a.exe")
    shutil.copyfile(NOTEPAD, d / "b.exe")  # byte-identical twin: every function must match
    if X86.is_file():
        shutil.copyfile(X86, d / "c32.exe")
    return d


@pytest.fixture
def ws(ws_dir: Path) -> Workspace:
    # fresh engines per test: some tests write
    return Workspace([str(ws_dir / "a.exe"), str(ws_dir / "b.exe")] + ([str(ws_dir / "c32.exe")] if (ws_dir / "c32.exe").exists() else []), use_project=False)


def test_alias_parsing() -> None:
    specs = parse_targets([r"C:\x\mal one.exe", r"first=C:\y\z.dll", r"D:\q\mal one.exe", r"E:\9lives.bin"])
    assert [s.alias for s in specs] == ["mal_one", "first", "mal_one_2", "s_9lives"]
    assert specs[1].path == r"C:\y\z.dll"


def test_samples_table(ws: Workspace) -> None:
    got = rows(ws, "SELECT alias, filetype, processor, functions FROM samples ORDER BY alias")
    assert [r[0] for r in got][:2] == ["a", "b"]
    assert got[0][1:] == ["PE", "X64", 504]
    assert rows(ws, "SELECT count(DISTINCT sha256) FROM samples WHERE alias IN ('a','b')") == [[1]]


def test_single_sample_queries_via_selector(ws: Workspace) -> None:
    assert rows(ws, "SELECT count(*) FROM funcs", sample="a") == [[504]]
    assert "no sample 'zzz'" in fail(ws, "SELECT 1", sample="zzz")
    assert "no such table" in fail(ws, "SELECT * FROM funcs")  # the workspace itself has no funcs


def test_collect_and_cross_sample_join(ws: Workspace) -> None:
    n = rows(ws, "SELECT collect('h', 'SELECT hex(addr) AS addr, pic_hash AS h, num_instructions AS n FROM func_hashes')")[0][0]
    assert n >= 2 * 504
    assert rows(ws, "SELECT count(DISTINCT sample) FROM h")[0][0] >= 2
    # identical twins: every function in a has a same-address, same-hash partner in b
    assert rows(ws, "SELECT count(*) FROM h x JOIN h y ON x.addr = y.addr AND x.h = y.h WHERE x.sample = 'a' AND y.sample = 'b'") == [[504]]
    # column name 'sample' in the user query is renamed instead of clashing
    rows(ws, "SELECT collect('t', 'SELECT 1 AS sample, 2 AS x')")
    assert [c[1] for c in ws.conn.execute("PRAGMA table_info(t)")] == ["sample", "sample_", "x"]


def test_collect_refuses_truncation_and_bad_input(ws: Workspace) -> None:
    rows(ws, "UPDATE runtime_settings SET value='10' WHERE key='collect_max_rows'") if False else None
    ws.settings.set("collect_max_rows", 10)
    assert "more than 10 rows" in fail(ws, "SELECT collect('t', 'SELECT addr FROM funcs')")
    ws.settings.set("collect_max_rows", 1_000_000)
    assert "not a valid table name" in fail(ws, "SELECT collect('bad name', 'SELECT 1')")
    assert "returns no columns" in fail(ws, "SELECT collect('t', 'UPDATE comments SET text = text')")
    assert "collect on a" in fail(ws, "SELECT collect('t', 'SELECT * FROM no_such_table')")
    assert "no sample 'q'" in fail(ws, "SELECT collect('t', 'SELECT 1', 'a,q')")


def test_propagate_names_across_samples_in_one_statement(ws: Workspace) -> None:
    # analyst names functions in a ...
    rows(ws, "SELECT on_sample('a', 'UPDATE funcs SET name = ''decode_cfg'' WHERE addr = (SELECT addr FROM funcs ORDER BY size DESC LIMIT 1)')")
    rows(ws, "SELECT collect('f', 'SELECT f.addr, f.name, h.pic_hash AS h, h.pic_count AS n FROM funcs f JOIN func_hashes h ON h.addr = f.addr')")
    # pic_hash alone is NOT an identity: tiny identical thunks share one. Without pic_count = 1 the
    # same statement renames the wrong functions (this is what the guard below prevents):
    naive = rows(
        ws,
        "SELECT count(*) FROM f x JOIN f y ON x.h = y.h AND x.sample = 'a' AND y.sample = 'b' "
        "WHERE x.name NOT LIKE 'sub\\_%' ESCAPE '\\' AND y.name LIKE 'sub\\_%' ESCAPE '\\'",
    )[0][0]
    assert naive > 1
    # ... and a single SQL statement carries every *unambiguous* matching name over to b
    changed = rows(
        ws,
        "SELECT sum(on_sample(y.sample, printf('UPDATE funcs SET name = %Q WHERE addr = %d', x.name, y.addr))) "
        "FROM f x JOIN f y ON x.h = y.h AND x.sample = 'a' AND y.sample = 'b' AND x.n = 1 AND y.n = 1 "
        "WHERE x.name NOT LIKE 'sub\\_%' ESCAPE '\\' AND y.name LIKE 'sub\\_%' ESCAPE '\\'",
    )[0][0]
    assert changed == 1
    biggest_b = rows(ws, "SELECT name FROM funcs ORDER BY size DESC LIMIT 1", sample="b")
    assert biggest_b == [["decode_cfg"]]


def test_on_sample_write_failures_abort_the_statement(ws: Workspace) -> None:
    msg = fail(ws, "SELECT on_sample('a', 'UPDATE strings SET text = ''x''')")
    assert "mutation.strings.update = false" in msg
    assert "no sample 'nope'" in fail(ws, "SELECT on_sample('nope', 'SELECT 1')")
    got = json.loads(rows(ws, "SELECT on_sample('a', 'SELECT count(*) AS n FROM funcs')")[0][0])
    assert got == {"columns": ["n"], "rows": [[504]]}


def test_decompile_alias_premise_is_validated(ws: Workspace) -> None:
    addr = rows(ws, "SELECT addr FROM funcs WHERE size BETWEEN 40 AND 200 AND num_instructions > 8 LIMIT 1", sample="a")[0][0]
    ws_code = rows(ws, f"SELECT decompile({addr})", sample="a")[0][0]
    var = next(tok for tok in ("param_1", "uVar1", "iVar1", "lVar1") if tok in ws_code)
    # claim about a variable that is not there -> loud failure instead of a silent no-op
    assert "does not occur" in fail(ws, f"INSERT INTO decompile_aliases(func_addr, old_name, new_name) VALUES ({addr}, 'no_such_var', 'x')", sample="a")
    assert "not a valid identifier" in fail(ws, f"INSERT INTO decompile_aliases(func_addr, old_name, new_name) VALUES ({addr}, '{var}', '1bad name')", sample="a")
    # renaming onto an existing name would merge two variables
    other = next(w for w in ("param_2", "uVar2", "iVar2", "lVar2", "param_3") if w in ws_code and w != var)
    assert "already exists" in fail(ws, f"INSERT INTO decompile_aliases(func_addr, old_name, new_name) VALUES ({addr}, '{var}', '{other}')", sample="a")
    rows(ws, f"INSERT INTO decompile_aliases(func_addr, old_name, new_name) VALUES ({addr}, '{var}', 'ctx')", sample="a")
    assert "ctx" in rows(ws, f"SELECT decompile({addr})", sample="a")[0][0]


def test_save_all_writes_every_project(ws: Workspace, ws_dir: Path) -> None:
    rows(ws, "SELECT on_sample('a', 'SELECT set_comment((SELECT addr FROM funcs LIMIT 1), ''hi'')')")
    assert rows(ws, "SELECT unsaved FROM samples WHERE alias = 'a'") == [[1]]
    assert rows(ws, "SELECT save_all()")[0][0] >= 2
    assert (ws_dir / "a.exe.malcat").is_file() and (ws_dir / "b.exe.malcat").is_file()
    assert rows(ws, "SELECT unsaved FROM samples WHERE alias = 'a'") == [[0]]
    for f in ws_dir.glob("*.malcat"):
        f.unlink()


def test_cross_architecture_sample_does_not_match(ws: Workspace) -> None:
    if "c32" not in [r[0] for r in rows(ws, "SELECT alias FROM samples")]:
        pytest.skip("no 32-bit notepad on this machine")
    rows(ws, "SELECT collect('hh', 'SELECT pic_hash AS h FROM func_hashes WHERE num_instructions > 20')")
    shared = rows(ws, "SELECT count(*) FROM hh x JOIN hh y ON x.h = y.h WHERE x.sample = 'a' AND y.sample = 'c32'")
    assert shared == [[0]]  # same source, different ISA: position-independent hashes of x64 vs x86 differ


def test_hamming_on_fuzzy_hashes(ws: Workspace) -> None:
    rows(ws, "SELECT collect('fz', 'SELECT addr, hex(fuzzy_hash) AS fz FROM func_hashes WHERE num_instructions > 30')")
    same = rows(ws, "SELECT count(*), max(hamming(x.fz, y.fz)) FROM fz x JOIN fz y ON x.addr = y.addr AND x.sample = 'a' AND y.sample = 'b'")[0]
    assert same[1] == 0 and same[0] > 10  # identical files -> zero distance
    assert rows(ws, "SELECT hamming(x'00ff', x'0f0f')") == [[8]]
    assert rows(ws, "SELECT hamming(x'00', x'0000')") == [[None]]


def test_workspace_over_http_with_sample_selector(ws_dir: Path) -> None:
    w = EngineWorker(open_engine_factory([str(ws_dir / "a.exe"), str(ws_dir / "b.exe")], use_project=False))
    try:
        client = TestClient(create_app(w))
        st = client.get("/status").json()
        assert st["mode"] == "workspace" and [s["alias"] for s in st["samples"]] == ["a", "b"]
        r = client.post("/query", content="SELECT alias FROM samples ORDER BY alias").json()
        assert r["results"][0]["rows"] == [["a"], ["b"]]
        r = client.post("/query?sample=b", content="SELECT count(*) FROM funcs").json()
        assert r["results"][0]["rows"] == [[504]]
        r = client.post("/query", json={"sql": "SELECT count(*) FROM funcs", "sample": "a"}).json()
        assert r["results"][0]["rows"] == [[504]]
        bad = client.post("/query?sample=zz", content="SELECT 1").json()
        assert bad["success"] is False and "no sample" in bad["error"]
    finally:
        w.close()


def test_single_sample_engine_rejects_sample_selector(engine: Any) -> None:
    env = engine.run("SELECT 1", sample="a")
    assert not env["success"] and "single sample" in env["error"]
