from __future__ import annotations

import json

import pytest

from conftest import err, q
from malcatsql.engine import Engine, split_statements
from malcatsql.tables import VIEWS

SKIP_BARE = {"byte_search", "pseudocode"}


def test_every_surface_answers(engine: Engine) -> None:
    for name in engine.table_names():
        if name in SKIP_BARE:
            continue
        env = engine.run(f"SELECT * FROM {name} LIMIT 1")
        assert env["success"], (name, env["error"])


def test_binary_orientation(engine: Engine) -> None:
    facts = dict((k, v) for k, v, _ in q(engine, "SELECT * FROM binary"))
    assert q(engine, "SELECT key FROM binary LIMIT 1") == [["summary"]]
    assert facts["tool_name"] == "malcatsql"
    assert facts["filetype"] == "PE"
    assert facts["processor"] == "X64"
    assert facts["is_64bit"] == "true"
    assert facts["image_base"] == "0x140000000"
    assert len(facts["sha256"]) == 64
    entry = q(engine, "SELECT addr FROM entries WHERE kind = 'entry'")[0][0]
    assert facts["entry_point"] == "0x%X" % entry


def test_addresses_are_virtual(engine: Engine) -> None:
    rows = q(engine, "SELECT addr, name FROM funcs WHERE name LIKE 'sub\\_%' ESCAPE '\\' LIMIT 50")
    assert rows
    for addr, name in rows:
        assert name == "sub_%x" % addr  # Malcat names auto functions after their VA
    # EA column stays available and converts back
    addr, ea = q(engine, "SELECT addr, ea FROM funcs LIMIT 1")[0]
    assert q(engine, f"SELECT va2ea({addr}), ea2va({ea})") == [[ea, addr]]


def test_hex_override(engine: Engine) -> None:
    assert q(engine, "SELECT hex(0x1400019C0), hex(x'00ff'), hex(NULL)") == [["0x1400019C0", "00FF", None]]


def test_instruction_pushdown_matches_function_stats(engine: Engine) -> None:
    for addr, n_ins, n_bb in q(engine, "SELECT addr, num_instructions, num_bb FROM funcs ORDER BY size DESC LIMIT 3"):
        assert q(engine, f"SELECT count(*) FROM instructions WHERE func_addr = {addr}") == [[n_ins]]
        assert q(engine, f"SELECT count(*) FROM blocks WHERE func_addr = {addr}") == [[n_bb]]


def test_join_pushes_function_address(engine: Engine) -> None:
    name, n_ins = q(engine, "SELECT name, num_instructions FROM funcs ORDER BY size DESC LIMIT 1")[0]
    rows = q(
        engine,
        f"SELECT count(*) FROM funcs f JOIN instructions i ON i.func_addr = f.addr WHERE f.name = '{name}'",
    )
    assert rows == [[n_ins]]
    plan = " ".join(str(r) for r in q(engine, f"EXPLAIN QUERY PLAN SELECT * FROM funcs f JOIN instructions i ON i.func_addr = f.addr WHERE f.name = '{name}'"))
    assert "func_addr" in plan


def test_instruction_by_addr(engine: Engine) -> None:
    addr, func_addr = q(engine, "SELECT addr, func_addr FROM instructions WHERE func_addr = (SELECT addr FROM funcs LIMIT 1) LIMIT 1")[0]
    row = q(engine, f"SELECT func_addr, disasm FROM instructions WHERE addr = {addr}")
    assert row[0][0] == func_addr
    assert q(engine, f"SELECT disasm({addr})") == [[row[0][1]]]


def test_byte_search_forms(engine: Engine) -> None:
    a = q(engine, "SELECT addr, size, matched_hex FROM byte_search('48 8B ?? 24') LIMIT 5")
    b = q(engine, "SELECT addr, size, matched_hex FROM byte_search WHERE pattern = '48 8B ?? 24' LIMIT 5")
    assert a == b and len(a) == 5
    assert all(r[2].startswith("488B") and r[2].endswith("24") for r in a)
    assert q(engine, "SELECT search_first('48 8B ?? 24')") == [[a[0][0]]]
    assert hex(a[0][0]).upper()[2:] in q(engine, f"SELECT hex(bytes({a[0][0]}, 4)), hex({a[0][0]})")[0][1]
    assert "no query solution" in err(engine, "SELECT * FROM byte_search")
    capped = q(engine, "SELECT count(*) FROM byte_search('48 8B ?? 24', NULL, NULL, 3)")
    assert capped == [[3]]


def test_pseudocode_requires_function(engine: Engine) -> None:
    assert "func_addr" in err(engine, "SELECT * FROM pseudocode")
    addr, name = q(engine, "SELECT addr, name FROM funcs WHERE size BETWEEN 40 AND 120 LIMIT 1")[0]
    text = q(engine, f"SELECT decompile({addr})")[0][0]
    assert name in text
    lines = q(engine, f"SELECT text FROM pseudocode WHERE func_addr = {addr} ORDER BY line")
    assert "\n".join(r[0] for r in lines) == text.rstrip("\n") or "\n".join(r[0] for r in lines) == "\n".join(text.splitlines())
    assert "no function starts" in err(engine, f"SELECT decompile({addr + 1})")


def test_xrefs_pushdown_consistent_with_scan(engine: Engine) -> None:
    target = q(engine, "SELECT to_addr FROM xrefs WHERE is_code = 1 AND to_addr IS NOT NULL GROUP BY to_addr ORDER BY count(*) DESC LIMIT 1")[0][0]
    pushed = sorted(q(engine, f"SELECT from_addr, type FROM xrefs WHERE to_addr = {target}"))
    scanned = sorted(q(engine, f"SELECT from_addr, type FROM xrefs WHERE to_addr + 0 = {target}"))
    assert pushed == scanned and pushed
    src = pushed[0][0]
    assert [src, target] in q(engine, f"SELECT from_addr, to_addr FROM xrefs WHERE from_addr = {src}")


def test_call_graph_views(engine: Engine) -> None:
    caller, callee = q(engine, "SELECT func_addr, callee_addr FROM callees LIMIT 1")[0]
    assert [caller] in q(engine, f"SELECT caller_addr FROM callers WHERE func_addr = {callee}")
    assert q(engine, f"SELECT func_start({callee})") == [[callee]]


def test_string_and_import_views(engine: Engine) -> None:
    rows = q(engine, "SELECT string_addr, func_addr, func_name FROM string_refs WHERE func_addr IS NOT NULL LIMIT 5")
    assert rows
    for _, func_addr, func_name in rows:
        assert q(engine, f"SELECT func_at({func_addr})") == [[func_name]]
    assert q(engine, "SELECT count(*) FROM import_refs WHERE func_addr IS NOT NULL")[0][0] > 0
    modules = {r[0] for r in q(engine, "SELECT DISTINCT module FROM imports")}
    assert "ADVAPI32" in {m.upper() for m in modules}


def test_entities_search(engine: Engine) -> None:
    found = json.loads(q(engine, "SELECT entities_search('CreateFile', 5)")[0][0])
    assert found and all("createfile" in (e["name"] + e["qualified_name"]).lower() for e in found)


def test_detection_surfaces(engine: Engine) -> None:
    assert q(engine, "SELECT count(*) FROM signatures")[0][0] >= 1
    assert q(engine, "SELECT count(*) FROM anomalies")[0][0] >= 1
    rules = q(engine, "SELECT rule, num_matches FROM capa")
    assert rules
    rule, n = rules[0]
    assert q(engine, f"SELECT count(*) FROM capa_matches WHERE rule = '{rule.replace(chr(39), chr(39) * 2)}'") == [[n]]


def test_capabilities_matrix(engine: Engine) -> None:
    caps = dict((k, v) for k, v, _ in q(engine, "SELECT * FROM capabilities"))
    assert caps["mutation.comments.insert"] == "true"
    assert caps["mutation.funcs.update"] == "true"
    assert caps["mutation.funcs.insert"] == "false"
    assert caps["mutation.strings.update"] == "false"
    assert caps["feature.decompiler"] == "true"


def test_read_only_surfaces_reject_writes(engine: Engine) -> None:
    assert "mutation.strings.update = false" in err(engine, "UPDATE strings SET text = 'x' WHERE addr = (SELECT addr FROM strings WHERE addr IS NOT NULL LIMIT 1)")
    assert "mutation.funcs.insert = false" in err(engine, "INSERT INTO funcs(addr, name) VALUES (1, 'x')")
    assert "mutation.binary.delete = false" in err(engine, "DELETE FROM binary WHERE key = 'summary'")


def test_runtime_settings(engine: Engine) -> None:
    q(engine, "UPDATE runtime_settings SET value = '5000' WHERE key = 'byte_search_max_results'")
    assert q(engine, "SELECT value FROM runtime_settings WHERE key = 'byte_search_max_results'") == [["5000"]]
    assert "invalid int" in err(engine, "UPDATE runtime_settings SET value = 'abc' WHERE key = 'query_timeout_ms'")
    q(engine, "UPDATE runtime_settings SET value = '1000' WHERE key = 'byte_search_max_results'")


def test_timeout_interrupts_runaway_query(engine: Engine) -> None:
    q(engine, "UPDATE runtime_settings SET value = '300' WHERE key = 'query_timeout_ms'")
    try:
        message = err(engine, "SELECT count(*) FROM funcs a, funcs b, funcs c")
        assert "nterrupt" in message or "timeout" in message
    finally:
        q(engine, "UPDATE runtime_settings SET value = '120000' WHERE key = 'query_timeout_ms'")


def test_python_gate(engine: Engine) -> None:
    assert "python is disabled" in err(engine, "SELECT malcat_python('print(1)')")


def test_multi_statement_envelope(engine: Engine) -> None:
    env = engine.run("SELECT 1 AS a; SELECT 'x;y' AS b; SELECT count(*) AS n FROM funcs WHERE 0")
    assert env["success"]
    assert [r["columns"] for r in env["results"]] == [["a"], ["b"], ["n"]]
    assert env["results"][1]["rows"] == [["x;y"]]
    assert split_statements("SELECT ';' ; -- c;\nSELECT 2") == ["SELECT ';' ;", "-- c;\nSELECT 2"]


def test_views_registered(engine: Engine) -> None:
    for view in VIEWS:
        assert engine.schema_of(view), view


@pytest.mark.parametrize("table", ["funcs", "strings", "names", "xrefs", "instructions", "byte_search"])
def test_schema_introspection(engine: Engine, table: str) -> None:
    cols = q(engine, f"SELECT name, hidden FROM pragma_table_xinfo('{table}')")
    assert cols
    if table == "byte_search":
        assert ["pattern", 1] in cols
