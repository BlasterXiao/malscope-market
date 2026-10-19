from __future__ import annotations

from typing import Callable

from conftest import err, q
from malcatsql.engine import Engine


def _small_function_with_caller(e: Engine) -> tuple[int, str, int]:
    callee, name, caller = q(
        e,
        "SELECT f.addr, f.name, c.caller_addr FROM funcs f JOIN callers c ON c.func_addr = f.addr "
        "WHERE f.name LIKE 'sub\\_%' ESCAPE '\\' AND f.size < 200 LIMIT 1",
    )[0]
    return callee, name, caller


def test_comments_crud(fresh: Callable[..., Engine]) -> None:
    e = fresh(use_project=False)
    addr = q(e, "SELECT addr FROM funcs LIMIT 1")[0][0]
    q(e, f"INSERT INTO comments(addr, text) VALUES ({addr}, 'first')")
    assert q(e, f"SELECT text FROM comments WHERE addr = {addr}") == [["first"]]
    assert e.session.a.comments[e.session.ea(addr)].text == "first"
    q(e, f"UPDATE comments SET text = 'second' WHERE addr = {addr}")
    assert q(e, f"SELECT text FROM comments WHERE addr = {addr}") == [["second"]]
    q(e, f"DELETE FROM comments WHERE addr = {addr}")
    assert q(e, "SELECT count(*) FROM comments") == [[0]]
    assert q(e, f"SELECT set_comment({addr}, 'udf')") == [[1]]
    assert q(e, "SELECT addr, text FROM comments") == [[addr, "udf"]]


def test_rename_function_reaches_callers_and_decompiler(fresh: Callable[..., Engine]) -> None:
    e = fresh(use_project=False)
    callee, old, caller = _small_function_with_caller(e)
    q(e, f"UPDATE funcs SET name = 'decrypt_config' WHERE addr = {callee}")
    assert e.session.dirty  # run() deferred
    assert q(e, f"SELECT name FROM funcs WHERE addr = {callee}") == [["decrypt_config"]]
    assert not e.session.dirty
    assert ["decrypt_config"] in q(e, f"SELECT name FROM names WHERE addr = {callee}")
    assert q(e, f"SELECT callee_name FROM callees WHERE func_addr = {caller} AND callee_addr = {callee}") == [["decrypt_config"]]
    assert "decrypt_config" in q(e, f"SELECT decompile({caller})")[0][0]
    q(e, f"UPDATE funcs SET name = NULL WHERE addr = {callee}")
    assert q(e, f"SELECT name FROM funcs WHERE addr = {callee}") == [[old]]


def test_batch_rename_runs_analysis_once(fresh: Callable[..., Engine]) -> None:
    e = fresh(use_project=False)
    s = e.session
    calls = {"n": 0}
    original = s.ensure_fresh

    def counting() -> None:
        if s.dirty:
            calls["n"] += 1
        original()

    s.ensure_fresh = counting  # type: ignore[method-assign]
    q(e, "UPDATE funcs SET name = 'batch_' || substr(hex(addr), 3) WHERE addr IN (SELECT addr FROM funcs WHERE name LIKE 'sub\\_%' ESCAPE '\\' LIMIT 20)")
    assert q(e, "SELECT count(*) FROM funcs WHERE name LIKE 'batch\\_%' ESCAPE '\\'") == [[20]]
    assert calls["n"] == 1  # 20 labels, one deferred Analysis.run()


def test_names_insert_delete(fresh: Callable[..., Engine]) -> None:
    e = fresh(use_project=False)
    addr = q(e, "SELECT addr FROM strings WHERE addr IS NOT NULL AND type = 'user' LIMIT 1")[0][0]
    q(e, f"INSERT INTO names(addr, name) VALUES ({addr}, 'g_config_blob')")
    assert ["g_config_blob", "label"] in q(e, f"SELECT name, type FROM names WHERE addr = {addr}")
    assert q(e, f"SELECT name_at({addr})") == [["g_config_blob"]]
    q(e, f"DELETE FROM names WHERE addr = {addr} AND name = 'g_config_blob'")
    assert ["g_config_blob"] not in q(e, f"SELECT name FROM names WHERE addr = {addr}")
    assert "non-empty name" in err(e, f"INSERT INTO names(addr, name) VALUES ({addr}, '')")


def test_unmapped_address_rejected(fresh: Callable[..., Engine]) -> None:
    e = fresh(use_project=False)
    assert "not mapped" in err(e, "INSERT INTO comments(addr, text) VALUES (0x10, 'x')")


def test_save_and_reload_project(fresh: Callable[..., Engine]) -> None:
    e = fresh(use_project=False)
    callee, _, _ = _small_function_with_caller(e)
    q(e, f"UPDATE funcs SET name = 'persisted_fn' WHERE addr = {callee}")
    q(e, f"SELECT set_comment({callee}, 'persisted comment')")
    facts = dict((k, v) for k, v, _ in q(e, "SELECT * FROM binary"))
    assert facts["unsaved_changes"] == "true"
    path = q(e, "SELECT save()")[0][0]
    assert path.endswith("notepad.exe.malcat")

    reopened = fresh()  # auto-loads <file>.malcat
    facts = dict((k, v) for k, v, _ in q(reopened, "SELECT * FROM binary"))
    assert facts["project_loaded"] == "true"
    assert q(reopened, f"SELECT name FROM funcs WHERE addr = {callee}") == [["persisted_fn"]]
    assert q(reopened, f"SELECT text FROM comments WHERE addr = {callee}") == [["persisted comment"]]

    pristine = fresh(use_project=False)
    assert q(pristine, f"SELECT name FROM funcs WHERE addr = {callee}") != [["persisted_fn"]]


def test_decompile_aliases_rename_variables(fresh: Callable[..., Engine]) -> None:
    e = fresh(use_project=False)
    addr = q(e, "SELECT addr FROM funcs WHERE size BETWEEN 40 AND 200 AND num_instructions > 8 LIMIT 1")[0][0]
    text = q(e, f"SELECT decompile({addr})")[0][0]
    var = next(tok for tok in ("param_1", "uVar1", "iVar1", "lVar1", "pvVar1") if tok in text)
    q(e, f"INSERT INTO decompile_aliases(func_addr, old_name, new_name) VALUES ({addr}, '{var}', 'ctx')")
    assert q(e, f"SELECT old_name, new_name FROM decompile_aliases WHERE func_addr = {addr}") == [[var, "ctx"]]
    renamed = q(e, f"SELECT decompile({addr})")[0][0]
    assert "ctx" in renamed and var not in renamed
    q(e, f"UPDATE decompile_aliases SET new_name = 'ctx2' WHERE func_addr = {addr}")
    assert "ctx2" in q(e, f"SELECT decompile({addr})")[0][0]
    q(e, f"DELETE FROM decompile_aliases WHERE func_addr = {addr}")
    assert var in q(e, f"SELECT decompile({addr})")[0][0]


def test_decompile_aliases_persist_in_project(fresh: Callable[..., Engine]) -> None:
    e = fresh(use_project=False)
    addr = q(e, "SELECT addr FROM funcs WHERE size BETWEEN 40 AND 200 AND num_instructions > 8 LIMIT 1")[0][0]
    q(e, f"INSERT INTO decompile_aliases(func_addr, old_name, new_name) VALUES ({addr}, 'param_1', 'ctx')")
    q(e, "SELECT save()")
    reopened = fresh()
    assert q(reopened, f"SELECT old_name, new_name FROM decompile_aliases WHERE func_addr = {addr}") == [["param_1", "ctx"]]


def test_python_enabled(fresh: Callable[..., Engine]) -> None:
    e = fresh(use_project=False, settings={"enable_python": True})
    out = q(e, "SELECT malcat_python('print(analysis.type, len(list(analysis.fns)) > 100)')")[0][0]
    assert out.strip() == "PE True"
    out = q(e, "SELECT malcat_python('print(sql(\"SELECT count(*) FROM segments\")[0][0] > 3)')")[0][0]
    assert out.strip() == "True"
