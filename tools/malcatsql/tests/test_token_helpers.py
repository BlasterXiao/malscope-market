"""Helpers that keep big-function analysis cheap in tokens: profile, grep, windows, compact, xor."""

from __future__ import annotations

import json
import re

from conftest import err, q
from malcatsql.engine import Engine
from malcatsql.functions import DECL_LINE, NOISE_LINE


def biggest(engine: Engine) -> int:
    return q(engine, "SELECT addr FROM funcs ORDER BY size DESC LIMIT 1")[0][0]


def test_func_profile_is_small_and_consistent(engine: Engine) -> None:
    addr = biggest(engine)
    raw = q(engine, f"SELECT func_profile({addr})")[0][0]
    p = json.loads(raw)
    stats = q(engine, f"SELECT name, size, num_bb, num_instructions, num_api_calls FROM funcs WHERE addr = {addr}")[0]
    assert (p["name"], p["size"], p["basic_blocks"], p["instructions"], p["api_calls"]) == tuple(stats)
    assert p["addr"] == addr
    assert len(raw) < 12_000
    # every listed callee must be a real callee according to the call graph view
    callees = {c[0] for c in p["callees"]["items"]}
    assert callees <= {r[0] for r in q(engine, f"SELECT callee_addr FROM callees WHERE func_addr = {addr}")}
    # imports/strings are plain lists with totals
    assert p["imports"]["total"] >= len(p["imports"]["items"])
    assert json.loads(q(engine, f"SELECT func_profile({addr}, 3)")[0][0])["callees"]["items"].__len__() <= 3


def test_func_profile_requires_function_start(engine: Engine) -> None:
    addr = biggest(engine)
    assert "no function starts" in err(engine, f"SELECT func_profile({addr + 1})")


def test_pseudocode_grep_context_and_numbers(engine: Engine) -> None:
    addr = biggest(engine)
    full = q(engine, f"SELECT decompile({addr})")[0][0].splitlines()
    word = next(w for w in ("return", "if (", "while") if any(w in l for l in full))
    out = q(engine, f"SELECT pseudocode_grep({addr}, '{re.escape(word)}', 1, 5)")[0][0]
    assert "matching lines" in out
    first = out.splitlines()[0]
    number = int(first.split("|")[0])
    assert full[number - 1] in first  # numbering is the original 1-based line number
    assert len(out) < len("\n".join(full))
    assert "no match" in q(engine, f"SELECT pseudocode_grep({addr}, 'zzzz_never_zzzz')")[0][0]
    assert "bad regex" in err(engine, f"SELECT pseudocode_grep({addr}, '(')")


def test_decompile_lines_window(engine: Engine) -> None:
    addr = biggest(engine)
    full = q(engine, f"SELECT decompile({addr})")[0][0].splitlines()
    out = q(engine, f"SELECT decompile_lines({addr}, 5, 10)")[0][0]
    shown = [l for l in out.splitlines() if "|" in l]
    assert shown and all(5 <= int(l.split("|")[0]) <= 14 for l in shown)
    assert all(NOISE_LINE.match(full[i]) or any(full[i] in l for l in shown) for i in range(4, 14))


def test_decompile_compact_drops_noise_only(engine: Engine) -> None:
    addr = biggest(engine)
    full = q(engine, f"SELECT decompile({addr})")[0][0].splitlines()
    out = q(engine, f"SELECT decompile_compact({addr})")[0][0]
    kept = [l.split("| ", 1)[1] for l in out.splitlines() if "| " in l]
    assert sum(len(l) for l in kept) < len("\n".join(full))  # content shrinks (numbers are extra)
    assert not any(NOISE_LINE.match(l) or DECL_LINE.match(l) for l in kept)
    # nothing meaningful is lost: every non-noise statement line appears
    for line in full:
        if line.strip() and not NOISE_LINE.match(line) and not DECL_LINE.match(line):
            assert line in kept


def test_noise_filters_do_not_eat_real_statements() -> None:
    assert NOISE_LINE.match("    *(&uStack_20 + iVar9) = 0x14010bea4;")
    assert not NOISE_LINE.match("    *(&stack0x00000038 + iVar9) = 0xd;")
    assert not NOISE_LINE.match("    x = foo(0x1);")
    assert DECL_LINE.match("    int64_t iVar9;")
    assert DECL_LINE.match("    code *pcVar1;")
    assert not DECL_LINE.match("    return;")
    assert not DECL_LINE.match("    iVar9 = 5;")


def test_xor_helpers(engine: Engine) -> None:
    assert q(engine, "SELECT hex(xor_bytes(x'6162', 0x20))") == [["4142"]]
    assert q(engine, "SELECT hex(xor_bytes('AB', 'k'))") == [["2A29"]]  # 0x41^0x6b, 0x42^0x6b
    # bytes listed in skip are left alone (decoder loops that skip 0x00 / 0x50 etc.)
    assert q(engine, "SELECT hex(xor_bytes(x'0061', 0x50, x'00'))") == [["0031"]]
    assert "empty key" in err(engine, "SELECT xor_bytes(x'00', x'')")
    # read_xor_string round-trips: encode what is at an address, then decode it back
    addr = q(engine, "SELECT addr FROM strings WHERE addr IS NOT NULL AND type = 'user' AND size >= 8 LIMIT 1")[0][0]
    plain = q(engine, f"SELECT read_string({addr})")[0][0]
    n = len(plain)
    assert q(engine, f"SELECT read_xor_string({addr}, {n}, 0)") == [[plain]]
    assert q(engine, f"SELECT xor_bytes(xor_bytes(bytes({addr}, {n}), 0x50), 0x50) = bytes({addr}, {n})") == [[1]]
