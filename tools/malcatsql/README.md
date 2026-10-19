# malcatsql

SQL interface for [Malcat](https://malcat.fr) analyses, modelled on
[bnsql](https://github.com/0xeb/bnsql). This folder is the engine; the Claude Code / Codex skills
that drive it are the `malcatsql` plugin of this marketplace (`plugins/malcatsql`).

```bash
malcatsql sample.exe -c "SELECT hex(addr), name, size FROM funcs ORDER BY size DESC LIMIT 10"
malcatsql sample.exe --http 8081     # session server: analyse once, POST /query many times
malcatsql sample.exe --mcp 9997      # MCP tools: query, status
```

Malcat analyses the file **statically** with its headless engine; nothing is executed and nothing
needs to run in the Malcat GUI.

### Several samples at once

```bash
malcatsql family_a.exe family_b.exe old=C:\cases\loader.dll --http 8081
malcatsql --url http://127.0.0.1:8081 -c "SELECT alias, filetype, functions FROM samples"
malcatsql --url http://127.0.0.1:8081 --sample old -c "SELECT * FROM binary"
```

`collect(name, sql)` runs a query on every sample and gathers the rows into a table with a
`sample` column; from there ordinary SQL answers cross-sample questions (shared strings, imports,
detections, code reuse via `func_hashes.pic_hash`), and `on_sample(alias, sql)` writes back, e.g.
carrying names from a solved sample to its relatives in one validated statement. See the
`workspace` skill.

## What you get

| Area | Surfaces |
|------|----------|
| Orientation | `binary`, `capabilities`, `runtime_settings`, `entries`, `metadata`, `entities` |
| Code | `funcs`, `segments`, `blocks`, `cfg_edges`, `instructions`, `loops` |
| References | `xrefs`, `call_edges`, `callers`, `callees`, `imports`, `import_refs` |
| Data | `strings`, `string_refs`, `byte_search`, `structures`, `carved`, `vfiles` |
| Malcat detections | `signatures`, `signature_hits` (Yara), `capa`, `capa_matches`, `anomalies`, `constants` |
| Decompiler | `decompile()`, `pseudocode`, `decompile_aliases` (writable) |
| Annotations | `comments`, `names`, `funcs.name`, `set_name()`, `set_comment()`, `save()` → `<file>.malcat` project, which the Malcat GUI loads automatically when you open the sample |
| Escape hatch | `malcat_python()` (gated) |

Full column list: [`plugins/malcatsql/skills/connect/references/schema-catalog.md`](../../plugins/malcatsql/skills/connect/references/schema-catalog.md)
(generated from a live session by `scripts/gen_catalog.py`).

## Requirements

- Malcat 0.9.x with a license that allows the Python API (tested with 0.9.15).
- **CPython 3.13** (Malcat's `malcat.pyd` is built for 3.13 only) with the `malcat` module
  importable: run `python install_api.py` from the Malcat directory with that interpreter.
- `apsw>=3.53` (SQLite with virtual tables), and for servers `fastapi`, `uvicorn`, `mcp`.

## Install

From the root of the malscope-market checkout, with the Python 3.13 that can `import malcat`:

```powershell
py -3.13 -m pip install -e "tools/malcatsql[server]"
malcatsql --version          # needs Python 3.13's Scripts folder on PATH
```

Then install the skills: `/plugin install malcatsql@malscope-market`. `/envcheck malcatsql` checks
the whole setup (see `plugins/envcheck/skills/envcheck/setup/malcatsql.md`).

Always call it as `malcatsql`, not `python -m malcatsql`: the sample-execution guard hook on
analysis machines denies commands that combine a protected sample folder with `python`.

## Skills

| Skill | Use it for |
|-------|-----------|
| `connect` | starting a session (one-shot or session server), CLI/HTTP/MCP, address model, contracts, routing |
| `analysis` | triage, ranking functions, crypto/network/persistence hunting |
| `detections` | Yara, capa (ATT&CK/MBC), anomalies, known constants |
| `disassembly` | functions, sections, blocks, CFG edges, instructions, loops |
| `xrefs` | references, call graph, imports and API call sites |
| `data` | strings, byte patterns, file structures, carved/virtual files, metadata |
| `decompiler` | pseudo-C, line search, variable aliases |
| `annotations` | renames, comments, labels, save/reload |
| `functions` | SQL function reference |
| `workspace` | several samples in one endpoint: `collect()`, `on_sample()`, cross-sample joins, name propagation |
| `python` | gated Python against the live Malcat API |

## Layout

```
tools/malcatsql/                    this engine (pip install -e)
  src/malcatsql/
    session.py      malcat analysis owner: address model, deferred run(), caches, projects
    vtab.py         apsw virtual-table plumbing (pushdown, hidden columns, writes)
    tables.py       every table + views
    functions.py    scalar SQL functions
    engine.py       connection, runtime settings, statement execution, timeouts
    worker.py       single thread owning malcat for the servers
    workspace.py    several samples in one endpoint
    client.py       `--url` client for running servers
    cli.py / http_server.py / mcp_server.py
  scripts/gen_catalog.py            regenerates the plugin's schema/function catalogs
  tests/                            pytest suite (notepad.exe; -m slow uses shell32.dll)
plugins/malcatsql/                  the skills + agent (Claude Code / Codex plugin)
```

## Engine notes (why it is built this way)

- **Virtual tables, not materialized tables.** shell32.dll has 1.5 M instructions; materializing
  them takes ~80 s and ~325 MB. With apsw virtual tables, `WHERE func_addr = X` disassembles
  one function (0.6 s for a 15 k-instruction function) and joins push the address per row.
- **No Malcat object outlives a `Filter` call.** `Function`/`BasicBlock`/... objects are invalid
  after `Analysis.run()`/`load()` and then return wrong data or crash the process. Surfaces copy
  plain ints/strings out immediately; caches are keyed by a generation counter.
- **Deferred re-analysis.** Labels need `Analysis.run()` (~1.5 s on big DLLs, independent of how
  many labels changed). Writes only mark the session dirty; the next read runs it once.
- **Virtual addresses in SQL.** Malcat's API uses effective addresses (EA); SQL exposes VAs (as
  printed in disassembly/pseudo-C), with `ea`/`offset` columns where useful.
- **Decompile aliases.** Malcat stores them in the project, but headless `decompile()` ignores
  them; malcatsql applies them as whole-word renames on output.
- **One engine thread.** HTTP/MCP requests are queued to a dedicated thread that owns the
  analysis and the SQLite connection.
- **Cooperative timeouts.** `query_timeout_ms` interrupts both SQLite work (progress handler)
  and long Python-side scans.

## Development

```powershell
python -m pytest -q                 # fast suite (notepad.exe)
python -m pytest -q -m slow         # large-binary checks (shell32.dll)
python scripts/gen_catalog.py       # refresh generated catalogs after changing surfaces
```

`tests/test_skill_examples.py` executes every ```` ```sql ```` block of the skills, so docs and engine
cannot drift apart silently.
