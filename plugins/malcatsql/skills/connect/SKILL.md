---
name: connect
description: "Start malcatsql sessions on samples with Malcat's headless engine and route to the other malcatsql skills. Use when starting analysis of a sample with malcatsql/Malcat, choosing between one-shot -c and a session server, or setting up CLI/HTTP/MCP connections."
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
---

## Why SQL (the design principle)

- The answer is a **row set** from the analysis, not a paraphrase: addresses, counts and strings
  come from queries, so they cannot be invented. Report what the query returned.
- Nested/recursive questions (call chains, reachability, "functions that call X but never Y") are
  one `WITH RECURSIVE` away.
- **Writes are checks.** Renames, comments and variable aliases are validated by the engine
  (unmapped address, variable not in the code, read-only table and name collisions all fail
  loudly). If a write is refused, your reading of the code was wrong: fix the premise, do not
  force it.
- Several samples live in one **workspace** (`malcatsql a.exe b.exe ...`, see the `workspace`
  skill): compare strings/imports/detections and match code across samples with ordinary joins.

## How to connect (headless)

malcatsql opens the sample itself with Malcat's headless engine. Nothing needs to be running in
the Malcat GUI and the analyst does not have to start anything: **you** start the session.

| Mode | Command | Use when |
|------|---------|----------|
| **Session server** (default) | `malcatsql <file> --http 8081 -q` in the background, then query it | any real analysis: the sample is analysed once, every later query is instant |
| One-shot | `malcatsql <file> -c "SQL"` | one or two questions; every call re-analyses (2-3 s small PE, 10 s+ large DLL) |
| Workspace server | `malcatsql a.exe b.dll c=<path> --http 8081 -q` | several samples at once (see the `workspace` skill) |
| MCP server | `malcatsql <file> --mcp 9997` | an MCP client wants a `query` tool |

### Start a session (once per sample or workspace)

```bash
# 1. start the server in the background (Bash tool: run_in_background)
malcatsql sample.bin --http 8081 -q

# 2. wait until it answers (analysis takes a few seconds)
curl -s http://127.0.0.1:8081/status

# 3. query it: curl is the fastest client (~0.15 s per call)
curl -s -X POST http://127.0.0.1:8081/query --data-binary "SELECT * FROM binary"
malcatsql --url http://127.0.0.1:8081 -c "SELECT * FROM binary"     # same, ~0.5 s per call
```

- Pick another port if 8081 is taken. Reuse a server that already serves the same sample
  (`GET /status` shows its file) instead of starting a second one.
- One server per sample, or one workspace server for a set. Stop it when the analysis is done
  (stop the background task); unsaved annotations are lost then, so `SELECT save();` first.
- Several statements in one request: separate them with `;`.

### Command name and the sample-execution guard

Always invoke it as **`malcatsql`** (a launcher on PATH). Never write `python -m malcatsql`: this
machine has a hook that denies commands mentioning a protected sample folder together with
`python` or an executable extension (`.exe`, `.dll`, ...). malcatsql never executes the sample,
but the hook cannot know that. If a command is denied:

- do **not** try to get around the hook (renaming, copying, encoding the path);
- tell the analyst which command was denied; they decide (`/unprotect`, or hand you a copy of the
  sample without an executable extension, e.g. named by its hash).

### If `malcatsql` is not installed (first use on a machine)

`malcatsql --version` fails with "command not found" → install it yourself with the plugin's
installer, `scripts/install.ps1` in this plugin's root (two levels above this skill's base
directory). First tell the analyst in one line what it does and wait for their OK, because it
changes the machine:

- checks CPython 3.13 (Malcat's `malcat.pyd` only loads in 3.13);
- makes `import malcat` work by writing `malcat.pth` (Malcat's own `install_api.py` does the same);
  Malcat is auto-detected, otherwise pass `-MalcatDir <folder with bin\malcat.pyd>`;
- `pip install`s the engine from the malscope-market GitHub repository;
- adds the folder holding `malcatsql.exe` to the **user** PATH.

```bash
pwsh -NoProfile -File "<plugin root>/scripts/install.ps1"
pwsh -NoProfile -File "<plugin root>/scripts/install.ps1" -MalcatDir "D:/Tools/malcat"
```

The last line is `MALCATSQL_EXE=<full path>`. Your current shell does not see the new PATH yet:
use that full path for the rest of this session (new sessions just type `malcatsql`). Running the
installer again upgrades the engine.

Stop and hand over to the analyst when it reports: Python 3.13 missing (offer
`winget install Python.Python.3.13`), Malcat not found and they do not know where it is, or
`import malcat` failing because of the license (activating Malcat is theirs to do; never enter a
license key yourself).

## CLI Help (verbatim `malcatsql --help`)

```
usage: malcatsql [-h] [--sample ALIAS] [-s SOURCE] [-c COMMAND] [-f SQL_FILE]
                 [-i] [--http [PORT]] [--mcp [PORT]] [--bind BIND]
                 [--token TOKEN] [--project PROJECT] [--no-project]
                 [-o KEY=VALUE] [--enable-python] [--url URL]
                 [--format {table,json,csv}] [-q] [-v]
                 [file ...]

malcatsql v0.3.0 - SQL interface for Malcat

positional arguments:
  file                  binary or .malcat project; give several ([alias=]path
                        ...) for a multi-sample workspace

options:
  -h, --help            show this help message and exit
  --sample ALIAS        workspace only: run -c/-f (or start the REPL) on this
                        sample instead of the workspace
  -s, --source SOURCE   same as the positional <file>
  -c, --command COMMAND
                        SQL to execute, then exit
  -f, --file SQL_FILE   SQL file to execute, then exit
  -i, --interactive     interactive SQL mode (default)
  --http [PORT]         HTTP server (default 8081)
  --mcp [PORT]          MCP server (default 9997)
  --bind BIND           server bind address (default 127.0.0.1)
  --token TOKEN         auth token for HTTP/MCP (Authorization: Bearer
                        <token>)
  --project PROJECT     explicit .malcat project path (default <file>.malcat)
  --no-project          do not auto-load <file>.malcat
  -o, --option KEY=VALUE
                        malcat.analyse option, e.g. -o flirt_disable=true -o
                        num_threads=8 (repeatable)
  --enable-python       start with enable_python=1
  --url URL             connect to a running malcatsql server (started with
                        `malcatsql <file> --http`)
  --format {table,json,csv}
                        output format for -c/-f/REPL
  -q, --quiet           suppress banner
  -v, --version         show program's version number and exit

<file> is a binary (.exe/.dll/elf/document/archive...) or a .malcat project (its source binary
must sit next to it). Annotations are applied in memory; SELECT save(); writes <file>.malcat,
which is loaded automatically next time.

Examples:
  malcatsql sample.exe -c "SELECT * FROM binary"
  malcatsql sample.exe -c "SELECT hex(addr), name, size FROM funcs ORDER BY size DESC LIMIT 10"
  malcatsql sample.exe --http 8081
  malcatsql sample.exe --mcp 9997
```

**Headless takeaway:** `malcatsql <file>` analyses the sample **statically** (nothing is executed)
in a few seconds (~2 s for 360 KB, ~12 s for an 8 MB DLL). Every `-c` invocation re-analyses, so for
more than a couple of queries start a session server once (`--http`) and query it with curl.

## Additional Resources

- CLI reference, REPL dot-commands, analysis options: [references/cli-reference.md](references/cli-reference.md)
- Canonical schema catalog (generated from a live session): [references/schema-catalog.md](references/schema-catalog.md)
- HTTP / MCP server guide: [references/server-guide.md](references/server-guide.md)

---

## Quick Start (Do This First)

```bash
# Session server (default): analyse once, query many times
malcatsql sample.exe --http 8081 -q                       # background
curl -s -X POST http://127.0.0.1:8081/query --data-binary "SELECT name, size FROM funcs LIMIT 5"

# One-shot queries (re-analyse on every call)
malcatsql sample.exe -c "SELECT * FROM binary"
malcatsql sample.exe -c "SELECT * FROM binary; SELECT COUNT(*) FROM funcs;"

# Interactive REPL (.tables, .schema <t>, .mode json, .save, .quit)
malcatsql sample.exe

# MCP server (streamable HTTP at /mcp, tools: query, status)
malcatsql sample.exe --mcp 9997
```

`malcatsql` runs on the **Python 3.13** that can `import malcat` (Malcat's `malcat.pyd` is built
for 3.13 only). If the command is missing, install it (see "If `malcatsql` is not installed" above).

Critical guardrails:

- Headless: give a file. It can be a raw sample or a `.malcat` project (whose source binary sits
  next to it). `<file>.malcat` is loaded automatically when present; pass `--no-project` for a
  pristine view.
- Writes (`comments`, `names`, `funcs.name`, `decompile_aliases`, `set_name`, `set_comment`) are
  **in memory** until `SELECT save();`, which writes `<file>.malcat` next to the sample.
- Discover schema before writing queries against unfamiliar surfaces:
  - REPL: `.schema <table>`
  - SQL: `PRAGMA table_xinfo(<table>);`
- Start orientation with `SELECT * FROM binary;`.

---

## Address model (read once)

- Every `addr` / `*_addr` column and every address argument is a **virtual address**, the same
  numbers Malcat prints in disassembly and pseudo-C (`sub_140013154` lives at `0x140013154`).
- Print addresses with `hex(addr)`; malcatsql overrides `hex()` so integers render as
  `0x140013154` (blobs/text keep SQLite semantics).
- SQLite accepts hex literals: `WHERE func_addr = 0x140013154`.
- `addr` is **NULL** for bytes that have no virtual address (PE header strings, overlay data);
  such rows still carry `offset` (file offset) and `ea` (Malcat's internal effective address).
- Converters: `va2off(addr)`, `off2va(offset)`, `rva(addr)`, `va2ea(addr)`, `ea2va(ea)`.

---

## Session Bootstrap Contract

1. Start or reuse a session server (`malcatsql <file> --http PORT -q`), or one-shot `-c`.
2. Orientation:
   ```sql
   SELECT * FROM binary;
   ```
3. Validate key entities exist:
   ```sql
   SELECT COUNT(*) AS funcs FROM funcs;
   SELECT COUNT(*) AS strings FROM strings;
   SELECT COUNT(*) AS imports FROM imports;
   ```
4. Check the capabilities matrix before any write:
   ```sql
   SELECT * FROM capabilities WHERE value = 'true';
   ```
5. Introspect target surfaces before complex SQL:
   ```sql
   PRAGMA table_xinfo(funcs);
   PRAGMA table_xinfo(xrefs);
   ```
6. Route to a domain skill using the matrix below.

Never skip steps 2-5 when the request is broad or ambiguous.

---

## Global Agent Contracts

### Read-First Contract

- `SELECT` the current state before any `INSERT`/`UPDATE`/`DELETE`.
- Target writes by stable keys (`addr`, `func_addr`), never by row position.

### Anti-Guessing Contract

- Do not assume columns for long-tail surfaces (`capa`, `signatures`, `anomalies`, `structures`,
  `carved`, `vfiles`, `metadata`, `runtime_settings`, `capabilities`). Use `PRAGMA table_xinfo`.
- Malcat names auto-functions `sub_<lowercase hex VA>`; do not invent names.

### Explicit-Save Contract

- Every write is applied to the session's analysis immediately but lives only in memory.
- `SELECT save();` writes `<file>.malcat` (comments, labels, decompile aliases); the Malcat GUI loads
  it automatically when the analyst opens the sample, so that is how your annotations reach them. `SELECT save('x.malcat')`
  saves elsewhere. `binary.unsaved_changes` tells you whether anything is pending.
- Renames trigger Malcat re-analysis **lazily**: the first read after a batch of renames pays one
  `Analysis.run()` (~0.03 s small files, ~1.5 s large DLLs), no matter how many rows changed. Batch
  renames into one `UPDATE` instead of looping single-row updates with reads in between.

### Performance Contract

- Constrain high-cost surfaces by key columns:
  - `instructions`, `blocks`, `cfg_edges`, `pseudocode`: `func_addr = X`
  - `xrefs`: `to_addr = X` (direct lookup) or `from_addr = X`
- `pseudocode` **refuses** unconstrained scans (decompiling costs ~3 s per function).
- An unconstrained `instructions` scan on a large DLL (1.5 M instructions) runs into
  `query_timeout_ms`; aggregate from `funcs` (`num_instructions`, `num_xor_ops`, `num_api_calls`...) instead.
- Use `callers` / `callees` views (pre-computed call graph) instead of per-row `func_start()` calls.
- The first full `xrefs` scan builds an index (~1 s small, ~20 s for shell32-size DLLs); later
  lookups are instant until the next rename.
- `capa` is computed on first query (seconds to tens of seconds) and cached for the session.

### Failure Recovery Contract

- `no such table/column` → `PRAGMA table_xinfo(...)` and retry.
- `no query solution` on `byte_search` → you forgot the pattern: `FROM byte_search('48 8B ?? 24')`.
- `pseudocode requires a func_addr constraint` → add `WHERE func_addr = 0x...`.
- `mutation.<table>.<op> = false` → that surface is read-only; check `capabilities`.
- `address 0x... is not mapped` → the VA is outside the image; check `segments`.
- `query timeout` → narrow scope or raise `query_timeout_ms` in `runtime_settings`.

### Output Contract

- **Selection**: answer the question; show supporting rows only when they help verification.
- **Fidelity**: when presenting code/data show the real artifact (pseudo-C, actual rows).
- **Mechanics**: HTTP `/query` returns `{success, results:[{statement, columns, rows, row_count,
  truncated, changes}], elapsed_ms, error}`. Consume the JSON directly; do not pipe it through
  `jq`/`python` just to pretty-print.

### Host Safety Contract

- malcatsql only reads the sample (static analysis). It never executes it. The only file it writes
  is the `.malcat` project on `save()`.
- `malcat_python()` executes **your** Python inside the session and is gated off by default.

---

## Skill Routing Matrix (Intent → Skill)

| User intent | Primary skill | Typical first query |
|-------------|---------------|---------------------|
| "what does this sample do?" / triage | `analysis` | `SELECT * FROM binary; SELECT * FROM signatures;` |
| Yara / capa / anomalies / known constants | `detections` | `SELECT rule, namespace FROM capa;` |
| functions, sections, blocks, instructions | `disassembly` | `SELECT * FROM funcs ORDER BY size DESC LIMIT 20;` |
| xrefs, callers/callees, imports | `xrefs` | `SELECT * FROM callers WHERE func_addr = 0x...;` |
| strings, bytes, patterns, embedded files | `data` | `SELECT * FROM strings WHERE score > 100 LIMIT 20;` |
| decompile / pseudo-C / variable renames | `decompiler` | `SELECT decompile(0x...);` |
| comments / renames / save | `annotations` | `SELECT * FROM comments;` |
| SQL function lookup | `functions` | `SELECT name FROM pragma_function_list WHERE name LIKE '%func%';` |
| compare several samples, code reuse, carry names between samples | `workspace` | `SELECT * FROM samples;` |
| run Python against the Malcat API | `python` | `SELECT malcat_python('print(analysis.type)');` |
| runtime knobs / timeouts | `connect` | `SELECT * FROM runtime_settings;` |

Cross-domain order: orientation here → primary skill → enrichment (`xrefs` + `decompiler` +
`annotations`).

---

## binary

Key/value table `(key, value, type)` with `type ∈ {string, hex, bool, int}`; the `summary` row
comes first. Keys: `summary`, `tool_name` (`malcatsql`), `tool_version`, `malcat_version`,
`processor` (Malcat architecture: `X86`, `X64`, `AARCH64`, `ARMV7`, `MIPS32`, `DOTNET`, `PY310`,
`AU3`, `NSIS`, `VBA`, `NONE`...), `filetype` (Malcat file type, e.g. `PE`, `ELF`, `ZIP`, `CFB`),
`category` (`PROGRAM`, `DOCUMENT`, `ARCHIVE`, `IMAGE`, `FILESYSTEM`...), `image_base`, `entry_point`,
`min_addr`, `max_addr`, `is_64bit`, `bits`, `endianness`, `filename`, `file_size`, `md5`, `sha1`,
`sha256`, `imphash`, `project_path`, `project_loaded`, `unsaved_changes`.

```sql
SELECT * FROM binary;
SELECT value FROM binary WHERE key = 'sha256';
```

## runtime_settings

Columns `key, value, type, scope, kind, settable, description`; UPDATE `value` to change a knob.

| Key | Default | Meaning |
|-----|---------|---------|
| `query_timeout_ms` | 120000 | abort a statement after N ms (0 = no limit) |
| `enable_python` | 0 | allow `malcat_python()` / `malcat_python_file()` |
| `python_output_max` | 65536 | cap captured Python stdout |
| `byte_search_max_results` | 1000 | default row cap for `byte_search` |
| `max_result_rows` | 100000 | rows returned per statement over HTTP/MCP |

```sql
UPDATE runtime_settings SET value = '600000' WHERE key = 'query_timeout_ms';
```

## capabilities

`(key, value, description)`. `feature.*` rows (`decompiler`, `capa`, `yara`, `python`, `kesakode`,
`persistence`) and one `mutation.<table>.<insert|update|delete>` row per table. Writable today:
`comments` (I/U/D), `names` (I/U/D), `funcs` (U `name`), `decompile_aliases` (I/U/D),
`runtime_settings` (U `value`). Everything else is read-only and says so in the error.

---

## What Malcat contributes beyond a disassembler

Malcat is a malware-analysis-oriented binary analyser. Besides functions, CFG, xrefs and a
decompiler it ships detections that become SQL tables here: Yara rules (`signatures`,
`signature_hits`), capa rules with ATT&CK/MBC (`capa`, `capa_matches`), anomaly checks
(`anomalies`), known-constant detection for crypto/hash tables (`constants`), file-structure
parsing (`structures`), embedded-file carving (`carved`) and virtual files (`vfiles`). It also
parses scripts/installers/documents (AutoIt, NSIS, VBA, .NET, Python bytecode), so `processor`
may be something other than x86/x64. Check `feature.decompiler` before calling `decompile()`.
