# malcatsql CLI reference

## Modes

| Invocation | Behaviour |
|------------|-----------|
| `malcatsql <file>` | Interactive REPL (default) |
| `malcatsql <file> -c "<sql>"` | Run one or more `;`-separated statements, print, exit |
| `malcatsql <file> -f q.sql` | Run a SQL file, print, exit |
| `malcatsql <file> --http [port]` | FastAPI server, default port 8081 |
| `malcatsql <file> --mcp [port]` | MCP server (streamable HTTP at `/mcp`), default port 9997 |

Exit code: `0` when every statement succeeded, `1` on the first SQL error (stderr gets `Error: ...`)
or when the file cannot be opened.

`-s/--source <file>` is an alias of the positional file.

## Output formats (`--format`)

- `table` (default): boxed table with a `N row(s)` footer; NULL prints as `NULL`; cells are cut at
  80 chars (use `json` for full text such as pseudo-C).
- `json`: the full envelope `{success, results:[...], elapsed_ms, error}`.
- `csv`: header + rows per statement.

## Projects (`.malcat`)

- Default project path: `<file>.malcat` (next to the sample). Loaded automatically if present.
- `--project other.malcat` uses an explicit path (for load *and* the default `save()` target).
- `--no-project` ignores any existing project (pristine analysis).
- Passing `sample.exe.malcat` as `<file>` opens `sample.exe` and loads that project.
- What persists (verified by the test-suite): user labels (`funcs.name`, `names`), comments,
  decompile aliases.

## Malcat analysis options (`-o KEY=VALUE`, repeatable)

Passed to `malcat.analyse(path, options)`. Values `true/false/yes/no/on/off` become booleans,
numbers (`0x...` allowed) become ints, anything else stays text.

| Option | Effect |
|--------|--------|
| `num_threads=8` | analysis threads |
| `filetype_force=PE` | force a file type parser |
| `imagebase_force=0x400000` | force the image base |
| `flirt_disable=true` | skip FLIRT library signatures |
| `sign_disable=true` | skip Yara (empties `signatures`) |
| `anom_disable=true` | skip anomaly detection |
| `cons_disable=true` | skip known-constant scanning |
| `str_disable=true` / `str_minsize=6` | strings off / minimum length |
| `subf_disable=true` | skip carving (empties `carved`) |
| `xref_disable=true` | skip cross-references (breaks `xrefs`, `callers`...) |
| `cfg_disable=true` / `func_disable=true` | skip CFG / function recovery (breaks most code tables) |

Disabling analyses speeds up opening huge files but empties the matching tables.

## REPL dot-commands

| Command | Action |
|---------|--------|
| `.tables` | list tables and views |
| `.schema [name]` | columns (with `HIDDEN` markers) for one or all surfaces |
| `.mode table\|json\|csv` | switch output format |
| `.save [path]` | `SELECT save([path])` |
| `.status` | session status JSON |
| `.help` | help |
| `.quit` / `.exit` | leave; warns when annotations are unsaved |

SQL statements end with `;` (multi-line input is buffered until the statement is complete).

## Environment

- Requires CPython **3.13** with Malcat's `malcat` module importable (run Malcat's
  `install_api.py` with that interpreter) and `apsw>=3.53`.
- Servers additionally need `fastapi`, `uvicorn`, `mcp` (`pip install malcatsql[server]`).
- Malcat needs a license that allows headless/API use.
