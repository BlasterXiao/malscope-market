---
name: python
description: "Execute Python against the session's Malcat analysis through malcatsql (malcat_python / malcat_python_file). Use when SQL surfaces are insufficient and direct Malcat API access is needed: custom decoders, extracting carved/virtual files, unexposed APIs."
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
---

# Python inside the session

`malcat_python(code)` / `malcat_python_file(path)` run Python in the malcatsql process against
the same Malcat analysis the SQL tables read, and return captured stdout.

## Gate (off by default)

```sql
SELECT value FROM runtime_settings WHERE key = 'enable_python';
UPDATE runtime_settings SET value = '1' WHERE key = 'enable_python';
UPDATE runtime_settings SET value = '200000' WHERE key = 'python_output_max';  -- stdout cap
```

or start with `malcatsql <file> --enable-python`. Over HTTP/MCP this is code execution on the
analyst machine: keep servers on loopback or behind `--token`.

## Namespace

| Name | Value |
|------|-------|
| `analysis`, `a` | the session's `malcat.Analysis` |
| `malcat` | the `malcat` module |
| `va(ea)` / `ea(addr)` | Malcat EA → virtual address / virtual address → EA |
| `sql(query, *args)` | run SQL on the same connection, returns a list of row tuples |
| `session` | malcatsql `Session` (project path, caches) |

Malcat APIs speak **effective addresses (EA)**; SQL speaks virtual addresses. Convert with
`ea(...)` going in and `va(...)` coming out.

## Rules that keep the session sane

1. **Never keep Malcat objects across calls.** `Function`/`BasicBlock`/`Instruction`/`Reference`
   objects become invalid after Malcat re-analyses (`analysis.run()`, project load). Reusing one
   returns silently wrong data or crashes the process. Re-fetch by address (`a.fns.find(ea)`).
2. After any `malcat_python()` call malcatsql marks the session dirty, so the next SQL read pays
   one `Analysis.run()` and sees your changes (labels, comments).
3. Do not call `analysis.load()` or `malcat.analyse()` on the same file from here; open another
   malcatsql session instead.
4. Kesakode lookups (`analysis.kesakode_lookup(...)`) consume license quota; only on explicit
   request.

## Examples

```sql
-- quick facts
SELECT malcat_python('print(analysis.type, analysis.architecture.name, len(list(analysis.fns)))');

-- use SQL from Python, then the Malcat API
SELECT malcat_python('
top = sql("SELECT addr FROM funcs ORDER BY size DESC LIMIT 1")[0][0]
fn = analysis.fns.find(ea(top))
print(fn.name, fn.num_bb_code, [c.name for c in fn.callees][:5])
');
```

Extract a carved file for a second malcatsql session (writes outside the sample folder):

```sql
SELECT malcat_python('
import pathlib
for i, c in enumerate(analysis.carved):
    data = analysis.file.read(analysis.a2p(c.address), c.size)
    out = pathlib.Path(r"C:/cases/out") / f"carved_{i}_{c.type}.bin"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    print(out, len(data))
');
```

Run a script file (custom string decoder, config extractor...):

```sql
SELECT malcat_python_file('C:/cases/decode_strings.py');
```

## Related skills

- `connect` for runtime settings and server auth
- `annotations` to write results back through SQL (preferred over Python for renames/comments)
