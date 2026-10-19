---
name: decompiler
description: "Decompile Malcat functions to pseudo-C via malcatsql: decompile(), the pseudocode line table and per-function variable renames (decompile_aliases). Always target one function address."
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
---

# Decompiler

Malcat decompiles x86, x64, ARM, AArch64 and MIPS (`SELECT value FROM capabilities WHERE key =
'feature.decompiler'`). Decompiling costs about **3 seconds per function**; results are cached for
the session until the next rename forces a re-analysis.

## Surfaces

| Surface | Use |
|---------|-----|
| `func_profile(addr[, limit])` | **start here**: JSON summary (size, blocks, loops, callers, callees, imports, strings, constants), a few KB for any function |
| `pseudocode_grep(addr, regex[, context[, max]])` | only the matching lines of the pseudo-C, with original line numbers and context |
| `decompile_lines(addr, start, count)` | a window of lines (original numbers) |
| `decompile_compact(addr)` | numbered full text minus stack-bookkeeping noise, local declarations and blank lines |
| `decompile(addr[, refresh])` | whole function as one raw text block: only for small functions |
| `pseudocode(func_addr, line, text)` | the same text split into lines; **requires** `func_addr = X` |
| `decompile_aliases(func_addr, old_name, new_name)` | rename decompiler variables (`param_1` → `ctx`); writable, persisted by `save()` |

`addr` must be the **start** of a function (`no function starts at 0x...` otherwise); use
`func_start(addr)` to get there from any address inside it.

## Token-saving workflow (big functions)

A large function decompiles to tens of KB, much of it noise (`*(&uStack_20 + iVar9) = 0x...;` stores
of return addresses into alloca frames, repeated inlined string-decode loops). Do **not** pull the
whole text into the conversation. Let SQL answer the question and read only the lines that matter:

```sql
-- 1. the overview, one small JSON document
SELECT func_profile((SELECT addr FROM funcs ORDER BY size DESC LIMIT 1));

-- 2. only the statements you care about, with context and original line numbers
SELECT pseudocode_grep((SELECT addr FROM funcs ORDER BY size DESC LIMIT 1), 'if \(|return', 1, 10);

-- 3. then read a window around a line you found
SELECT decompile_lines((SELECT addr FROM funcs ORDER BY size DESC LIMIT 1), 20, 30);

-- 4. last resort: the compact full text
SELECT length(decompile_compact((SELECT addr FROM funcs ORDER BY size DESC LIMIT 1)));
```

Everything in the answer (addresses, strings, counts) should come from rows like these, not from
memory or guesses. Per-function fact gathering is mechanical work: delegate it to the
`malcat-analyst` agent (Haiku) and keep the main session for choosing what to look at and for
the conclusions.

## Quick patterns

```sql
-- one function
SELECT decompile((SELECT addr FROM funcs WHERE size BETWEEN 60 AND 200 LIMIT 1));

-- from any address inside a function
SELECT decompile(func_start((SELECT addr FROM instructions
                             WHERE func_addr = (SELECT addr FROM funcs ORDER BY size DESC LIMIT 1)
                             LIMIT 1 OFFSET 10)));

-- grep inside one function's pseudo-C
SELECT line, text FROM pseudocode
WHERE func_addr = (SELECT addr FROM funcs WHERE size BETWEEN 60 AND 200 LIMIT 1)
  AND text LIKE '%if (%';

-- force a fresh decompilation (ignore the cache)
SELECT decompile((SELECT addr FROM funcs WHERE size BETWEEN 60 AND 200 LIMIT 1), 1);
```

Never run `SELECT * FROM pseudocode` without a `func_addr` filter: it is refused on purpose.
To survey many functions, pick a short list from `funcs` first (see `analysis` ranking recipe) and
decompile them one by one.

## Renaming variables

```sql
-- inspect current aliases of a function
SELECT * FROM decompile_aliases WHERE func_addr = (SELECT addr FROM funcs WHERE size BETWEEN 60 AND 200 LIMIT 1);

-- rename param_1 -> ctx (old_name must be the decompiler's own name)
INSERT INTO decompile_aliases(func_addr, old_name, new_name)
VALUES ((SELECT addr FROM funcs WHERE size BETWEEN 60 AND 200 LIMIT 1), 'param_1', 'ctx');

-- change / remove
UPDATE decompile_aliases SET new_name = 'config'
WHERE func_addr = (SELECT addr FROM funcs WHERE size BETWEEN 60 AND 200 LIMIT 1) AND old_name = 'param_1';
DELETE FROM decompile_aliases
WHERE func_addr = (SELECT addr FROM funcs WHERE size BETWEEN 60 AND 200 LIMIT 1) AND old_name = 'param_1';
```

Alias writes are **validated**: `old_name` must be a name that really occurs in the function's
decompiled text, `new_name` must be a valid identifier that is not already used in that function
(otherwise two variables would silently merge). A refusal means the variable you meant is not
there: re-read the code instead of retrying.

Malcat stores aliases in the project but its headless decompiler does not render them;
malcatsql applies them to `decompile()`/`pseudocode` output as whole-word renames. Function names
come from labels instead: rename functions with `UPDATE funcs SET name = ...` (`annotations`).

## Review-ready workflow

1. `SELECT decompile(X);`
2. Callers/callees and strings for context (`xrefs`, `data`).
3. Rename the function and key callees (`UPDATE funcs SET name = ... WHERE addr IN (...)`),
   rename variables (`decompile_aliases`), add a summary comment (`set_comment(X, ...)`).
4. `SELECT decompile(X);` again: new names appear (one re-analysis is paid on the first read).
5. `SELECT save();`

## Related skills

- `annotations` for function names and comments
- `disassembly` when the decompiler output is unclear (`disasm_func(X)`)
