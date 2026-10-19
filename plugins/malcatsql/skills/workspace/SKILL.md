---
name: workspace
description: "Analyse several Malcat samples at once with malcatsql: load N files into one SQL endpoint, compare them with ordinary joins (shared strings/imports/constants/detections, code reuse by function hash), and carry names from a solved sample to its relatives in one validated statement."
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
---

# Multi-sample workspace

One server, several samples. Every sample keeps its own full SQL surface (`funcs`, `strings`,
`xrefs`, `decompile()` ...). The workspace adds the glue to ask questions **across** samples in
plain SQL, so the result is a row set you can verify, not a paragraph you have to trust.

## Start

```bash
# aliases default to the file stem; give your own with alias=path
malcatsql family_a.exe family_b.exe old=C:\cases\2024\loader.dll --http 8081
malcatsql --url http://127.0.0.1:8081 -c "SELECT alias, filetype, processor, functions FROM samples"
```

| Where | Runs on |
|-------|---------|
| plain statement (no selector) | the **workspace** (`samples`, tables you `collect()`, the three functions below) |
| `--sample ALIAS`, `?sample=ALIAS` / JSON `"sample"`, MCP `query(sample=...)`, REPL `.use ALIAS` | that one sample, exactly like a single-sample session |
| `on_sample(alias, sql)` inside SQL | one statement on one sample, from within a workspace query |

## The three workspace functions

| Function | Meaning |
|----------|---------|
| `collect(name, sql[, 'a,b'])` | run `sql` on every sample (or the listed aliases) and store all rows in TEMP table `name` with a leading `sample` column; returns the row count. It **refuses** (never truncates silently) past `collect_max_rows`. Blobs arrive as hex text |
| `on_sample(alias, sql)` | SELECT → JSON `{columns, rows}`; INSERT/UPDATE/DELETE → changed rows. A failing statement aborts the whole calling statement, so a wrong premise in a bulk write is an error, not a skipped row |
| `save_all()` | write every sample's `.malcat` project |

After `collect`, the data is an ordinary table: joins, `GROUP BY`, window functions, recursive
CTEs, `json_each` all work.

## Orientation

```sql
SELECT alias, filetype, processor, size, functions, strings, substr(sha256, 1, 12) AS sha, imphash FROM samples;

-- which samples share an import hash (same toolchain / same family build)?
SELECT imphash, group_concat(alias) AS samples, count(*) AS n FROM samples GROUP BY imphash HAVING n > 1;
```

## What do the samples have in common?

```sql
-- strings that appear in at least two samples (Malcat scores them 0-255)
SELECT collect('str', 'SELECT text, score, tag FROM strings WHERE score >= 80 AND length(text) >= 6');
SELECT text, count(DISTINCT sample) AS in_samples, group_concat(DISTINCT sample) AS which, max(score) AS score
FROM str GROUP BY text HAVING in_samples >= 2 ORDER BY in_samples DESC, score DESC LIMIT 30;

-- imports: shared core vs. what only one sample uses
SELECT collect('imp', 'SELECT qualified_name AS api FROM imports');
SELECT api, count(*) AS n, group_concat(sample) AS which FROM imp GROUP BY api HAVING n < (SELECT count(*) FROM samples) ORDER BY n, api LIMIT 40;

-- detection matrix: which Yara rules / capa rules fire in which sample
SELECT collect('sig', 'SELECT id, type FROM signatures');
SELECT id, type, group_concat(sample) AS which FROM sig GROUP BY id ORDER BY count(*) DESC, id LIMIT 30;
SELECT collect('cp', 'SELECT rule, namespace FROM capa');
SELECT rule, count(*) AS n FROM cp GROUP BY rule ORDER BY n DESC LIMIT 20;

-- known crypto constants present in every sample vs. only some
SELECT collect('cst', 'SELECT DISTINCT name, category FROM constants');
SELECT name, category, count(*) AS n, group_concat(sample) AS which FROM cst GROUP BY name, category ORDER BY n DESC LIMIT 20;
```

## Code reuse by function fingerprint

`func_hashes` has `pic_hash` (position-independent code hash: equal means the same code at a
different address or base) and `pic_count` = how many functions **in that sample** share it.
Tiny thunks and stubs share hashes; **only `pic_count = 1` on both sides identifies a function**.
Also filter out trivial sizes.

```sql
SELECT collect('fh', 'SELECT f.addr, f.name, f.size, h.pic_hash AS h, h.pic_count AS n FROM funcs f JOIN func_hashes h ON h.addr = f.addr WHERE f.num_instructions >= 12');

-- how much of `new` is code seen in `old`?
SELECT x.sample AS a, y.sample AS b, count(*) AS shared_functions, sum(x.size) AS shared_bytes
FROM fh x JOIN fh y ON x.h = y.h AND x.n = 1 AND y.n = 1 AND x.sample < y.sample
GROUP BY a, b ORDER BY shared_bytes DESC;

-- the biggest reused functions and what each sample calls them
SELECT hex(x.addr) AS addr_a, x.name AS name_a, hex(y.addr) AS addr_b, y.name AS name_b, x.size
FROM fh x JOIN fh y ON x.h = y.h AND x.n = 1 AND y.n = 1 AND x.sample < y.sample
ORDER BY x.size DESC LIMIT 20;
```

For near matches use Malcat's fuzzy hash. `hamming()` counts differing bits (0 = identical);
**look at the distribution before choosing a threshold**, do not assume one:

```sql
SELECT collect('fz', 'SELECT addr, hex(fuzzy_hash) AS fz FROM func_hashes WHERE num_instructions >= 30');
SELECT x.sample AS a, y.sample AS b, hamming(x.fz, y.fz) AS bits, count(*) AS pairs
FROM fz x JOIN fz y ON x.addr = y.addr AND x.sample < y.sample GROUP BY a, b, bits ORDER BY bits LIMIT 20;
```

## Carry names from a solved sample to its relatives

Preview first (a plain SELECT), then run the same join through `on_sample`. The guard
`n = 1` on both sides and "only rename what is still unnamed" are what keep this exact.

```sql
SELECT collect('names', 'SELECT f.addr, f.name, h.pic_hash AS h, h.pic_count AS n FROM funcs f JOIN func_hashes h ON h.addr = f.addr WHERE f.num_instructions >= 12');

-- 1. preview: which unnamed functions in `new` would get which name from `old`?
SELECT hex(y.addr) AS addr_new, y.name AS now, x.name AS from_old
FROM names x JOIN names y ON x.h = y.h AND x.n = 1 AND y.n = 1 AND x.sample = 'old' AND y.sample = 'new'
WHERE x.name NOT LIKE 'sub\_%' ESCAPE '\' AND y.name LIKE 'sub\_%' ESCAPE '\';

-- 2. apply (the select list evaluates on_sample once per row; any failure aborts everything)
SELECT sum(on_sample('new', printf('UPDATE funcs SET name = %Q WHERE addr = %d', x.name, y.addr))) AS renamed
FROM names x JOIN names y ON x.h = y.h AND x.n = 1 AND y.n = 1 AND x.sample = 'old' AND y.sample = 'new'
WHERE x.name NOT LIKE 'sub\_%' ESCAPE '\' AND y.name LIKE 'sub\_%' ESCAPE '\';

-- 3. persist every sample's annotations
SELECT save_all();
```

The same pattern moves comments (`on_sample('new', printf('SELECT set_comment(%d, %Q)', ...))`).

## Drilling into one sample

```sql
-- from a workspace query, read one thing from one sample
SELECT on_sample('old', 'SELECT func_profile((SELECT addr FROM funcs ORDER BY size DESC LIMIT 1))');
```

or switch the whole session with `--sample old` / `.use old`, then use the other skills
(`decompiler`, `xrefs`, ...) unchanged.

## Rules of thumb

- Facts come from rows. Say "N functions match with `pic_count = 1`", not "the samples look related".
- A hash match is evidence of identical code, not of identical purpose; read the function before
  you rename on faith, and prefer the preview step.
- Writes are validated by the engine (unmapped addresses, missing variables, read-only tables all
  fail loudly). If a bulk write errors, the premise was wrong: fix the query, do not work around it.
- `collect` copies rows into memory. Select only the columns you need and filter first.
