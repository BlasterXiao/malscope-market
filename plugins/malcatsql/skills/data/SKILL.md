---
name: data
description: "Query Malcat strings, raw bytes and byte patterns via malcatsql (byte_search), plus parsed file structures, carved embedded files, virtual files and metadata."
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
---

# Data: strings, bytes, structures, embedded files

## Tables

| Surface | Key columns | Notes |
|---------|-------------|-------|
| `strings` | `addr`, `text`, `size`, `characters`, `encoding` (`ascii`/`utf8`/`utf16`/`binary`), `type`, `tag`, `score` (0-255), `category`, `num_xrefs`, `entropy`, `offset`, `ea` | `type`: `user` (referenced), `meta` (compiler), `dynamic` (stack strings rebuilt by Malcat), `scanned` (unreferenced). `tag`: `url`, `ip`, `path`, `base64`, `hexa`... |
| `string_refs` (view) | `string_addr`, `text`, `string_type`, `from_addr`, `func_addr`, `func_name` | strings joined with the code that references them |
| `byte_search` | `addr`, `offset`, `size`, `matched_hex` + hidden `pattern` (required), `start_addr`, `end_addr`, `max_results` | Malcat's yara-like hex pattern (`File.search_bytes`): `??` wildcard bytes; Malcat's own example is `00 12 [45-5f] ?? 2f` |
| `structures` | `name`, `category`, `addr`, `offset`, `size`, `ea` | top-level structures parsed by Malcat (MZ, PE, OptionalHeader, sections, resources...) |
| `carved` | `name`, `type`, `category`, `addr`, `offset`, `size` | embedded files Malcat carved (PE in resources, images, archives...) |
| `vfiles` | `path`, `type`, `filetype`, `size`, `unpack_method` | virtual files (archive members, resources, overlay) |
| `metadata` | `category`, `key`, `value` | version info, debug path, compile timestamps... |

`strings.addr` is NULL for strings outside mapped memory (e.g. the DOS stub); use `offset`.

## Strings

```sql
-- most interesting first
SELECT hex(addr) AS addr, type, tag, score, substr(text, 1, 100) AS text
FROM strings WHERE score >= 100 ORDER BY score DESC LIMIT 30;

-- tagged indicators
SELECT tag, hex(addr), text FROM strings WHERE tag IS NOT NULL ORDER BY tag;

-- stack strings Malcat reconstructed
SELECT hex(addr), text FROM strings WHERE type = 'dynamic';

-- which functions use a string
SELECT func_name, hex(func_addr), substr(text, 1, 60) FROM string_refs
WHERE text LIKE '%Software%' LIMIT 20;

-- functions referencing the most strings
SELECT func_name, hex(func_addr), COUNT(*) AS n FROM string_refs
WHERE func_addr IS NOT NULL GROUP BY func_addr ORDER BY n DESC LIMIT 10;
```

## Bytes and patterns

```sql
-- table-valued form
SELECT hex(addr) AS addr, offset, matched_hex FROM byte_search('48 8B ?? 24') LIMIT 10;

-- hidden-column form with a range and a cap
SELECT hex(addr), matched_hex FROM byte_search
WHERE pattern = 'E8 ?? ?? ?? ??' AND start_addr = (SELECT start_addr FROM segments WHERE name = '.text')
  AND max_results = 5;

-- first match only
SELECT hex(search_first('4D 5A 90 00'));

-- raw bytes / C strings at an address
SELECT hex(bytes((SELECT addr FROM funcs LIMIT 1), 16));
SELECT read_string((SELECT addr FROM strings WHERE type = 'user' AND encoding = 'ascii' LIMIT 1));
SELECT read_string((SELECT addr FROM strings WHERE encoding = 'utf16' AND addr IS NOT NULL LIMIT 1), 'utf16le');
```

A bare `SELECT * FROM byte_search` fails with `no query solution`: the pattern is mandatory.
`byte_search_max_results` (runtime setting) caps rows when `max_results` is not given.

## File structure, carved and virtual files

```sql
SELECT name, category, hex(addr), offset, size FROM structures ORDER BY offset LIMIT 40;
SELECT name, type, category, hex(addr), offset, size FROM carved;
SELECT path, type, size, unpack_method FROM vfiles;
SELECT category, key, value FROM metadata;
```

To analyse a carved or virtual file, extract it with `malcat_python()` (see `python` skill) and open
it in a new malcatsql session.

## Related skills

- `xrefs` for references to data
- `detections` for constants and Yara hits inside data
