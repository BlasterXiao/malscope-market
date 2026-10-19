---
name: xrefs
description: "Analyze Malcat cross-references via malcatsql: code/data/struct references, callers, callees, imports and import call sites. Use the callers/callees/import_refs views for performance."
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
---

# Cross-References

## Tables and views

| Surface | Columns | Performance |
|---------|---------|-------------|
| `xrefs` | `from_addr`, `to_addr`, `type` (`code`/`data`/`struct`/`symbol`), `is_code`, `access` (`r`/`w`/`x` combos), `from_func` | `to_addr = X` is a direct Malcat lookup; `from_addr = X` and full scans use an index built on first use |
| `call_edges` | `caller_addr`, `callee_addr` | function-level call graph from Malcat |
| `callers` (view) | `func_addr`, `caller_addr`, `caller_name` | who calls `func_addr` |
| `callees` (view) | `func_addr`, `callee_addr`, `callee_name` | what `func_addr` calls |
| `imports` | `addr` (IAT slot), `module`, `name`, `qualified_name` (`module.name`), `ordinal` | tiny |
| `import_refs` (view) | `import_addr`, `module`, `name`, `qualified_name`, `from_addr`, `func_addr`, `func_name` | references to import slots, i.e. API call sites |
| `string_refs` (view) | see `data` skill | |

`from_func` is pre-computed (start VA of the function containing a code reference; NULL for
data/struct references). `type = 'struct'` rows come from Malcat's file-structure parser (e.g.
header fields pointing into the image); filter them out with `is_code = 1` or `type = 'data'`.

## Use views, not per-row UDFs

```sql
-- SLOW-ish: one Malcat lookup per row
SELECT func_start(from_addr), to_addr FROM xrefs WHERE is_code = 1 LIMIT 100;

-- FAST: pre-computed call graph
SELECT func_addr, callee_addr FROM callees LIMIT 100;
```

## Quick patterns

```sql
-- incoming references to one address
SELECT hex(from_addr) AS src, type, access, hex(from_func) AS func, func_at(from_addr) AS func_name
FROM xrefs WHERE to_addr = (SELECT addr FROM funcs ORDER BY size DESC LIMIT 1);

-- outgoing references from one instruction
SELECT hex(to_addr), type FROM xrefs
WHERE from_addr = (SELECT from_addr FROM xrefs WHERE is_code = 1 AND to_addr IS NOT NULL LIMIT 1);

-- functions ranked by number of callers
SELECT f.name, hex(f.addr) AS addr, COUNT(*) AS callers
FROM callers c JOIN funcs f ON f.addr = c.func_addr
GROUP BY c.func_addr ORDER BY callers DESC LIMIT 10;

-- orphan functions (no callers, not an entry/export) - often callbacks or dead code
SELECT hex(f.addr), f.name FROM funcs f
WHERE NOT EXISTS (SELECT 1 FROM call_edges e WHERE e.callee_addr = f.addr)
  AND f.addr NOT IN (SELECT addr FROM entries) LIMIT 30;

-- who calls a given API (any import whose name contains Reg)
SELECT name, func_name, hex(from_addr) AS call_site FROM import_refs
WHERE name LIKE 'Reg%' AND func_addr IS NOT NULL ORDER BY name;

-- import dependencies
SELECT module, COUNT(*) AS api_count FROM imports GROUP BY module ORDER BY api_count DESC;

-- APIs used by one function
SELECT DISTINCT qualified_name FROM import_refs
WHERE func_addr = (SELECT func_addr FROM import_refs WHERE func_addr IS NOT NULL LIMIT 1);

-- call graph two levels down from the entry point
WITH RECURSIVE down(addr, depth) AS (
    SELECT addr, 0 FROM entries WHERE kind = 'entry'
    UNION
    SELECT c.callee_addr, d.depth + 1 FROM down d JOIN callees c ON c.func_addr = d.addr
    WHERE d.depth < 2
)
SELECT DISTINCT d.depth, hex(d.addr) AS addr, f.name FROM down d LEFT JOIN funcs f ON f.addr = d.addr
ORDER BY d.depth, f.name;
```

## Related skills

- `disassembly` for the instruction stream around a reference
- `data` for `string_refs`
- `decompiler` to read the calling code
