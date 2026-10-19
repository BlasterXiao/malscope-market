---
name: analysis
description: "malcatsql analysis workflows: malware triage, capability mapping, crypto/network/persistence hunting, function ranking and multi-table queries over a Malcat analysis."
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
---

# Analysis Workflows

High-level recipes that compose the other malcatsql skills (`detections`, `disassembly`,
`xrefs`, `data`, `decompiler`, `annotations`). Malcat analysis is static: nothing here runs the
sample.

## Recipe: unknown sample triage

```sql
-- 1. Orientation
SELECT * FROM binary;
SELECT * FROM entries;
SELECT category, key, value FROM metadata;

-- 2. What Malcat already flags (see `detections`)
SELECT id, type, category, reliability, description FROM signatures ORDER BY reliability DESC;
SELECT name, level, category, COUNT(*) AS hits FROM anomalies GROUP BY name ORDER BY level;
SELECT rule, namespace, attack FROM capa ORDER BY namespace;

-- 3. Layout: packed / odd sections?
SELECT name, hex(start_addr) AS start, size, phys_size, perm FROM segments;

-- 4. Imports hint at the capability surface
SELECT module, COUNT(*) AS apis FROM imports GROUP BY module ORDER BY apis DESC;

-- 5. Most interesting strings (Malcat scores them 0-255)
SELECT hex(addr) AS addr, type, tag, score, substr(text, 1, 80) AS text
FROM strings WHERE score >= 100 ORDER BY score DESC LIMIT 40;

-- 6. Embedded payloads
SELECT name, type, hex(addr) AS addr, offset, size FROM carved;
```

## Recipe: rank functions worth reading first

Malcat's own heuristic (used by its MCP server): malware/unknown category first, then known
constants, xor density, API calls, string references.

```sql
SELECT hex(addr) AS addr, name, size, category, num_known_constants, num_xor_ops,
       num_api_calls, num_string_refs
FROM funcs
WHERE is_library = 0
ORDER BY (category IN ('malware', 'unknown')) DESC, num_known_constants DESC,
         num_xor_ops DESC, num_api_calls DESC, num_string_refs DESC
LIMIT 25;
```

## Recipe: crypto / encoding candidates

```sql
-- Known crypto constants (S-boxes, CRC tables, hash IVs) and the functions using them
SELECT c.name, c.category, hex(c.addr) AS addr, hex(c.func_addr) AS func, f.name AS func_name
FROM constants c LEFT JOIN funcs f ON f.addr = c.func_addr
ORDER BY c.category, c.name;

-- Xor-heavy loops: classic custom decoders
SELECT hex(f.addr) AS addr, f.name, f.num_xor_ops, f.size, COUNT(l.start_addr) AS loops
FROM funcs f JOIN loops l ON l.func_addr = f.addr
WHERE f.num_xor_ops >= 3 AND f.is_library = 0
GROUP BY f.addr ORDER BY f.num_xor_ops DESC LIMIT 20;

-- capa crypto/encoding rules
SELECT rule, namespace FROM capa
WHERE namespace LIKE 'data-manipulation/%' OR namespace LIKE '%crypt%';
```

## Recipe: network / C2 surface

```sql
SELECT module, name, func_name, hex(from_addr) AS call_site
FROM import_refs
WHERE func_addr IS NOT NULL
  AND (module LIKE 'ws2_32%' OR module LIKE 'wininet%' OR module LIKE 'winhttp%'
       OR module LIKE 'urlmon%' OR module LIKE 'dnsapi%' OR module LIKE 'iphlpapi%')
ORDER BY func_name;

-- URLs / IPs / domains Malcat tagged
SELECT tag, hex(addr) AS addr, text FROM strings WHERE tag IN ('url', 'ip') ORDER BY tag;

-- Functions referencing both a network API and a tagged string
SELECT DISTINCT r.func_name, hex(r.func_addr) AS func
FROM import_refs r
JOIN string_refs s ON s.func_addr = r.func_addr
WHERE (r.module LIKE 'ws2_32%' OR r.module LIKE 'wininet%' OR r.module LIKE 'winhttp%')
  AND s.text LIKE '%http%';
```

## Recipe: persistence / execution / injection APIs

```sql
SELECT name, func_name, hex(func_addr) AS func
FROM import_refs
WHERE name IN ('RegSetValueExW', 'RegSetValueExA', 'RegCreateKeyExW', 'CreateServiceW',
               'CreateServiceA', 'ShellExecuteW', 'ShellExecuteExW', 'WinExec',
               'CreateProcessW', 'CreateProcessA', 'VirtualAllocEx', 'WriteProcessMemory',
               'CreateRemoteThread', 'NtUnmapViewOfSection', 'SetWindowsHookExW')
  AND func_addr IS NOT NULL
ORDER BY name;
```

## Recipe: explain one function end-to-end

```sql
-- pick a target (here: the biggest non-library function)
SELECT hex(addr), name FROM funcs WHERE is_library = 0 ORDER BY size DESC LIMIT 1;

-- context: who calls it, what it calls, which strings/imports it touches
SELECT caller_name, hex(caller_addr) FROM callers
WHERE func_addr = (SELECT addr FROM funcs WHERE is_library = 0 ORDER BY size DESC LIMIT 1);
SELECT callee_name, hex(callee_addr) FROM callees
WHERE func_addr = (SELECT addr FROM funcs WHERE is_library = 0 ORDER BY size DESC LIMIT 1);
SELECT DISTINCT substr(text, 1, 80) FROM string_refs
WHERE func_addr = (SELECT addr FROM funcs WHERE is_library = 0 ORDER BY size DESC LIMIT 1);
SELECT DISTINCT qualified_name FROM import_refs
WHERE func_addr = (SELECT addr FROM funcs WHERE is_library = 0 ORDER BY size DESC LIMIT 1);
```

Then read the code with the `decompiler` skill and record conclusions with `annotations`.

## Discovery: `entities` view + `entities_search()`

`entities(name, kind, addr, parent_name, qualified_name, source)` unions functions, non-function
symbols, segments, imports and strings (text truncated to 256 chars).
`entities_search(pattern[, limit[, offset]])` returns a JSON array (case-insensitive substring;
limit defaults to 50, max 500):

```sql
SELECT value ->> 'kind' AS kind, value ->> 'name' AS name, hex(value ->> 'addr') AS addr
FROM json_each(entities_search('Reg', 20));
```

## Related skills

- `detections` for Yara/capa/anomaly/constant details
- `xrefs` and `data` for drilling into references and strings
- `decompiler` + `annotations` to read and document the code
