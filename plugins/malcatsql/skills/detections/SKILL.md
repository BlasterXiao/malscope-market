---
name: detections
description: "Query Malcat's built-in detections through malcatsql: Yara signatures and hit locations, capa rules with ATT&CK/MBC, anomalies, and known constants (crypto tables, hashes, magic values)."
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
---

# Malcat Detections

These surfaces are Malcat-specific (no Binary Ninja equivalent). They are the fastest way to
learn what a sample is before reading any code.

## Tables

| Table | Columns (key ones) | Notes |
|-------|--------------------|-------|
| `signatures` | `id`, `name`, `type`, `category`, `reliability`, `description`, `tags`, `num_patterns` | Matching Yara rules. `type`: `malware`, `suspicious`, `uncommon`, `tool`, `info`. `reliability` 0 (FP-prone) .. 100 |
| `signature_hits` | `rule_id`, `pattern`, `addr`, `offset`, `size`, `func_addr` | Where each rule's strings/byte patterns matched (rules with only conditions have no rows) |
| `capa` | `rule`, `namespace`, `scope`, `attack`, `mbc`, `description`, `num_matches` | Computed on first query and cached; `attack`/`mbc` are JSON arrays |
| `capa_matches` | `rule`, `addr`, `scope`, `func_addr` | Match locations per capa rule |
| `anomalies` | `name`, `category`, `level`, `label`, `comment`, `addr`, `size` | One row per location; `level`: `trace` < `odd` < `warning` < `error` |
| `constants` | `addr`, `name`, `category`, `size`, `is_code`, `func_addr` | Known constants; `func_addr` set for immediates in code |

Pushdown: `signatures.id/type`, `signature_hits.rule_id/func_addr`, `capa.rule`,
`capa_matches.rule/func_addr`, `anomalies.name/category/level`,
`constants.addr/name/category/func_addr`.

## Yara

```sql
-- Verdict-oriented view
SELECT id, type, category, reliability, description
FROM signatures
ORDER BY CASE type WHEN 'malware' THEN 0 WHEN 'suspicious' THEN 1 WHEN 'tool' THEN 2
                   WHEN 'uncommon' THEN 3 ELSE 4 END, reliability DESC;

-- Where did the patterns hit, and in which function?
SELECT h.rule_id, h.pattern, hex(h.addr) AS addr, h.offset, h.size, f.name AS func
FROM signature_hits h LEFT JOIN funcs f ON f.addr = h.func_addr
ORDER BY h.rule_id;
```

## capa

```sql
SELECT rule, namespace, scope, num_matches, attack FROM capa ORDER BY namespace;

-- ATT&CK techniques present (attack is a JSON array)
SELECT DISTINCT j.value AS technique
FROM capa, json_each(capa.attack) AS j
ORDER BY technique;

-- Functions carrying the most capa behaviours
SELECT hex(m.func_addr) AS func, f.name, COUNT(DISTINCT m.rule) AS rules,
       group_concat(DISTINCT m.rule) AS what
FROM capa_matches m LEFT JOIN funcs f ON f.addr = m.func_addr
WHERE m.func_addr IS NOT NULL
GROUP BY m.func_addr ORDER BY rules DESC LIMIT 15;
```

The first `capa`/`capa_matches` query runs capa (about 1.5 s on a small PE, much longer on large
DLLs). The result is cached for the session and is not affected by renames.

## Anomalies

```sql
SELECT name, level, category, COUNT(*) AS hits, max(comment) AS why
FROM anomalies GROUP BY name
ORDER BY CASE level WHEN 'error' THEN 0 WHEN 'warning' THEN 1 WHEN 'odd' THEN 2 ELSE 3 END;

-- anomaly locations inside code
SELECT a.name, hex(a.addr) AS addr, func_at(a.addr) AS func
FROM anomalies a WHERE a.addr IS NOT NULL AND a.category = 'code' LIMIT 30;
```

## Known constants

```sql
SELECT category, name, COUNT(*) AS hits FROM constants GROUP BY category, name ORDER BY category;

-- crypto constants used in code, with the owning function
SELECT c.name, hex(c.addr) AS addr, f.name AS func
FROM constants c JOIN funcs f ON f.addr = c.func_addr
WHERE c.is_code = 1 ORDER BY f.name;
```

## Not exposed

Kesakode (Malcat's online function/string reputation lookup) consumes license quota and needs
network access, so malcatsql does not call it (`feature.kesakode = false`). Use the Malcat GUI or
`malcat_python()` with `analysis.kesakode_lookup(...)` deliberately if you need it.

## Related skills

- `analysis` for end-to-end triage recipes
- `xrefs` / `decompiler` to follow a detection into code
