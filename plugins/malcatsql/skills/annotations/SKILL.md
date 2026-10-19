---
name: annotations
description: "Edit Malcat analyses through malcatsql: comments, function/symbol renames (user labels), decompiler variable aliases and persistence. Mutations require SELECT save() to persist into the .malcat project."
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
---

# Annotations

## Writable surfaces

| Surface | Operations | Effect in Malcat |
|---------|------------|------------------|
| `comments(addr, text, ea)` | INSERT / UPDATE `text` / DELETE | user comment at an address |
| `funcs` | UPDATE `name` (NULL/'' removes the label) | user label at the function start |
| `names(addr, name, type, ea)` | INSERT / UPDATE `name` / DELETE | user label at any mapped address |
| `decompile_aliases` | INSERT / UPDATE `new_name` / DELETE | decompiler variable renames (see `decompiler`) |
| `set_name(addr, name)`, `set_comment(addr, text)` | scalar UDFs | same as above, usable inside SELECT |

Everything else is read-only: writes fail with `mutation.<table>.<op> = false`. Check first:

```sql
SELECT key, value FROM capabilities WHERE key LIKE 'mutation.%' AND value = 'true';
```

## Persistence model

- Writes hit the session's analysis immediately, **in memory**.
- `SELECT save();` writes `<file>.malcat` next to the sample; `SELECT save('C:/cases/x.malcat');`
  writes elsewhere and makes that the session's project. The next `malcatsql <file>` (or
  `malcatsql x.malcat`) loads it automatically.
- `SELECT value FROM binary WHERE key = 'unsaved_changes';` tells you whether a save is pending.
- Labels, comments and decompile aliases survive a save/reload round-trip (covered by tests).

## Re-analysis cost

Labels only show up in Malcat (callers' pseudo-C, xref names) after `Analysis.run()`. malcatsql
defers that: writes mark the session dirty and the **next read** runs it once (~0.03 s small
files, ~1.5 s large DLLs). So rename in batches:

```sql
-- one UPDATE, one re-analysis
UPDATE funcs SET name = 'str_decrypt_' || substr(hex(addr), 3)
WHERE addr IN (SELECT addr FROM funcs WHERE num_xor_ops >= 5 AND is_library = 0 LIMIT 5);
```

## Quick patterns

```sql
-- rename a function (read first, then write by address)
SELECT hex(addr), name FROM funcs WHERE size BETWEEN 60 AND 200 LIMIT 1;
UPDATE funcs SET name = 'parse_config' WHERE addr = (SELECT addr FROM funcs WHERE size BETWEEN 60 AND 200 LIMIT 1);

-- label data (e.g. an encrypted blob)
INSERT INTO names(addr, name)
VALUES ((SELECT addr FROM strings WHERE type = 'user' AND addr IS NOT NULL LIMIT 1), 'g_encrypted_cfg');

-- comments
INSERT INTO comments(addr, text) VALUES ((SELECT addr FROM funcs LIMIT 1), 'entry of unpacking stub');
UPDATE comments SET text = 'unpacking stub: RC4, key at g_key' WHERE addr = (SELECT addr FROM funcs LIMIT 1);
SELECT hex(addr), text FROM comments;
DELETE FROM comments WHERE addr = (SELECT addr FROM funcs LIMIT 1);

-- UDF forms (handy inside larger SELECTs)
SELECT set_comment(addr, 'calls ' || num_api_calls || ' APIs') FROM funcs WHERE num_api_calls > 20;
SELECT set_name((SELECT addr FROM funcs LIMIT 1), NULL);   -- remove a label

-- remove a user label through names
DELETE FROM names WHERE addr = (SELECT addr FROM names WHERE name = 'g_encrypted_cfg');

-- persist
SELECT save();
```

Label rules: Malcat refuses some names (empty, duplicates it cannot resolve); the error says
`malcat refused label ...`. Writes to unmapped addresses fail with `address 0x... is not mapped`.

## Not supported (yet)

Byte patches, type/struct editing and bookmarks/highlights are not exposed. Use
`malcat_python()` (gated) if you must.

## Related skills

- `decompiler` for variable aliases and checking renamed output
- `connect` for the explicit-save contract
