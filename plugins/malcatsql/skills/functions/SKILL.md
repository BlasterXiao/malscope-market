---
name: functions
description: "Complete malcatsql SQL function reference: address conversion, function lookup, disassembly/decompile helpers, bytes, search, annotation UDFs, save/refresh and the gated Python runner."
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
---

# SQL Functions

The authoritative list with arities is generated from the engine:
[references/function-catalog.md](references/function-catalog.md). From a live session:

```sql
SELECT DISTINCT name FROM pragma_function_list
WHERE name IN ('hex','decompile','disasm','disasm_func','func_start','func_at','set_name','save')
ORDER BY name;
```

## By purpose

| Purpose | Functions |
|---------|-----------|
| Formatting | `hex(x)`: integers → `0x...` (overrides SQLite's `hex` for ints only) |
| Address conversion | `va2off(addr)`, `off2va(offset)`, `rva(addr)`, `va2ea(addr)`, `ea2va(ea)` |
| Function lookup | `func_start(addr)`, `func_end(addr)`, `func_at(addr)` (name), `name_at(addr)` |
| Code text | `disasm(addr)` (one instruction), `disasm_func(addr)`, `decompile(addr[, refresh])` |
| Token-saving code views | `func_profile(addr[, limit])` (JSON overview), `pseudocode_grep(addr, regex[, context[, max]])`, `decompile_lines(addr, start, count)`, `decompile_compact(addr)` |
| Bytes | `bytes(addr, n)` → blob, `read_string(addr[, 'ascii'\|'utf8'\|'utf16le'\|'utf16be'[, max_bytes]])` |
| XOR decoding | `xor_bytes(data, key[, skip])` (int or repeating blob key; bytes in `skip` stay unchanged), `read_xor_string(addr, n, key[, skip])` |
| Search | `search_first(pattern)`; table form: `byte_search('...')` (see `data`) |
| Discovery | `entities_search(pattern[, limit[, offset]])` → JSON array |
| Annotations | `set_name(addr, name)`, `set_comment(addr, text)`; NULL/'' removes |
| Session | `save([path])` → project path, `refresh()` forces the deferred re-analysis |
| Python (gated) | `malcat_python(code)`, `malcat_python_file(path)` (see `python`) |

Plus everything SQLite 3.53 ships (JSON1 `json_each`/`->>`, window functions, CTEs, `printf`,
`group_concat`...).

## Examples

```sql
SELECT hex(addr), rva(addr), va2off(addr) FROM funcs LIMIT 3;
SELECT func_at(addr), hex(func_start(addr)), hex(func_end(addr))
FROM instructions WHERE func_addr = (SELECT addr FROM funcs LIMIT 1) LIMIT 1;
SELECT name_at((SELECT addr FROM entries WHERE kind = 'entry'));
SELECT hex(bytes((SELECT addr FROM entries WHERE kind = 'entry'), 8));
SELECT value FROM json_each(entities_search('Create', 5));
SELECT hex(xor_bytes(x'6162', 0x20));
SELECT hex(xor_bytes(x'0061', 0x50, x'00'));   -- skip list: 0x00 is left unchanged
```

## Semantics worth knowing

- Address arguments accept integers (`0x140001000` literals work) or `'0x140001000'` text.
- Unmapped addresses raise `address 0x... is not mapped` (writes) or return NULL (lookups).
- `decompile`/`disasm_func` require a function **start**; wrap with `func_start()` otherwise.
- `bytes()` returns NULL for virtual-only memory (e.g. `.bss`), which has no file bytes.
- Lookups and `decompile` first run any pending re-analysis caused by earlier renames.
