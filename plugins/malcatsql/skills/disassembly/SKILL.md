---
name: disassembly
description: "Query Malcat disassembly via malcatsql: functions, segments, basic blocks, CFG edges, instructions and loops. Use for code-level analysis and instruction inspection."
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
---

# Disassembly

## Tables

| Table | Key columns | Filter |
|-------|-------------|--------|
| `funcs` | `addr`, `name`, `fullname`, `size`, `end_addr`, `category`, `num_bb`, `num_instructions`, `num_calls`, `num_api_calls`, `num_string_refs`, `num_xor_ops`, `num_known_constants`, `num_dynamic_jumps`, `num_arith_ops`, `is_leaf`, `is_library`, `has_loop`, `ea` | cheap full scan; pushdown `addr`, `name` |
| `segments` | `name`, `start_addr`, `end_addr`, `size`, `offset`, `phys_size`, `perm` (`rwx`), `is_rsrc` | tiny |
| `blocks` | `start_addr`, `end_addr`, `func_addr`, `size`, `is_loop`, `num_in`, `num_out` | `func_addr = X` |
| `cfg_edges` | `func_addr`, `from_addr`, `to_addr`, `edge_type` (`jump`/`step`/`call`/`except`) | `func_addr = X` |
| `instructions` | `addr`, `func_addr`, `block_addr`, `mnemonic`, `disasm`, `size`, `itype`, `num_refs` | `func_addr = X` or `addr = X` |
| `loops` | `func_addr`, `start_addr`, `end_addr`, `size` | cheap |

`funcs.category` is Malcat's function reputation (`clean`, `library`, `malware`, `unknown`...).
`instructions.itype` is Malcat's coarse class: `assign`, `call`, `cjump`, `jump`, `return`, `xor`,
`cmp`, `add`, `sub`, `push`, `pop`, `stack`, `fpu`, `mmx`, `syscall`, `nop`, `other`...

## Performance

- Always filter `instructions`, `blocks`, `cfg_edges` by `func_addr`. Joins push the address in
  per row: `funcs f JOIN instructions i ON i.func_addr = f.addr WHERE f.name = ...` only
  disassembles that function.
- Unconstrained `instructions` scans touch every instruction (~37 k for a small PE in ~4 s,
  1.5 M for an 8 MB DLL, which hits `query_timeout_ms`). Prefer `funcs` statistics.
- `disasm(addr)` gives one instruction; `disasm_func(addr)` the whole listing (Malcat's text).

## Quick patterns

```sql
-- biggest functions
SELECT hex(addr) AS addr, name, size, num_bb, num_instructions FROM funcs ORDER BY size DESC LIMIT 20;

-- sections with suspicious permissions
SELECT name, hex(start_addr) AS start, size, perm FROM segments WHERE perm LIKE '%w%x%';

-- instructions of one function
SELECT hex(addr) AS addr, disasm FROM instructions
WHERE func_addr = (SELECT addr FROM funcs ORDER BY size DESC LIMIT 1)
ORDER BY addr LIMIT 40;

-- mnemonic histogram of one function
SELECT mnemonic, COUNT(*) AS n FROM instructions
WHERE func_addr = (SELECT addr FROM funcs ORDER BY size DESC LIMIT 1)
GROUP BY mnemonic ORDER BY n DESC LIMIT 15;

-- indirect calls / dynamic jumps (resolve-at-runtime APIs, switch tables, VM handlers)
SELECT hex(addr) AS addr, disasm FROM instructions
WHERE func_addr = (SELECT addr FROM funcs ORDER BY num_dynamic_jumps DESC LIMIT 1)
  AND itype IN ('call', 'jump') AND disasm NOT LIKE '%sub\_%' ESCAPE '\';

-- cyclomatic complexity per function (edges - nodes + 2), intra-function edges only
SELECT hex(f.addr) AS addr, f.name,
       (SELECT COUNT(*) FROM cfg_edges e WHERE e.func_addr = f.addr AND e.edge_type != 'call')
         - f.num_bb + 2 AS complexity
FROM funcs f WHERE f.is_library = 0 ORDER BY f.size DESC LIMIT 10;

-- blocks inside loops
SELECT hex(start_addr), size FROM blocks
WHERE func_addr = (SELECT func_addr FROM loops WHERE func_addr IS NOT NULL LIMIT 1) AND is_loop = 1;

-- functions without loops that make many API calls (wrappers / dispatchers)
SELECT hex(addr), name, num_api_calls FROM funcs
WHERE has_loop = 0 AND num_api_calls >= 5 ORDER BY num_api_calls DESC LIMIT 15;
```

## Single-address helpers

```sql
SELECT disasm(addr), func_at(addr), hex(func_start(addr)) FROM instructions
WHERE func_addr = (SELECT addr FROM funcs LIMIT 1) LIMIT 3;
SELECT disasm_func((SELECT addr FROM funcs WHERE size < 64 LIMIT 1));
```

## Related skills

- `xrefs` for callers/callees
- `decompiler` for pseudo-C of the same function
- `annotations` to rename what you understood
