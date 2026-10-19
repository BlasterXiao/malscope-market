# malcatsql server guide

Opening a sample costs one Malcat analysis (seconds). For iterative work start a server once and
send many queries; all requests share one analysis, one annotation state and one cache.

## HTTP (FastAPI)

```bash
malcatsql sample.exe --http 8081                     # loopback only
malcatsql sample.exe --http 8081 --token s3cret      # require a token
malcatsql sample.exe --http 8081 --bind 0.0.0.0 --token s3cret
```

| Endpoint | Purpose |
|----------|---------|
| `POST /query` | body = raw SQL (`curl -d "SELECT ..."`) or JSON `{"sql": "...", "max_rows": N}`; `?max_rows=N` also works |
| `GET /status` | file, project, architecture, tables, python gate |
| `GET /health` | liveness (no auth) |
| `GET /docs` | OpenAPI UI |

```bash
curl -s -X POST http://127.0.0.1:8081/query -d "SELECT * FROM binary"
curl -s -X POST http://127.0.0.1:8081/query -H "Content-Type: application/json" \
     -d '{"sql": "SELECT hex(addr), name FROM funcs LIMIT 5"}'
curl -s -H "Authorization: Bearer s3cret" http://127.0.0.1:8081/status
```

Response envelope:

```json
{"success": true,
 "results": [{"statement": "SELECT ...;", "columns": ["..."], "rows": [[...]],
              "row_count": 5, "truncated": false, "changes": 0}],
 "elapsed_ms": 3.1, "error": null}
```

A failing statement stops the script: `success=false`, `error` holds the message, `results` holds
what completed before it. Blobs come back as uppercase hex strings. `max_result_rows`
(runtime setting, default 100000) caps rows per statement unless `max_rows` is given.

Auth: send `Authorization: Bearer <token>` or `X-XSQL-Token: <token>`. Binding a non-loopback
address without `--token` prints a warning; with `--enable-python` that is remote code execution
on the analyst machine, so always set a token.

## MCP

```bash
malcatsql sample.exe --mcp 9997 [--token s3cret]
```

Streamable-HTTP MCP endpoint at `http://127.0.0.1:9997/mcp` with two tools:

- `query(sql, max_rows?)` → the same envelope as HTTP `/query`
- `status()` → session status

Claude Code registration example:

```bash
claude mcp add --transport http malcatsql http://127.0.0.1:9997/mcp
```

## Concurrency model

The Malcat analysis and the SQLite connection live on one dedicated worker thread; HTTP/MCP
requests are queued to it. Requests are therefore serialized: a slow statement (first `capa`
query, a big `xrefs` scan, a decompile) delays the others. Keep slow work bounded with
`query_timeout_ms`.

## Lifecycle

Stop the server with Ctrl+C (or stop the background task that runs it). Unsaved annotations are
lost; run `SELECT save();` first.
