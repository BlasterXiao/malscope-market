"""MCP server (streamable HTTP at /mcp) exposing `query` and `status` tools."""

from __future__ import annotations

import sys
from typing import Any, Optional

import anyio.to_thread

from . import TOOL_NAME
from .http_server import token_matches
from .worker import EngineWorker, JobHost, open_engine_factory

INSTRUCTIONS = """\
malcatsql exposes a Malcat analysis as SQL (SQLite dialect). Start with
SELECT * FROM binary; then SELECT * FROM capabilities; and PRAGMA table_xinfo(<table>) before
writing queries against unfamiliar tables. Addresses are virtual addresses; print them with hex().
Filter instructions/blocks/cfg_edges/pseudocode by func_addr and xrefs by to_addr/from_addr.
Writes (comments, names, funcs.name, decompile_aliases) are in-memory until SELECT save().
"""


def build_mcp(worker: JobHost, bind: str, port: int) -> Any:
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(TOOL_NAME, instructions=INSTRUCTIONS, host=bind, port=port, log_level="WARNING")

    # async + to_thread: a slow statement (capa, full xrefs, decompile) must not block the event loop
    @mcp.tool()
    async def query(sql: str, max_rows: Optional[int] = None, sample: Optional[str] = None) -> dict[str, Any]:
        """Run one or more SQL statements against the Malcat session; returns the JSON envelope
        {success, results:[{columns, rows, row_count, truncated, changes}], elapsed_ms, error}.
        In a multi-sample workspace pass `sample` (alias) to run on one sample; without it the
        statement runs on the workspace (samples table, collect(), on_sample())."""
        return await anyio.to_thread.run_sync(worker.query, sql, max_rows, sample)

    @mcp.tool()
    async def status() -> dict[str, Any]:
        """Session status: file, project, architecture, tables, python gate."""
        return await anyio.to_thread.run_sync(worker.status)

    return mcp


def serve_mcp(
    targets: list[str], bind: str, port: int, token: Optional[str], open_kwargs: dict[str, Any], quiet: bool = False
) -> int:
    import uvicorn

    try:
        worker = EngineWorker(open_engine_factory(targets, **open_kwargs))
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    mcp = build_mcp(worker, bind, port)
    app = mcp.streamable_http_app()
    if token:
        app = _TokenGate(app, token)
    if not quiet:
        print(f"{TOOL_NAME} MCP server on http://{bind}:{port}/mcp  (tools: query, status)", file=sys.stderr)
    try:
        uvicorn.run(app, host=bind, port=port, log_level="warning")
    finally:
        worker.close()
    return 0


class _TokenGate:
    """Minimal ASGI wrapper rejecting HTTP requests without the bearer / X-XSQL-Token header."""

    def __init__(self, app: Any, token: str) -> None:
        self.app = app
        self.token = token

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
            if not token_matches(self.token, headers.get("authorization"), headers.get("x-xsql-token")):
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json")]})
                await send({"type": "http.response.body", "body": b'{"detail":"missing or invalid token"}'})
                return
        await self.app(scope, receive, send)
