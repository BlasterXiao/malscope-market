"""HTTP REST server (FastAPI): POST /query with raw SQL, GET /status, GET /health."""

from __future__ import annotations

import hmac
import sys
from typing import Any, Optional

import anyio.to_thread
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from . import TOOL_NAME, __version__
from .worker import EngineWorker, JobHost, open_engine_factory


class QueryBody(BaseModel):
    sql: str = Field(..., min_length=1, description="one or more SQL statements")
    sample: Optional[str] = Field(None, description="workspace only: run on this sample alias")
    max_rows: Optional[int] = Field(None, ge=1, description="row cap per statement")


def token_matches(expected: Optional[str], authorization: Optional[str], x_token: Optional[str]) -> bool:
    if not expected:
        return True
    supplied = x_token
    if authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    return supplied is not None and hmac.compare_digest(supplied, expected)


def create_app(worker: JobHost, token: Optional[str] = None) -> FastAPI:
    app = FastAPI(title=TOOL_NAME, version=__version__, description="SQL interface for Malcat analyses")

    def auth(
        authorization: Optional[str] = Header(None),
        x_xsql_token: Optional[str] = Header(None),
    ) -> None:
        if not token_matches(token, authorization, x_xsql_token):
            raise HTTPException(status_code=401, detail="missing or invalid token")

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "tool": TOOL_NAME, "version": __version__}

    @app.get("/status", dependencies=[Depends(auth)])
    def status() -> dict[str, Any]:
        return worker.status()

    @app.post("/query", dependencies=[Depends(auth)])
    async def query(
        request: Request,
        max_rows: Optional[int] = Query(None, ge=1),
        sample: Optional[str] = Query(None),
    ) -> dict[str, Any]:
        """Body is raw SQL (``curl -d "SELECT ..."``) or JSON ``{"sql": "...", "max_rows": N,
        "sample": "alias"}``. ``sample`` (also ``?sample=``) only applies to multi-sample workspaces."""
        raw = (await request.body()).decode("utf-8", errors="replace")
        sql, cap = raw, max_rows
        if "application/json" in request.headers.get("content-type", ""):
            body = QueryBody.model_validate_json(raw)
            sql, cap, sample = body.sql, body.max_rows or max_rows, body.sample or sample
        if not sql.strip():
            raise HTTPException(status_code=400, detail="empty SQL")
        # the worker thread serializes every engine call; awaiting here keeps the event loop free
        return await anyio.to_thread.run_sync(worker.query, sql, cap, sample)

    return app


def serve_http(
    targets: list[str], bind: str, port: int, token: Optional[str], open_kwargs: dict[str, Any], quiet: bool = False
) -> int:
    import uvicorn

    try:
        worker = EngineWorker(open_engine_factory(targets, **open_kwargs))
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not quiet:
        print(f"{TOOL_NAME} HTTP server on http://{bind}:{port}  (POST /query, GET /status)", file=sys.stderr)
    try:
        uvicorn.run(create_app(worker, token), host=bind, port=port, log_level="warning")
    finally:
        worker.close()
    return 0
