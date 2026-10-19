"""HTTP client for a running malcatsql server (started with ``malcatsql <file> --http``).

Implements the small part of the Engine interface the CLI/REPL uses, so ``malcatsql --url``
behaves like a local session. Standard library only.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional


class RemoteEngine:
    def __init__(self, url: str, token: Optional[str] = None, timeout: float = 600.0) -> None:
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _request(self, path: str, body: Optional[bytes] = None) -> Any:
        req = urllib.request.Request(self.url + path, data=body, method="POST" if body is not None else "GET")
        if body is not None:
            req.add_header("Content-Type", "text/plain; charset=utf-8")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise ConnectionError(f"{self.url}{path}: HTTP {exc.code} {detail}") from None
        except urllib.error.URLError as exc:
            raise ConnectionError(
                f"cannot reach {self.url} ({exc.reason}). Is the malcatsql server running "
                "(`malcatsql <file> --http`)?"
            ) from None

    def run(self, sql: str, max_rows: Optional[int] = None, sample: Optional[str] = None) -> dict[str, Any]:
        path = "/query" + (f"?sample={urllib.parse.quote(sample)}" if sample else "")
        try:
            return self._request(path, sql.encode("utf-8"))
        except ConnectionError as exc:
            return {"success": False, "results": [], "elapsed_ms": 0, "error": str(exc)}

    def status(self) -> dict[str, Any]:
        st = self._request("/status")
        st["url"] = self.url
        return st

    def table_names(self) -> list[str]:
        st = self.status()
        return list(st.get("tables", [])) + list(st.get("views", []))

    def schema_of(self, name: str) -> list[tuple[Any, ...]]:
        env = self.run(f"SELECT * FROM pragma_table_xinfo('{name.replace(chr(39), chr(39) * 2)}')")
        if not env["success"] or not env["results"]:
            return []
        return [tuple(r) for r in env["results"][0]["rows"]]
