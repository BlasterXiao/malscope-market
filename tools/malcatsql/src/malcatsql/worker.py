"""Single-thread owners of the Session/Engine for the HTTP and MCP servers.

Malcat's pybind objects and the apsw connection are used on exactly one thread; server threads
only enqueue work and wait on a Future. No locking of malcat objects is attempted.

* :class:`EngineWorker` - a dedicated thread opens the file and serves jobs.
"""

from __future__ import annotations

import queue
import threading
from concurrent.futures import Future
from typing import Any, Callable, Optional, TypeVar

from .engine import Engine
from .session import Session

T = TypeVar("T")
Job = Optional[tuple[Callable[[Engine], Any], "Future[Any]"]]


class JobHost:
    engine: Engine

    def __init__(self) -> None:
        self._jobs: queue.Queue[Job] = queue.Queue()

    def submit(self, fn: Callable[[Engine], T]) -> T:
        fut: Future[T] = Future()
        self._jobs.put((fn, fut))
        return fut.result()

    def query(self, sql: str, max_rows: Optional[int] = None, sample: Optional[str] = None) -> dict[str, Any]:
        def job(e: Engine) -> dict[str, Any]:
            cap = max_rows if max_rows is not None else e.settings.get_int("max_result_rows")
            return e.run(sql, max_rows=cap, sample=sample)

        return self.submit(job)

    def status(self) -> dict[str, Any]:
        return self.submit(lambda e: e.status())

    def _run_job(self, job: tuple[Callable[[Engine], Any], Future[Any]]) -> None:
        fn, fut = job
        if not fut.set_running_or_notify_cancel():
            return
        try:
            fut.set_result(fn(self.engine))
        except BaseException as exc:  # noqa: BLE001 - forwarded to the waiting server thread
            fut.set_exception(exc)


class EngineWorker(JobHost):
    def __init__(self, open_engine: Callable[[], Engine]) -> None:
        super().__init__()
        self._ready: Future[Engine] = Future()
        self._thread = threading.Thread(target=self._loop, args=(open_engine,), name="malcatsql-engine", daemon=True)
        self._thread.start()
        self.engine = self._ready.result()  # re-raises open errors in the caller

    def _loop(self, open_engine: Callable[[], Engine]) -> None:
        try:
            engine = open_engine()
        except BaseException as exc:  # noqa: BLE001 - forwarded to the constructor
            self._ready.set_exception(exc)
            return
        self._ready.set_result(engine)
        while True:
            job = self._jobs.get()
            if job is None:
                return
            self._run_job(job)

    def close(self) -> None:
        self._jobs.put(None)
        self._thread.join(timeout=5)


def open_engine_factory(
    targets: str | list[str],
    *,
    options: Optional[dict[str, Any]] = None,
    project: Optional[str] = None,
    use_project: bool = True,
    settings: Optional[dict[str, Any]] = None,
) -> Callable[[], Engine]:
    """One path -> :class:`Engine`; several -> a multi-sample :class:`Workspace`."""
    paths = [targets] if isinstance(targets, str) else list(targets)

    def factory() -> Engine:
        if len(paths) > 1:
            from .workspace import Workspace

            return Workspace(paths, options=options, use_project=use_project, settings=settings)
        session = Session(paths[0], options=options, project=project, use_project=use_project)
        return Engine(session, settings)

    return factory
