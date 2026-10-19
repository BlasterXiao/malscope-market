"""Command line entry point: ``malcatsql <file> [-c SQL | -f FILE | --http | --mcp]``."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Optional

from . import TOOL_NAME, __version__
from .session import parse_option_value

HELP_EPILOG = """\
<file> is a binary (.exe/.dll/elf/document/archive...) or a .malcat project (its source binary
must sit next to it). Annotations are applied in memory; SELECT save(); writes <file>.malcat,
which is loaded automatically next time.

Examples:
  malcatsql sample.exe -c "SELECT * FROM binary"
  malcatsql sample.exe -c "SELECT hex(addr), name, size FROM funcs ORDER BY size DESC LIMIT 10"
  malcatsql sample.exe --http 8081
  malcatsql sample.exe --mcp 9997
"""

REPL_HELP = """\
.tables              list tables and views
.schema [name]       columns of a table/view (all when omitted)
.mode table|json|csv output format
.save [path]         same as SELECT save([path]) (workspace without .use: save_all())
.use [alias]         workspace: run statements on one sample; '.use' alone returns to the workspace
.status              session status
.quit / .exit        leave (unsaved annotations are lost)
End SQL statements with ';'.
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"{TOOL_NAME} v{__version__} - SQL interface for Malcat",
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "file",
        nargs="*",
        help="binary or .malcat project; give several ([alias=]path ...) for a multi-sample workspace",
    )
    p.add_argument(
        "--sample",
        metavar="ALIAS",
        help="workspace only: run -c/-f (or start the REPL) on this sample instead of the workspace",
    )
    p.add_argument("-s", "--source", help="same as the positional <file>")
    p.add_argument("-c", "--command", help="SQL to execute, then exit")
    p.add_argument("-f", "--file", dest="sql_file", help="SQL file to execute, then exit")
    p.add_argument("-i", "--interactive", action="store_true", help="interactive SQL mode (default)")
    p.add_argument("--http", nargs="?", const=8081, type=int, metavar="PORT", help="HTTP server (default 8081)")
    p.add_argument("--mcp", nargs="?", const=9997, type=int, metavar="PORT", help="MCP server (default 9997)")
    p.add_argument("--bind", default="127.0.0.1", help="server bind address (default 127.0.0.1)")
    p.add_argument("--token", help="auth token for HTTP/MCP (Authorization: Bearer <token>)")
    p.add_argument("--project", help="explicit .malcat project path (default <file>.malcat)")
    p.add_argument("--no-project", action="store_true", help="do not auto-load <file>.malcat")
    p.add_argument(
        "-o",
        "--option",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="malcat.analyse option, e.g. -o flirt_disable=true -o num_threads=8 (repeatable)",
    )
    p.add_argument("--enable-python", action="store_true", help="start with enable_python=1")
    p.add_argument(
        "--url",
        metavar="URL",
        help="connect to a running malcatsql server (started with `malcatsql <file> --http`)",
    )
    p.add_argument("--format", choices=("table", "json", "csv"), default="table", help="output format for -c/-f/REPL")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress banner")
    p.add_argument("-v", "--version", action="version", version=f"{TOOL_NAME} {__version__}")
    return p


def parse_options(pairs: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise SystemExit(f"--option expects KEY=VALUE, got {pair!r}")
        out[key.strip()] = parse_option_value(value)
    return out


def _utf8_console() -> None:
    # sample strings/metadata are arbitrary Unicode; a cp936/cp1252 pipe must not crash printing
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def main(argv: Optional[list[str]] = None) -> int:
    _utf8_console()
    args = build_parser().parse_args(argv)
    if args.url:
        from .client import RemoteEngine

        remote = RemoteEngine(args.url, args.token)
        if args.command or args.sql_file:
            sql = args.command if args.command else Path(args.sql_file).read_text(encoding="utf-8")
            envelope = remote.run(sql, sample=args.sample)
            _print_envelope(envelope, args.format)
            return 0 if envelope["success"] else 1
        try:
            if not args.quiet:
                _banner(remote)
        except ConnectionError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return repl(remote, args.format, args.sample)
    targets = ([args.source] if args.source else []) + list(args.file)
    if not targets:
        build_parser().print_help()
        return 2
    if args.http is not None and args.mcp is not None:
        print("error: choose either --http or --mcp", file=sys.stderr)
        return 2

    options = parse_options(args.option)
    settings = {"enable_python": True} if args.enable_python else {}
    open_kwargs = dict(options=options, project=args.project, use_project=not args.no_project, settings=settings)

    if args.http is not None or args.mcp is not None:
        if args.bind not in ("127.0.0.1", "localhost", "::1") and not args.token:
            print(
                f"warning: binding {args.bind} without --token exposes the session"
                + (" (and Python execution)" if args.enable_python else ""),
                file=sys.stderr,
            )
        if args.http is not None:
            from .http_server import serve_http

            return serve_http(targets, args.bind, args.http, args.token, open_kwargs, quiet=args.quiet)
        from .mcp_server import serve_mcp

        return serve_mcp(targets, args.bind, args.mcp, args.token, open_kwargs, quiet=args.quiet)

    from .worker import open_engine_factory

    try:
        engine = open_engine_factory(targets, **open_kwargs)()
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not args.quiet and not (args.command or args.sql_file):
        _banner(engine)

    if args.command or args.sql_file:
        sql = args.command if args.command else Path(args.sql_file).read_text(encoding="utf-8")
        envelope = engine.run(sql, sample=args.sample)
        _print_envelope(envelope, args.format)
        return 0 if envelope["success"] else 1
    return repl(engine, args.format, args.sample)


def _banner(engine: Any) -> None:
    st = engine.status()
    print(f"{TOOL_NAME} v{__version__} | {st['file']} | {st['filetype']} {st['architecture']} "
          f"| {st.get('mode', 'headless')}"
          + (f" | {st['url']}" if st.get("url") else f" | analysed in {st['analysis_seconds']}s")
          + (f" | project {st['project']}" if st["project_loaded"] else ""))
    print("Type .help for commands; end SQL with ';'.")


def repl(engine: Any, fmt: str, sample: Optional[str] = None) -> int:
    buf = ""
    while True:
        try:
            prompt = f"malcatsql[{sample}]> " if sample else "malcatsql> "
            line = input(prompt if not buf else "     ...> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        stripped = line.strip()
        if not buf and stripped.startswith("."):
            cmd, _, arg = stripped.partition(" ")
            if cmd in (".quit", ".exit"):
                break
            if cmd == ".use":  # workspace: pick the sample statements run on ('.use' alone = workspace)
                sample = arg.strip() or None
                print(f"statements now run on {'sample ' + sample if sample else 'the workspace'}")
                continue
            fmt = _dot_command(engine, cmd, arg.strip(), fmt, sample)
            continue
        buf += line + "\n"
        import apsw

        if apsw.complete(buf):
            _print_envelope(engine.run(buf, sample=sample), fmt)
            buf = ""
    session = getattr(engine, "session", None)
    if session is not None and session.unsaved_changes:
        print("note: annotations were not saved (SELECT save(); persists them)", file=sys.stderr)
    return 0


def _dot_command(engine: Any, cmd: str, arg: str, fmt: str, sample: Optional[str] = None) -> str:
    if cmd == ".help":
        print(REPL_HELP)
    elif cmd == ".tables":
        print("  ".join(engine.table_names()))
    elif cmd == ".schema":
        names = [arg] if arg else engine.table_names()
        for name in names:
            cols = engine.schema_of(name)
            if not cols:
                print(f"no such table: {name}")
                continue
            # pragma_table_xinfo: cid, name, type, notnull, dflt, pk, hidden
            rendered = ", ".join(f"{c[1]} {c[2]}".strip() + (" HIDDEN" if c[6] else "") for c in cols)
            print(f"{name}({rendered})")
    elif cmd == ".mode":
        if arg in ("table", "json", "csv"):
            fmt = arg
        else:
            print("usage: .mode table|json|csv")
    elif cmd == ".save":
        if getattr(engine, "engines", None) is not None and not sample:
            _print_envelope(engine.run("SELECT save_all()"), fmt)
        else:
            _print_envelope(engine.run(f"SELECT save({_sql_str(arg)})" if arg else "SELECT save()", sample=sample), fmt)
    elif cmd == ".status":
        print(json.dumps(engine.status(), indent=2))
    else:
        print(f"unknown command {cmd}; try .help")
    return fmt


def _sql_str(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _print_envelope(env: dict[str, Any], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(env, indent=2, ensure_ascii=False))
        return
    for res in env["results"]:
        if res["columns"]:
            if fmt == "csv":
                w = csv.writer(sys.stdout, lineterminator="\n")
                w.writerow(res["columns"])
                w.writerows(res["rows"])
            else:
                print(format_table(res["columns"], res["rows"]))
        elif res.get("changes"):
            print(f"({res['changes']} row(s) changed)")
    if not env["success"]:
        print(f"Error: {env['error']}", file=sys.stderr)


def format_table(columns: list[str], rows: list[list[Any]], max_width: int = 80) -> str:
    def cell(v: Any) -> str:
        if v is None:
            return "NULL"
        text = str(v).replace("\r", "\\r").replace("\n", "\\n")
        return text if len(text) <= max_width else text[: max_width - 3] + "..."

    body = [[cell(v) for v in r] for r in rows]
    widths = [len(c) for c in columns]
    for r in body:
        for i, v in enumerate(r):
            widths[i] = max(widths[i], len(v))
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def line(vals: list[str]) -> str:
        return "| " + " | ".join(v.ljust(w) for v, w in zip(vals, widths)) + " |"

    out = [sep, line(columns), sep]
    out.extend(line(r) for r in body)
    out.append(sep)
    out.append(f"{len(rows)} row(s)")
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main())
