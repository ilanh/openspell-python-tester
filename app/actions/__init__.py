"""Registry of the playground's test actions.

Each action is a small function that tries one thing the sandbox policy either
allows or denies. The `@openshell` comments directly above the call inside each
function are the policy: `openshell-annotate generate` turns them into
`openshell/policy.yaml`.

An action also declares the exact operation it performs (`op=`), so the page can
show the request, path or binary and look up the policy rule that governs it.
"""

from __future__ import annotations

import inspect
import os
import re
import shlex
import shutil
import sys
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal
from urllib.parse import urlsplit

Verdict = Literal["ALLOW", "DENY"]
Outcome = Literal["ALLOW", "DENY", "ERROR"]

ROOT = Path(__file__).resolve().parents[2]
DIRECTIVE = re.compile(r"#\s*(@openshell\s.*)$")
# Full output is returned to the page; this cap only guards against a runaway body.
MAX_OUTPUT = 200_000

# OpenShell matches egress rules on the real executable path, so show that one.
PYTHON = os.path.realpath(sys.executable)
CURL = os.path.realpath(shutil.which("curl") or "/usr/bin/curl")


def shell_join(argv: list[str]) -> str:
    """A copy-pasteable command line, with newlines shown as \\n."""
    return shlex.join(argv).replace("\n", "\\n")


def http_op(method: str, host: str, port: int, path: str) -> dict:
    """An HTTP request made by the Python server itself (`requests`)."""
    scheme = "https" if port == 443 else "http"
    return {
        "kind": "http",
        "client": "python requests",
        "method": method,
        "url": f"{scheme}://{host}{path}",
        "host": host,
        "port": port,
        "path": path,
        "binary": PYTHON,
    }


def _http_from_url(method: str, url: str) -> dict:
    u = urlsplit(url)
    return {**http_op(method, u.hostname or "", u.port or (443 if u.scheme == "https" else 80), u.path or "/"), "url": url}


def curl_op(argv: list[str]) -> dict:
    """An HTTP GET made by a curl subprocess of the Python server; the URL is the last argument."""
    return {
        **_http_from_url("GET", argv[-1]),
        "kind": "exec",
        "client": "curl subprocess",
        "command": shell_join(argv),
        "binary": CURL,
        "parent": PYTHON,
    }


def file_op(mode: Literal["read", "write"], path: str) -> dict:
    """A file read or write by the Python server."""
    return {"kind": "fs", "mode": mode, "path": path, "binary": PYTHON}


@dataclass
class Action:
    id: str
    group: str
    title: str
    expect: Verdict
    why: str
    op: dict
    fn: Callable[[], tuple]

    def source(self) -> dict:
        """The `@openshell` lines inside the function, with their file:line."""
        lines, start = inspect.getsourcelines(self.fn)
        file = Path(inspect.getsourcefile(self.fn) or "").resolve()
        try:
            rel = file.relative_to(ROOT).as_posix()
        except ValueError:
            rel = file.name
        directives = []
        for offset, text in enumerate(lines):
            m = DIRECTIVE.search(text.strip())
            if m:
                directives.append({"line": start + offset, "text": m.group(1)})
        return {"file": rel, "line": start, "directives": directives}

    def describe(self) -> dict:
        return {
            "id": self.id,
            "group": self.group,
            "title": self.title,
            "expect": self.expect,
            "why": self.why,
            "op": self.op,
            **self.source(),
        }

    def run(self) -> dict:
        started = time.monotonic()
        extra: dict = {}
        try:
            outcome, detail, *rest = self.fn()
            extra = rest[0] if rest else {}
        except PermissionError as e:
            outcome = "DENY"
            detail = f"PermissionError: [Errno {e.errno}] {e.strerror or e} ({e.filename})"
            extra = {"output": detail}
        except Exception as e:  # noqa: BLE001 - surfaced to the page as-is
            outcome, detail = "ERROR", f"{type(e).__name__}: {e}"
            extra = {"output": traceback.format_exc()}
        output = str(extra.get("output", detail))
        truncated = len(output) > MAX_OUTPUT
        return {
            "id": self.id,
            "outcome": outcome,
            "expect": self.expect,
            "match": outcome == self.expect,
            "detail": detail,
            "http_status": extra.get("http_status"),
            "exit_code": extra.get("exit_code"),
            "output": output[:MAX_OUTPUT],
            "output_truncated": truncated,
            "ms": round((time.monotonic() - started) * 1000),
        }


REGISTRY: dict[str, Action] = {}


def action(id: str, group: str, title: str, expect: Verdict, why: str, op: dict):
    def register(fn: Callable[[], tuple]):
        REGISTRY[id] = Action(id, group, title, expect, why, op, fn)
        return fn

    return register


def load() -> dict[str, Action]:
    # Importing the modules registers their actions, in display order.
    from . import net, fs, proc  # noqa: F401

    return REGISTRY
