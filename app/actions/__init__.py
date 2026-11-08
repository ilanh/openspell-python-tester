"""Registry of the playground's test actions.

Each action is a small function that tries one thing the sandbox policy either
allows or denies. The `@openshell` comments directly above the call inside each
function are the policy: `openshell-annotate generate` turns them into
`openshell/policy.yaml`.
"""

from __future__ import annotations

import inspect
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

Verdict = Literal["ALLOW", "DENY"]
Outcome = Literal["ALLOW", "DENY", "ERROR"]

ROOT = Path(__file__).resolve().parents[2]
DIRECTIVE = re.compile(r"#\s*(@openshell\s.*)$")


@dataclass
class Action:
    id: str
    group: str
    title: str
    expect: Verdict
    why: str
    fn: Callable[[], tuple[Outcome, str]]

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
            **self.source(),
        }

    def run(self) -> dict:
        started = time.monotonic()
        try:
            outcome, detail = self.fn()
        except PermissionError as e:
            outcome, detail = "DENY", f"PermissionError: {e.strerror or e} ({e.filename})"
        except OSError as e:
            outcome, detail = "ERROR", f"{type(e).__name__}: {e}"
        except Exception as e:  # noqa: BLE001 - surfaced to the page as-is
            outcome, detail = "ERROR", f"{type(e).__name__}: {e}"
        return {
            "id": self.id,
            "outcome": outcome,
            "detail": detail[:400],
            "match": outcome == self.expect,
            "ms": round((time.monotonic() - started) * 1000),
        }


REGISTRY: dict[str, Action] = {}


def action(id: str, group: str, title: str, expect: Verdict, why: str):
    def register(fn: Callable[[], tuple[Outcome, str]]):
        REGISTRY[id] = Action(id, group, title, expect, why, fn)
        return fn

    return register


def load() -> dict[str, Action]:
    # Importing the modules registers their actions, in display order.
    from . import net, fs, proc  # noqa: F401

    return REGISTRY
