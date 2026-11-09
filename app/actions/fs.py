"""Filesystem actions. OpenShell enforces these with Landlock (EACCES on denial)."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from . import action


@action(
    "write-data",
    group="filesystem",
    title="write /data/out.txt",
    expect="ALLOW",
    why="fs write rule for /data",
)
def write_data():
    stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    # @openshell fs write /data reason="demo: results directory"
    Path("/data/out.txt").write_text(f"written at {stamp}\n")
    return "ALLOW", f"wrote {len(stamp) + 12} bytes to /data/out.txt"


@action(
    "write-forbidden",
    group="filesystem",
    title="write /opt/forbidden/x.txt",
    expect="DENY",
    why="no fs rule: /opt is outside the policy and OpenShell's baseline",
)
def write_forbidden():
    # Deliberately unannotated: `make lint` flags this write, Landlock blocks it.
    Path("/opt/forbidden/x.txt").write_text("should never land\n")
    return "ALLOW", "wrote /opt/forbidden/x.txt"


@action(
    "write-app",
    group="filesystem",
    title="write /app/x.txt",
    expect="DENY",
    why="/app is declared with fs read, so it is read-only",
)
def write_app():
    # Deliberately unannotated: the `fs read /app` rule in app/main.py does not grant writes.
    Path("/app/x.txt").write_text("should never land\n")
    return "ALLOW", "wrote /app/x.txt"


@action(
    "read-os-release",
    group="filesystem",
    title="read /etc/os-release",
    expect="ALLOW",
    why="/etc is in OpenShell's read-only baseline when the policy has network rules",
)
def read_os_release():
    text = Path("/etc/os-release").read_text()
    name = next((l.split("=", 1)[1].strip('"') for l in text.splitlines() if l.startswith("PRETTY_NAME=")), "?")
    return "ALLOW", f"PRETTY_NAME={name}"


@action(
    "read-forbidden",
    group="filesystem",
    title="read /opt/forbidden/secret.txt",
    expect="DENY",
    why="reads are restricted too: /opt is not readable",
)
def read_forbidden():
    text = Path("/opt/forbidden/secret.txt").read_text()
    return "ALLOW", f"read {len(text)} bytes"
