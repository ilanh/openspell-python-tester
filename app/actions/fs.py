"""Filesystem actions. OpenShell enforces these with Landlock (EACCES on denial)."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from . import action, file_op


@action(
    "write-data",
    group="filesystem",
    title="write /data/out.txt",
    expect="ALLOW",
    why="fs write rule for /data",
    op=file_op("write", "/data/out.txt"),
)
def write_data():
    stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    # @openshell fs write /data reason="demo: results directory"
    Path("/data/out.txt").write_text(f"written at {stamp}\n")
    content = Path("/data/out.txt").read_text()
    return "ALLOW", f"wrote {len(content)} bytes to /data/out.txt", {"output": content}


@action(
    "write-forbidden",
    group="filesystem",
    title="write /opt/forbidden/x.txt",
    expect="DENY",
    why="no fs rule: /opt is outside the policy and OpenShell's baseline",
    op=file_op("write", "/opt/forbidden/x.txt"),
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
    op=file_op("write", "/app/x.txt"),
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
    op=file_op("read", "/etc/os-release"),
)
def read_os_release():
    text = Path("/etc/os-release").read_text()
    name = next((l.split("=", 1)[1].strip('"') for l in text.splitlines() if l.startswith("PRETTY_NAME=")), "?")
    return "ALLOW", f"read {len(text)} bytes, PRETTY_NAME={name}", {"output": text}


@action(
    "read-forbidden",
    group="filesystem",
    title="read /opt/forbidden/secret.txt",
    expect="DENY",
    why="reads are restricted too: /opt is not readable",
    op=file_op("read", "/opt/forbidden/secret.txt"),
)
def read_forbidden():
    text = Path("/opt/forbidden/secret.txt").read_text()
    return "ALLOW", f"read {len(text)} bytes", {"output": text}
