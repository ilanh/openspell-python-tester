"""Policy Playground: one page, one button per action the sandbox policy allows or denies."""

from __future__ import annotations

import os
import socket
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse

from .actions import ROOT, load

# The server imports its own code, page and generated policy from /app.
# @openshell fs read /app reason="application code, static page and policy.yaml"
ACTIONS = load()
POLICY = ROOT / "openshell" / "policy.yaml"
STATIC = Path(__file__).parent / "static"

app = FastAPI(title="Policy Playground", docs_url=None, redoc_url=None)


def in_sandbox() -> bool:
    # The OpenShell runtime mounts its TLS CA here and points the client env vars at it.
    return Path("/run/openshell-supervisor-ca").exists() or "openshell" in os.environ.get(
        "REQUESTS_CA_BUNDLE", ""
    )


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/actions")
def list_actions() -> dict:
    return {
        "sandbox": in_sandbox(),
        "host": socket.gethostname(),
        "actions": [a.describe() for a in ACTIONS.values()],
    }


@app.post("/api/run/{action_id}")
def run(action_id: str) -> dict:
    a = ACTIONS.get(action_id)
    if a is None:
        raise HTTPException(404, f"unknown action {action_id}")
    return a.run()


@app.get("/api/policy", response_class=PlainTextResponse)
def policy() -> str:
    try:
        return POLICY.read_text()
    except OSError as e:
        return f"# could not read {POLICY}: {e}\n# run `make policy` to generate it\n"
