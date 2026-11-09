"""Subprocess actions: how OpenShell matches the binary named in an egress rule.

A rule's `binaries` match the connecting executable *or any of its ancestors*
(OpenShell's sandbox-policy.rego: "ancestor exact path (e.g., claude spawns node)").
curl started by the allowed Python server therefore inherits Python's rules.
The reverse does not hold: a rule bound to curl does not cover Python.
"""

from __future__ import annotations

import subprocess

import requests

from . import action
from .net import TIMEOUT, _call


def _curl(url: str) -> tuple[str, str]:
    p = subprocess.run(
        ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "8", url],
        capture_output=True,
        text=True,
        timeout=15,
    )
    code = p.stdout.strip() or "000"
    err = " ".join(p.stderr.split())[:200]
    if p.returncode == 0 and code.startswith("2"):
        return "ALLOW", f"curl exit 0, HTTP {code}"
    if code == "403" or p.returncode in (7, 35, 56):
        return "DENY", f"curl exit {p.returncode}, HTTP {code} {err}"
    return "ERROR", f"curl exit {p.returncode}, HTTP {code} {err}"


@action(
    "curl-github",
    group="process",
    title="curl https://api.github.com/zen",
    expect="ALLOW",
    why="the api.github.com rule names only Python, but OpenShell also matches parent processes: curl is a child of the Python server",
)
def curl_github():
    # No rule names /usr/bin/curl. The sandbox log shows it allowed under api_github_com
    # because its parent process is /usr/local/bin/python3.12.
    return _curl("https://api.github.com/zen")


@action(
    "curl-icanhazip",
    group="process",
    title="curl https://icanhazip.com",
    expect="ALLOW",
    why="bin=/usr/bin/curl binds the icanhazip.com rule to curl",
)
def curl_icanhazip():
    # @openshell egress icanhazip.com:443 reason="demo: rule bound to curl only" access=read-only bin=/usr/bin/curl
    return _curl("https://icanhazip.com")


@action(
    "python-icanhazip",
    group="process",
    title="GET https://icanhazip.com from Python",
    expect="DENY",
    why="the icanhazip.com rule names only curl, and curl is not an ancestor of the Python server",
)
def python_icanhazip():
    # @openshell ignore kind=net reason="demo: host is declared above for curl only; Python is refused"
    return _call(lambda: requests.get("https://icanhazip.com", timeout=TIMEOUT))
