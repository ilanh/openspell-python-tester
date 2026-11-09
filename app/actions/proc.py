"""Subprocess actions: how OpenShell matches the binary named in an egress rule.

A rule's `binaries` match the connecting executable *or any of its ancestors*
(OpenShell's sandbox-policy.rego: "ancestor exact path (e.g., claude spawns node)").
curl started by the allowed Python server therefore inherits Python's rules.
The reverse does not hold: a rule bound to curl does not cover Python.
"""

from __future__ import annotations

import subprocess

import requests

from . import action, curl_op, http_op, shell_join
from .net import TIMEOUT, _call


# The exact command each curl card runs; the URL is appended.
CURL_ARGV = ["curl", "-sS", "-o", "-", "-w", "\n%{http_code}", "--max-time", "8"]


def _curl(url: str) -> tuple[str, str, dict]:
    p = subprocess.run(
        [*CURL_ARGV, url],
        capture_output=True,
        text=True,
        timeout=15,
    )
    body, _, code = p.stdout.rpartition("\n")
    code = code.strip() or "000"
    err = " ".join(p.stderr.split())[:200]
    extra = {
        "exit_code": p.returncode,
        "http_status": int(code) if code.isdigit() and code != "000" else None,
        "output": f"$ {shell_join([*CURL_ARGV, url])}\nexit {p.returncode}, HTTP {code}\n\n"
        f"--- stdout ---\n{body}\n\n--- stderr ---\n{p.stderr}",
    }
    if p.returncode == 0 and code.startswith("2"):
        return "ALLOW", f"curl exit 0, HTTP {code}", extra
    if code == "403" or p.returncode in (7, 35, 56):
        return "DENY", f"curl exit {p.returncode}, HTTP {code} {err}", extra
    return "ERROR", f"curl exit {p.returncode}, HTTP {code} {err}", extra


@action(
    "curl-github",
    group="process",
    title="curl https://api.github.com/zen",
    expect="ALLOW",
    why="the api.github.com rule names only Python, but OpenShell also matches parent processes: curl is a child of the Python server",
    op=curl_op([*CURL_ARGV, "https://api.github.com/zen"]),
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
    op=curl_op([*CURL_ARGV, "https://icanhazip.com"]),
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
    op=http_op("GET", "icanhazip.com", 443, "/"),
)
def python_icanhazip():
    # @openshell ignore kind=net reason="demo: host is declared above for curl only; Python is refused"
    return _call(lambda: requests.get("https://icanhazip.com", timeout=TIMEOUT))
