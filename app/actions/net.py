"""Network actions. Every egress rule is the comment right above its call."""

from __future__ import annotations

import requests

from . import action

TIMEOUT = 8


def _verdict(r: requests.Response) -> tuple[str, str]:
    body = " ".join(r.text.split())[:120]
    # OpenShell's proxy answers a denied request with 403; none of the targets
    # below return 403 on their own for these requests.
    if r.status_code == 403:
        return "DENY", f"HTTP 403 {body}"
    return ("ALLOW" if r.ok else "ERROR"), f"HTTP {r.status_code} {body}"


def _call(fn) -> tuple[str, str]:
    try:
        return _verdict(fn())
    except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError) as e:
        return "DENY", f"{type(e).__name__}: {str(e)[:200]}"
    except requests.exceptions.SSLError as e:
        return "ERROR", f"SSLError (client does not trust the OpenShell CA?): {str(e)[:200]}"


@action(
    "github-zen",
    group="network",
    title="GET https://api.github.com/zen",
    expect="ALLOW",
    why="egress rule for api.github.com:443, read-only, for the Python binary",
)
def github_zen():
    # @openshell egress api.github.com:443 reason="demo: an allowed host" access=read-only
    return _call(lambda: requests.get("https://api.github.com/zen", timeout=TIMEOUT))


@action(
    "example-com",
    group="network",
    title="GET https://example.com",
    expect="DENY",
    why="no egress rule: the proxy refuses hosts the policy does not list",
)
def example_com():
    # Deliberately unannotated: `make lint` flags this line, the sandbox blocks it.
    return _call(lambda: requests.get("https://example.com", timeout=TIMEOUT))


@action(
    "httpbin-get",
    group="network",
    title="GET https://httpbin.org/get",
    expect="ALLOW",
    why="L7 rule allows exactly GET /get on httpbin.org",
)
def httpbin_get():
    # @openshell egress httpbin.org:443 reason="demo: L7 path rule" allow=GET:/get
    return _call(lambda: requests.get("https://httpbin.org/get", timeout=TIMEOUT))


@action(
    "httpbin-post",
    group="network",
    title="POST https://httpbin.org/post",
    expect="DENY",
    why="same host, but POST /post is not in the rule's allow list",
)
def httpbin_post():
    # Covered by the httpbin.org rule above, which only allows GET:/get.
    # @openshell ignore kind=net reason="demo: host is declared above; the L7 rule denies this request"
    return _call(
        lambda: requests.post("https://httpbin.org/post", json={"hi": 1}, timeout=TIMEOUT)
    )
