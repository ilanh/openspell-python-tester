"""Network actions. Every egress rule is the comment right above its call."""

from __future__ import annotations

import requests

from . import action, http_op

TIMEOUT = 8


def _transcript(r: requests.Response) -> str:
    """The request line, response status, headers and full body, as the page shows them."""
    req = r.request
    lines = [f"> {req.method} {req.url}", ""]
    lines.append(f"< HTTP {r.status_code} {r.reason}")
    lines += [f"< {k}: {v}" for k, v in r.headers.items()]
    lines += ["", r.text]
    return "\n".join(lines)


def _verdict(r: requests.Response) -> tuple[str, str, dict]:
    body = " ".join(r.text.split())[:160]
    extra = {"http_status": r.status_code, "output": _transcript(r)}
    # OpenShell's proxy answers a denied request with 403; none of the targets
    # below return 403 on their own for these requests.
    if r.status_code == 403:
        return "DENY", f"HTTP 403 {body}", extra
    return ("ALLOW" if r.ok else "ERROR"), f"HTTP {r.status_code} {body}", extra


def _call(fn) -> tuple[str, str, dict]:
    try:
        return _verdict(fn())
    except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError) as e:
        return "DENY", f"{type(e).__name__}: {str(e)[:200]}", {"output": f"{type(e).__name__}: {e}"}
    except requests.exceptions.SSLError as e:
        msg = f"SSLError (client does not trust the OpenShell CA?): {e}"
        return "ERROR", msg[:260], {"output": msg}


@action(
    "github-zen",
    group="network",
    title="GET https://api.github.com/zen",
    expect="ALLOW",
    why="egress rule for api.github.com:443, read-only, for the Python binary",
    op=http_op("GET", "api.github.com", 443, "/zen"),
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
    op=http_op("GET", "example.com", 443, "/"),
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
    op=http_op("GET", "httpbin.org", 443, "/get"),
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
    op=http_op("POST", "httpbin.org", 443, "/post"),
)
def httpbin_post():
    # Covered by the httpbin.org rule above, which only allows GET:/get.
    # @openshell ignore kind=net reason="demo: host is declared above; the L7 rule denies this request"
    return _call(
        lambda: requests.post("https://httpbin.org/post", json={"hi": 1}, timeout=TIMEOUT)
    )


@action(
    "github-port-80",
    group="network",
    title="GET http://api.github.com/zen (port 80)",
    expect="DENY",
    why="the api.github.com rule is for port 443 only: the port is part of the endpoint",
    op=http_op("GET", "api.github.com", 80, "/zen"),
)
def github_port_80():
    # Deliberately unannotated: the host is declared, but not on port 80.
    # No redirects, so an unsandboxed run reports GitHub's 301 instead of following it to 443.
    return _call(
        lambda: requests.get("http://api.github.com/zen", timeout=TIMEOUT, allow_redirects=False)
    )


@action(
    "postman-get",
    group="network",
    title="GET https://postman-echo.com/get",
    expect="ALLOW",
    why="allow=GET:/** covers every GET path on postman-echo.com",
    op=http_op("GET", "postman-echo.com", 443, "/get"),
)
def postman_get():
    # @openshell egress postman-echo.com:443 reason="demo: deny rule carves a path out of an allow" allow=GET:/** deny=GET:/status/**
    return _call(lambda: requests.get("https://postman-echo.com/get", timeout=TIMEOUT))


@action(
    "postman-status",
    group="network",
    title="GET https://postman-echo.com/status/200",
    expect="DENY",
    why="same allow=GET:/**, but deny=GET:/status/** subtracts this path",
    op=http_op("GET", "postman-echo.com", 443, "/status/200"),
)
def postman_status():
    # Covered by the postman-echo.com rule above; its deny_rules entry blocks this path.
    # @openshell ignore kind=net reason="demo: host is declared above; the deny rule refuses this request"
    return _call(lambda: requests.get("https://postman-echo.com/status/200", timeout=TIMEOUT))


@action(
    "jsonplaceholder-audit",
    group="network",
    title="POST https://jsonplaceholder.typicode.com/posts",
    expect="ALLOW",
    why="the rule only allows GET /todos/1, but enforce=audit logs the violation instead of blocking it",
    op=http_op("POST", "jsonplaceholder.typicode.com", 443, "/posts"),
)
def jsonplaceholder_audit():
    # @openshell egress jsonplaceholder.typicode.com:443 reason="demo: audit mode logs instead of blocking" allow=GET:/todos/1 enforce=audit
    return _call(
        lambda: requests.post(
            "https://jsonplaceholder.typicode.com/posts", json={"title": "hi"}, timeout=TIMEOUT
        )
    )
