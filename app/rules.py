"""Find the rule in the generated policy.yaml that governs one action's operation.

This is a read-only explanation for the page, not an enforcement engine: OpenShell
decides. It follows the same rules the cards demonstrate (host + port endpoints,
binaries matched on the process or a parent, L7 allow/deny rules, audit mode,
filesystem read/write roots) so each card can show *why* its verdict is expected.
"""

from __future__ import annotations

import re
from fnmatch import fnmatchcase

import yaml

# OpenShell's built-in read-only paths, present without any policy entry
# (shown as "baseline", never claimed as a rule in policy.yaml).
BASELINE_READ = ("/etc", "/usr", "/lib", "/bin", "/sbin", "/proc")
READ_ONLY_METHODS = {"GET", "HEAD", "OPTIONS"}


def _under(path: str, root: str) -> bool:
    root = root.rstrip("/") or "/"
    return path == root or path.startswith(root + "/")


def _path_match(pattern: str, path: str) -> bool:
    # ** spans segments, * stays inside one.
    rx = "".join(
        ".*" if tok == "**" else "[^/]*" if tok == "*" else re.escape(tok)
        for tok in re.split(r"(\*\*|\*)", pattern)
    )
    return re.fullmatch(rx, path) is not None


def _method_match(pattern: str, method: str) -> bool:
    return pattern in ("*", method) or fnmatchcase(method, pattern)


def _excerpt(text: str, header: str) -> str:
    """The YAML block starting at `header` (an exact line), comments included."""
    lines = text.splitlines()
    try:
        i = lines.index(header)
    except ValueError:
        return ""
    indent = len(header) - len(header.lstrip())
    out = [header]
    for line in lines[i + 1 :]:
        if line.strip() and len(line) - len(line.lstrip()) <= indent:
            break
        out.append(line)
    return "\n".join(out).rstrip()


def _fs_excerpt(text: str, section: str, root: str) -> str:
    """`filesystem_policy.<section>` trimmed to one root and its reason comment."""
    lines = text.splitlines()
    target = f'    - "{root}"'
    for i, line in enumerate(lines):
        if line == target:
            comment = [lines[i - 1]] if i and lines[i - 1].lstrip().startswith("#") else []
            return "\n".join(["filesystem_policy:", f"  {section}:", *comment, line])
    return ""


def explain(op: dict, policy_text: str) -> dict:
    try:
        policy = yaml.safe_load(policy_text) or {}
    except yaml.YAMLError as e:
        return {"status": "error", "predict": None, "summary": f"policy.yaml does not parse: {e}"}
    if op["kind"] == "fs":
        return _explain_fs(op, policy, policy_text)
    return _explain_net(op, policy, policy_text)


def _explain_fs(op: dict, policy: dict, text: str) -> dict:
    fsp = policy.get("filesystem_policy") or {}
    path, mode = op["path"], op["mode"]
    for section, writable in (("read_write", True), ("read_only", False)):
        for root in fsp.get(section) or []:
            if _under(path, root):
                ok = writable or mode == "read"
                why = (
                    f"{path} is under {section} root {root}"
                    + ("" if ok else f": {mode} is not granted on a read-only root")
                )
                return {
                    "status": "rule",
                    "name": f"filesystem_policy.{section}",
                    "yaml": _fs_excerpt(text, section, root),
                    "predict": "ALLOW" if ok else "DENY",
                    "summary": why,
                }
    if mode == "read" and any(_under(path, r) for r in BASELINE_READ):
        return {
            "status": "baseline",
            "name": "OpenShell baseline (read-only)",
            "yaml": "",
            "predict": "ALLOW",
            "summary": f"{path} is in OpenShell's built-in read-only baseline, not in policy.yaml",
        }
    return {
        "status": "none",
        "name": None,
        "yaml": "",
        "predict": "DENY",
        "summary": f"no filesystem rule covers {path} → default deny (Landlock returns EACCES)",
    }


def _explain_net(op: dict, policy: dict, text: str) -> dict:
    host, port, method, path = op["host"], op["port"], op["method"], op["path"]
    same_host = []
    for name, entry in (policy.get("network_policies") or {}).items():
        for ep in entry.get("endpoints") or []:
            if ep.get("host") != host:
                continue
            if ep.get("port") != port:
                same_host.append((name, ep))
                continue
            return _explain_endpoint(op, name, entry, ep, text)
    if same_host:
        name, ep = same_host[0]
        return {
            "status": "none",
            "name": None,
            "yaml": _excerpt(text, f"  {name}:"),
            "predict": "DENY",
            "summary": f"{host} is declared only on port {ep.get('port')} ({name}); "
            f"no rule for {host}:{port} → default deny",
        }
    return {
        "status": "none",
        "name": None,
        "yaml": "",
        "predict": "DENY",
        "summary": f"no egress rule for {host}:{port} → default deny (proxy answers 403)",
    }


def _explain_endpoint(op: dict, name: str, entry: dict, ep: dict, text: str) -> dict:
    method, path = op["method"], op["path"]
    notes: list[str] = []
    binaries = [b.get("path") for b in entry.get("binaries") or []]
    predict = "ALLOW"
    if op["binary"] in binaries:
        notes.append(f"binary {op['binary']} is listed")
    elif op.get("parent") in binaries:
        notes.append(f"{op['binary']} is not listed, but its parent {op['parent']} is: binaries match ancestors too")
    else:
        notes.append(f"binary {op['binary']} is not listed (rule names {', '.join(binaries) or 'none'})")
        predict = "DENY"

    l7_ok = True
    if ep.get("access"):
        l7_ok = ep["access"] != "read-only" or method in READ_ONLY_METHODS
        notes.append(f"access={ep['access']} {'allows' if l7_ok else 'does not allow'} {method}")
    if ep.get("rules"):
        allowed = [
            r["allow"] for r in ep["rules"]
            if "allow" in r and _method_match(r["allow"].get("method", "*"), method)
            and _path_match(r["allow"].get("path", "/**"), path)
        ]
        l7_ok = bool(allowed)
        if allowed:
            notes.append(f"{method} {path} matches allow {allowed[0].get('method')}:{allowed[0].get('path')}")
        else:
            rules = ", ".join(f"{r['allow'].get('method')}:{r['allow'].get('path')}" for r in ep["rules"] if "allow" in r)
            notes.append(f"{method} {path} is not in the allow list ({rules})")
    for d in ep.get("deny_rules") or []:
        if _method_match(d.get("method", "*"), method) and _path_match(d.get("path", "/**"), path):
            l7_ok = False
            notes.append(f"{method} {path} matches deny_rules {d.get('method')}:{d.get('path')}")
    audit = ep.get("enforcement") == "audit"
    if not l7_ok:
        if audit:
            notes.append("enforcement: audit, so the violation is logged and the request still passes")
        else:
            predict = "DENY"
    return {
        "status": "rule",
        "name": f"network_policies.{name}",
        "yaml": _excerpt(text, f"  {name}:"),
        "predict": predict,
        "audit": audit and not l7_ok,
        "enforcement": ep.get("enforcement"),
        "summary": "; ".join(notes),
    }
