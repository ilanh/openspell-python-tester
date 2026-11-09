# Policy Playground

A one-screen demo of [openshell-annotate](https://github.com/ilanh/openshell-annotate) on
[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell). Each card on the page runs one action
inside the sandbox. You can see whether the policy allowed or denied it, and whether that matched what the code's
`@openshell` comments say should happen.

**The comments are the policy.** `openshell/policy.yaml` is generated from them, never edited by hand.

## The actions

| Card | Annotation in the code | Expected | What it shows |
|---|---|---|---|
| `GET api.github.com/zen` | `egress api.github.com:443 access=read-only` | ALLOW | a declared host |
| `GET example.com` | none | DENY | undeclared hosts are refused by the proxy |
| `GET httpbin.org/get` | `egress httpbin.org:443 allow=GET:/get` | ALLOW | L7 rule on method + path |
| `POST httpbin.org/post` | same rule | DENY | same host, request not in the allow list |
| `GET http://api.github.com/zen` | none for port 80 | DENY | the port is part of the endpoint |
| `GET postman-echo.com/get` | `egress postman-echo.com:443 allow=GET:/** deny=GET:/status/**` | ALLOW | wildcard L7 allow |
| `GET postman-echo.com/status/200` | same rule | DENY | `deny_rules` subtract from the allow |
| `POST jsonplaceholder.typicode.com/posts` | `egress ... allow=GET:/todos/1 enforce=audit` | ALLOW | audit mode logs the violation instead of blocking it |
| `write /data/out.txt` | `fs write /data` | ALLOW | declared write root |
| `write /opt/forbidden/x.txt` | none | DENY | Landlock blocks writes outside the policy |
| `write /app/x.txt` | `fs read /app` only | DENY | a read root is read-only |
| `read /etc/os-release` | none (OpenShell baseline) | ALLOW | baseline read-only paths |
| `read /opt/forbidden/secret.txt` | none | DENY | reads are restricted too |
| `curl api.github.com/zen` | rule names only Python | ALLOW | binaries match the process *or a parent*: curl runs as a child of Python |
| `curl icanhazip.com` | `egress icanhazip.com:443 ... bin=/usr/bin/curl` | ALLOW | a rule bound to one binary |
| `GET icanhazip.com` from Python | same rule | DENY | the reverse does not hold: Python is not a child of curl |
| (startup) | `fs read /app` in `app/main.py` | — | the server can't import its own code without it |

The code is in [`app/actions/`](app/actions): `net.py`, `fs.py` and `proc.py`. Each card shows its directive lines with `file:line`,
read live from the source.

## Prerequisites

- OpenShell CLI and gateway: `curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh`
- A container engine for the gateway (Docker or Podman; set `ENGINE=podman` if you use Podman)
- `make install-annotate` (installs `openshell-annotate` into `~/.local/bin`)
- [uv](https://docs.astral.sh/uv/) for `make dev` only

## Walkthrough

```bash
make scan        # every @openshell directive with its file:line
make policy      # generate openshell/policy.yaml (validated against the OpenShell schema)
make lint        # flags the unannotated example.com and api.github.com:80 calls and the /opt/forbidden and /app writes, plus an info for the curl subprocess
make sandbox     # build the image, start it in OpenShell with the policy, forward :8080
```

Open http://localhost:8080 and click **Run all**. The header pill should read *in OpenShell sandbox*, and every card should
show ✓.

Then close the loop with the sandbox's own logs:

```bash
make diff-logs   # maps the logged denials back to suggested @openshell directives (e.g. example.com:443)
make drift       # CI check: fails if policy.yaml no longer matches the comments
make down
```

Try changing a verdict: add `# @openshell egress example.com:443 reason="now allowed"` above the call in
`app/actions/net.py`, then run `make policy` and `openshell policy update playground ...` (network rules reload live), or just
`make sandbox` again. The card flips to ALLOW, and it now shows ✗ until you change its `expect`.

`make dev` runs the page on your machine without a sandbox. Nothing is enforced there, so the DENY rows come back ALLOW
or ERROR. The page says so in a banner.

## Notes

- **Binary paths.** OpenShell matches egress rules on the real executable path. The image is `python:3.12-slim`, and
  `make sandbox` starts uvicorn with `/usr/local/bin/python3.12`, the same path as `[languages].python` in
  `openshell-annotate.toml`. If you change the base image, change both.
- **TLS inspection.** The L7 rules make OpenShell terminate TLS. OpenShell points `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` at its
  CA, so `requests` and curl trust it with no extra setup.
- **Filesystem denials are not logged** by OpenShell 0.1.6 (NVIDIA/OpenShell#4270). The cards show the `EACCES`, but
  `diff-logs` only sees the network rows.
- `include_workdir = false` keeps the sandbox strict, so only `/app` (read), `/data` (write) and OpenShell's baseline paths are reachable.
- **No `WORKDIR` in the Dockerfile.** OpenShell refuses an image working directory that the non-root sandbox user can't
  use (`WorkspaceValidationFailed`). Without one, it uses its own `/sandbox`.
- **Docker Desktop on macOS.** The gateway's Docker driver defaults to host networking for the sandbox supervisor, and on
  Docker Desktop that can't reach a gateway bound to the Mac's `127.0.0.1` (`Startup configuration fetch failed`). Fix it
  by adding the following to the gateway config (Homebrew: `/opt/homebrew/var/openshell/gateway.toml`) and running
  `brew services restart openshell`:
  ```toml
  [openshell.drivers.docker]
  supervisor_network_mode = "bridge"
  ```
