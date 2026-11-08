# Policy Playground: a one-screen demo of openshell-annotate on NVIDIA OpenShell.
SANDBOX  ?= playground
IMAGE    ?= policy-playground:dev
PORT     ?= 8080
ENGINE   ?= docker
# Use openshell-annotate from PATH, else where `make install-annotate` puts it.
ANNOTATE ?= $(or $(shell command -v openshell-annotate 2>/dev/null),$(HOME)/.local/bin/openshell-annotate)
ANNOTATE_VERSION ?= v0.1.0-rc.2
POLICY   := openshell/policy.yaml
PY       := /usr/local/bin/python3.12

.PHONY: help install-annotate dev scan policy lint drift image sandbox logs diff-logs down

help: ## list targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-17s %s\n", $$1, $$2}'

install-annotate: ## install the openshell-annotate CLI into ~/.local/bin
	curl -fsSL https://raw.githubusercontent.com/ilanh/openshell-annotate/main/install.sh | sh -s -- --version $(ANNOTATE_VERSION)

dev: ## run the page on this machine, unsandboxed (nothing is enforced)
	uv run --python 3.12 --with-requirements requirements.txt uvicorn app.main:app --reload --port $(PORT)

scan: ## list every @openshell directive with its file:line
	$(ANNOTATE) scan

policy: ## generate openshell/policy.yaml from the annotations
	$(ANNOTATE) generate -o $(POLICY)

lint: ## flag code that touches network/fs/exec with no annotation (the DENY rows)
	-$(ANNOTATE) lint --policy $(POLICY)

drift: ## fail if openshell/policy.yaml no longer matches the annotations
	$(ANNOTATE) drift --policy $(POLICY)

image: policy ## build the sandbox image
	$(ENGINE) build -t $(IMAGE) .

sandbox: image ## start the app in an OpenShell sandbox, forwarded to localhost:$(PORT)
	-openshell sandbox delete $(SANDBOX) 2>/dev/null
	@echo "open http://localhost:$(PORT) once uvicorn reports it is running"
	openshell sandbox create --name $(SANDBOX) --from $(IMAGE) --policy $(POLICY) \
	  --no-auto-providers --forward $(PORT) -- \
	  $(PY) -m uvicorn app.main:app --app-dir /app --host 0.0.0.0 --port $(PORT)

logs: ## save the sandbox's allow/deny events to logs/sandbox.log
	@mkdir -p logs
	openshell logs $(SANDBOX) --since 30m --source sandbox > logs/sandbox.log
	@echo "wrote logs/sandbox.log"

diff-logs: logs ## map logged denials back to missing or stale directives
	-$(ANNOTATE) diff-logs logs/sandbox.log

down: ## delete the sandbox
	openshell sandbox delete $(SANDBOX)
