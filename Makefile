SHELL := /bin/bash
COMPOSE := docker compose
RELEASE := artifacts/release

# Stop Git Bash / MSYS from mangling Unix-style paths into Windows paths
# when passed to native binaries like docker.exe. Without this, args like
# "/tools/gen_pcap.py" get rewritten to "C:/Program Files/Git/tools/...".
export MSYS_NO_PATHCONV := 1

.PHONY: help up down build pcap demo analyze test test-local evidence clean status all

help:
	@echo "Targets:"
	@echo "  make up        - build container images"
	@echo "  make pcap      - regenerate sample pcap (deterministic)"
	@echo "  make demo      - end-to-end: pcap -> zeek -> analyzer -> evidence"
	@echo "  make test      - run pytest with coverage in dev container"
	@echo "  make evidence  - snapshot artifacts/release into a timestamped bundle"
	@echo "  make clean     - remove runtime artifacts (preserves release/)"
	@echo "  make down      - tear down compose"

up: build

build:
	$(COMPOSE) build

pcap: build
	$(COMPOSE) run --rm --entrypoint "" -v "$(PWD)/tools:/tools:ro" -v "$(PWD)/pcaps:/pcaps:rw" \
		analyzer python /tools/gen_pcap.py --out /pcaps/sample/demo.pcap
	@mkdir -p $(RELEASE)
	@cp pcaps/sample/demo.pcap $(RELEASE)/demo.pcap

demo: pcap analyze status

analyze:
	@mkdir -p zeek/logs $(RELEASE)
	$(COMPOSE) run --rm zeek 2>&1 | tee $(RELEASE)/run.log
	@cp zeek/logs/notice.log $(RELEASE)/notice.log 2>/dev/null || echo "(no notice.log produced)"
	$(COMPOSE) run --rm analyzer 2>&1 | tee -a $(RELEASE)/run.log

test:
	docker build -t zeek-ids/analyzer-dev:local -f analyzer/Dockerfile.dev analyzer
	docker run --rm zeek-ids/analyzer-dev:local \
		pytest --cov=analyzer --cov-report=term tests/

test-local:
	cd analyzer && python -m pytest --cov=analyzer --cov-report=term tests/

evidence:
	@bash tools/snapshot_evidence.sh

status:
	@echo "--- summary.json ---" && cat $(RELEASE)/summary.json || true
	@echo
	@echo "Artifacts in $(RELEASE):" && ls -la $(RELEASE)

clean:
	rm -rf zeek/logs/* analyzer/.pytest_cache analyzer/.coverage analyzer/htmlcov
	@echo "cleaned runtime artifacts (release/ preserved)"

down:
	$(COMPOSE) down --remove-orphans

all: up demo test
