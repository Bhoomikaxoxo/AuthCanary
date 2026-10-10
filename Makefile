# AuthCanary — Developer Makefile
# Provides common workflow shortcuts.
#
# Usage:
#   make setup       — create venv + install deps
#   make run         — run one analysis pass
#   make serve       — start the live dashboard on :8080
#   make test        — run the test suite
#   make lint        — static analysis (ruff / flake8 fallback)
#   make docker-build
#   make docker-run
#   make install-agent   — install the macOS LaunchAgent (macOS only)
#   make uninstall-agent — remove the macOS LaunchAgent
#   make install-service — install the systemd user service (Linux only)

PYTHON      := .venv/bin/python
PIP         := .venv/bin/pip
PYTEST      := .venv/bin/pytest
SCRIPT_DIR  := $(shell pwd)
PLIST_NAME  := com.authcanary.agent.plist
PLIST_DIR   := $(HOME)/Library/LaunchAgents
IMAGE_NAME  := authcanary

.PHONY: all setup run serve test lint clean \
        docker-build docker-run \
        install-agent uninstall-agent \
        install-service uninstall-service

all: setup

# ── Environment ────────────────────────────────────────────────────

setup: .venv/bin/activate
	@echo "✓ Setup complete. Run 'make run' to start."

.venv/bin/activate: requirements.txt
	python3 -m venv .venv
	$(PIP) install -q --upgrade pip
	$(PIP) install -q -r requirements.txt
	@touch .venv/bin/activate

# ── Running ────────────────────────────────────────────────────────

run: setup
	$(PYTHON) main.py --config config.yaml

run-dry: setup
	$(PYTHON) main.py --config config.yaml --dry-run

run-skip-warmup: setup
	$(PYTHON) main.py --config config.yaml --skip-warmup

serve: setup
	$(PYTHON) main.py --config config.yaml --serve --open

reset: setup
	$(PYTHON) main.py --config config.yaml --reset-baseline

# ── Testing & Quality ──────────────────────────────────────────────

test: setup
	$(PYTEST) tests/ -v

lint: setup
	@if $(PIP) show ruff > /dev/null 2>&1; then \
		.venv/bin/ruff check .; \
	elif $(PIP) show flake8 > /dev/null 2>&1; then \
		.venv/bin/flake8 . --max-line-length=110 --exclude=.venv; \
	else \
		echo "No linter found. Install ruff: pip install ruff"; \
	fi

# ── Docker ─────────────────────────────────────────────────────────

docker-build:
	docker build -t $(IMAGE_NAME):latest .

docker-run: docker-build
	docker run --rm \
		-v $(HOME)/.authcanary:/data \
		-v /var/log/auth.log:/var/log/auth.log:ro \
		$(IMAGE_NAME):latest

docker-serve: docker-build
	docker run --rm \
		-p 8080:8080 \
		-v $(HOME)/.authcanary:/data \
		$(IMAGE_NAME):latest --serve --bind 0.0.0.0

# ── macOS LaunchAgent ──────────────────────────────────────────────

install-agent:
	@if [ "$$(uname -s)" != "Darwin" ]; then \
		echo "❌ LaunchAgent is macOS-only. Use 'make install-service' on Linux."; exit 1; \
	fi
	@mkdir -p "$(PLIST_DIR)"
	@sed "s|AUTHCANARY_DIR_PLACEHOLDER|$(SCRIPT_DIR)|g" \
		schedulers/$(PLIST_NAME) > "$(PLIST_DIR)/$(PLIST_NAME)"
	@launchctl unload "$(PLIST_DIR)/$(PLIST_NAME)" 2>/dev/null || true
	@launchctl load "$(PLIST_DIR)/$(PLIST_NAME)"
	@echo "✓ LaunchAgent installed and started (every 15 min)."
	@echo "  Status: launchctl list | grep authcanary"
	@echo "  Logs:   tail -f /tmp/authcanary.stdout.log"

uninstall-agent:
	@launchctl unload "$(PLIST_DIR)/$(PLIST_NAME)" 2>/dev/null || true
	@rm -f "$(PLIST_DIR)/$(PLIST_NAME)"
	@echo "✓ LaunchAgent removed."

# ── Linux systemd user service ─────────────────────────────────────

install-service:
	@if [ "$$(uname -s)" != "Linux" ]; then \
		echo "❌ systemd service is Linux-only. Use 'make install-agent' on macOS."; exit 1; \
	fi
	@UNIT_DIR="$(HOME)/.config/systemd/user"; \
	mkdir -p "$$UNIT_DIR"; \
	sed "s|%h/authcanary|$(SCRIPT_DIR)|g" \
		schedulers/authcanary.service > "$$UNIT_DIR/authcanary.service"; \
	cp schedulers/authcanary.timer "$$UNIT_DIR/authcanary.timer"; \
	systemctl --user daemon-reload; \
	systemctl --user enable --now authcanary.timer
	@echo "✓ systemd timer installed and started (every 15 min)."
	@echo "  Status: systemctl --user status authcanary.timer"

uninstall-service:
	@systemctl --user disable --now authcanary.timer 2>/dev/null || true
	@rm -f $(HOME)/.config/systemd/user/authcanary.service \
	       $(HOME)/.config/systemd/user/authcanary.timer
	@systemctl --user daemon-reload
	@echo "✓ systemd service removed."

# ── Housekeeping ───────────────────────────────────────────────────

clean:
	rm -rf .venv __pycache__ .pytest_cache dist build *.egg-info
	find . -name "*.pyc" -delete
