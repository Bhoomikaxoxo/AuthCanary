# AuthCanary 🐤🔍

[![CI](https://github.com/Bhoomikaxoxo/AuthCanary/actions/workflows/ci.yml/badge.svg)](https://github.com/Bhoomikaxoxo/AuthCanary/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **macOS & Linux Authentication Log & Security Activity Monitor with Deterministic Security Invariants.**

AuthCanary continuously monitors authentication activity and system logs, building an empirical baseline of normal behavior and alerting on suspicious anomalies, kill-chain escalation sequences, and configuration drift.

---

## 🌟 Key Features

- **Cross-Platform Ingestion**:
  - **macOS**: Reads directly from Unified Logging (`log stream` / `log show`) for `sudo`, `authd`, `sshd`, `opendirectoryd`, and `tcc`.
  - **Linux**: Ingests `journald` or `/var/log/auth.log` / `/var/log/secure`.
- **Deterministic Invariant Engine**: Evaluates authentication events against strict rules (e.g. `UNAUTHORIZED_KEY_ADD`, `KILL_CHAIN_ESCALATION`, `CONFIG_DRIFT`).
- **Baseline & Novelty Tracking**: Tracks users, processes, source IPs, ASN records, and hour-of-day access patterns with warm-up baseline building.
- **Integrity & Persistence Monitoring**:
  - File hash verification for `/etc/ssh/sshd_config`, `~/.ssh/authorized_keys`, `/etc/sudoers`.
  - Detection of persistence artifacts (LaunchAgents/Daemons, cron jobs, shell profiles).
- **Enrichment**: Offline caching and rate-limited geolocation and ASN enrichment via IP-API.
- **Live Activity Monitor & Web Dashboard**: Built-in HTTP server providing a modern real-time incident triage UI and exportable reports (`report.html` and `report.json`).

---

## 🚀 Quick Start

### 1. Automated Setup (Recommended)

Run the automated setup script to set up a virtual environment and optionally install scheduling agents:

```bash
./setup.sh
```

Or using `make`:

```bash
make setup
```

### 2. Manual Installation

```bash
# Clone the repository
git clone https://github.com/Bhoomikaxoxo/AuthCanary.git
cd AuthCanary

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies (or install as editable package)
pip install -r requirements.txt
pip install -e .
```

---

## 💻 Usage

### Command Line Interface

```bash
# Run a single log analysis pass
authcanary --config config.yaml

# Skip warmup period and alert immediately
authcanary --skip-warmup

# Run in dry-run mode (no baseline database mutations)
authcanary --dry-run

# Start the interactive web console & dashboard
authcanary --serve --open --port 8080
```

### Developer Makefile Shortcuts

```bash
make run              # Run single analysis pass
make run-dry          # Run analysis in dry-run mode
make serve            # Launch the web dashboard on :8080 and open browser
make reset            # Reset the baseline DB and cursor
make test             # Run pytest test suite
make lint             # Run static analysis
make docker-build     # Build Docker image
make docker-run       # Run analysis inside container
```

---

## ⚙️ Configuration

AuthCanary is configured via `config.yaml`:

```yaml
log_source:
  path: "auto"       # "auto" detects OS, or specify explicit log file / "journald"

monitor:
  processes:
    - sudo
    - authd
    - sshd
    - opendirectoryd
    - tcc
  live_stream: true
  stream_poll_sec: 2

invariants:
  alert_severities:
    - CRITICAL
    - WARNING

integrity:
  enabled: true
  targets:
    - "/etc/ssh/sshd_config"
    - "~/.ssh/authorized_keys"
    - "/etc/sudoers"

storage:
  db_path: "~/.authcanary/authcanary.db"
  cursor_path: "~/.authcanary/cursor.json"
```

---

## ⏰ Background Scheduling & Deployment

### macOS LaunchAgent
To run AuthCanary periodically in the background every 15 minutes:

```bash
make install-agent
# Check agent status
launchctl list | grep authcanary
# To uninstall
make uninstall-agent
```

### Linux systemd Service & Timer
To run AuthCanary as a user systemd timer:

```bash
make install-service
# View timer status
systemctl --user list-timers | grep authcanary
# View logs
journalctl --user -u authcanary.service
```

---

## 🐳 Docker Deployment

A lightweight multi-stage Docker image is included:

```bash
# Build the container
docker build -t authcanary:latest .

# Run one-shot analysis against mounted log & persistent storage
docker run --rm \
  -v ~/.authcanary:/data \
  -v /var/log/auth.log:/var/log/auth.log:ro \
  authcanary:latest

# Run the live web dashboard on port 8080
docker run --rm -p 8080:8080 \
  -v ~/.authcanary:/data \
  authcanary:latest --serve --bind 0.0.0.0
```

---

## 🧪 Testing

AuthCanary includes a full pytest test suite covering adapters, invariant engines, enrichment caches, and report generators:

```bash
make test
# or
pytest tests/ -v
```

Continuous Integration is configured via [GitHub Actions](.github/workflows/ci.yml) testing against Python 3.10–3.13 on both macOS and Linux environments.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for details.
