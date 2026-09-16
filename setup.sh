#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
# SentinelLog — Setup Script
#
# Detects the OS, creates a venv, installs deps, sets up storage,
# and optionally installs a scheduled job (with user confirmation).
# ──────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STORAGE_DIR="$HOME/.sentinellog"

echo "SentinelLog Setup"
echo "═════════════════"
echo ""

# ── Python check ──────────────────────────────────────────────────

if ! command -v python3 &>/dev/null; then
    echo "✗ Python 3 is required but not found."
    echo "  Install Python 3.10+ and try again."
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "  Python: $PY_VERSION"

# ── Virtual environment ───────────────────────────────────────────

if [ ! -d "$SCRIPT_DIR/.venv" ]; then
    echo "  Creating virtual environment..."
    python3 -m venv "$SCRIPT_DIR/.venv"
fi

source "$SCRIPT_DIR/.venv/bin/activate"
pip install -q -r "$SCRIPT_DIR/requirements.txt"
echo "  Dependencies: installed"

# ── Storage directory ─────────────────────────────────────────────

mkdir -p "$STORAGE_DIR"
echo "  Storage: $STORAGE_DIR"

# ── Log file access check ────────────────────────────────────────

OS="$(uname -s)"
echo "  OS: $OS"

if [ "$OS" = "Linux" ]; then
    AUTH_LOG="/var/log/auth.log"
    if [ -f "$AUTH_LOG" ]; then
        if [ -r "$AUTH_LOG" ]; then
            echo "  Log source: $AUTH_LOG (readable ✓)"
        else
            echo ""
            echo "  ⚠ Log source: $AUTH_LOG exists but is NOT readable."
            echo "    You may need to run SentinelLog with elevated privileges,"
            echo "    or add your user to the 'adm' group:"
            echo ""
            echo "      sudo usermod -aG adm \$USER"
            echo "      # then log out and back in"
            echo ""
        fi
    elif command -v journalctl &>/dev/null; then
        echo "  Log source: journalctl (systemd detected)"
    else
        echo "  ⚠ No supported log source detected."
        echo "    Use --log-source to point at an auth.log file."
    fi
elif [ "$OS" = "Darwin" ]; then
    echo "  Log source: macOS unified log (via 'log show')"
    echo "  Note: Reading sshd logs may require Full Disk Access"
    echo "  in System Preferences → Privacy & Security."
fi

echo ""
echo "✓ Core setup complete."
echo ""

# ── Scheduled job (requires confirmation) ─────────────────────────

echo "Would you like to install a scheduled job to run SentinelLog"
echo "every 15 minutes automatically?"
echo ""

read -rp "Install scheduled job? [y/N] " INSTALL_JOB

if [[ "$INSTALL_JOB" =~ ^[Yy]$ ]]; then
    if [ "$OS" = "Linux" ] && command -v systemctl &>/dev/null; then
        # systemd
        UNIT_DIR="$HOME/.config/systemd/user"
        mkdir -p "$UNIT_DIR"

        # Update service file with actual path
        sed "s|%h/sentinellog|$SCRIPT_DIR|g" \
            "$SCRIPT_DIR/schedulers/sentinellog.service" > "$UNIT_DIR/sentinellog.service"
        cp "$SCRIPT_DIR/schedulers/sentinellog.timer" "$UNIT_DIR/sentinellog.timer"

        systemctl --user daemon-reload
        systemctl --user enable --now sentinellog.timer
        echo "  ✓ systemd timer installed and started."
        echo "    Check status: systemctl --user status sentinellog.timer"

    elif [ "$OS" = "Darwin" ]; then
        # launchd
        PLIST_DIR="$HOME/Library/LaunchAgents"
        PLIST_NAME="com.sentinellog.agent.plist"
        mkdir -p "$PLIST_DIR"

        sed "s|SENTINELLOG_DIR_PLACEHOLDER|$SCRIPT_DIR|g" \
            "$SCRIPT_DIR/schedulers/com.sentinellog.plist" > "$PLIST_DIR/$PLIST_NAME"

        launchctl load "$PLIST_DIR/$PLIST_NAME" 2>/dev/null || true
        echo "  ✓ launchd agent installed."
        echo "    Check status: launchctl list | grep sentinellog"

    else
        echo "  ⚠ Automatic installation not supported on this OS."
        echo "    For Windows, set up a Task Scheduler entry manually:"
        echo "    - Program: python3"
        echo "    - Arguments: $SCRIPT_DIR/main.py --config $SCRIPT_DIR/config.yaml"
        echo "    - Trigger: Every 15 minutes"
    fi
else
    echo "  Skipped. Run manually with:"
    echo "    cd $SCRIPT_DIR && .venv/bin/python main.py"
fi

echo ""
echo "Quick start:"
echo "  1. Generate test data:  .venv/bin/python tools/generate_fake_auth_log.py"
echo "  2. Run analysis:        .venv/bin/python main.py --log-source test_data/auth.log --skip-warmup"
echo "  3. View report:         open output/report.html"
