#!/usr/bin/env python3
"""
AuthCanary — Synthetic auth.log generator.

Produces a realistic multi-day auth.log with:
  - Normal daily patterns for 3 users across ~10 days
  - 5 deliberately injected anomalies on the final day

The generated data naturally spans past the default warm-up period
(7 days / 50 events), so anomalies are immediately visible when demoing.

Usage:
    python tools/generate_fake_auth_log.py [--output PATH] [--days N]
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path


# ── User profiles ──────────────────────────────────────────────────

USERS = {
    "alice": {
        "ips": ["8.8.8.8", "8.8.4.4"],             # Google DNS — consistent ASN
        "hours": range(9, 18),                       # 9am–5pm developer
        "auth_method": "password",
        "does_sudo": False,
        "sessions_per_day": (3, 8),
    },
    "bob": {
        "ips": ["1.1.1.1", "1.0.0.1", "9.9.9.9"],  # Cloudflare + Quad9 — 2 ASNs
        "hours": range(8, 23),                       # 8am–10pm ops
        "auth_method": "password",
        "does_sudo": True,
        "sessions_per_day": (5, 15),
    },
    "deploy": {
        "ips": ["208.67.222.222"],                   # OpenDNS — consistent ASN
        "hours": range(0, 24),                       # All hours, service account
        "auth_method": "publickey",
        "does_sudo": False,
        "sessions_per_day": (8, 20),
    },
}

HOSTNAME = "prod-web-01"




ANOMALY_IP = "185.220.101.34"       # Tor exit node (Romania)
ANOMALY_ASN = "AS205100 F3 Netze"   # Never-before-seen ASN
BRUTE_FORCE_IP = "45.33.32.156"     # Attacker IP for brute force


def _fmt_timestamp(dt: datetime) -> str:
    """Format datetime as syslog timestamp: 'Sep 10 14:23:05'."""
    return dt.strftime("%b %d %H:%M:%S")  # Note: day is not zero-padded in real syslog
    # Actually syslog uses space-padded day: 'Sep  3 14:23:05'
    # Let's match that


def _syslog_ts(dt: datetime) -> str:
    """Syslog timestamp with space-padded day."""
    return dt.strftime("%b") + dt.strftime(" %d ").replace(" 0", "  ") + dt.strftime("%H:%M:%S")


def _gen_login(dt: datetime, user: str, ip: str, method: str,
               success: bool = True) -> str:
    """Generate an sshd log line."""
    ts = _syslog_ts(dt)
    status = "Accepted" if success else "Failed"
    pid = random.randint(1000, 65000)
    port = random.randint(40000, 65535)
    return (
        f"{ts} {HOSTNAME} sshd[{pid}]: {status} {method} "
        f"for {user} from {ip} port {port} ssh2"
    )


def _gen_sudo(dt: datetime, user: str) -> str:
    """Generate a sudo log line."""
    ts = _syslog_ts(dt)
    pid = random.randint(1000, 65000)
    return (
        f"{ts} {HOSTNAME} sudo: {user} : TTY=pts/0 ; "
        f"PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt update"
    )


def _gen_ssh_key_added(dt: datetime, user: str,
                       fingerprint: str) -> str:
    """Generate an SSH key addition log line."""
    ts = _syslog_ts(dt)
    pid = random.randint(1000, 65000)
    return (
        f"{ts} {HOSTNAME} sshd[{pid}]: "
        f"key added: SHA256:{fingerprint} for user {user} "
        f"added to authorized_keys"
    )


def _gen_useradd(dt: datetime, user: str) -> str:
    """Generate a useradd log line."""
    ts = _syslog_ts(dt)
    pid = random.randint(1000, 65000)
    return f"{ts} {HOSTNAME} useradd[{pid}]: new user: name={user}, UID=1001, GID=1001"


def generate_normal_day(base_date: datetime, lines: list[str]) -> None:
    """Generate a full day of normal authentication activity."""
    for username, profile in USERS.items():
        n_sessions = random.randint(*profile["sessions_per_day"])
        for _ in range(n_sessions):
            hour = random.choice(list(profile["hours"]))
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            dt = base_date.replace(hour=hour, minute=minute, second=second)
            ip = random.choice(profile["ips"])
            method = profile["auth_method"]

            # Mostly successful logins
            if random.random() < 0.08:
                # Occasional typo / failed login
                lines.append(_gen_login(dt, username, ip, method, success=False))
                # Then a successful retry
                retry_dt = dt + timedelta(seconds=random.randint(5, 30))
                lines.append(_gen_login(retry_dt, username, ip, method, success=True))
            else:
                lines.append(_gen_login(dt, username, ip, method, success=True))

            # Bob uses sudo regularly
            if profile["does_sudo"] and random.random() < 0.4:
                sudo_dt = dt + timedelta(minutes=random.randint(1, 30))
                lines.append(_gen_sudo(sudo_dt, username))


def generate_anomaly_day(base_date: datetime, lines: list[str]) -> None:
    """Inject 5 specific anomalies into the final day.

    1. alice logs in from a brand-new IP/ASN (Romania VPN)
    2. alice logs in at 3:17am (never logged in outside 9am-5pm)
    3. New SSH key added for deploy
    4. alice uses sudo for the first time
    5. Brute-force pattern against bob (5 failures → success from unknown IP)
    """
    # Also generate some normal traffic so it looks realistic
    generate_normal_day(base_date, lines)

    # Anomaly 1: alice from new IP/ASN at 3:17am (stacks new_ip + unusual_hour)
    dt1 = base_date.replace(hour=3, minute=17, second=44)
    lines.append(_gen_login(dt1, "alice", ANOMALY_IP, "password", success=True))

    # Anomaly 2: alice at 4:02am from known IP (unusual hour only)
    dt2 = base_date.replace(hour=4, minute=2, second=11)
    lines.append(_gen_login(dt2, "alice", "8.8.8.8", "password", success=True))

    # Anomaly 3: new SSH key for deploy
    dt3 = base_date.replace(hour=11, minute=5, second=33)
    fingerprint = "nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"
    lines.append(_gen_ssh_key_added(dt3, "deploy", fingerprint))

    # Anomaly 4: alice uses sudo (never has before)
    dt4 = base_date.replace(hour=14, minute=45, second=8)
    lines.append(_gen_sudo(dt4, "alice"))

    # Anomaly 5: brute force against bob
    bf_start = base_date.replace(hour=2, minute=30, second=0)
    for i in range(5):
        dt_fail = bf_start + timedelta(seconds=random.randint(10, 60) * (i + 1))
        lines.append(_gen_login(dt_fail, "bob", BRUTE_FORCE_IP, "password", success=False))
    # Success after the failures
    dt_success = bf_start + timedelta(minutes=6, seconds=random.randint(0, 30))
    lines.append(_gen_login(dt_success, "bob", BRUTE_FORCE_IP, "password", success=True))


def generate_fake_log(output_path: str, days: int = 10) -> str:
    """Generate a complete synthetic auth.log.

    Args:
        output_path: where to write the file.
        days: total days of data (last day has anomalies).

    Returns:
        Path to the generated file.
    """
    lines: list[str] = []
    today = datetime.now().replace(microsecond=0)
    start_date = today - timedelta(days=days - 1)

    for day_offset in range(days):
        base_date = start_date + timedelta(days=day_offset)

        if day_offset == days - 1:
            # Final day: inject anomalies
            generate_anomaly_day(base_date, lines)
        else:
            # Normal day
            generate_normal_day(base_date, lines)

    # Sort by timestamp (syslog format sorts lexicographically within a month)
    lines.sort()

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return str(out)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate synthetic auth.log for AuthCanary testing.",
    )
    parser.add_argument(
        "--output", "-o",
        default="./test_data/auth.log",
        help="Output file path (default: ./test_data/auth.log)",
    )
    parser.add_argument(
        "--days", "-d",
        type=int,
        default=10,
        help="Number of days of data to generate (default: 10)",
    )
    parser.add_argument(
        "--seed", "-s",
        type=int,
        default=42,
        help="Random seed for reproducible output (default: 42)",
    )
    args = parser.parse_args()

    random.seed(args.seed)
    path = generate_fake_log(args.output, args.days)
    line_count = sum(1 for _ in open(path))
    print(f"✓ Generated {line_count} log lines across {args.days} days")
    print(f"  Output: {path}")
    print(f"  Days 1–{args.days - 1}: normal patterns for alice, bob, deploy")
    print(f"  Day {args.days}: 5 injected anomalies")
    print(f"  Seed: {args.seed}")


if __name__ == "__main__":
    main()
