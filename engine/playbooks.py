"""
AuthCanary — Actionable Incident Response Playbooks.

Provides concise, display-only operator guidance and standard containment
commands for each anomaly signal and correlated sequence.

SAFETY GUARDRAIL:
All playbooks are strictly text-based decision-support advice for human
operators. Commands are NEVER automatically executed by the application.
"""

from __future__ import annotations

PLAYBOOK_TEMPLATES = {
    "kill_chain": (
        "🚨 High-Priority Incident Response: Multi-stage post-compromise sequence detected.\n"
        "1. Verify active sessions: run 'w' or 'who'.\n"
        "2. If unauthorized, isolate connection: run 'pkill -u {user}'.\n"
        "3. Audit persistence: inspect ~/.ssh/authorized_keys, /etc/sudoers, and cron jobs for backdoors."
    ),
    "new_ssh_key": (
        "Persistence Audit:\n"
        "1. Inspect authorized keys: run 'ssh-keygen -lf ~/.ssh/authorized_keys'.\n"
        "2. Verify key comment and fingerprint against authorized admin key inventory.\n"
        "3. If unrecognized, remove key line immediately and check recent bash history."
    ),
    "first_sudo": (
        "Privilege Escalation Review:\n"
        "1. Inspect elevated commands: check '/var/log/auth.log' (or 'journalctl _COMM=sudo') for commands run by '{user}'.\n"
        "2. Verify with user whether sudo elevation was planned and authorized."
    ),
    "brute_force_pattern": (
        "Account Protection & Containment:\n"
        "1. Block attacker IP: run 'fail2ban-client set sshd banip {ip}' or 'iptables -A INPUT -s {ip} -j DROP'.\n"
        "2. Check if password was compromised; force credential rotation for '{user}'.\n"
        "3. Verify that public-key authentication is enforced and password auth is disabled in sshd_config."
    ),
    "new_asn": (
        "Unusual Origin Triage:\n"
        "1. Contact '{user}' to confirm if they are traveling or using a VPN/proxy from ASN {asn}.\n"
        "2. If unauthorized, terminate session: run 'pkill -u {user}'.\n"
        "3. Check /var/log/auth.log for other login attempts from this network."
    ),
    "new_ip_new_asn": (
        "Unusual Origin Triage:\n"
        "1. Contact '{user}' to confirm if they are traveling or using a VPN/proxy from {city}, {country} ({asn}).\n"
        "2. If unauthorized, terminate session: run 'pkill -u {user}'.\n"
        "3. Check /var/log/auth.log for other login attempts from {ip}."
    ),
    "integrity_drift": (
        "Configuration Drift Remediation:\n"
        "1. Inspect modification: compare '{path}' against version control or backup.\n"
        "2. Review file permissions and modification time: run 'ls -la {path}'.\n"
        "3. If unauthorized, restore known good baseline and review auth logs around mtime."
    ),
}


def get_playbook(
    signals: list[str],
    user: str = "user",
    ip: str = "unknown",
    asn: str = "unknown",
    city: str = "",
    country: str = "",
    path: str = "",
) -> str:
    """Generate human-readable remediation guidance based on triggered signals.

    Returns:
        Formatted playbook text string for operator guidance.
    """
    # Correlated kill chain takes top precedence
    if any("kill_chain" in s or "correlated" in s for s in signals):
        return PLAYBOOK_TEMPLATES["kill_chain"].format(user=user)

    if "new_ssh_key" in signals:
        return PLAYBOOK_TEMPLATES["new_ssh_key"].format(user=user)

    if "brute_force_pattern" in signals:
        return PLAYBOOK_TEMPLATES["brute_force_pattern"].format(user=user, ip=ip)

    if "first_sudo" in signals:
        return PLAYBOOK_TEMPLATES["first_sudo"].format(user=user)

    if "new_ip_new_asn" in signals:
        return PLAYBOOK_TEMPLATES["new_ip_new_asn"].format(
            user=user, ip=ip, asn=asn, city=city or "unknown", country=country or "unknown"
        )

    if "new_asn" in signals:
        return PLAYBOOK_TEMPLATES["new_asn"].format(user=user, asn=asn)

    if "integrity_drift" in signals:
        return PLAYBOOK_TEMPLATES["integrity_drift"].format(path=path or "monitored file")

    return "Standard Triage: Review event details against user baseline. Verify with user if action was unexpected."
