"""
AuthCanary — Tests for File Integrity Monitoring (FIM) & Configuration Drift.
"""

from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.integrity import IntegrityChecker, IntegrityResult


def test_integrity_initial_baseline(tmp_path):
    db_path = str(tmp_path / "test.db")
    file1 = tmp_path / "sshd_config"
    file1.write_text("PermitRootLogin no\n", encoding="utf-8")

    checker = IntegrityChecker(db_path=db_path, targets=[str(file1)])
    results = checker.check()

    assert len(results) == 1
    assert results[0].status == "OK"
    assert results[0].is_alert is False
    assert len(results[0].sha256) == 64


def test_integrity_detects_modified_file(tmp_path):
    db_path = str(tmp_path / "test.db")
    file1 = tmp_path / "sudoers"
    file1.write_text("root ALL=(ALL:ALL) ALL\n", encoding="utf-8")

    checker = IntegrityChecker(db_path=db_path, targets=[str(file1)])
    # Initial run establishes baseline
    checker.check()

    # Attacker appends unauthorized backdoor line
    file1.write_text("root ALL=(ALL:ALL) ALL\nevil ALL=(ALL:ALL) NOPASSWD:ALL\n", encoding="utf-8")

    # Second audit detects drift
    results2 = checker.check()
    assert len(results2) == 1
    res = results2[0]
    assert res.status == "MODIFIED"
    assert res.is_alert is True
    assert "drift detected" in res.message.lower()
    assert "Configuration Drift Remediation" in res.playbook


def test_integrity_detects_deleted_file(tmp_path):
    db_path = str(tmp_path / "test.db")
    file1 = tmp_path / "authorized_keys"
    file1.write_text("ssh-ed25519 AAAAC3... admin@corp\n", encoding="utf-8")

    checker = IntegrityChecker(db_path=db_path, targets=[str(file1)])
    checker.check()

    # File deleted
    file1.unlink()

    results2 = checker.check()
    assert len(results2) == 1
    res = results2[0]
    assert res.status == "DELETED"
    assert res.is_alert is True
    assert "deleted" in res.message.lower()


def test_integrity_detects_created_file_in_dir(tmp_path):
    db_path = str(tmp_path / "test.db")
    sudoers_d = tmp_path / "sudoers.d"
    sudoers_d.mkdir()
    legit = sudoers_d / "01-admin"
    legit.write_text("%admin ALL=(ALL) ALL\n", encoding="utf-8")

    checker = IntegrityChecker(db_path=db_path, targets=[str(sudoers_d)])
    checker.check()

    # Drop-in persistence file added
    backdoor = sudoers_d / "99-backdoor"
    backdoor.write_text("backdoor ALL=(ALL) NOPASSWD:ALL\n", encoding="utf-8")

    results2 = checker.check()
    created = [r for r in results2 if r.status == "CREATED"]
    assert len(created) == 1
    assert created[0].filepath == str(backdoor)
    assert created[0].is_alert is True


def test_integrity_permission_denied_diagnostic(tmp_path):
    db_path = str(tmp_path / "test.db")
    restricted_file = tmp_path / "root_sudoers"
    restricted_file.write_text("secure\n", encoding="utf-8")

    checker = IntegrityChecker(db_path=db_path, targets=[str(restricted_file)])

    # Mock open raising PermissionError
    with patch("builtins.open", side_effect=PermissionError("Permission denied")):
        results = checker.check()

    assert len(results) == 1
    res = results[0]
    assert res.status == "PERMISSION_DENIED"
    assert res.is_alert is False
    assert "permission denied" in res.message.lower()
    assert "elevated permissions" in res.message.lower()
