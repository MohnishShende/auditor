"""
Unit tests for deterministic health, exposure, and drift analysis.
"""

from serveraudit.analysis.health import evaluate_health
from serveraudit.analysis.exposure import evaluate_exposure
from serveraudit.analysis.drift import compare_snapshots


def test_health_evaluation_smart_and_fs():
    """Verify health rules detect SMART failures, high disk utilization, and failed units."""
    mock_audit = {
        "smart": {
            "devices": [
                {"device": "/dev/sda", "healthy": False, "status": "FAILED", "reallocated_sectors": 48},
                {"device": "/dev/nvme0n1", "healthy": True, "status": "PASSED", "critical_warning": 1},
            ]
        },
        "filesystems": {
            "mounts": [
                {"target": "/var", "percent_used": 96, "available_formatted": "2.1 GB"},
            ]
        },
        "systemd": {
            "failed_units": [
                {"unit": "nginx.service", "active": "failed", "sub": "failed", "description": "Nginx Web Server"}
            ]
        },
    }

    findings = evaluate_health(mock_audit)
    assert len(findings) >= 4

    severities = [f["severity"] for f in findings]
    assert "CRITICAL" in severities
    assert "WARNING" in severities

    titles = [f["title"] for f in findings]
    assert any("Disk SMART Failure" in t for t in titles)
    assert any("NVMe Critical Warning" in t for t in titles)
    assert any("Disk Space Critical" in t for t in titles)
    assert any("Failed systemd unit" in t for t in titles)


def test_configuration_drift_detection():
    """Verify snapshot comparison engine identifies exact changes across kernel, containers, and ports."""
    snapshot_a = {
        "metadata": {"hostname": "nodezero", "timestamp": "2026-09-20T10:00:00"},
        "system": {"kernel": {"release": "7.0.0-31-generic"}},
        "docker": {
            "containers": [
                {"name": "caddy", "image": "caddy:2.8.4"},
            ]
        },
        "ports": {"listening_ports": [{"protocol": "tcp", "port": 80}]},
        "ssh": {"effective_config": {"pubkey_authentication": "yes"}},
        "packages": {"installed_count": 1200},
    }

    snapshot_b = {
        "metadata": {"hostname": "nodezero", "timestamp": "2026-09-24T10:00:00"},
        "system": {"kernel": {"release": "7.0.0-34-generic"}},
        "docker": {
            "containers": [
                {"name": "caddy", "image": "caddy:2.8.4"},
                {"name": "paperless-webserver", "image": "ghcr.io/paperless-ngx/paperless-ngx:latest"},
            ]
        },
        "ports": {
            "listening_ports": [
                {"protocol": "tcp", "port": 80},
                {"protocol": "tcp", "port": 8000},
            ]
        },
        "ssh": {"effective_config": {"pubkey_authentication": "no"}},
        "packages": {"installed_count": 1215},
    }

    drift = compare_snapshots(snapshot_a, snapshot_b)

    assert drift["has_drift"] is True
    categories = drift["categories"]

    assert "System" in categories
    assert categories["System"][0]["old"] == "7.0.0-31-generic"
    assert categories["System"][0]["new"] == "7.0.0-34-generic"

    assert "Docker Containers" in categories
    assert "paperless-webserver" in categories["Docker Containers"]["added"]

    assert "Listening Ports" in categories
    assert "tcp/8000" in categories["Listening Ports"]["opened"]

    assert "SSH Configuration" in categories
    assert categories["SSH Configuration"][0]["old"] == "yes"
    assert categories["SSH Configuration"][0]["new"] == "no"

    assert "Packages" in categories
    assert categories["Packages"]["installed_count_delta"] == 15
