"""
Unit tests for Markdown, JSON, and HTML renderers.
"""

import json
from serveraudit.renderers.markdown import MarkdownRenderer
from serveraudit.renderers.json import JsonRenderer
from serveraudit.renderers.html import HtmlRenderer


def test_markdown_renderer_structure():
    """Verify Markdown renderer generates correct headers and executive summary."""
    mock_data = {
        "metadata": {
            "hostname": "nodezero",
            "timestamp": "2026-09-24T10:17:00",
            "profile": "private",
            "duration_seconds": 1.42,
            "tool_name": "serveraudit",
            "tool_version": "0.1.0",
            "privileges_available": True,
        },
        "system": {
            "os": {"pretty_name": "Ubuntu 26.04.1 LTS"},
            "kernel": {"release": "7.0.0-34-generic", "architecture": "x86_64"},
            "uptime_seconds": 86400,
        },
        "hardware": {"system": {"manufacturer": "Dell Inc.", "product_name": "PowerEdge R640"}},
        "cpu": {"model_name": "Intel Xeon Gold 6230", "physical_cores": 20, "logical_cpus": 40},
        "memory": {"ram": {"total_bytes": 68719476736, "used_bytes": 17179869184, "percent_used": 25.0}},
        "storage": {"disks": [{"path": "/dev/nvme0n1", "media": "nvme", "size_formatted": "1.00 TB"}]},
        "smart": {"overall_health_passed": True, "devices": []},
        "network": {"interfaces": []},
        "ssh": {"effective_config": {"port": 22, "permit_root_login": "prohibit-password", "password_authentication": "no"}},
        "docker": {"engine": {"active": True, "containers_running": 5, "containers_total": 5}},
        "caddy": {"sites": []},
        "applications": {"applications": []},
        "collectors": {"system": {"status": "SUCCESS", "duration_seconds": 0.05}},
        "analysis": {"health": [], "exposure": [], "conflicts": []},
        "topology": {"storage_chains": []},
    }

    md_output = MarkdownRenderer.render(mock_data)

    assert "# Linux Server Audit: `nodezero`" in md_output
    assert "## 1. Executive Summary" in md_output
    assert "nodezero" in md_output
    assert "Ubuntu 26.04.1 LTS" in md_output
    assert "Intel Xeon Gold 6230" in md_output
    assert "Dell Inc." in md_output
    assert "## 14. Audit Provenance & Collector Limitations" in md_output


def test_json_and_html_renderers():
    """Verify JSON and HTML renderers produce valid structures."""
    mock_data = {
        "metadata": {"hostname": "testserver", "timestamp": "2026-09-24T10:00:00", "profile": "public", "duration_seconds": 0.5},
        "system": {"os": {"pretty_name": "Debian GNU/Linux 12"}},
        "analysis": {"health": [], "exposure": []},
        "storage": {"disks": []},
        "docker": {"containers": []},
    }

    json_str = JsonRenderer.render(mock_data)
    parsed = json.loads(json_str)
    assert parsed["metadata"]["hostname"] == "testserver"

    html_str = HtmlRenderer.render(mock_data)
    assert "<!DOCTYPE html>" in html_str
    assert "testserver" in html_str
    assert "Debian GNU/Linux 12" in html_str
