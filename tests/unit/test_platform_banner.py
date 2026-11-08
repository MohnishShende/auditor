"""
The tool targets Linux (it reads /proc, runs ip/lsblk/systemctl...). On other platforms it
still runs but collects very little, so it must say so instead of producing a report that
looks like a normal audit (e.g. "Linux Kernel: 27.2.0" for Darwin).
"""

from serveraudit.cli.audit import unsupported_platform_message
from serveraudit.renderers.markdown import MarkdownRenderer


def _report(platform):
    meta = {"hostname": "h", "timestamp": "t", "profile": "private", "duration_seconds": 1.0,
            "tool_name": "serveraudit", "tool_version": "0.1.2", "audit_mode": "user",
            "privileges_available": False}
    if platform is not None:
        meta["platform"] = platform
    return {"metadata": meta, "system": {"os": {"pretty_name": "x"}, "kernel": {"release": "1", "architecture": "arm64"}},
            "collectors": {}, "analysis": {"health": [], "exposure": [], "conflicts": []}, "topology": {"storage_chains": []}}


def test_message_is_none_on_linux_and_explains_otherwise():
    assert unsupported_platform_message("Linux") is None
    msg = unsupported_platform_message("Darwin")
    assert "Darwin" in msg and "Linux" in msg and "incomplete" in msg.lower()


def test_report_header_has_banner_on_non_linux():
    md = MarkdownRenderer.render(_report("Darwin"))
    header = md.split("## 📑 Table of Contents")[0]
    assert "Platform Support" in header and "Darwin" in header and "Unsupported" in header


def test_report_has_no_banner_on_linux_or_legacy_snapshots():
    for p in ("Linux", None):
        header = MarkdownRenderer.render(_report(p)).split("## 📑 Table of Contents")[0]
        assert "Platform Support" not in header
