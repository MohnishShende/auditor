"""
Requested output that cannot be produced must be reported, not silently dropped:
`--format ...,pdf` without WeasyPrint used to exit 0 with no PDF and no message.
"""

from unittest.mock import patch

import pytest

from serveraudit.cli.audit import AuditOrchestrator


@pytest.fixture(autouse=True)
def _as_linux():
    """Keep stderr free of the non-Linux platform warning so these tests behave the same on any OS."""
    with patch("serveraudit.cli.audit.platform.system", return_value="Linux"):
        yield


def _run(tmp_path, formats):
    return AuditOrchestrator(output_dir=str(tmp_path), formats=formats, quiet=True).run_audit()


def test_pdf_without_weasyprint_warns_and_still_succeeds(tmp_path, capsys):
    with patch("serveraudit.cli.audit.PdfRenderer.is_available", return_value=False):
        snap = _run(tmp_path, ["markdown", "json", "pdf"])
    err = capsys.readouterr().err
    assert "WeasyPrint" in err and "pdf" in err.lower() and "pip install" in err
    assert not (snap / "audit.pdf").exists()
    assert (snap / "audit.md").exists() and (snap / "audit.json").exists()


def test_pdf_render_failure_warns_even_when_weasyprint_imports(tmp_path, capsys):
    with patch("serveraudit.cli.audit.PdfRenderer.is_available", return_value=True), \
         patch("serveraudit.cli.audit.PdfRenderer.render", return_value=None):
        snap = _run(tmp_path, ["markdown", "json", "pdf"])
    assert "PDF" in capsys.readouterr().err
    assert not (snap / "audit.pdf").exists()


def test_unknown_format_names_are_reported(tmp_path, capsys):
    snap = _run(tmp_path, ["markdown", "json", "pdff", "docx"])
    err = capsys.readouterr().err
    assert "pdff" in err and "docx" in err
    assert (snap / "audit.md").exists()


def test_no_warning_when_formats_are_fine(tmp_path, capsys):
    _run(tmp_path, ["markdown", "json", "html"])
    assert capsys.readouterr().err == ""
