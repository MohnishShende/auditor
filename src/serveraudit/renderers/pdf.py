"""
Optional PDF report renderer for Linux Server Audit.
Uses WeasyPrint if available; fails gracefully if optional dependency is not installed.
"""

from __future__ import annotations
import io
from typing import Any, Dict, Optional
from .html import HtmlRenderer


class PdfRenderer:
    """Renders canonical audit data into PDF bytes via WeasyPrint."""

    @staticmethod
    def is_available() -> bool:
        """Check if WeasyPrint is installed and usable."""
        try:
            import weasyprint  # type: ignore
            return True
        except ImportError:
            return False

    @classmethod
    def render(cls, data: Dict[str, Any]) -> Optional[bytes]:
        """Renders audit data to PDF bytes if WeasyPrint is available."""
        if not cls.is_available():
            return None

        try:
            import weasyprint  # type: ignore
            html_content = HtmlRenderer.render(data)
            pdf_file = io.BytesIO()
            weasyprint.HTML(string=html_content).write_pdf(pdf_file)
            return pdf_file.getvalue()
        except Exception:
            return None
