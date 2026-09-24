"""
CLI command for re-rendering an existing canonical audit snapshot into Markdown, HTML, or PDF.
"""

from __future__ import annotations
import json
from pathlib import Path
import sys
from typing import Optional

from ..renderers import MarkdownRenderer, HtmlRenderer, PdfRenderer


def run_render(json_path: str, output_format: str = "markdown", output_file: Optional[str] = None) -> int:
    """Loads audit.json and outputs rendered format."""
    p = Path(json_path)
    if not p.exists():
        print(f"Error: Snapshot JSON not found at '{json_path}'", file=sys.stderr)
        return 1

    with open(p, "r", encoding="utf-8") as f:
        data = json.load(f)

    fmt = output_format.lower()
    if fmt in ("md", "markdown"):
        result = MarkdownRenderer.render(data)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result)
            print(f"Rendered Markdown saved to {output_file}")
        else:
            print(result)

    elif fmt in ("html", "htm"):
        result = HtmlRenderer.render(data)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result)
            print(f"Rendered HTML saved to {output_file}")
        else:
            print(result)

    elif fmt == "pdf":
        if not PdfRenderer.is_available():
            print("Error: PDF rendering requires WeasyPrint ('pip install weasyprint')", file=sys.stderr)
            return 1
        pdf_bytes = PdfRenderer.render(data)
        if not pdf_bytes:
            print("Error: Failed to generate PDF bytes", file=sys.stderr)
            return 1
        out_p = output_file or "audit.pdf"
        with open(out_p, "wb") as f:
            f.write(pdf_bytes)
        print(f"Rendered PDF saved to {out_p}")

    else:
        print(f"Error: Unsupported format '{output_format}' (choose markdown, html, or pdf)", file=sys.stderr)
        return 1

    return 0
