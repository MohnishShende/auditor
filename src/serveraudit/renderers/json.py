"""
Canonical JSON report renderer for Linux Server Audit.
"""

from __future__ import annotations
import json
from typing import Any, Dict


class JsonRenderer:
    """Renders canonical audit data dictionary into formatted JSON."""

    @staticmethod
    def render(data: Dict[str, Any], indent: int = 2) -> str:
        return json.dumps(data, indent=indent, ensure_ascii=False)
