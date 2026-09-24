"""
Data normalization and typed formatting utilities for Linux Server Audit.
"""

from __future__ import annotations
import datetime
import re
from typing import Optional, Union


class Normalizer:
    """Normalizes raw system units, timestamps, and sizes into canonical representations."""

    @staticmethod
    def parse_bytes(value: Union[str, int, float, None]) -> Optional[int]:
        """Convert various size strings (e.g. '1.5G', '500MB', '1024') into integer bytes."""
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return int(value)

        val_str = str(value).strip().upper()
        if not val_str or val_str == "N/A" or val_str == "-":
            return None

        # Pure integer string
        if val_str.isdigit():
            return int(val_str)

        units = {
            "B": 1,
            "K": 1024,
            "KB": 1024,
            "KIB": 1024,
            "M": 1024**2,
            "MB": 1024**2,
            "MIB": 1024**2,
            "G": 1024**3,
            "GB": 1024**3,
            "GIB": 1024**3,
            "T": 1024**4,
            "TB": 1024**4,
            "TIB": 1024**4,
            "P": 1024**5,
            "PB": 1024**5,
            "PIB": 1024**5,
        }

        match = re.match(r"^([0-9.]+)\s*([A-Z]+)$", val_str)
        if match:
            number = float(match.group(1))
            unit = match.group(2)
            if unit in units:
                return int(number * units[unit])

        return None

    @staticmethod
    def format_bytes(num_bytes: Optional[int]) -> str:
        """Formats byte count into human-readable string (e.g. '1.82 TB')."""
        if num_bytes is None or num_bytes < 0:
            return "N/A"
        if num_bytes == 0:
            return "0 B"

        units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"]
        size = float(num_bytes)
        unit_idx = 0
        while size >= 1024 and unit_idx < len(units) - 1:
            size /= 1024.0
            unit_idx += 1

        if unit_idx == 0:
            return f"{int(size)} {units[unit_idx]}"
        return f"{size:.2f} {units[unit_idx]}"

    @staticmethod
    def format_uptime(seconds: Optional[Union[int, float]]) -> str:
        """Converts uptime in seconds into 'X days, Y hours, Z mins'."""
        if seconds is None or seconds < 0:
            return "Unknown"

        total_secs = int(seconds)
        days = total_secs // 86400
        hours = (total_secs % 86400) // 3600
        mins = (total_secs % 3600) // 60

        parts = []
        if days > 0:
            parts.append(f"{days} day{'s' if days != 1 else ''}")
        if hours > 0 or days > 0:
            parts.append(f"{hours} hr{'s' if hours != 1 else ''}")
        parts.append(f"{mins} min{'s' if mins != 1 else ''}")

        return ", ".join(parts)

    @staticmethod
    def iso_timestamp(dt: Optional[datetime.datetime] = None) -> str:
        """Returns ISO 8601 timestamp with timezone."""
        if dt is None:
            dt = datetime.datetime.now(datetime.timezone.utc).astimezone()
        return dt.isoformat()
