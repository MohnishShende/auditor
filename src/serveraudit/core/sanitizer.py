"""
Secret detection and typed sanitization engine for Linux Server Audit.
Supports 'private' and 'public' (shareable) profiles.
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
import re
from typing import Any, Dict, List, Pattern, Set, Union


class SanitizationProfile(str, Enum):
    PRIVATE = "private"
    PUBLIC = "public"


# Sensitive environment variable and configuration key names
SECRET_KEY_PATTERNS = [
    re.compile(r".*(password|passwd|pass|pwd).*", re.IGNORECASE),
    re.compile(r".*(secret|token|apikey|api_key|auth|bearer).*", re.IGNORECASE),
    re.compile(r".*(private_key|privkey|certificate_key|credential).*", re.IGNORECASE),
    re.compile(r".*(db_pass|database_pass|dbpass|db_password).*", re.IGNORECASE),
    re.compile(r"^(aws_secret_access_key|github_token|gitlab_token|slack_token|openai_api_key)$", re.IGNORECASE),
]

# Sensitive pattern regular expressions
PRIVATE_KEY_REGEX = re.compile(
    r"-----BEGIN [A-Z0-9_-]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9_-]+ PRIVATE KEY-----",
    re.MULTILINE,
)
PASSWORD_HASH_REGEX = re.compile(
    r"\$(1|2a|2b|2y|5|6|argon2i|argon2d|argon2id|sha512)\$[A-Za-z0-9./+=,$_\-]+"
)
URL_CREDENTIALS_REGEX = re.compile(
    r"://([^:@/]*):([^@/]+)@"
)
KEY_VALUE_SECRET_REGEX = re.compile(
    r"""(?i)\b(password|passwd|secret|api_key|apikey|access_token|auth_token|token)\s*([:=])\s*['"]?([^'"\s,;&]+)['"]?"""
)
BEARER_TOKEN_REGEX = re.compile(
    r"""(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*"""
)

# MAC address pattern
MAC_REGEX = re.compile(r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b")

# IPv4 and IPv6 patterns
IPV4_PRIVATE_REGEX = re.compile(
    r"\b((10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3}))\b"
)
IPV4_PUBLIC_REGEX = re.compile(
    r"\b((?!10\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)(?!192\.168\.)(?!127\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)


@dataclass
class SanitizerConfig:
    profile: SanitizationProfile = SanitizationProfile.PRIVATE
    redact_passwords: bool = True
    redact_tokens: bool = True
    redact_private_keys: bool = True
    redact_env_secrets: bool = True
    mask_ips: bool = False
    mask_macs: bool = False
    mask_serials: bool = False
    mask_uuids: bool = False
    mask_hostname: bool = False
    known_hostnames: Set[str] = None

    @classmethod
    def from_profile(cls, profile_name: str | SanitizationProfile) -> SanitizerConfig:
        profile_enum = SanitizationProfile(profile_name) if isinstance(profile_name, str) else profile_name
        if profile_enum == SanitizationProfile.PUBLIC:
            return cls(
                profile=SanitizationProfile.PUBLIC,
                redact_passwords=True,
                redact_tokens=True,
                redact_private_keys=True,
                redact_env_secrets=True,
                mask_ips=True,
                mask_macs=True,
                mask_serials=True,
                mask_uuids=True,
                mask_hostname=True,
            )
        return cls(
            profile=SanitizationProfile.PRIVATE,
            redact_passwords=True,
            redact_tokens=True,
            redact_private_keys=True,
            redact_env_secrets=True,
            mask_ips=False,
            mask_macs=False,
            mask_serials=False,
            mask_uuids=False,
            mask_hostname=False,
        )


class Sanitizer:
    """Recursively inspects and sanitizes audit observation data."""

    def __init__(self, config: Optional[SanitizerConfig] = None) -> None:
        self.config = config or SanitizerConfig()

    def is_secret_key(self, key_name: str) -> bool:
        """Determines if a configuration or environment key name implies secret content."""
        if not key_name:
            return False
        return any(pattern.match(key_name) for pattern in SECRET_KEY_PATTERNS)

    def sanitize_string(self, text: str, key_context: Optional[str] = None) -> str:
        """Sanitizes sensitive values from a string."""
        if not text:
            return text

        # If key context is a known secret, redact entire string
        if key_context and self.is_secret_key(key_context):
            return "[REDACTED]"

        # Redact environment variable strings like FOO_PASSWORD=secret or API_TOKEN=xyz
        if "=" in text:
            parts = text.split("=", 1)
            var_name = parts[0].strip()
            if self.is_secret_key(var_name):
                return f"{var_name}=[REDACTED]"

        # Redact private keys
        if self.config.redact_private_keys:
            text = PRIVATE_KEY_REGEX.sub("[REDACTED_PRIVATE_KEY]", text)

        # Redact password hashes
        text = PASSWORD_HASH_REGEX.sub("[REDACTED_HASH]", text)

        # Redact credentials in URLs (e.g. postgres://user:pass@host/db)
        if self.config.redact_passwords:
            text = URL_CREDENTIALS_REGEX.sub(r"://\1:[REDACTED]@", text)

        # Redact key-value secrets in text (e.g. password=XYZ, DB_PASS: 123)
        if self.config.redact_passwords or self.config.redact_tokens:
            text = KEY_VALUE_SECRET_REGEX.sub(r"\1\2[REDACTED]", text)
            # Match any word containing secret keywords followed by = or :
            text = re.sub(
                r"""(?i)\b([A-Za-z0-9_-]*(?:password|passwd|pass|secret|token|apikey|api_key|auth|bearer)[A-Za-z0-9_-]*)\s*([:=])\s*['"]?([^'"\s,;&]+)['"]?""",
                r"\1\2[REDACTED]",
                text,
            )

        # Redact Bearer / Basic tokens
        if self.config.redact_tokens:
            text = BEARER_TOKEN_REGEX.sub(r"\1 [REDACTED_TOKEN]", text)

        # Public mode transformations
        if self.config.mask_macs:
            text = MAC_REGEX.sub(lambda m: m.group(0)[:9] + "xx:xx:xx", text)

        if self.config.mask_ips:
            # Mask public IPs
            text = IPV4_PUBLIC_REGEX.sub("xxx.xxx.xxx.xxx", text)
            # Mask private IPs (e.g. 192.168.1.15 -> 192.168.x.x)
            text = IPV4_PRIVATE_REGEX.sub(r"\g<1>", text)
            # Mask trailing octets of private subnet
            text = re.sub(r"\b(192\.168\.)\d{1,3}\.\d{1,3}\b", r"\1x.x", text)
            text = re.sub(r"\b(10\.)\d{1,3}\.\d{1,3}\.\d{1,3}\b", r"\1x.x.x", text)

        return text

    def sanitize(self, data: Any, key_context: Optional[str] = None) -> Any:
        """Recursively sanitizes dictionaries, lists, and primitives."""
        if isinstance(data, dict):
            sanitized_dict = {}
            for k, v in data.items():
                str_k = str(k)
                # Specific public profile key redactions
                if self.config.mask_serials and str_k.lower() in ("serial", "serial_number", "wwn", "chassis_serial"):
                    sanitized_dict[k] = "[REDACTED_SERIAL]"
                elif self.config.mask_uuids and str_k.lower() in ("uuid", "machine_id", "boot_id"):
                    sanitized_dict[k] = "[REDACTED_ID]"
                elif self.is_secret_key(str_k):
                    sanitized_dict[k] = "[REDACTED]"
                else:
                    sanitized_dict[k] = self.sanitize(v, key_context=str_k)
            return sanitized_dict

        elif isinstance(data, list):
            return [self.sanitize(item, key_context=key_context) for item in data]

        elif isinstance(data, tuple):
            return tuple(self.sanitize(item, key_context=key_context) for item in data)

        elif isinstance(data, str):
            return self.sanitize_string(data, key_context=key_context)

        return data
