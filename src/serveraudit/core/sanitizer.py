"""
Secret detection and typed sanitization engine for Linux Server Audit.
Supports 'private' and 'public' (shareable) profiles.
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Pattern, Set, Union


class SanitizationProfile(str, Enum):
    PRIVATE = "private"
    PUBLIC = "public"


# Key-name classification.
#
# A key is split into lower-case words on "_", "-", ".", whitespace and camelCase
# boundaries, and the words decide whether the key *holds* a secret. Substring
# matching was used before and also redacted settings that merely talk about
# secrets: sshd's ``password_authentication`` (yes/no), ``users[].password_status``
# (locked/active), ``max_auth_tries``, fstab ``passno``,
# ``cpu.vulnerabilities.spec_store_bypass`` and ``smart.overall_health_passed``
# all came out as "[REDACTED]" in real reports.

# Words that denote a secret value when they are the LAST word of a key
# (db_password, access_token, mysql_pwd, client_secret).
SECRET_LAST_WORDS = frozenset({
    "password", "passwords", "passwd", "passphrase", "pass", "pwd",
    "secret", "secrets", "token", "tokens", "apikey", "privkey",
    "credential", "credentials", "bearer",
})
# Words that denote a secret value wherever they appear in a key, because they
# are not used to name settings about secrets (secret_key_base, smtp_passwd_file).
SECRET_ANY_WORDS = frozenset({
    "secret", "secrets", "passwd", "passphrase", "apikey", "privkey",
    "credential", "credentials",
})
# "key" alone is ambiguous (host_key, public_key, key_type); it denotes a secret
# only when qualified by one of these words earlier in the key (api_key,
# private_key, aws_secret_access_key, signing_key).
SECRET_KEY_QUALIFIERS = frozenset({
    "api", "secret", "private", "access", "auth", "signing", "encryption",
    "master", "license", "session", "service", "account",
})
# Single-word keys are matched by suffix so that PGPASSWORD, JWTSECRET or
# GITHUBTOKEN are still caught; "pwd", "pass" and "bearer" alone are not secrets
# (PWD, OLDPWD).
SECRET_WORD_SUFFIXES = ("password", "passwd", "passphrase", "secret", "token", "apikey")

_CAMEL_BOUNDARY_REGEX = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_KEY_WORD_SPLIT_REGEX = re.compile(r"[^a-z0-9]+")


def key_words(key_name: str) -> list[str]:
    """Splits a configuration or environment key name into lower-case words."""
    spaced = _CAMEL_BOUNDARY_REGEX.sub("_", key_name)
    return [w.rstrip("0123456789") or w for w in _KEY_WORD_SPLIT_REGEX.split(spaced.lower()) if w]


def is_secret_key_name(key_name: str) -> bool:
    """Determines whether a key names a secret VALUE, as opposed to a setting about secrets."""
    words = key_words(key_name or "")
    if not words:
        return False
    last = words[-1]
    if len(words) == 1:
        if last in ("pass", "pwd", "bearer"):
            return False
        return last in SECRET_LAST_WORDS or last.endswith(SECRET_WORD_SUFFIXES)
    if last in SECRET_LAST_WORDS:
        return True
    if last == "key" and any(w in SECRET_KEY_QUALIFIERS for w in words[:-1]):
        return True
    return any(w in SECRET_ANY_WORDS for w in words)


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
# "NAME=value" / "NAME: value" pairs inside free text; NAME is classified with
# is_secret_key_name() so DB_PASS=... is redacted but MaxAuthTries=6 is not.
NAMED_VALUE_REGEX = re.compile(
    r"""\b([A-Za-z][A-Za-z0-9_.-]*)\s*([:=])\s*['"]?([^'"\s,;&]+)['"]?"""
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
        return is_secret_key_name(key_name)

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
            # Redact NAME=value pairs whose NAME denotes a secret (same rules as
            # dictionary keys), e.g. DB_PASS=..., but not PasswordAuthentication=no.
            text = NAMED_VALUE_REGEX.sub(
                lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]" if is_secret_key_name(m.group(1)) else m.group(0),
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
