"""
TLS and X.509 PKI certificate inspector collector for Linux Server Audit.
Strictly NEVER exports private keys.
"""

from __future__ import annotations
import datetime
from pathlib import Path
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class TlsCollector(BaseCollector):
    manifest = CollectorManifest(
        name="tls",
        category="security",
        description="Inspect X.509 TLS certificates, expiration dates, SANs, issuers, and near-expiry warnings",
        requires_root=True,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["openssl x509 -in <cert> -noout -text -dates -subject -issuer"],
        outputs=["certificates", "expired_certificates", "expiring_soon"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        if not executor.which("openssl"):
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.DEPENDENCY_MISSING,
                message="openssl utility not found",
            )

        data: Dict[str, Any] = {
            "certificates": [],
            "expired_certificates": [],
            "expiring_soon": [],
        }

        # Targeted certificate search paths (avoid massive system CA bundle duplicates)
        search_dirs = [
            Path("/etc/letsencrypt/live"),
            Path("/var/lib/caddy/.local/share/caddy/certificates"),
            Path("/etc/caddy/certificates"),
            Path("/etc/ssl/certs"),
        ]

        found_certs = []
        for sdir in search_dirs:
            if sdir.exists():
                try:
                    for f in sdir.glob("**/*.crt"):
                        if f.is_file():
                            found_certs.append(f)
                    for f in sdir.glob("**/*.pem"):
                        if f.is_file() and "privkey" not in f.name and "key" not in f.name:
                            found_certs.append(f)
                except Exception:
                    pass

        now = datetime.datetime.now(datetime.timezone.utc)

        # Inspect found certificates (up to 25 to avoid overhead)
        for cert_path in found_certs[:25]:
            res = executor.run(["openssl", "x509", "-in", str(cert_path), "-noout", "-dates", "-subject", "-issuer"], use_sudo=True)
            if res.success and res.stdout:
                subject = None
                issuer = None
                not_before = None
                not_after = None
                days_remaining = None
                is_expired = False

                for line in res.stdout.splitlines():
                    if line.startswith("subject="):
                        subject = line.split("=", 1)[1].strip()
                    elif line.startswith("issuer="):
                        issuer = line.split("=", 1)[1].strip()
                    elif line.startswith("notBefore="):
                        not_before = line.split("=", 1)[1].strip()
                    elif line.startswith("notAfter="):
                        not_after_str = line.split("=", 1)[1].strip()
                        not_after = not_after_str
                        # Parse openssl date format: May 24 10:17:00 2026 GMT
                        try:
                            exp_dt = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                            delta = exp_dt - now
                            days_remaining = delta.days
                            if days_remaining < 0:
                                is_expired = True
                        except Exception:
                            pass

                cert_info = {
                    "path": str(cert_path),
                    "subject": subject,
                    "issuer": issuer,
                    "is_self_signed": subject == issuer if subject and issuer else False,
                    "not_before": not_before,
                    "not_after": not_after,
                    "days_remaining": days_remaining,
                    "is_expired": is_expired,
                }
                data["certificates"].append(cert_info)

                if is_expired:
                    data["expired_certificates"].append(cert_info)
                elif days_remaining is not None and days_remaining <= 30:
                    data["expiring_soon"].append(cert_info)

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['certificates'])} certificates ({len(data['expired_certificates'])} expired, {len(data['expiring_soon'])} expiring soon)",
        )
