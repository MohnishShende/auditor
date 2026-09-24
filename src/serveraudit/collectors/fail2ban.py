"""
Fail2ban and CrowdSec intrusion prevention collector for Linux Server Audit.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class Fail2banCollector(BaseCollector):
    manifest = CollectorManifest(
        name="fail2ban",
        category="security",
        description="Inspect Fail2ban and CrowdSec intrusion prevention services, active jails, and ban counts",
        requires_root=True,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["fail2ban-client status", "cscli metrics"],
        outputs=["fail2ban", "crowdsec"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "fail2ban": {
                "installed": executor.which("fail2ban-client") is not None,
                "active": False,
                "jails_count": 0,
                "jails": [],
            },
            "crowdsec": {
                "installed": executor.which("cscli") is not None,
                "active": False,
            },
        }

        # 1. Fail2ban
        if data["fail2ban"]["installed"]:
            f2b_res = executor.run(["fail2ban-client", "status"], use_sudo=True)
            if f2b_res.success and f2b_res.stdout:
                data["fail2ban"]["active"] = True
                for line in f2b_res.stdout.splitlines():
                    if "Number of jail:" in line:
                        num_m = re.search(r"(\d+)", line)
                        if num_m:
                            data["fail2ban"]["jails_count"] = int(num_m.group(1))
                    elif "Jail list:" in line:
                        jails = [j.strip() for j in line.split(":", 1)[1].split(",") if j.strip()]
                        data["fail2ban"]["jails"] = jails

        # 2. CrowdSec
        if data["crowdsec"]["installed"]:
            cs_res = executor.run(["cscli", "version"], use_sudo=True)
            if cs_res.success:
                data["crowdsec"]["active"] = True

        if not data["fail2ban"]["installed"] and not data["crowdsec"]["installed"]:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.SKIPPED,
                data=data,
                message="Neither Fail2ban nor CrowdSec is installed",
            )

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message="Intrusion prevention service status collected",
        )
