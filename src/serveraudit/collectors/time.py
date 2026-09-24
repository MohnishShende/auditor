"""
Time synchronization, NTP implementation, and RTC state collector for Linux Server Audit.
"""

from __future__ import annotations
import datetime
from typing import Any, Dict

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class TimeCollector(BaseCollector):
    manifest = CollectorManifest(
        name="time",
        category="system",
        description="Inspect system clock, RTC time, timezone, NTP synchronization state, and active time daemon",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["timedatectl status", "chronyc tracking"],
        outputs=["timezone", "ntp_synchronized", "time_daemon"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "system_time": datetime.datetime.now().isoformat(),
            "timezone": None,
            "ntp_synchronized": False,
            "ntp_service": "unknown",
            "rtc_in_local_tz": False,
        }

        # 1. timedatectl
        if executor.which("timedatectl"):
            td_res = executor.run(["timedatectl", "status"])
            if td_res.success and td_res.stdout:
                for line in td_res.stdout.splitlines():
                    if ":" in line:
                        k, v = [x.strip() for x in line.split(":", 1)]
                        if "Time zone" in k:
                            data["timezone"] = v.split()[0]
                        elif "NTP service" in k:
                            data["ntp_service"] = v
                        elif "System clock synchronized" in k or "NTP synchronized" in k:
                            data["ntp_synchronized"] = v.lower() == "yes"
                        elif "RTC in local TZ" in k:
                            data["rtc_in_local_tz"] = v.lower() == "yes"

        # 2. Check chrony if active
        if executor.which("chronyc"):
            chr_res = executor.run(["chronyc", "tracking"])
            if chr_res.success:
                data["ntp_service"] = "chrony"
                data["ntp_synchronized"] = True

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Time sync collected (NTP Synced: {data['ntp_synchronized']}, Timezone: {data['timezone'] or 'unknown'})",
        )
