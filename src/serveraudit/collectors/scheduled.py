"""
Scheduled tasks (cron, crontabs, /etc/cron.*, at jobs) collector for Linux Server Audit.
"""

from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class ScheduledCollector(BaseCollector):
    manifest = CollectorManifest(
        name="scheduled",
        category="system",
        description="Inspect system cron, /etc/cron.* directories, user crontabs, and scheduled maintenance tasks",
        requires_root=True,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["crontab -l", "ls -la /etc/cron*"],
        outputs=["cron_jobs", "cron_files", "cron_directories"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "system_crontab": [],
            "cron_directories": {},
            "user_crontabs": [],
        }

        # 1. /etc/crontab
        sys_cron = executor.read_file("/etc/crontab")
        if sys_cron:
            for line in sys_cron.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not "=" in line.split()[0]:
                    data["system_crontab"].append(line)

        # 2. Inspect /etc/cron.d, /etc/cron.daily, /etc/cron.hourly, /etc/cron.weekly, /etc/cron.monthly
        cron_dirs = ["cron.d", "cron.daily", "cron.hourly", "cron.weekly", "cron.monthly"]
        for cdir in cron_dirs:
            p = Path(f"/etc/{cdir}")
            if p.exists():
                files = [f.name for f in p.iterdir() if f.is_file() and not f.name.startswith(".")]
                data["cron_directories"][cdir] = files

        # 3. User crontabs in /var/spool/cron/crontabs
        spool = Path("/var/spool/cron/crontabs")
        if spool.exists():
            try:
                for ufile in spool.iterdir():
                    if ufile.is_file():
                        u_content = executor.read_file(ufile, use_sudo=True)
                        lines = [l.strip() for l in (u_content or "").splitlines() if l.strip() and not l.strip().startswith("#")]
                        if lines:
                            data["user_crontabs"].append({
                                "user": ufile.name,
                                "jobs_count": len(lines),
                                "jobs": lines,
                            })
            except Exception:
                pass

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message="Scheduled tasks and cron inventory collected",
        )
