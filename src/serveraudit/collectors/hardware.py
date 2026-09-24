"""
Hardware, motherboard, chassis, and DMI/SMBIOS collector for Linux Server Audit.
"""

from __future__ import annotations
from pathlib import Path
from typing import Any, Dict

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class HardwareCollector(BaseCollector):
    manifest = CollectorManifest(
        name="hardware",
        category="hardware",
        description="Collect motherboard, chassis, system manufacturer, and DMI metadata",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["dmidecode -t system", "dmidecode -t baseboard", "dmidecode -t chassis"],
        outputs=["system", "motherboard", "chassis"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "system": {
                "manufacturer": None,
                "product_name": None,
                "version": None,
                "serial_number": None,
                "uuid": None,
                "family": None,
            },
            "motherboard": {
                "manufacturer": None,
                "product_name": None,
                "version": None,
                "serial_number": None,
                "asset_tag": None,
            },
            "chassis": {
                "manufacturer": None,
                "type": None,
                "version": None,
                "serial_number": None,
                "asset_tag": None,
            },
        }

        # 1. Try reading from /sys/class/dmi/id directly (unprivileged, fastest)
        dmi_dir = Path("/sys/class/dmi/id")
        if dmi_dir.exists():
            mapping = {
                "sys_vendor": ("system", "manufacturer"),
                "product_name": ("system", "product_name"),
                "product_version": ("system", "version"),
                "product_serial": ("system", "serial_number"),
                "product_uuid": ("system", "uuid"),
                "product_family": ("system", "family"),
                "board_vendor": ("motherboard", "manufacturer"),
                "board_name": ("motherboard", "product_name"),
                "board_version": ("motherboard", "version"),
                "board_serial": ("motherboard", "serial_number"),
                "board_asset_tag": ("motherboard", "asset_tag"),
                "chassis_vendor": ("chassis", "manufacturer"),
                "chassis_type": ("chassis", "type"),
                "chassis_version": ("chassis", "version"),
                "chassis_serial": ("chassis", "serial_number"),
                "chassis_asset_tag": ("chassis", "asset_tag"),
            }
            for filename, (section, key) in mapping.items():
                content = executor.read_file(dmi_dir / filename)
                if content:
                    val = content.strip()
                    if val and val != "None" and val != "Default string":
                        data[section][key] = val

        # 2. If privileged dmidecode is available, supplement any missing details
        if executor.which("dmidecode") and executor.privileges.can_elevate:
            # System
            dmi_sys = executor.run(["dmidecode", "-t", "system"], use_sudo=True)
            if dmi_sys.success:
                for line in dmi_sys.stdout.splitlines():
                    if ":" in line:
                        k, v = [x.strip() for x in line.split(":", 1)]
                        if k == "Manufacturer" and not data["system"]["manufacturer"]:
                            data["system"]["manufacturer"] = v
                        elif k == "Product Name" and not data["system"]["product_name"]:
                            data["system"]["product_name"] = v
                        elif k == "Serial Number" and not data["system"]["serial_number"]:
                            data["system"]["serial_number"] = v

            # Baseboard
            dmi_bb = executor.run(["dmidecode", "-t", "baseboard"], use_sudo=True)
            if dmi_bb.success:
                for line in dmi_bb.stdout.splitlines():
                    if ":" in line:
                        k, v = [x.strip() for x in line.split(":", 1)]
                        if k == "Manufacturer" and not data["motherboard"]["manufacturer"]:
                            data["motherboard"]["manufacturer"] = v
                        elif k == "Product Name" and not data["motherboard"]["product_name"]:
                            data["motherboard"]["product_name"] = v

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message="Hardware and platform metadata collected",
        )
