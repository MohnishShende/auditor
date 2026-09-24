"""
SMART and NVMe physical disk health inspection collector for Linux Server Audit.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class SmartCollector(BaseCollector):
    manifest = CollectorManifest(
        name="smart",
        category="storage",
        description="Collect SMART and NVMe physical disk health, wear, temperatures, and error logs",
        requires_root=True,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["smartctl --scan -j", "smartctl -a -j <device>", "nvme smart-log <device> -o json"],
        outputs=["disks", "overall_health", "temperatures", "wear_indicators"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        if not executor.which("smartctl") and not executor.which("nvme"):
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.DEPENDENCY_MISSING,
                message="Neither smartctl (smartmontools) nor nvme-cli is installed",
            )

        data: Dict[str, Any] = {
            "devices": [],
            "overall_health_passed": True,
            "disks_with_warnings": 0,
        }

        # 1. Discover devices via smartctl --scan -j
        scanned_devices = []
        if executor.which("smartctl"):
            scan_res = executor.run(["smartctl", "--scan", "-j"], use_sudo=True)
            if scan_res.success and scan_res.stdout:
                try:
                    scan_json = json.loads(scan_res.stdout)
                    for d in scan_json.get("devices", []):
                        scanned_devices.append(d.get("name"))
                except Exception:
                    pass

        # Fallback to /sys/block device discovery if scan produced no devices
        if not scanned_devices:
            sys_block = Path("/sys/block")
            if sys_block.exists():
                for dev in sys_block.iterdir():
                    name = dev.name
                    if name.startswith(("sd", "nvme", "hd", "vd")):
                        # Avoid loop, ram, dm
                        scanned_devices.append(f"/dev/{name}")

        if not scanned_devices:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.SKIPPED,
                data=data,
                message="No inspectable physical storage devices detected",
            )

        # 2. Query each device
        partial = False
        for dev_path in scanned_devices:
            dev_data: Dict[str, Any] = {
                "device": dev_path,
                "model_name": None,
                "serial_number": None,
                "type": "unknown",
                "healthy": True,
                "status": "UNKNOWN",
                "temperature_c": None,
                "power_on_hours": None,
                "power_cycle_count": None,
                "reallocated_sectors": 0,
                "pending_sectors": 0,
                "uncorrectable_errors": 0,
                "percentage_used": None,
                "available_spare_percent": None,
                "critical_warning": None,
            }

            if executor.which("smartctl"):
                smart_res = executor.run(["smartctl", "-a", "-j", dev_path], use_sudo=True)
                if smart_res.success and smart_res.stdout:
                    try:
                        s_json = json.loads(smart_res.stdout)
                        dev_data["model_name"] = s_json.get("model_name") or s_json.get("device", {}).get("name")
                        dev_data["serial_number"] = s_json.get("serial_number")
                        dev_data["type"] = s_json.get("device", {}).get("type", "unknown")

                        # Overall SMART Status
                        smart_status = s_json.get("smart_status", {})
                        is_passed = smart_status.get("passed", True)
                        dev_data["healthy"] = is_passed
                        dev_data["status"] = "PASSED" if is_passed else "FAILED"
                        if not is_passed:
                            data["overall_health_passed"] = False
                            data["disks_with_warnings"] += 1

                        # Temperature
                        temp_obj = s_json.get("temperature", {})
                        if temp_obj.get("current"):
                            dev_data["temperature_c"] = temp_obj.get("current")

                        # Power On Time
                        pot_obj = s_json.get("power_on_time", {})
                        if pot_obj.get("hours") is not None:
                            dev_data["power_on_hours"] = pot_obj.get("hours")

                        if s_json.get("power_cycle_count") is not None:
                            dev_data["power_cycle_count"] = s_json.get("power_cycle_count")

                        # NVMe specific
                        nvme_log = s_json.get("nvme_smart_health_information_log", {})
                        if nvme_log:
                            dev_data["type"] = "nvme"
                            dev_data["temperature_c"] = nvme_log.get("temperature", dev_data["temperature_c"])
                            dev_data["percentage_used"] = nvme_log.get("percentage_used")
                            dev_data["available_spare_percent"] = nvme_log.get("available_spare")
                            dev_data["critical_warning"] = nvme_log.get("critical_warning")
                            if nvme_log.get("critical_warning", 0) > 0:
                                dev_data["healthy"] = False
                                data["disks_with_warnings"] += 1

                        # ATA Attributes table
                        ata_table = s_json.get("ata_smart_attributes", {}).get("table", [])
                        for attr in ata_table:
                            attr_id = attr.get("id")
                            raw_val = attr.get("raw", {}).get("value", 0)
                            if attr_id == 5:  # Reallocated_Sector_Ct
                                dev_data["reallocated_sectors"] = raw_val
                                if raw_val > 0:
                                    data["disks_with_warnings"] += 1
                            elif attr_id == 197:  # Current_Pending_Sector
                                dev_data["pending_sectors"] = raw_val
                                if raw_val > 0:
                                    data["disks_with_warnings"] += 1
                            elif attr_id == 198:  # Offline_Uncorrectable
                                dev_data["uncorrectable_errors"] = raw_val

                        data["devices"].append(dev_data)
                        continue
                    except Exception:
                        pass

            # If smartctl failed or is missing, check if nvme-cli can read nvme device
            if "nvme" in dev_path and executor.which("nvme"):
                nvme_res = executor.run(["nvme", "smart-log", dev_path, "-o", "json"], use_sudo=True)
                if nvme_res.success and nvme_res.stdout:
                    try:
                        n_json = json.loads(nvme_res.stdout)
                        dev_data["type"] = "nvme"
                        dev_data["temperature_c"] = n_json.get("temperature")
                        dev_data["percentage_used"] = n_json.get("percent_used")
                        dev_data["available_spare_percent"] = n_json.get("avail_spare")
                        dev_data["critical_warning"] = n_json.get("critical_warning")
                        dev_data["status"] = "PASSED" if n_json.get("critical_warning", 0) == 0 else "WARNING"
                        data["devices"].append(dev_data)
                        continue
                    except Exception:
                        pass

            partial = True
            dev_data["status"] = "UNAVAILABLE"
            data["devices"].append(dev_data)

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.PARTIAL if partial and not data["devices"] else CollectorStatus.SUCCESS,
            data=data,
            message=f"Collected health metrics for {len(data['devices'])} physical disks",
        )
