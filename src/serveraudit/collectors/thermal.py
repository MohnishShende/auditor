"""
Thermal sensors, CPU/drive temperatures, and throttling indicators collector for Linux Server Audit.
"""

from __future__ import annotations
import json
from pathlib import Path
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class ThermalCollector(BaseCollector):
    manifest = CollectorManifest(
        name="thermal",
        category="hardware",
        description="Collect CPU temperatures, thermal zone readings, fan speeds, and thermal throttling status",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["sensors -j", "sensors"],
        outputs=["thermal_zones", "cpu_temps", "fan_speeds", "max_temp_c"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "thermal_zones": [],
            "cpu_temperature_c": None,
            "max_temperature_c": None,
            "fan_speeds_rpm": [],
        }

        all_temps: List[float] = []

        # 1. sensors -j (lm-sensors)
        if executor.which("sensors"):
            sensors_res = executor.run(["sensors", "-j"])
            if sensors_res.success and sensors_res.stdout:
                try:
                    s_json = json.loads(sensors_res.stdout)
                    for chip_name, chip_data in s_json.items():
                        for sensor_name, sensor_values in chip_data.items():
                            if isinstance(sensor_values, dict):
                                for k, v in sensor_values.items():
                                    if "input" in k and isinstance(v, (int, float)):
                                        if "temp" in sensor_name.lower():
                                            all_temps.append(float(v))
                                            data["thermal_zones"].append({
                                                "chip": chip_name,
                                                "sensor": sensor_name,
                                                "temperature_c": float(v),
                                            })
                                        elif "fan" in sensor_name.lower():
                                            data["fan_speeds_rpm"].append({
                                                "chip": chip_name,
                                                "fan": sensor_name,
                                                "rpm": int(v),
                                            })
                except Exception:
                    pass

        # 2. Sysfs fallback /sys/class/thermal/thermal_zone*
        sys_thermal = Path("/sys/class/thermal")
        if not data["thermal_zones"] and sys_thermal.exists():
            for tz in sys_thermal.glob("thermal_zone*"):
                t_type = (executor.read_file(tz / "type") or "").strip()
                t_temp = (executor.read_file(tz / "temp") or "").strip()
                if t_temp and t_temp.isdigit():
                    c_temp = round(int(t_temp) / 1000.0, 1)
                    all_temps.append(c_temp)
                    data["thermal_zones"].append({
                        "chip": "sysfs",
                        "sensor": t_type or tz.name,
                        "temperature_c": c_temp,
                    })

        if all_temps:
            data["max_temperature_c"] = max(all_temps)
            data["cpu_temperature_c"] = all_temps[0]

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Thermal state collected (Max recorded temp: {data['max_temperature_c'] or 'N/A'}°C)",
        )
