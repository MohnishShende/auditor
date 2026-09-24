"""
CPU, architecture, topology, frequencies, cache, and vulnerability mitigations collector.
"""

from __future__ import annotations
import os
from pathlib import Path
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class CpuCollector(BaseCollector):
    manifest = CollectorManifest(
        name="cpu",
        category="hardware",
        description="Collect CPU model, cores, thread topology, governor, frequencies, cache, and kernel mitigations",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["lscpu -J", "lscpu"],
        outputs=["model", "topology", "frequency", "cache", "vulnerabilities"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "model_name": None,
            "architecture": None,
            "vendor_id": None,
            "sockets": 1,
            "physical_cores": 1,
            "logical_cpus": 1,
            "threads_per_core": 1,
            "microcode": None,
            "frequencies_mhz": {
                "current": None,
                "min": None,
                "max": None,
            },
            "governor": None,
            "scaling_driver": None,
            "virtualization": None,
            "capabilities": {
                "virtualization_extensions": False,
                "aes_ni": False,
                "avx": False,
                "avx2": False,
                "avx512": False,
            },
            "cache": {
                "l1d": None,
                "l1i": None,
                "l2": None,
                "l3": None,
            },
            "vulnerabilities": {},
        }

        # 1. Parse /proc/cpuinfo
        cpuinfo = executor.read_file("/proc/cpuinfo")
        if cpuinfo:
            processors = []
            core_ids = set()
            physical_ids = set()

            for block in cpuinfo.strip().split("\n\n"):
                info: Dict[str, str] = {}
                for line in block.splitlines():
                    if ":" in line:
                        k, v = [x.strip() for x in line.split(":", 1)]
                        info[k] = v
                if not info:
                    continue
                processors.append(info)

                if "model name" in info and not data["model_name"]:
                    data["model_name"] = info["model_name"]
                if "vendor_id" in info and not data["vendor_id"]:
                    data["vendor_id"] = info["vendor_id"]
                if "cpu MHz" in info and not data["frequencies_mhz"]["current"]:
                    try:
                        data["frequencies_mhz"]["current"] = round(float(info["cpu MHz"]), 2)
                    except ValueError:
                        pass
                if "microcode" in info and not data["microcode"]:
                    data["microcode"] = info["microcode"]

                if "core id" in info:
                    core_ids.add((info.get("physical id", "0"), info["core id"]))
                if "physical id" in info:
                    physical_ids.add(info["physical id"])

                flags = info.get("flags", "").split()
                if "vmx" in flags or "svm" in flags:
                    data["capabilities"]["virtualization_extensions"] = True
                    data["virtualization"] = "Intel VT-x (vmx)" if "vmx" in flags else "AMD-V (svm)"
                if "aes" in flags:
                    data["capabilities"]["aes_ni"] = True
                if "avx" in flags:
                    data["capabilities"]["avx"] = True
                if "avx2" in flags:
                    data["capabilities"]["avx2"] = True
                if any(f.startswith("avx512") for f in flags):
                    data["capabilities"]["avx512"] = True

            data["logical_cpus"] = len(processors) or 1
            if physical_ids:
                data["sockets"] = len(physical_ids)
            if core_ids:
                data["physical_cores"] = len(core_ids)
            elif "cpu cores" in processors[0]:
                try:
                    data["physical_cores"] = int(processors[0]["cpu cores"]) * data["sockets"]
                except ValueError:
                    data["physical_cores"] = data["logical_cpus"]
            else:
                data["physical_cores"] = data["logical_cpus"]

            if data["physical_cores"] > 0:
                data["threads_per_core"] = data["logical_cpus"] // data["physical_cores"]

        # 2. CPU governor & scaling from /sys/devices/system/cpu/cpu0/cpufreq
        cpufreq_dir = Path("/sys/devices/system/cpu/cpu0/cpufreq")
        if cpufreq_dir.exists():
            gov = executor.read_file(cpufreq_dir / "scaling_governor")
            if gov:
                data["governor"] = gov.strip()
            driver = executor.read_file(cpufreq_dir / "scaling_driver")
            if driver:
                data["scaling_driver"] = driver.strip()
            min_freq = executor.read_file(cpufreq_dir / "scaling_min_freq")
            if min_freq and min_freq.strip().isdigit():
                data["frequencies_mhz"]["min"] = round(int(min_freq.strip()) / 1000.0, 2)
            max_freq = executor.read_file(cpufreq_dir / "scaling_max_freq")
            if max_freq and max_freq.strip().isdigit():
                data["frequencies_mhz"]["max"] = round(int(max_freq.strip()) / 1000.0, 2)

        # 3. Cache from /sys/devices/system/cpu/cpu0/cache
        cache_dir = Path("/sys/devices/system/cpu/cpu0/cache")
        if cache_dir.exists():
            for idx_dir in sorted(cache_dir.glob("index*")):
                level = (executor.read_file(idx_dir / "level") or "").strip()
                type_ = (executor.read_file(idx_dir / "type") or "").strip()
                size = (executor.read_file(idx_dir / "size") or "").strip()
                if level == "1" and type_ == "Data":
                    data["cache"]["l1d"] = size
                elif level == "1" and type_ == "Instruction":
                    data["cache"]["l1i"] = size
                elif level == "2":
                    data["cache"]["l2"] = size
                elif level == "3":
                    data["cache"]["l3"] = size

        # 4. CPU Vulnerabilities & Mitigations from /sys/devices/system/cpu/vulnerabilities
        vuln_dir = Path("/sys/devices/system/cpu/vulnerabilities")
        if vuln_dir.exists():
            for vuln_file in vuln_dir.iterdir():
                val = executor.read_file(vuln_file)
                if val:
                    data["vulnerabilities"][vuln_file.name] = val.strip()

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message="CPU topology and vulnerability mitigations collected",
        )
