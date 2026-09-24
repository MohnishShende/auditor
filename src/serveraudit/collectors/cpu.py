"""
CPU, architecture, topology, frequencies, cache, and vulnerability mitigations collector.
"""

from __future__ import annotations
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

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

        has_useful_data = False

        # 1. Parse /proc/cpuinfo
        try:
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

                    # Model name matching across architectures
                    model = (
                        info.get("model name")
                        or info.get("Model")
                        or info.get("Hardware")
                        or info.get("Processor")
                        or info.get("cpu")
                    )
                    if model and not data["model_name"]:
                        data["model_name"] = model
                        has_useful_data = True

                    vendor = info.get("vendor_id") or info.get("vendor id") or info.get("Vendor")
                    if vendor and not data["vendor_id"]:
                        data["vendor_id"] = vendor

                    if "cpu MHz" in info and not data["frequencies_mhz"]["current"]:
                        try:
                            data["frequencies_mhz"]["current"] = round(float(info["cpu MHz"]), 2)
                        except (ValueError, TypeError):
                            pass

                    if "microcode" in info and not data["microcode"]:
                        data["microcode"] = info.get("microcode")

                    if "core id" in info:
                        core_ids.add((info.get("physical id", "0"), info.get("core id")))
                    if "physical id" in info:
                        physical_ids.add(info.get("physical id"))

                    flags = info.get("flags", "").split() or info.get("Features", "").split()
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

                if processors:
                    data["logical_cpus"] = len(processors)
                    has_useful_data = True

                    if physical_ids:
                        data["sockets"] = len(physical_ids)
                    if core_ids:
                        data["physical_cores"] = len(core_ids)
                    elif "cpu cores" in processors[0]:
                        try:
                            data["physical_cores"] = int(processors[0]["cpu cores"]) * data["sockets"]
                        except (ValueError, TypeError):
                            data["physical_cores"] = data["logical_cpus"]
                    else:
                        data["physical_cores"] = data["logical_cpus"]

                    if data["physical_cores"] > 0:
                        data["threads_per_core"] = max(1, data["logical_cpus"] // data["physical_cores"])
        except Exception:
            pass

        # 2. Supplementary / Fallback: lscpu
        if executor.which("lscpu"):
            try:
                lscpu_json_res = executor.run(["lscpu", "-J"])
                if lscpu_json_res.success and lscpu_json_res.stdout:
                    try:
                        parsed = json.loads(lscpu_json_res.stdout)
                        for item in parsed.get("lscpu", []):
                            f = item.get("field", "").rstrip(":")
                            d = item.get("data", "")
                            if not d:
                                continue
                            if f == "Model name" and not data["model_name"]:
                                data["model_name"] = d
                                has_useful_data = True
                            elif f == "Architecture" and not data["architecture"]:
                                data["architecture"] = d
                            elif f == "Vendor ID" and not data["vendor_id"]:
                                data["vendor_id"] = d
                            elif f == "Socket(s)":
                                try:
                                    data["sockets"] = int(d)
                                except (ValueError, TypeError):
                                    pass
                            elif f == "CPU(s)":
                                try:
                                    data["logical_cpus"] = int(d)
                                    has_useful_data = True
                                except (ValueError, TypeError):
                                    pass
                            elif f == "Core(s) per socket":
                                try:
                                    data["physical_cores"] = int(d) * data.get("sockets", 1)
                                except (ValueError, TypeError):
                                    pass
                            elif f == "Thread(s) per core":
                                try:
                                    data["threads_per_core"] = int(d)
                                except (ValueError, TypeError):
                                    pass
                            elif f == "CPU max MHz" and not data["frequencies_mhz"]["max"]:
                                try:
                                    data["frequencies_mhz"]["max"] = round(float(d), 2)
                                except (ValueError, TypeError):
                                    pass
                            elif f == "CPU min MHz" and not data["frequencies_mhz"]["min"]:
                                try:
                                    data["frequencies_mhz"]["min"] = round(float(d), 2)
                                except (ValueError, TypeError):
                                    pass
                    except Exception:
                        pass
                elif not lscpu_json_res.success:
                    # Fallback plain text lscpu
                    lscpu_text_res = executor.run(["lscpu"])
                    if lscpu_text_res.success and lscpu_text_res.stdout:
                        for line in lscpu_text_res.stdout.splitlines():
                            if ":" in line:
                                k, v = [x.strip() for x in line.split(":", 1)]
                                if k == "Model name" and not data["model_name"]:
                                    data["model_name"] = v
                                    has_useful_data = True
                                elif k == "Architecture" and not data["architecture"]:
                                    data["architecture"] = v
                                elif k == "Vendor ID" and not data["vendor_id"]:
                                    data["vendor_id"] = v
            except Exception:
                pass

        # 3. CPU governor & scaling from /sys/devices/system/cpu/cpu0/cpufreq
        try:
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
        except Exception:
            pass

        # 4. Cache from /sys/devices/system/cpu/cpu0/cache
        try:
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
        except Exception:
            pass

        # 5. CPU Vulnerabilities & Mitigations from /sys/devices/system/cpu/vulnerabilities
        try:
            vuln_dir = Path("/sys/devices/system/cpu/vulnerabilities")
            if vuln_dir.exists():
                for vuln_file in vuln_dir.iterdir():
                    val = executor.read_file(vuln_file)
                    if val:
                        data["vulnerabilities"][vuln_file.name] = val.strip()
        except Exception:
            pass

        # Determine status
        if data["model_name"] and data["logical_cpus"] > 0:
            status = CollectorStatus.SUCCESS
            msg = f"CPU {data['model_name']} ({data['physical_cores']}C/{data['logical_cpus']}T) collected"
        elif has_useful_data:
            status = CollectorStatus.PARTIAL
            msg = f"Partial CPU info collected ({data.get('logical_cpus', 1)} logical CPUs detected)"
        else:
            status = CollectorStatus.PARTIAL
            msg = "Minimal CPU information could be collected from host"

        return CollectorResult(
            collector=self.name,
            status=status,
            data=data,
            message=msg,
        )
