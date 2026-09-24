"""
Firmware, BIOS, UEFI, TPM, and Secure Boot collector for Linux Server Audit.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class FirmwareCollector(BaseCollector):
    manifest = CollectorManifest(
        name="firmware",
        category="firmware",
        description="Collect BIOS version, release date, UEFI, Secure Boot, and TPM state",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["mokutil --sb-state", "fwupdmgr get-devices --json"],
        outputs=["bios", "uefi", "secure_boot", "tpm"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "bios": {
                "vendor": None,
                "version": None,
                "release_date": None,
                "revision": None,
            },
            "uefi": {
                "supported": Path("/sys/firmware/efi").exists(),
                "runtime_supported": Path("/sys/firmware/efi/runtime").exists(),
            },
            "secure_boot": {
                "enabled": False,
                "state": "unknown",
            },
            "tpm": {
                "present": False,
                "version": None,
                "description": None,
            },
            "firmware_devices": [],
        }

        # 1. BIOS info from /sys/class/dmi/id
        dmi_dir = Path("/sys/class/dmi/id")
        if dmi_dir.exists():
            data["bios"]["vendor"] = (executor.read_file(dmi_dir / "bios_vendor") or "").strip() or None
            data["bios"]["version"] = (executor.read_file(dmi_dir / "bios_version") or "").strip() or None
            data["bios"]["release_date"] = (executor.read_file(dmi_dir / "bios_date") or "").strip() or None

        # 2. Secure Boot status
        if executor.which("mokutil"):
            res = executor.run(["mokutil", "--sb-state"])
            if res.success:
                if "SecureBoot enabled" in res.stdout:
                    data["secure_boot"]["enabled"] = True
                    data["secure_boot"]["state"] = "enabled"
                elif "SecureBoot disabled" in res.stdout:
                    data["secure_boot"]["enabled"] = False
                    data["secure_boot"]["state"] = "disabled"

        # 3. TPM detection
        tpm_dir = Path("/sys/class/tpm")
        if tpm_dir.exists() and any(tpm_dir.iterdir()):
            data["tpm"]["present"] = True
            tpm_device = next(tpm_dir.iterdir())
            desc_file = tpm_device / "device/description"
            if desc_file.exists():
                data["tpm"]["description"] = (executor.read_file(desc_file) or "").strip()
            # Check TPM 2.0 vs 1.2
            if (tpm_device / "tpm_version_major").exists():
                ver = (executor.read_file(tpm_device / "tpm_version_major") or "").strip()
                data["tpm"]["version"] = f"TPM {ver}.0" if ver else "TPM 2.0"
            elif Path("/dev/tpmrm0").exists() or Path("/dev/tpm0").exists():
                data["tpm"]["version"] = "TPM 2.0"

        # 4. fwupd devices if available
        if executor.which("fwupdmgr"):
            fw_res = executor.run(["fwupdmgr", "get-devices", "--json"])
            if fw_res.success and fw_res.stdout:
                try:
                    fw_json = json.loads(fw_res.stdout)
                    devices = fw_json.get("Devices", []) if isinstance(fw_json, dict) else fw_json
                    for dev in devices[:10]:  # Cap to top 10 devices
                        data["firmware_devices"].append({
                            "name": dev.get("Name"),
                            "version": dev.get("Version"),
                            "vendor": dev.get("Vendor"),
                            "guid": dev.get("Guid", [None])[0] if isinstance(dev.get("Guid"), list) else dev.get("Guid"),
                        })
                except Exception:
                    pass

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message="Firmware, BIOS, and Secure Boot metadata collected",
        )
