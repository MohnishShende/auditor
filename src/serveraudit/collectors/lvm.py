"""
LVM (Logical Volume Manager) collector for Linux Server Audit.
"""

from __future__ import annotations
import json
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from ..core.normalizer import Normalizer
from . import register_collector


@register_collector
class LvmCollector(BaseCollector):
    manifest = CollectorManifest(
        name="lvm",
        category="storage",
        description="Collect LVM Physical Volumes, Volume Groups, and Logical Volumes with extents and mappings",
        requires_root=True,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["pvs --reportformat json --units b", "vgs --reportformat json --units b", "lvs --reportformat json --units b"],
        outputs=["physical_volumes", "volume_groups", "logical_volumes"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        if not executor.which("pvs") and not executor.which("vgs") and not executor.which("lvs"):
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.SKIPPED,
                message="LVM tools (pvs/vgs/lvs) not installed",
            )

        data: Dict[str, Any] = {
            "physical_volumes": [],
            "volume_groups": [],
            "logical_volumes": [],
        }

        # 1. Physical Volumes
        pvs_res = executor.run(["pvs", "--reportformat", "json", "--units", "b"], use_sudo=True)
        if pvs_res.success and pvs_res.stdout:
            try:
                pvs_json = json.loads(pvs_res.stdout)
                for report in pvs_json.get("report", []):
                    for pv in report.get("pv", []):
                        size_b = Normalizer.parse_bytes(pv.get("pv_size"))
                        free_b = Normalizer.parse_bytes(pv.get("pv_free"))
                        data["physical_volumes"].append({
                            "pv_name": pv.get("pv_name"),
                            "vg_name": pv.get("vg_name"),
                            "pv_fmt": pv.get("pv_fmt"),
                            "pv_size_bytes": size_b,
                            "pv_size_formatted": Normalizer.format_bytes(size_b),
                            "pv_free_bytes": free_b,
                            "pv_free_formatted": Normalizer.format_bytes(free_b),
                            "pv_uuid": pv.get("pv_uuid"),
                        })
            except Exception:
                pass

        # 2. Volume Groups
        vgs_res = executor.run(["vgs", "--reportformat", "json", "--units", "b"], use_sudo=True)
        if vgs_res.success and vgs_res.stdout:
            try:
                vgs_json = json.loads(vgs_res.stdout)
                for report in vgs_json.get("report", []):
                    for vg in report.get("vg", []):
                        size_b = Normalizer.parse_bytes(vg.get("vg_size"))
                        free_b = Normalizer.parse_bytes(vg.get("vg_free"))
                        data["volume_groups"].append({
                            "vg_name": vg.get("vg_name"),
                            "pv_count": int(vg.get("pv_count", 0)),
                            "lv_count": int(vg.get("lv_count", 0)),
                            "vg_size_bytes": size_b,
                            "vg_size_formatted": Normalizer.format_bytes(size_b),
                            "vg_free_bytes": free_b,
                            "vg_free_formatted": Normalizer.format_bytes(free_b),
                            "vg_uuid": vg.get("vg_uuid"),
                        })
            except Exception:
                pass

        # 3. Logical Volumes
        lvs_res = executor.run(["lvs", "--reportformat", "json", "--units", "b"], use_sudo=True)
        if lvs_res.success and lvs_res.stdout:
            try:
                lvs_json = json.loads(lvs_res.stdout)
                for report in lvs_json.get("report", []):
                    for lv in report.get("lv", []):
                        size_b = Normalizer.parse_bytes(lv.get("lv_size"))
                        data["logical_volumes"].append({
                            "lv_name": lv.get("lv_name"),
                            "vg_name": lv.get("vg_name"),
                            "lv_attr": lv.get("lv_attr"),
                            "lv_size_bytes": size_b,
                            "lv_size_formatted": Normalizer.format_bytes(size_b),
                            "pool_lv": lv.get("pool_lv"),
                            "origin": lv.get("origin"),
                            "data_percent": lv.get("data_percent"),
                            "lv_uuid": lv.get("lv_uuid"),
                            "dm_path": f"/dev/{lv.get('vg_name')}/{lv.get('lv_name')}",
                        })
            except Exception:
                pass

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['physical_volumes'])} PVs, {len(data['volume_groups'])} VGs, and {len(data['logical_volumes'])} LVs",
        )
