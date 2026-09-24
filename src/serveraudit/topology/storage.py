"""
Storage-to-Application topology reconstruction for Linux Server Audit.
Builds chains: Disk -> Partition -> LUKS -> LVM PV -> VG -> LV -> FS -> Mount -> Container -> App.
"""

from __future__ import annotations
from typing import Any, Dict, List
from .graph import TopologyGraph


def build_storage_topology(
    storage_data: Dict[str, Any],
    lvm_data: Dict[str, Any],
    encryption_data: Dict[str, Any],
    filesystems_data: Dict[str, Any],
    docker_data: Dict[str, Any],
    apps_data: Dict[str, Any],
    graph: TopologyGraph,
) -> List[Dict[str, Any]]:
    """Reconstructs complete storage chains from physical disk to running applications."""
    chains = []

    # Map mounts to filesystems
    mounts = filesystems_data.get("mounts", []) + filesystems_data.get("network_mounts", [])
    containers = docker_data.get("containers", [])
    applications = apps_data.get("applications", [])

    # Map encrypted devices
    enc_map = {}
    for ev in encryption_data.get("encrypted_volumes", []):
        underlying = ev.get("underlying_device")
        target = ev.get("target_name")
        if underlying and target:
            enc_map[underlying] = f"/dev/mapper/{target}"

    # Map LVM PVs to VGs and LVs
    pv_to_vg = {}
    for pv in lvm_data.get("physical_volumes", []):
        pv_to_vg[pv.get("pv_name")] = pv.get("vg_name")

    vg_to_lvs = {}
    for lv in lvm_data.get("logical_volumes", []):
        vg = lv.get("vg_name")
        if vg not in vg_to_lvs:
            vg_to_lvs[vg] = []
        vg_to_lvs[vg].append(lv.get("dm_path"))

    # Traverse disks and partitions
    for disk in storage_data.get("disks", []):
        disk_name = disk.get("name")
        disk_id = f"disk_{disk_name}"
        disk_label = f"Disk: {disk.get('path')} ({disk.get('size_formatted')})"
        graph.add_node(disk_id, disk_label, "disk", disk)

        for part in disk.get("children", []):
            part_name = part.get("name")
            part_path = part.get("path")
            part_id = f"part_{part_name}"
            part_label = f"Partition: {part_path} ({part.get('size_formatted')})"
            graph.add_node(part_id, part_label, "partition", part)
            graph.add_edge(disk_id, part_id, "contains")

            current_device_path = part_path
            current_node_id = part_id

            # Check for LUKS encryption
            if current_device_path in enc_map:
                luks_path = enc_map[current_device_path]
                luks_id = f"luks_{luks_path.replace('/', '_')}"
                graph.add_node(luks_id, f"LUKS: {luks_path}", "luks")
                graph.add_edge(current_node_id, luks_id, "encrypted_as")
                current_device_path = luks_path
                current_node_id = luks_id

            # Check for LVM PV
            vg_name = pv_to_vg.get(current_device_path)
            if vg_name:
                vg_id = f"vg_{vg_name}"
                graph.add_node(vg_id, f"VG: {vg_name}", "lvm_vg")
                graph.add_edge(current_node_id, vg_id, "member_of")

                # Connect LVs in this VG
                for lv_path in vg_to_lvs.get(vg_name, []):
                    lv_id = f"lv_{lv_path.replace('/', '_')}"
                    graph.add_node(lv_id, f"LV: {lv_path}", "lvm_lv")
                    graph.add_edge(vg_id, lv_id, "allocates")

                    # Check for filesystem mount on LV
                    for m in mounts:
                        if m.get("source") == lv_path or lv_path in m.get("source", ""):
                            mount_id = f"mount_{m.get('target').replace('/', '_')}"
                            graph.add_node(mount_id, f"Mount: {m.get('target')} ({m.get('fstype')})", "mount", m)
                            graph.add_edge(lv_id, mount_id, "mounted_at")
                            
                            # Connect containers using this mount
                            for c in containers:
                                for cm in c.get("mounts", []):
                                    if cm.get("source") and (cm.get("source") == m.get("target") or cm.get("source").startswith(m.get("target"))):
                                        c_id = f"container_{c.get('name')}"
                                        graph.add_node(c_id, f"Container: {c.get('name')}", "container", c)
                                        graph.add_edge(mount_id, c_id, "bind_mounted_in")

                                        # Connect application
                                        for app in applications:
                                            if app.get("container_name") == c.get("name"):
                                                app_id = f"app_{app.get('name')}"
                                                graph.add_node(app_id, f"App: {app.get('name')}", "app", app)
                                                graph.add_edge(c_id, app_id, "runs_app")

                                                chains.append({
                                                    "disk": disk.get("path"),
                                                    "partition": part_path,
                                                    "luks": luks_path if current_device_path != part_path else None,
                                                    "vg": vg_name,
                                                    "lv": lv_path,
                                                    "mount": m.get("target"),
                                                    "container": c.get("name"),
                                                    "app": app.get("name"),
                                                })

            # Check direct filesystem mount on partition
            for m in mounts:
                if m.get("source") == current_device_path:
                    mount_id = f"mount_{m.get('target').replace('/', '_')}"
                    graph.add_node(mount_id, f"Mount: {m.get('target')} ({m.get('fstype')})", "mount", m)
                    graph.add_edge(current_node_id, mount_id, "mounted_at")

                    for c in containers:
                        for cm in c.get("mounts", []):
                            if cm.get("source") and (cm.get("source") == m.get("target") or cm.get("source").startswith(m.get("target"))):
                                c_id = f"container_{c.get('name')}"
                                graph.add_node(c_id, f"Container: {c.get('name')}", "container", c)
                                graph.add_edge(mount_id, c_id, "bind_mounted_in")

    return chains
