"""
Historical configuration drift and snapshot comparison engine for Linux Server Audit.
Distinguishes stable configuration drift from volatile runtime fluctuations.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Set


def compare_snapshots(snapshot_a: Dict[str, Any], snapshot_b: Dict[str, Any]) -> Dict[str, Any]:
    """Compares two canonical audit JSON dictionaries and outputs structured drift."""
    drift_report: Dict[str, Any] = {
        "metadata_a": snapshot_a.get("metadata", {}),
        "metadata_b": snapshot_b.get("metadata", {}),
        "has_drift": False,
        "categories": {},
    }

    # 1. System / Kernel Drift
    sys_a = snapshot_a.get("system", {})
    sys_b = snapshot_b.get("system", {})
    sys_changes = []

    k_a = sys_a.get("kernel", {}).get("release")
    k_b = sys_b.get("kernel", {}).get("release")
    if k_a and k_b and k_a != k_b:
        sys_changes.append({"item": "Kernel Release", "old": k_a, "new": k_b})

    os_a = sys_a.get("os", {}).get("pretty_name")
    os_b = sys_b.get("os", {}).get("pretty_name")
    if os_a and os_b and os_a != os_b:
        sys_changes.append({"item": "Operating System", "old": os_a, "new": os_b})

    if sys_changes:
        drift_report["categories"]["System"] = sys_changes
        drift_report["has_drift"] = True

    # 2. Docker Container Drift
    dock_a = snapshot_a.get("docker", {})
    dock_b = snapshot_b.get("docker", {})
    c_a_map = {c["name"]: c for c in dock_a.get("containers", []) if isinstance(c, dict) and "name" in c}
    c_b_map = {c["name"]: c for c in dock_b.get("containers", []) if isinstance(c, dict) and "name" in c}

    added_containers = sorted(list(set(c_b_map.keys()) - set(c_a_map.keys())))
    removed_containers = sorted(list(set(c_a_map.keys()) - set(c_b_map.keys())))
    changed_containers = []

    for cname in set(c_a_map.keys()) & set(c_b_map.keys()):
        img_a = c_a_map[cname].get("image")
        img_b = c_b_map[cname].get("image")
        if img_a and img_b and img_a != img_b:
            changed_containers.append({"container": cname, "item": "image", "old": img_a, "new": img_b})

    if added_containers or removed_containers or changed_containers:
        drift_report["categories"]["Docker Containers"] = {
            "added": added_containers,
            "removed": removed_containers,
            "changed": changed_containers,
        }
        drift_report["has_drift"] = True

    # 3. SSH Configuration Drift
    ssh_a = snapshot_a.get("ssh", {}).get("effective_config", {})
    ssh_b = snapshot_b.get("ssh", {}).get("effective_config", {})
    ssh_diffs = []
    for key in ("permit_root_login", "password_authentication", "pubkey_authentication", "port"):
        val_a = ssh_a.get(key)
        val_b = ssh_b.get(key)
        if val_a != val_b and val_a is not None and val_b is not None:
            ssh_diffs.append({"setting": key, "old": val_a, "new": val_b})

    if ssh_diffs:
        drift_report["categories"]["SSH Configuration"] = ssh_diffs
        drift_report["has_drift"] = True

    # 4. Listening Ports Drift
    ports_a = {f"{p.get('protocol')}/{p.get('port')}" for p in snapshot_a.get("ports", {}).get("listening_ports", [])}
    ports_b = {f"{p.get('protocol')}/{p.get('port')}" for p in snapshot_b.get("ports", {}).get("listening_ports", [])}

    opened_ports = sorted(list(ports_b - ports_a))
    closed_ports = sorted(list(ports_a - ports_b))

    if opened_ports or closed_ports:
        drift_report["categories"]["Listening Ports"] = {
            "opened": opened_ports,
            "closed": closed_ports,
        }
        drift_report["has_drift"] = True

    # 5. Caddy Routes Drift
    caddy_a = {f"{r.get('hostname')} -> {r.get('upstream')}" for r in snapshot_a.get("caddy", {}).get("reverse_proxies", [])}
    caddy_b = {f"{r.get('hostname')} -> {r.get('upstream')}" for r in snapshot_b.get("caddy", {}).get("reverse_proxies", [])}

    added_routes = sorted(list(caddy_b - caddy_a))
    removed_routes = sorted(list(caddy_a - caddy_b))

    if added_routes or removed_routes:
        drift_report["categories"]["Caddy Routes"] = {
            "added": added_routes,
            "removed": removed_routes,
        }
        drift_report["has_drift"] = True

    # 6. Users & Sudo Drift
    users_a = {u["username"] for u in snapshot_a.get("users", {}).get("users", []) if isinstance(u, dict) and "username" in u}
    users_b = {u["username"] for u in snapshot_b.get("users", {}).get("users", []) if isinstance(u, dict) and "username" in u}
    sudo_a = {u["username"] for u in snapshot_a.get("users", {}).get("sudo_users", []) if isinstance(u, dict) and "username" in u}
    sudo_b = {u["username"] for u in snapshot_b.get("users", {}).get("sudo_users", []) if isinstance(u, dict) and "username" in u}

    added_users = sorted(list(users_b - users_a))
    removed_users = sorted(list(users_a - users_b))
    added_sudo = sorted(list(sudo_b - sudo_a))
    removed_sudo = sorted(list(sudo_a - sudo_b))

    if added_users or removed_users or added_sudo or removed_sudo:
        drift_report["categories"]["Users & Groups"] = {
            "added_users": added_users,
            "removed_users": removed_users,
            "added_sudo": added_sudo,
            "removed_sudo": removed_sudo,
        }
        drift_report["has_drift"] = True

    # 7. Package Count Drift
    pkg_a = snapshot_a.get("packages", {}).get("installed_count", 0)
    pkg_b = snapshot_b.get("packages", {}).get("installed_count", 0)
    if pkg_a != pkg_b and pkg_a > 0 and pkg_b > 0:
        drift_report["categories"]["Packages"] = {
            "installed_count_delta": pkg_b - pkg_a,
            "old_count": pkg_a,
            "new_count": pkg_b,
        }
        drift_report["has_drift"] = True

    return drift_report
