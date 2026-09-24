"""
Service exposure and attack surface analysis for Linux Server Audit.
"""

from __future__ import annotations
from typing import Any, Dict, List


def evaluate_exposure(audit_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Classifies network exposure across ports, containers, and reverse proxies."""
    exposure_list: List[Dict[str, Any]] = []

    ports_data = audit_data.get("ports", {})
    caddy_data = audit_data.get("caddy", {})
    proxied_upstreams = {r.get("upstream") for r in caddy_data.get("reverse_proxies", [])} if isinstance(caddy_data, dict) else set()

    if isinstance(ports_data, dict):
        for lp in ports_data.get("listening_ports", []):
            proto = lp.get("protocol")
            port = lp.get("port")
            addr = lp.get("address")
            proc = lp.get("process")
            exp_type = lp.get("exposure")

            is_proxied = any(f":{port}" in u for u in proxied_upstreams)

            risk_level = "LOW"
            if exp_type == "all_interfaces":
                risk_level = "HIGH" if port in (22, 80, 443, 3306, 5432, 6379, 27017, 2375) else "MEDIUM"
            elif exp_type == "lan_only":
                risk_level = "MEDIUM" if port in (3306, 5432, 6379) else "LOW"

            exposure_list.append({
                "port": port,
                "protocol": proto,
                "bound_address": addr,
                "process": proc,
                "exposure_type": exp_type,
                "is_behind_caddy": is_proxied,
                "risk_rating": risk_level,
            })

    return exposure_list
