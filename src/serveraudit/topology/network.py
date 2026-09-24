"""
Network-to-Container topology reconstruction for Linux Server Audit.
"""

from __future__ import annotations
from typing import Any, Dict, List
from .graph import TopologyGraph


def build_network_topology(
    network_data: Dict[str, Any],
    docker_data: Dict[str, Any],
    graph: TopologyGraph,
) -> List[Dict[str, Any]]:
    """Builds network interface to IP to bridge to container relationships."""
    routes = []
    interfaces = network_data.get("interfaces", [])
    containers = docker_data.get("containers", [])
    docker_nets = docker_data.get("networks", [])

    for iface in interfaces:
        if_name = iface.get("name")
        if_id = f"net_iface_{if_name}"
        if_label = f"Interface: {if_name} ({iface.get('state')})"
        graph.add_node(if_id, if_label, "interface", iface)

        # Connect IP addresses
        for ip_obj in iface.get("ipv4", []):
            cidr = ip_obj.get("cidr")
            ip_id = f"net_ip_{cidr.replace('/', '_').replace('.', '_')}"
            graph.add_node(ip_id, f"IP: {cidr}", "ip_address", ip_obj)
            graph.add_edge(if_id, ip_id, "assigned_ip")

    return routes
