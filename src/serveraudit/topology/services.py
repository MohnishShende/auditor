"""
Service and reverse proxy exposure topology reconstruction for Linux Server Audit.
Builds chains: Hostname -> Caddy Route -> Port -> Process -> Container -> App.
"""

from __future__ import annotations
from typing import Any, Dict, List
from .graph import TopologyGraph


def build_service_topology(
    caddy_data: Dict[str, Any],
    ports_data: Dict[str, Any],
    docker_data: Dict[str, Any],
    apps_data: Dict[str, Any],
    graph: TopologyGraph,
) -> List[Dict[str, Any]]:
    """Builds reverse proxy to port to application mapping."""
    service_routes = []
    sites = caddy_data.get("sites", [])
    listening_ports = ports_data.get("listening_ports", [])
    containers = docker_data.get("containers", [])
    apps = apps_data.get("applications", [])

    for site in sites:
        hostname = site.get("hostname")
        site_id = f"site_{hostname.replace(':', '_').replace('/', '_').replace('.', '_')}"
        graph.add_node(site_id, f"Caddy Site: {hostname}", "caddy_site", site)

        for upstream in site.get("reverse_proxies", []):
            upstream_id = f"upstream_{upstream.replace(':', '_').replace('.', '_')}"
            graph.add_node(upstream_id, f"Upstream: {upstream}", "upstream")
            graph.add_edge(site_id, upstream_id, "proxies_to")

            # Try to match upstream port to listening port
            upstream_port = None
            if ":" in upstream:
                p_str = upstream.split(":")[-1]
                if p_str.isdigit():
                    upstream_port = int(p_str)

            matched_proc = None
            matched_container = None
            matched_app = None

            if upstream_port:
                for lp in listening_ports:
                    if lp.get("port") == upstream_port:
                        matched_proc = lp.get("process")
                        break

                for c in containers:
                    for cp in c.get("ports", []):
                        if cp.get("host_port") and int(cp.get("host_port")) == upstream_port:
                            matched_container = c.get("name")
                            break

                for a in apps:
                    if upstream_port in a.get("ports", []):
                        matched_app = a.get("name")
                        break

            service_routes.append({
                "hostname": hostname,
                "upstream": upstream,
                "port": upstream_port,
                "process": matched_proc,
                "container": matched_container,
                "application": matched_app,
            })

    return service_routes
