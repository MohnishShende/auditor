"""
Application discovery collector for Linux Server Audit.
Discovers self-hosted applications across Docker containers and native host services.
"""

from __future__ import annotations
import re
from typing import Any, Dict, List

from ..applications import KNOWN_APPS, DiscoveredApplication
from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class ApplicationsCollector(BaseCollector):
    manifest = CollectorManifest(
        name="applications",
        category="applications",
        description="Discover self-hosted applications (Jellyfin, Paperless, Pi-hole, *arr stack, Databases) and their mounts/ports",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=[],
        outputs=["applications", "apps_count"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "applications": [],
            "apps_count": 0,
        }

        # Context contains previously collected results (docker, ports, etc.)
        docker_data = context.get("docker", {})
        containers = docker_data.get("containers", []) if isinstance(docker_data, dict) else []
        ports_data = context.get("ports", {})
        listening_ports = ports_data.get("listening_ports", []) if isinstance(ports_data, dict) else []

        seen_app_names = set()

        # 1. Match against Docker containers
        for container in containers:
            c_name = container.get("name", "")
            c_image = container.get("image", "")

            for app_sig in KNOWN_APPS:
                name_match = re.search(app_sig["container_match"], c_name, re.IGNORECASE)
                image_match = re.search(app_sig["image_match"], c_image, re.IGNORECASE)

                if name_match or image_match:
                    app_key = f"{app_sig['name']}-{c_name}"
                    if app_key not in seen_app_names:
                        seen_app_names.add(app_key)
                        
                        # Extract storage paths from mounts
                        storage = [m.get("source") for m in container.get("mounts", []) if m.get("source")]
                        
                        # Extract exposed host ports
                        exposed_ports = []
                        for p in container.get("ports", []):
                            hp = p.get("host_port")
                            if hp:
                                exposed_ports.append(int(hp))

                        app_entry = DiscoveredApplication(
                            name=app_sig["name"],
                            category=app_sig["category"],
                            deployment_type="docker",
                            container_name=c_name,
                            ports=exposed_ports or [app_sig.get("default_port")],
                            storage_paths=storage,
                            status=container.get("state", "running"),
                            details={
                                "image": c_image,
                                "compose_project": container.get("compose_project"),
                            },
                        )
                        data["applications"].append(app_entry.to_dict())

        # 2. Match against native listening ports if not already matched
        for lp in listening_ports:
            proc = (lp.get("process") or "").lower()
            port = lp.get("port")
            for app_sig in KNOWN_APPS:
                if (proc and proc in app_sig["name"].lower()) or (port == app_sig.get("default_port")):
                    app_key = f"{app_sig['name']}-native-{port}"
                    if app_key not in seen_app_names and not any(a["name"] == app_sig["name"] for a in data["applications"]):
                        seen_app_names.add(app_key)
                        data["applications"].append(
                            DiscoveredApplication(
                                name=app_sig["name"],
                                category=app_sig["category"],
                                deployment_type="native",
                                ports=[port],
                                status="running",
                                details={"process": proc},
                            ).to_dict()
                        )

        data["apps_count"] = len(data["applications"])

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {data['apps_count']} self-hosted applications",
        )
