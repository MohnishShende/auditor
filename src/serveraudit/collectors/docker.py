"""
Docker engine, containers, images, volumes, networks, Compose, and container security collector.
Strictly NEVER exports cleartext passwords or secret environment variables.
"""

from __future__ import annotations
import json
from pathlib import Path
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from ..core.normalizer import Normalizer
from . import register_collector


@register_collector
class DockerCollector(BaseCollector):
    manifest = CollectorManifest(
        name="docker",
        category="containers",
        description="Inspect Docker engine, containers, images, volumes, networks, compose projects, and container security",
        requires_root=False,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["docker info --format '{{json .}}'", "docker ps -a --format '{{json .}}'", "docker inspect <container>"],
        outputs=["engine", "containers", "images", "volumes", "networks", "compose", "security"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        if not executor.which("docker"):
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.SKIPPED,
                message="docker binary not installed",
            )

        data: Dict[str, Any] = {
            "engine": {
                "installed": True,
                "active": False,
                "server_version": None,
                "storage_driver": None,
                "cgroup_driver": None,
                "cgroup_version": None,
                "docker_root_dir": None,
                "containers_total": 0,
                "containers_running": 0,
                "containers_stopped": 0,
                "images_total": 0,
            },
            "containers": [],
            "images": [],
            "volumes": [],
            "networks": [],
            "compose_projects": [],
            "security_findings": [],
        }

        # 1. Docker Info
        info_res = executor.run(["docker", "info", "--format", "{{json .}}"], use_sudo=True)
        if not info_res.success:
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.SKIPPED,
                data=data,
                message="Docker daemon is not running or inaccessible",
            )

        try:
            info_json = json.loads(info_res.stdout)
            eng = data["engine"]
            eng["active"] = True
            eng["server_version"] = info_json.get("ServerVersion")
            eng["storage_driver"] = info_json.get("Driver")
            eng["cgroup_driver"] = info_json.get("CgroupDriver")
            eng["cgroup_version"] = info_json.get("CgroupVersion")
            eng["docker_root_dir"] = info_json.get("DockerRootDir")
            eng["containers_total"] = info_json.get("Containers", 0)
            eng["containers_running"] = info_json.get("ContainersRunning", 0)
            eng["containers_stopped"] = info_json.get("ContainersStopped", 0)
            eng["images_total"] = info_json.get("Images", 0)
        except Exception:
            pass

        # 2. Inspect all containers
        ps_res = executor.run(["docker", "ps", "-a", "--format", "{{.ID}}"], use_sudo=True)
        if ps_res.success and ps_res.stdout.strip():
            container_ids = ps_res.stdout.strip().split()
            if container_ids:
                # Inspect in batches
                inspect_res = executor.run(["docker", "inspect"] + container_ids, use_sudo=True)
                if inspect_res.success and inspect_res.stdout:
                    try:
                        inspect_list = json.loads(inspect_res.stdout)
                        for c in inspect_list:
                            c_id = c.get("Id", "")[:12]
                            c_name = c.get("Name", "").lstrip("/")
                            state_obj = c.get("State", {})
                            c_state = state_obj.get("Status", "unknown")
                            image_name = c.get("Config", {}).get("Image", "")
                            
                            # Parse mounts
                            mounts = []
                            has_docker_sock = False
                            for m in c.get("Mounts", []):
                                m_type = m.get("Type")
                                m_src = m.get("Source")
                                m_dst = m.get("Destination")
                                m_rw = m.get("RW", True)
                                mounts.append({
                                    "type": m_type,
                                    "source": m_src,
                                    "destination": m_dst,
                                    "read_write": m_rw,
                                })
                                if m_src == "/var/run/docker.sock":
                                    has_docker_sock = True

                            # Parse ports
                            port_bindings = []
                            network_settings = c.get("NetworkSettings", {})
                            ports = network_settings.get("Ports", {}) or {}
                            for container_port, host_bindings in ports.items():
                                if host_bindings:
                                    for hb in host_bindings:
                                        port_bindings.append({
                                            "container_port": container_port,
                                            "host_ip": hb.get("HostIp"),
                                            "host_port": hb.get("HostPort"),
                                        })
                                else:
                                    port_bindings.append({
                                        "container_port": container_port,
                                        "host_ip": None,
                                        "host_port": None,
                                    })

                            # Security posture
                            host_config = c.get("HostConfig", {})
                            is_privileged = host_config.get("Privileged", False)
                            net_mode = host_config.get("NetworkMode", "")
                            cap_add = host_config.get("CapAdd", []) or []
                            user = c.get("Config", {}).get("User", "")
                            is_root = user == "" or user == "0" or user == "root"

                            # Environment variable names ONLY (prevent secret value leakage)
                            env_names = []
                            for env_line in c.get("Config", {}).get("Env", []):
                                if "=" in env_line:
                                    env_names.append(env_line.split("=", 1)[0])

                            labels = c.get("Config", {}).get("Labels", {}) or {}
                            compose_project = labels.get("com.docker.compose.project")
                            compose_service = labels.get("com.docker.compose.service")

                            container_entry = {
                                "id": c_id,
                                "name": c_name,
                                "state": c_state,
                                "image": image_name,
                                "privileged": is_privileged,
                                "host_network": net_mode == "host",
                                "mounts": mounts,
                                "ports": port_bindings,
                                "compose_project": compose_project,
                                "compose_service": compose_service,
                                "environment_keys": env_names,
                                "labels": labels,
                            }
                            data["containers"].append(container_entry)

                            # Record security observations
                            if is_privileged:
                                data["security_findings"].append({
                                    "container": c_name,
                                    "severity": "WARNING",
                                    "finding": "Container executes in privileged mode",
                                })
                            if net_mode == "host":
                                data["security_findings"].append({
                                    "container": c_name,
                                    "severity": "NOTICE",
                                    "finding": "Container uses host network namespace",
                                })
                            if has_docker_sock:
                                data["security_findings"].append({
                                    "container": c_name,
                                    "severity": "WARNING",
                                    "finding": "Docker socket /var/run/docker.sock mounted into container",
                                })

                    except Exception:
                        pass

        # 3. Docker Images
        img_res = executor.run(["docker", "images", "--format", "{{json .}}"], use_sudo=True)
        if img_res.success and img_res.stdout:
            for line in img_res.stdout.splitlines():
                try:
                    img_obj = json.loads(line)
                    data["images"].append({
                        "repository": img_obj.get("Repository"),
                        "tag": img_obj.get("Tag"),
                        "id": img_obj.get("ID"),
                        "size": img_obj.get("Size"),
                        "created": img_obj.get("CreatedAt"),
                    })
                except Exception:
                    pass

        # 4. Docker Volumes
        vol_res = executor.run(["docker", "volume", "ls", "--format", "{{json .}}"], use_sudo=True)
        if vol_res.success and vol_res.stdout:
            for line in vol_res.stdout.splitlines():
                try:
                    vol_obj = json.loads(line)
                    data["volumes"].append({
                        "name": vol_obj.get("Name"),
                        "driver": vol_obj.get("Driver"),
                        "scope": vol_obj.get("Scope"),
                    })
                except Exception:
                    pass

        # 5. Docker Networks
        net_res = executor.run(["docker", "network", "ls", "--format", "{{json .}}"], use_sudo=True)
        if net_res.success and net_res.stdout:
            for line in net_res.stdout.splitlines():
                try:
                    net_obj = json.loads(line)
                    data["networks"].append({
                        "name": net_obj.get("Name"),
                        "driver": net_obj.get("Driver"),
                        "id": net_obj.get("ID"),
                        "scope": net_obj.get("Scope"),
                    })
                except Exception:
                    pass

        # 6. Docker Compose discovery
        if executor.which("docker"):
            comp_res = executor.run(["docker", "compose", "ls", "--format", "json"], use_sudo=True)
            if comp_res.success and comp_res.stdout:
                try:
                    comp_json = json.loads(comp_res.stdout)
                    for cp in comp_json:
                        data["compose_projects"].append({
                            "name": cp.get("Name"),
                            "status": cp.get("Status"),
                            "config_files": cp.get("ConfigFiles", "").split(",") if cp.get("ConfigFiles") else [],
                        })
                except Exception:
                    pass

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message=f"Discovered {len(data['containers'])} containers, {len(data['images'])} images, and {len(data['volumes'])} volumes",
        )
