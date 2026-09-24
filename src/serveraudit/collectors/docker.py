"""
Docker engine, containers, images, volumes, networks, Compose, and container security collector.
Strictly NEVER exports cleartext passwords or secret environment variables.
"""

from __future__ import annotations
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor, CommandOutput
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

    def _exec_docker(self, executor: CommandExecutor, args: List[str], use_sudo_pref: bool = False) -> CommandOutput:
        """Executes docker command trying unprivileged first unless sudo preferred."""
        cmd = ["docker"] + args
        if use_sudo_pref and executor.privileges.can_elevate:
            return executor.run(cmd, use_sudo=True)

        res = executor.run(cmd, use_sudo=False)
        # If unprivileged failed with permission denied, retry with sudo if available
        if not res.success and ("permission denied" in res.stderr.lower() or "got permission denied" in res.stderr.lower()):
            if executor.privileges.can_elevate:
                return executor.run(cmd, use_sudo=True)
        return res

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        if not executor.which("docker"):
            return CollectorResult(
                collector=self.name,
                status=CollectorStatus.SKIPPED,
                message="Docker CLI binary not found in PATH",
            )

        data: Dict[str, Any] = {
            "engine": {
                "installed": True,
                "active": False,
                "server_version": None,
                "api_version": None,
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

        # 1. Test Connectivity / Accessibility via docker version or docker info
        use_sudo = False
        test_res = executor.run(["docker", "version", "--format", "{{json .}}"], use_sudo=False)
        
        # Check if unprivileged failed due to permission denied
        if not test_res.success:
            stderr_lower = (test_res.stderr or "").lower()
            if "permission denied" in stderr_lower or "got permission denied" in stderr_lower:
                if executor.privileges.can_elevate:
                    test_res = executor.run(["docker", "version", "--format", "{{json .}}"], use_sudo=True)
                    if test_res.success:
                        use_sudo = True
                else:
                    return CollectorResult(
                        collector=self.name,
                        status=CollectorStatus.PERMISSION_DENIED,
                        data=data,
                        message="Permission denied connecting to Docker socket /var/run/docker.sock",
                    )
            elif "cannot connect to the docker daemon" in stderr_lower or "is the docker daemon running" in stderr_lower:
                return CollectorResult(
                    collector=self.name,
                    status=CollectorStatus.SKIPPED,
                    data=data,
                    message="Docker daemon is not running (socket unreachable)",
                )

        # Parse docker version if available
        eng = data["engine"]
        if test_res.success and test_res.stdout:
            try:
                ver_json = json.loads(test_res.stdout)
                server_obj = ver_json.get("Server", {})
                if isinstance(server_obj, dict):
                    eng["active"] = True
                    eng["server_version"] = server_obj.get("Version")
                    eng["api_version"] = server_obj.get("ApiVersion")
            except Exception:
                # Text fallback
                eng["active"] = True

        # If docker version format failed, try plain docker version
        if not eng["active"]:
            plain_ver = self._exec_docker(executor, ["version"], use_sudo_pref=use_sudo)
            if plain_ver.success:
                eng["active"] = True
                for line in plain_ver.stdout.splitlines():
                    if "Version:" in line and not eng["server_version"]:
                        eng["server_version"] = line.split(":", 1)[1].strip()
                    elif "API version:" in line and not eng["api_version"]:
                        eng["api_version"] = line.split(":", 1)[1].strip()

        # 2. Docker Info
        info_res = self._exec_docker(executor, ["info", "--format", "{{json .}}"], use_sudo_pref=use_sudo)
        if info_res.success and info_res.stdout:
            try:
                info_json = json.loads(info_res.stdout)
                eng["active"] = True
                if not eng["server_version"]:
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
        elif not eng["active"]:
            # Check stderr of info
            stderr_lower = (info_res.stderr or "").lower()
            if "permission denied" in stderr_lower:
                return CollectorResult(
                    collector=self.name,
                    status=CollectorStatus.PERMISSION_DENIED,
                    data=data,
                    message="Permission denied accessing Docker daemon",
                )
            if "cannot connect" in stderr_lower or "is the docker daemon running" in stderr_lower:
                return CollectorResult(
                    collector=self.name,
                    status=CollectorStatus.SKIPPED,
                    data=data,
                    message="Docker daemon is not running (socket unreachable)",
                )

        # 3. Inspect all containers via docker ps -a
        ps_res = self._exec_docker(executor, ["ps", "-a", "--format", "{{.ID}}"], use_sudo_pref=use_sudo)
        if ps_res.success and ps_res.stdout.strip():
            container_ids = ps_res.stdout.strip().split()
            if container_ids:
                eng["active"] = True
                # Inspect in batches
                inspect_res = self._exec_docker(executor, ["inspect"] + container_ids, use_sudo_pref=use_sudo)
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
                            user = c.get("Config", {}).get("User", "")

                            # Environment variable names ONLY
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

        # 4. Docker Images
        img_res = self._exec_docker(executor, ["images", "--format", "{{json .}}"], use_sudo_pref=use_sudo)
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

        # 5. Docker Volumes
        vol_res = self._exec_docker(executor, ["volume", "ls", "--format", "{{json .}}"], use_sudo_pref=use_sudo)
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

        # 6. Docker Networks
        net_res = self._exec_docker(executor, ["network", "ls", "--format", "{{json .}}"], use_sudo_pref=use_sudo)
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

        # 7. Docker Compose discovery
        comp_res = self._exec_docker(executor, ["compose", "ls", "--format", "json"], use_sudo_pref=use_sudo)
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

        # Update totals if info was incomplete
        if not eng["containers_total"] and data["containers"]:
            eng["containers_total"] = len(data["containers"])
            eng["containers_running"] = sum(1 for c in data["containers"] if c.get("state") == "running")
            eng["containers_stopped"] = eng["containers_total"] - eng["containers_running"]
        if not eng["images_total"] and data["images"]:
            eng["images_total"] = len(data["images"])

        if eng["active"] or data["containers"]:
            status = CollectorStatus.SUCCESS
            msg = f"Discovered {len(data['containers'])} containers, {len(data['images'])} images, and {len(data['volumes'])} volumes"
        else:
            status = CollectorStatus.PARTIAL
            msg = "Docker CLI present but engine details partially accessible"

        return CollectorResult(
            collector=self.name,
            status=status,
            data=data,
            message=msg,
        )
