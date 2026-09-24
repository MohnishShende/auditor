"""
SSH client, server, configuration fragments, effective sshd -T, and host key collector.
Strictly NEVER collects or exports private keys.
"""

from __future__ import annotations
from pathlib import Path
import re
from typing import Any, Dict, List

from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
from ..core.executor import CommandExecutor
from . import register_collector


@register_collector
class SshCollector(BaseCollector):
    manifest = CollectorManifest(
        name="ssh",
        category="security",
        description="Inspect SSH server version, effective sshd -T config, host key fingerprints, and auth security",
        requires_root=True,
        network_access=False,
        writes_system_state=False,
        collects_secrets=False,
        commands=["sshd -T", "ssh -V", "ssh-keygen -l -f <key>"],
        outputs=["server_version", "effective_config", "host_keys", "security_posture"],
    )

    def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
        data: Dict[str, Any] = {
            "client_version": None,
            "server_version": None,
            "service_active": False,
            "effective_config": {
                "port": 22,
                "listen_addresses": [],
                "permit_root_login": "unknown",
                "password_authentication": "unknown",
                "pubkey_authentication": "unknown",
                "kbd_interactive_authentication": "unknown",
                "max_auth_tries": 6,
                "ciphers": [],
                "kex_algorithms": [],
                "macs": [],
            },
            "host_keys": [],
            "config_files": [],
        }

        # 1. ssh -V (client version)
        ssh_v = executor.run(["ssh", "-V"])
        # ssh -V writes to stderr
        version_out = ssh_v.stdout or ssh_v.stderr
        if version_out:
            data["client_version"] = version_out.strip()

        # 2. Config files discovery in /etc/ssh
        ssh_dir = Path("/etc/ssh")
        if ssh_dir.exists():
            if (ssh_dir / "sshd_config").exists():
                data["config_files"].append("/etc/ssh/sshd_config")
            sshd_d = ssh_dir / "sshd_config.d"
            if sshd_d.exists():
                for f in sorted(sshd_d.glob("*.conf")):
                    data["config_files"].append(str(f))

        # 3. Effective sshd configuration via sshd -T
        if executor.which("sshd"):
            sshd_t = executor.run(["sshd", "-T"], use_sudo=True)
            if sshd_t.success and sshd_t.stdout:
                data["service_active"] = True
                cfg: Dict[str, str] = {}
                for line in sshd_t.stdout.splitlines():
                    if " " in line:
                        k, v = line.strip().split(" ", 1)
                        cfg[k.lower()] = v

                eff = data["effective_config"]
                eff["port"] = int(cfg.get("port", "22"))
                eff["permit_root_login"] = cfg.get("permitrootlogin", "unknown")
                eff["password_authentication"] = cfg.get("passwordauthentication", "unknown")
                eff["pubkey_authentication"] = cfg.get("pubkeyauthentication", "unknown")
                eff["kbd_interactive_authentication"] = cfg.get("kbdinteractiveauthentication", cfg.get("challengeresponseauthentication", "unknown"))
                eff["max_auth_tries"] = int(cfg.get("maxauthtries", "6")) if cfg.get("maxauthtries", "").isdigit() else 6
                eff["ciphers"] = cfg.get("ciphers", "").split(",") if cfg.get("ciphers") else []
                eff["kex_algorithms"] = cfg.get("kexalgorithms", "").split(",") if cfg.get("kexalgorithms") else []
                eff["macs"] = cfg.get("macs", "").split(",") if cfg.get("macs") else []

        # 4. Host key fingerprints (public keys only)
        if executor.which("ssh-keygen") and ssh_dir.exists():
            for pub in sorted(ssh_dir.glob("ssh_host_*_key.pub")):
                keygen_res = executor.run(["ssh-keygen", "-l", "-f", str(pub)])
                if keygen_res.success and keygen_res.stdout:
                    # Example: 256 SHA256:abcd... root@host (ED25519)
                    parts = keygen_res.stdout.strip().split()
                    if len(parts) >= 4:
                        data["host_keys"].append({
                            "path": str(pub),
                            "bits": parts[0],
                            "fingerprint": parts[1],
                            "comment": parts[2],
                            "type": parts[3].strip("()"),
                        })

        return CollectorResult(
            collector=self.name,
            status=CollectorStatus.SUCCESS,
            data=data,
            message="SSH server configuration and host key fingerprints collected",
        )
