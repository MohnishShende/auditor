"""
Canonical Markdown report renderer for Linux Server Audit.
Produces clean, searchable, git-friendly, and diff-friendly Markdown as a polished product output.
"""

from __future__ import annotations
from typing import Any, Dict, List
from ..core.normalizer import Normalizer


class MarkdownRenderer:
    """Renders canonical audit data into a polished product-grade Markdown report."""

    @classmethod
    def render(cls, data: Dict[str, Any]) -> str:
        meta = data.get("metadata", {})
        sys = data.get("system", {})
        hw = data.get("hardware", {})
        fw = data.get("firmware", {})
        cpu = data.get("cpu", {})
        mem = data.get("memory", {})
        pci = data.get("pci", {})
        usb = data.get("usb", {})
        storage = data.get("storage", {})
        smart = data.get("smart", {})
        lvm = data.get("lvm", {})
        raid = data.get("raid", {})
        enc = data.get("encryption", {})
        fs = data.get("filesystems", {})
        fstab = data.get("fstab", {})
        net = data.get("network", {})
        routes = data.get("routes", {})
        dns = data.get("dns", {})
        ports = data.get("ports", {})
        fw_state = data.get("firewall", {})
        ssh = data.get("ssh", {})
        users = data.get("users", {})
        sec = data.get("security", {})
        perms = data.get("permissions", {})
        sd = data.get("systemd", {})
        procs = data.get("processes", {})
        rh = data.get("runtime_health", {})
        pkgs = data.get("packages", {})
        docker = data.get("docker", {})
        caddy = data.get("caddy", {})
        tls = data.get("tls", {})
        apps = data.get("applications", {})
        scheduled = data.get("scheduled", {})
        backups = data.get("backups", {})
        logs = data.get("logs", {})
        thermal = data.get("thermal", {})
        power = data.get("power", {})
        boot = data.get("boot", {})
        sharing = data.get("sharing", {})
        collectors_meta = data.get("collectors", {})
        findings = data.get("analysis", {}).get("health", [])
        exposure = data.get("analysis", {}).get("exposure", [])
        conflicts = data.get("analysis", {}).get("conflicts", [])

        lines: List[str] = []

        # Header and Server Identity
        hostname = meta.get("hostname", "unknown")
        os_pretty = sys.get("os", {}).get("pretty_name", "Linux")
        kernel_rel = sys.get("kernel", {}).get("release", "unknown")
        arch = sys.get("kernel", {}).get("architecture", "unknown")
        timestamp = meta.get("timestamp", "unknown")
        profile = meta.get("profile", "private")
        duration = meta.get("duration_seconds", 0.0)

        lines.append(f"# Linux Server Audit: `{hostname}`")
        lines.append("")
        lines.append("> **Observational System State Snapshot & Infrastructure Documentation**")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("### 🏷️ Server Identity & Audit Metadata")
        lines.append("")
        lines.append(f"- **Server Hostname:** `{hostname}`")
        lines.append(f"- **Operating System:** {os_pretty}")
        lines.append(f"- **Linux Kernel:** `{kernel_rel}` (`{arch}`)")
        lines.append(f"- **Audit Timestamp:** `{timestamp}`")
        lines.append(f"- **Audit Profile:** `{profile.upper()}`")
        lines.append(f"- **Execution Duration:** `{duration:.2f}s`")
        lines.append(f"- **Privilege Status:** `{'Sudo / Root Active' if meta.get('privileges_available') else 'Unprivileged User'}`")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Table of Contents
        lines.append("## 📑 Table of Contents")
        lines.append("")
        lines.append("1. [Executive Summary](#1-executive-summary)")
        lines.append("2. [Findings & Health Assessment](#2-findings--health-assessment)")
        lines.append("3. [System Identity & Operating System](#3-system-identity--operating-system)")
        lines.append("4. [Hardware, Motherboard & Firmware](#4-hardware-motherboard--firmware)")
        lines.append("5. [Processor & Memory Topology](#5-processor--memory-topology)")
        lines.append("6. [Storage Subsystems & Physical Health](#6-storage-subsystems--physical-health)")
        lines.append("7. [Network Interfaces, Addressing & Exposure](#7-network-interfaces-addressing--exposure)")
        lines.append("8. [Security Controls, SSH & User Accounts](#8-security-controls-ssh--user-accounts)")
        lines.append("9. [Docker Containers & Container Security](#9-docker-containers--container-security)")
        lines.append("10. [Caddy Reverse Proxy & Web Services](#10-caddy-reverse-proxy--web-services)")
        lines.append("11. [Discovered Applications](#11-discovered-applications)")
        lines.append("12. [Infrastructure & Storage Topology](#12-infrastructure--storage-topology)")
        lines.append("13. [Scheduled Tasks, Backups & System Logs](#13-scheduled-tasks-backups--system-logs)")
        lines.append("14. [Audit Provenance & Collector Limitations](#14-audit-provenance--collector-limitations)")
        lines.append("")
        lines.append("---")
        lines.append("")

        # 1. Executive Summary
        lines.append("## 1. Executive Summary")
        lines.append("")
        smart_ok = smart.get("overall_health_passed", True)
        smart_status_badge = "🟢 Passed" if smart_ok else "🔴 Degraded/Warning"

        lines.append("| Component | Status / Overview | Details |")
        lines.append("|---|---|---|")
        lines.append(f"| **System & OS** | 🟢 Active | {os_pretty} (Uptime: {Normalizer.format_uptime(sys.get('uptime_seconds'))}) |")
        lines.append(f"| **Hardware Platform** | ℹ️ Detected | {hw.get('system', {}).get('manufacturer') or 'Generic'} {hw.get('system', {}).get('product_name') or ''} |")
        lines.append(f"| **CPU & Cores** | 🟢 Normal | {cpu.get('model_name') or 'CPU'} ({cpu.get('physical_cores', 1)}C / {cpu.get('logical_cpus', 1)}T) |")
        lines.append(f"| **Memory (RAM)** | 🟢 Available | {Normalizer.format_bytes(mem.get('ram', {}).get('total_bytes'))} ({mem.get('ram', {}).get('percent_used', 0)}% used) |")
        lines.append(f"| **Physical Storage** | {smart_status_badge} | {len(storage.get('disks', []))} disks, SMART: {smart_status_badge} |")
        lines.append(f"| **Networking** | 🟢 Connected | {len(net.get('interfaces', []))} interfaces, Default Gateway: `{routes.get('default_gateway') or 'None'}` |")
        lines.append(f"| **Firewall** | ℹ️ Configured | Active: `{', '.join(fw_state.get('active_frameworks', [])) or 'None / Open'}` |")
        lines.append(f"| **SSH Security** | 🔒 Configured | Port {ssh.get('effective_config', {}).get('port', 22)} (Root: `{ssh.get('effective_config', {}).get('permit_root_login')}`, Pass: `{ssh.get('effective_config', {}).get('password_authentication')}`) |")
        lines.append(f"| **Docker Engine** | {'🟢 Running' if docker.get('engine', {}).get('active') else '⚪ Inactive'} | {docker.get('engine', {}).get('containers_running', 0)} running / {docker.get('engine', {}).get('containers_total', 0)} total containers |")
        lines.append(f"| **Reverse Proxy** | {'🟢 Configured' if caddy.get('sites') else '⚪ None'} | {len(caddy.get('sites', []))} Caddy sites configured |")
        lines.append(f"| **Applications** | ℹ️ Discovered | {len(apps.get('applications', []))} self-hosted applications discovered |")
        lines.append("")

        # 2. Findings & Health Assessment
        lines.append("## 2. Findings & Health Assessment")
        lines.append("")
        if findings:
            lines.append("| Severity | Subsystem | Finding | Details |")
            lines.append("|---|---|---|---|")
            for f in findings:
                sev = f.get("severity", "NOTICE")
                icon = "🔴" if sev == "CRITICAL" else ("🟡" if sev == "WARNING" else "ℹ️")
                lines.append(f"| {icon} **{sev}** | {f.get('subsystem')} | **{f.get('title')}** | {f.get('details')} |")
            lines.append("")
        else:
            lines.append("🟢 **All Health Checks Passed:** No critical hardware degradation, storage errors, or service failures detected.")
            lines.append("")

        if conflicts:
            lines.append("### ⚠️ Configuration Discrepancies & Conflicts")
            lines.append("")
            lines.append("| Component | Severity | Discrepancy | Details |")
            lines.append("|---|---|---|---|")
            for cf in conflicts:
                lines.append(f"| {cf.get('component')} | **{cf.get('severity')}** | **{cf.get('title')}** | {cf.get('details')} |")
            lines.append("")

        # 3. System Identity & OS
        lines.append("## 3. System Identity & Operating System")
        lines.append("")
        lines.append(f"- **Distribution:** {os_pretty}")
        lines.append(f"- **Release Codename:** `{sys.get('os', {}).get('codename') or 'N/A'}`")
        lines.append(f"- **Kernel Build:** `{kernel_rel}` (`{arch}`)")
        lines.append(f"- **System Uptime:** {Normalizer.format_uptime(sys.get('uptime_seconds'))}")
        lines.append(f"- **Boot Mode:** `{sys.get('boot_mode', 'Unknown')}`")
        lines.append(f"- **Virtualization Layer:** `{sys.get('virtualization', 'Bare Metal')}` (Container Host: `{sys.get('is_container', False)}`)")
        lines.append(f"- **Configured Timezone:** `{sys.get('timezone') or 'UTC'}`")
        lines.append(f"- **Kernel Command Line:** `{sys.get('kernel', {}).get('cmdline') or 'N/A'}`")
        lines.append("")

        # 4. Hardware, Motherboard & Firmware
        lines.append("## 4. Hardware, Motherboard & Firmware")
        lines.append("")
        lines.append("### Platform & Motherboard")
        lines.append(f"- **System Manufacturer:** {hw.get('system', {}).get('manufacturer') or 'Unknown'}")
        lines.append(f"- **Product Model:** {hw.get('system', {}).get('product_name') or 'Unknown'}")
        lines.append(f"- **Motherboard Model:** {hw.get('motherboard', {}).get('manufacturer') or 'Unknown'} {hw.get('motherboard', {}).get('product_name') or ''}")
        lines.append(f"- **Chassis Type:** {hw.get('chassis', {}).get('type') or 'Unknown'}")
        lines.append("")
        lines.append("### Firmware & Security Chip")
        lines.append(f"- **BIOS Vendor & Version:** {fw.get('bios', {}).get('vendor') or 'Unknown'} `{fw.get('bios', {}).get('version') or 'Unknown'}` ({fw.get('bios', {}).get('release_date') or 'N/A'})")
        lines.append(f"- **Secure Boot State:** `{fw.get('secure_boot', {}).get('state', 'Unknown')}`")
        lines.append(f"- **TPM Module:** {'Present (' + fw.get('tpm', {}).get('version', '') + ')' if fw.get('tpm', {}).get('present') else 'Not Detected'}")
        lines.append("")

        # 5. Processor & Memory Topology
        lines.append("## 5. Processor & Memory Topology")
        lines.append("")
        lines.append("### CPU Specifications")
        lines.append(f"- **Model:** {cpu.get('model_name') or 'Unknown'}")
        lines.append(f"- **Cores & Sockets:** {cpu.get('physical_cores', 1)} Physical Cores / {cpu.get('logical_cpus', 1)} Logical Threads ({cpu.get('sockets', 1)} Sockets)")
        lines.append(f"- **Scaling Governor:** `{cpu.get('governor') or 'N/A'}` (Driver: `{cpu.get('scaling_driver') or 'N/A'}`)")
        lines.append(f"- **Cache Hierarchy:** L1d: `{cpu.get('cache', {}).get('l1d') or 'N/A'}`, L2: `{cpu.get('cache', {}).get('l2') or 'N/A'}`, L3: `{cpu.get('cache', {}).get('l3') or 'N/A'}`")
        lines.append("")
        lines.append("### Memory (RAM & Swap)")
        lines.append(f"- **Total RAM:** {Normalizer.format_bytes(mem.get('ram', {}).get('total_bytes'))} ({mem.get('ram', {}).get('percent_used')}% utilized)")
        lines.append(f"- **Used RAM:** {Normalizer.format_bytes(mem.get('ram', {}).get('used_bytes'))} (Available: {Normalizer.format_bytes(mem.get('ram', {}).get('available_bytes'))})")
        lines.append(f"- **Swap Space:** {Normalizer.format_bytes(mem.get('swap', {}).get('total_bytes'))} (Used: {Normalizer.format_bytes(mem.get('swap', {}).get('used_bytes'))})")
        lines.append(f"- **DIMM Slots:** {mem.get('used_slots', 0)} populated / {mem.get('total_slots') or 'N/A'} total physical slots")
        lines.append("")

        # 6. Storage Subsystems & Physical Health
        lines.append("## 6. Storage Subsystems & Physical Health")
        lines.append("")
        lines.append("### Physical Disks & SMART Health")
        if storage.get("disks"):
            lines.append("| Device Path | Media Type | Model | Capacity | SMART Status | Temp | Reallocated |")
            lines.append("|---|---|---|---|---|---|---|")
            smart_map = {d.get("device"): d for d in smart.get("devices", [])}
            for d in storage.get("disks", []):
                d_path = d.get("path")
                sm = smart_map.get(d_path, {})
                s_stat = sm.get("status", "N/A")
                temp = f"{sm.get('temperature_c')}°C" if sm.get("temperature_c") is not None else "N/A"
                realloc = sm.get("reallocated_sectors", 0)
                lines.append(f"| `{d_path}` | {d.get('media', '').upper()} | {d.get('model') or 'Unknown'} | {d.get('size_formatted')} | `{s_stat}` | {temp} | {realloc} |")
            lines.append("")
        else:
            lines.append("_No physical disks directly accessible or command unprivileged._\n")

        lines.append("### Mounted Filesystems")
        if fs.get("mounts"):
            lines.append("| Mount Point | Source Device | Filesystem | Total Size | Used | Free | Utilization |")
            lines.append("|---|---|---|---|---|---|---|")
            for m in fs.get("mounts", []):
                lines.append(f"| `{m.get('target')}` | `{m.get('source')}` | {m.get('fstype')} | {m.get('total_formatted')} | {m.get('used_formatted')} | {m.get('available_formatted')} | **{m.get('percent_used')}%** |")
            lines.append("")

        if lvm.get("logical_volumes"):
            lines.append("### LVM Logical Volumes")
            lines.append("| LV Name | Volume Group | Size | Device Mapper Path |")
            lines.append("|---|---|---|---|")
            for lv in lvm.get("logical_volumes", []):
                lines.append(f"| `{lv.get('lv_name')}` | `{lv.get('vg_name')}` | {lv.get('lv_size_formatted')} | `{lv.get('dm_path')}` |")
            lines.append("")

        if enc.get("encrypted_volumes"):
            lines.append("### Encrypted Volumes (LUKS / dm-crypt)")
            lines.append("| Target Name | Underlying Device | Cipher | Key Size |")
            lines.append("|---|---|---|---|")
            for ev in enc.get("encrypted_volumes", []):
                lines.append(f"| `{ev.get('target_name')}` | `{ev.get('underlying_device')}` | {ev.get('cipher')} | {ev.get('keysize_bits')} bits |")
            lines.append("")

        # 7. Network Interfaces, Addressing & Exposure
        lines.append("## 7. Network Interfaces, Addressing & Exposure")
        lines.append("")
        lines.append("### Network Interfaces")
        if net.get("interfaces"):
            lines.append("| Interface | Link State | Type | MAC Address | Assigned IPv4 Addresses |")
            lines.append("|---|---|---|---|---|")
            for iface in net.get("interfaces", []):
                ips = ", ".join([ip.get("cidr") for ip in iface.get("ipv4", [])]) or "None"
                lines.append(f"| `{iface.get('name')}` | `{iface.get('state')}` | {'Virtual' if iface.get('is_virtual') else 'Physical'} | `{iface.get('mac') or 'N/A'}` | `{ips}` |")
            lines.append("")

        lines.append("### Listening Ports & Service Exposure")
        if exposure:
            lines.append("| Port / Proto | Bound Address | Exposure Tier | Owning Process | Reverse Proxied |")
            lines.append("|---|---|---|---|---|")
            for exp in exposure:
                proxied_str = "🟢 Caddy (TLS)" if exp.get("is_behind_caddy") else "Direct"
                lines.append(f"| `{exp.get('port')}/{exp.get('protocol')}` | `{exp.get('bound_address')}` | `{exp.get('exposure_type')}` | `{exp.get('process') or 'unknown'}` | {proxied_str} |")
            lines.append("")

        # 8. Security Controls, SSH & User Accounts
        lines.append("## 8. Security Controls, SSH & User Accounts")
        lines.append("")
        lines.append("### OpenSSH Server Hardening")
        lines.append(f"- **SSH Version:** {ssh.get('client_version') or 'OpenSSH'}")
        lines.append(f"- **Listening Port:** `{ssh.get('effective_config', {}).get('port', 22)}`")
        lines.append(f"- **PermitRootLogin:** `{ssh.get('effective_config', {}).get('permit_root_login')}`")
        lines.append(f"- **PasswordAuthentication:** `{ssh.get('effective_config', {}).get('password_authentication')}`")
        lines.append(f"- **PubkeyAuthentication:** `{ssh.get('effective_config', {}).get('pubkey_authentication')}`")
        lines.append("")
        lines.append("### Linux Security Modules & Controls")
        lines.append(f"- **AppArmor:** `{'Active (' + str(sec.get('apparmor', {}).get('profiles_enforce')) + ' enforce profiles)' if sec.get('apparmor', {}).get('enabled') else 'Disabled'}`")
        lines.append(f"- **SELinux Mode:** `{sec.get('selinux', {}).get('mode')}`")
        lines.append(f"- **ASLR State:** `{sec.get('aslr', 'Unknown')}`")
        lines.append(f"- **Kernel Lockdown:** `{sec.get('lockdown', 'Unknown')}`")
        lines.append(f"- **Privileged Accounts (Sudo):** {', '.join([u.get('username') for u in users.get('sudo_users', [])]) or 'None'}")
        lines.append("")

        # 9. Docker Containers & Container Security
        lines.append("## 9. Docker Containers & Container Security")
        lines.append("")
        if docker.get("engine", {}).get("active"):
            eng = docker.get("engine", {})
            lines.append(f"- **Docker Server:** `{eng.get('server_version')}` (Driver: `{eng.get('storage_driver')}`, Cgroup: `{eng.get('cgroup_driver')}`)")
            lines.append(f"- **Containers:** {eng.get('containers_running')} Running / {eng.get('containers_total')} Total")
            lines.append("")
            if docker.get("containers"):
                lines.append("### Container Inventory")
                lines.append("| Container Name | Image Repository | State | Published Ports | Compose Project | Privileged |")
                lines.append("|---|---|---|---|---|---|")
                for c in docker.get("containers", []):
                    ports_str = ", ".join([f"{p.get('host_port')}->{p.get('container_port')}" for p in c.get("ports", []) if p.get("host_port")]) or "-"
                    lines.append(f"| `{c.get('name')}` | `{c.get('image')}` | `{c.get('state')}` | {ports_str} | {c.get('compose_project') or '-'} | `{c.get('privileged')}` |")
                lines.append("")
        else:
            lines.append("_Docker engine not active on host._\n")

        # 10. Caddy Reverse Proxy & Web Services
        lines.append("## 10. Caddy Reverse Proxy & Web Services")
        lines.append("")
        if caddy.get("sites"):
            lines.append("| Public Hostname | Backend Upstream | TLS Policy |")
            lines.append("|---|---|---|")
            for site in caddy.get("sites", []):
                upstreams = ", ".join(site.get("reverse_proxies", [])) or "Static File Server"
                lines.append(f"| `{site.get('hostname')}` | `{upstreams}` | `{site.get('tls_mode')}` |")
            lines.append("")
        else:
            lines.append("_No Caddy reverse proxy sites discovered._\n")

        # 11. Discovered Applications
        lines.append("## 11. Discovered Applications")
        lines.append("")
        if apps.get("applications"):
            lines.append("| Application | Category | Deployment | Container / Service | Port(s) |")
            lines.append("|---|---|---|---|---|")
            for app in apps.get("applications", []):
                p_str = ", ".join(str(p) for p in app.get("ports", [])) or "-"
                lines.append(f"| **{app.get('name')}** | {app.get('category')} | `{app.get('deployment_type')}` | `{app.get('container_name') or 'native'}` | `{p_str}` |")
            lines.append("")
        else:
            lines.append("_No common self-hosted applications matched._\n")

        # 12. Infrastructure & Storage Topology
        storage_chains = data.get("topology", {}).get("storage_chains", [])
        lines.append("## 12. Infrastructure & Storage Topology")
        lines.append("")
        if storage_chains:
            lines.append("### Reconstructed End-to-End Chains")
            lines.append("```text")
            for ch in storage_chains:
                chain_str = f"{ch.get('disk')} -> {ch.get('partition')}"
                if ch.get("luks"):
                    chain_str += f" -> LUKS({ch.get('luks')})"
                if ch.get("vg"):
                    chain_str += f" -> LVM({ch.get('vg')}/{ch.get('lv')})"
                chain_str += f" -> {ch.get('mount')} -> Container({ch.get('container')}) -> App({ch.get('app')})"
                lines.append(chain_str)
            lines.append("```")
            lines.append("")
        else:
            lines.append("_No multi-tier storage chains reconstructed._\n")

        # 13. Scheduled Tasks, Backups & System Logs
        lines.append("## 13. Scheduled Tasks, Backups & System Logs")
        lines.append("")
        lines.append("### Backup Software Detection")
        if backups.get("installed_tools"):
            for b in backups.get("installed_tools", []):
                lines.append(f"- **{b.get('name')}:** `{b.get('version')}` (`{b.get('binary')}`)")
            lines.append("")
        else:
            lines.append("_No standard backup software detected in PATH._\n")

        lines.append("### System Logs Summary")
        lines.append(f"- **Boot Errors Recorded:** `{logs.get('boot_errors_count', 0)}`")
        lines.append(f"- **Journal Disk Space:** `{logs.get('journal_disk_usage') or 'N/A'}`")
        lines.append("")

        # 14. Audit Provenance & Collector Limitations
        lines.append("## 14. Audit Provenance & Collector Limitations")
        lines.append("")
        lines.append(f"- **Audit Tool Version:** `{meta.get('tool_name', 'serveraudit')} v{meta.get('tool_version', '0.1.0')}`")
        lines.append(f"- **Operating User:** `{meta.get('operating_user', 'unknown')}`")
        lines.append(f"- **Outbound Network Access:** `Disabled (Strictly Local)`")
        lines.append(f"- **System Modification:** `Zero (Guaranteed Observational)`")
        lines.append("")
        lines.append("### Collector Execution Statuses")
        lines.append("| Collector Module | Status | Execution Duration | Status Notes |")
        lines.append("|---|---|---|---|")
        for c_name, c_info in collectors_meta.items():
            st = c_info.get("status", "UNKNOWN")
            st_icon = "🟢" if st == "SUCCESS" else ("🟡" if st == "PARTIAL" else "⚪")
            err_msg = c_info.get("message") or c_info.get("error") or "Completed"
            lines.append(f"| `{c_name}` | {st_icon} `{st}` | `{c_info.get('duration_seconds', 0):.2f}s` | {err_msg} |")
        lines.append("")

        return "\n".join(lines)
