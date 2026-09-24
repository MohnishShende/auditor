"""Generate realistic synthetic demo files for examples/"""
import json
import os
from serveraudit.renderers.markdown import MarkdownRenderer
from serveraudit.renderers.json import JsonRenderer
from serveraudit.renderers.html import HtmlRenderer

sample_audit_data = {
    "metadata": {
        "hostname": "srv-prod-node01.infra.internal",
        "timestamp": "2026-09-24T05:30:00Z",
        "tool_name": "serveraudit",
        "tool_version": "0.1.0",
        "profile": "public",
        "duration_seconds": 3.84,
        "privileges_available": True,
        "operating_user": "audit-operator",
        "platform": "Linux 6.8.0-45-generic x86_64"
    },
    "system": {
        "hostname": "srv-prod-node01.infra.internal",
        "fqdn": "srv-prod-node01.infra.internal",
        "os": {
            "name": "Ubuntu",
            "version": "24.04.1 LTS",
            "pretty_name": "Ubuntu 24.04.1 LTS (Noble Numbat)",
            "id": "ubuntu",
            "version_id": "24.04"
        },
        "kernel": {
            "release": "6.8.0-45-generic",
            "version": "#45-Ubuntu SMP PREEMPT_DYNAMIC",
            "architecture": "x86_64"
        },
        "uptime_seconds": 3680580,
        "boot_time": "2026-08-12T15:06:37Z",
        "virtualization": "none (bare-metal)",
        "timezone": "UTC"
    },
    "hardware": {
        "system": {
            "manufacturer": "Supermicro",
            "product_name": "SYS-5019P-MT",
            "serial_number": "[REDACTED_SERIAL]",
            "chassis": "Rack Mount"
        },
        "motherboard": {
            "manufacturer": "Supermicro",
            "product_name": "X11SPM-TPF",
            "version": "1.02",
            "serial_number": "[REDACTED_SERIAL]"
        },
        "bios": {
            "vendor": "American Megatrends Inc.",
            "version": "3.4b",
            "release_date": "2024-03-15",
            "uefi": True
        }
    },
    "cpu": {
        "model_name": "Intel(R) Xeon(R) E-2288G CPU @ 3.50GHz",
        "sockets": 1,
        "physical_cores": 8,
        "logical_cpus": 16,
        "base_clock_mhz": 3500.0,
        "max_clock_mhz": 5000.0,
        "flags": ["fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce", "cx8", "apic", "sep", "mtrr", "pge", "mca", "cmov", "pat", "pse36", "clflush", "dts", "acpi", "mmx", "fxsr", "sse", "sse2", "ss", "ht", "tm", "pbe", "syscall", "nx", "pdpe1gb", "rdtscp", "lm", "constant_tsc", "art", "arch_perfmon", "pebs", "bts", "rep_good", "nopl", "xtopology", "nonstop_tsc", "cpuid", "aperfmperf", "pni", "pclmulqdq", "dtes64", "monitor", "ds_cpl", "vmx", "smx", "est", "tm2", "ssse3", "sdbg", "fma", "cx16", "xtpr", "pdcm", "pcid", "sse4_1", "sse4_2", "x2apic", "movbe", "popcnt", "tsc_deadline_timer", "aes", "xsave", "avx", "f16c", "rdrand", "hypervisor", "lahf_lm", "abm", "3dnowprefetch", "cpuid_fault", "epb", "invpcid_single", "pti", "ssbd", "ibrs", "ibpb", "stibp", "tpr_shadow", "vnmi", "flexpriority", "ept", "vpid", "fsgsbase", "tsc_adjust", "bmi1", "hle", "avx2", "smep", "bmi2", "erms", "invpcid", "rtm", "mpx", "rdseed", "adx", "smap", "clflushopt", "intel_pt", "xsaveopt", "xsavec", "xgetbv1", "xsaves", "dtherm", "ida", "arat", "pln", "pts", "hwp", "hwp_notify", "hwp_act_window", "hwp_epp", "md_clear", "flush_l1d", "arch_capabilities"],
        "vulnerabilities": {
            "spectre_v1": "Mitigation: usercopy/swapgs barriers and __user pointer sanitization",
            "spectre_v2": "Mitigation: Enhanced / Automatic IBRS; IBPB: conditional; RSB filling; PBRSB-eIBRS: SW sequence; BHI: SW loop, KVM: SW loop",
            "meltdown": "Not affected",
            "mds": "Not affected",
            "retbleed": "Mitigation: Enhanced IBRS"
        }
    },
    "memory": {
        "ram": {
            "total_bytes": 67420413952,
            "total_formatted": "62.8 GB",
            "used_bytes": 28437184512,
            "used_formatted": "26.5 GB",
            "free_bytes": 38983229440,
            "free_formatted": "36.3 GB",
            "percent_used": 42.18
        },
        "swap": {
            "total_bytes": 17179869184,
            "total_formatted": "16.0 GB",
            "used_bytes": 0,
            "used_formatted": "0 B",
            "free_bytes": 17179869184,
            "free_formatted": "16.0 GB",
            "percent_used": 0.0
        },
        "ecc_supported": True,
        "dimm_slots": 4,
        "dimms_populated": 2
    },
    "storage": {
        "disks": [
            {"path": "/dev/nvme0n1", "media": "nvme", "size_formatted": "1.90 TB", "model": "Samsung SSD 980 PRO 2TB", "serial": "[REDACTED_SERIAL]", "transport": "nvme", "rotational": False},
            {"path": "/dev/nvme1n1", "media": "nvme", "size_formatted": "1.90 TB", "model": "Samsung SSD 980 PRO 2TB", "serial": "[REDACTED_SERIAL]", "transport": "nvme", "rotational": False},
            {"path": "/dev/sda", "media": "hdd", "size_formatted": "18.20 TB", "model": "WDC WD181KFGX-68AFPN0", "serial": "[REDACTED_SERIAL]", "transport": "sata", "rotational": True},
            {"path": "/dev/sdb", "media": "hdd", "size_formatted": "18.20 TB", "model": "WDC WD181KFGX-68AFPN0", "serial": "[REDACTED_SERIAL]", "transport": "sata", "rotational": True}
        ],
        "partitions": [
            {"device": "/dev/nvme0n1p1", "size": "1.0 GB", "type": "vfat", "mount": "/boot/efi"},
            {"device": "/dev/nvme0n1p2", "size": "1.9 TB", "type": "linux_raid_member"},
            {"device": "/dev/nvme1n1p2", "size": "1.9 TB", "type": "linux_raid_member"},
            {"device": "/dev/sda1", "size": "18.2 TB", "type": "linux_raid_member"},
            {"device": "/dev/sdb1", "size": "18.2 TB", "type": "linux_raid_member"}
        ],
        "filesystems": [
            {"mount": "/", "device": "/dev/mapper/vg_system-lv_root", "fstype": "ext4", "total_formatted": "98.0 GB", "used_formatted": "24.0 GB", "free_formatted": "70.0 GB", "percent_used": 26},
            {"mount": "/var", "device": "/dev/mapper/vg_system-lv_var", "fstype": "ext4", "total_formatted": "492.0 GB", "used_formatted": "112.0 GB", "free_formatted": "358.0 GB", "percent_used": 24},
            {"mount": "/mnt/media", "device": "/dev/mapper/vg_data-lv_media", "fstype": "xfs", "total_formatted": "15.9 TB", "used_formatted": "8.4 TB", "free_formatted": "7.5 TB", "percent_used": 53}
        ]
    },
    "smart": {
        "overall_health_passed": True,
        "devices": [
            {"device": "/dev/nvme0n1", "health": "PASSED", "temperature_c": 36, "power_on_hours": 11200, "critical_warning": 0, "available_spare_percent": 100},
            {"device": "/dev/nvme1n1", "health": "PASSED", "temperature_c": 37, "power_on_hours": 11200, "critical_warning": 0, "available_spare_percent": 100},
            {"device": "/dev/sda", "health": "PASSED", "temperature_c": 32, "power_on_hours": 18450, "reallocated_sectors": 0, "pending_sectors": 0},
            {"device": "/dev/sdb", "health": "PASSED", "temperature_c": 33, "power_on_hours": 18450, "reallocated_sectors": 0, "pending_sectors": 0}
        ]
    },
    "network": {
        "interfaces": [
            {"name": "eno1", "state": "UP", "is_virtual": False, "mac": "[REDACTED_MAC]", "mtu": 1500, "speed_mbps": 1000, "ipv4": [{"cidr": "10.0.10.15/24"}], "ipv6": [{"cidr": "fe80::1/64"}]},
            {"name": "wg0", "state": "UP", "is_virtual": True, "mac": None, "mtu": 1420, "ipv4": [{"cidr": "10.8.0.1/24"}], "ipv6": []}
        ],
        "routes": [
            {"destination": "default", "gateway": "10.0.10.1", "interface": "eno1", "metric": 100},
            {"destination": "10.0.10.0/24", "gateway": "0.0.0.0", "interface": "eno1", "metric": 100}
        ],
        "dns": {
            "nameservers": ["10.0.10.1", "1.1.1.1"],
            "search_domains": ["infra.internal"],
            "systemd_resolved": True
        },
        "firewall": {
            "system": "ufw",
            "active": True,
            "default_incoming": "deny",
            "default_outgoing": "allow",
            "rules": [
                {"action": "allow", "port": "22/tcp", "comment": "SSH restricted"},
                {"action": "allow", "port": "80/tcp", "comment": "HTTP Caddy"},
                {"action": "allow", "port": "443/tcp", "comment": "HTTPS Caddy"}
            ]
        }
    },
    "ports": {
        "listening_ports": [
            {"protocol": "tcp", "bind_address": "0.0.0.0", "port": 22, "process": "sshd", "pid": 892},
            {"protocol": "tcp", "bind_address": "0.0.0.0", "port": 80, "process": "caddy", "pid": 1420},
            {"protocol": "tcp", "bind_address": "0.0.0.0", "port": 443, "process": "caddy", "pid": 1420},
            {"protocol": "tcp", "bind_address": "127.0.0.1", "port": 5432, "process": "postgres", "pid": 1650},
            {"protocol": "tcp", "bind_address": "127.0.0.1", "port": 6379, "process": "redis-server", "pid": 1690},
            {"protocol": "tcp", "bind_address": "10.0.10.15", "port": 8096, "process": "jellyfin", "pid": 2105}
        ]
    },
    "ssh": {
        "client_version": "OpenSSH_9.6p1 Ubuntu-3ubuntu13.4",
        "effective_config": {
            "permit_root_login": "prohibit-password",
            "password_authentication": "no",
            "pubkey_authentication": "yes",
            "port": 22,
            "x11_forwarding": "no"
        }
    },
    "users": {
        "users": [
            {"username": "root", "uid": 0, "gid": 0, "shell": "/bin/bash", "has_password": True, "sudoer": True},
            {"username": "admin", "uid": 1000, "gid": 1000, "shell": "/bin/bash", "has_password": True, "sudoer": True},
            {"username": "caddy", "uid": 998, "gid": 998, "shell": "/usr/sbin/nologin", "has_password": False, "sudoer": False}
        ],
        "sudo_users": [
            {"username": "root"},
            {"username": "admin"}
        ]
    },
    "security": {
        "apparmor": {
            "enabled": True,
            "profiles_loaded": 68,
            "profiles_enforce": 68
        },
        "selinux": {
            "mode": "disabled"
        },
        "aslr": "Full Randomization (2)",
        "lockdown": "none",
        "fail2ban": {
            "active": True,
            "jails": ["sshd"],
            "banned_ips": 4
        }
    },
    "docker": {
        "engine": {
            "active": True,
            "server_version": "27.2.0",
            "storage_driver": "overlay2",
            "cgroup_driver": "systemd",
            "containers_running": 5,
            "containers_total": 5
        },
        "containers": [
            {"name": "jellyfin", "image": "jellyfin/jellyfin:latest", "state": "running", "ports": [{"host_port": 8096, "container_port": 8096}], "compose_project": "media", "privileged": False},
            {"name": "paperless-ngx", "image": "ghcr.io/paperless-ngx/paperless-ngx:latest", "state": "running", "ports": [{"host_port": 8000, "container_port": 8000}], "compose_project": "docs", "privileged": False},
            {"name": "pihole", "image": "pihole/pihole:latest", "state": "running", "ports": [{"host_port": 53, "container_port": 53}], "compose_project": "dns", "privileged": False},
            {"name": "searxng", "image": "searxng/searxng:latest", "state": "running", "ports": [{"host_port": 8080, "container_port": 8080}], "compose_project": "search", "privileged": False},
            {"name": "redis", "image": "redis:7-alpine", "state": "running", "ports": [{"host_port": 6379, "container_port": 6379}], "compose_project": "docs", "privileged": False}
        ]
    },
    "caddy": {
        "sites": [
            {"hostname": "media.example.com", "reverse_proxies": ["http://127.0.0.1:8096"], "tls_mode": "Automated Let's Encrypt"},
            {"hostname": "docs.example.com", "reverse_proxies": ["http://127.0.0.1:8000"], "tls_mode": "Automated Let's Encrypt"}
        ]
    },
    "applications": {
        "applications": [
            {"name": "Jellyfin", "category": "Media Server", "deployment_type": "Docker", "container_name": "jellyfin", "ports": [8096]},
            {"name": "Paperless-ngx", "category": "Document Management", "deployment_type": "Docker", "container_name": "paperless-ngx", "ports": [8000]},
            {"name": "Pi-hole", "category": "DNS & Ad Blocking", "deployment_type": "Docker", "container_name": "pihole", "ports": [53]},
            {"name": "PostgreSQL", "category": "Database", "deployment_type": "Native Systemd", "container_name": None, "ports": [5432]},
            {"name": "Redis", "category": "In-Memory Cache", "deployment_type": "Docker", "container_name": "redis", "ports": [6379]}
        ]
    },
    "topology": {
        "storage_chains": [
            {
                "disk": "/dev/nvme0n1",
                "partition": "/dev/nvme0n1p2",
                "luks": None,
                "vg": "vg_system",
                "lv": "lv_root",
                "mount": "/",
                "container": None,
                "app": "OS Root"
            },
            {
                "disk": "/dev/sda",
                "partition": "/dev/sda1",
                "luks": "cryptdata",
                "vg": "vg_data",
                "lv": "lv_media",
                "mount": "/mnt/media",
                "container": "jellyfin",
                "app": "Jellyfin Media Library"
            }
        ]
    },
    "scheduled": {
        "cron_jobs": [
            {"schedule": "0 3 * * *", "user": "root", "command": "/usr/local/bin/backup-postgres.sh"}
        ],
        "systemd_timers": [
            {"timer": "apt-daily.timer", "next_trigger": "2026-09-24T06:00:00Z", "service": "apt-daily.service"},
            {"timer": "fstrim.timer", "next_trigger": "2026-09-28T00:00:00Z", "service": "fstrim.service"}
        ]
    },
    "backups": {
        "installed_tools": [
            {"name": "restic", "version": "0.16.4", "binary": "/usr/bin/restic"},
            {"name": "rsync", "version": "3.2.7", "binary": "/usr/bin/rsync"}
        ]
    },
    "logs": {
        "boot_errors_count": 0,
        "journal_disk_usage": "1.2 GB"
    },
    "thermal": {
        "cpu_temp_c": 38.0,
        "throttling_detected": False
    },
    "power": {
        "governor": "performance",
        "energy_perf_profile": "performance"
    },
    "boot": {
        "secure_boot": True,
        "boot_mode": "UEFI"
    },
    "sharing": {
        "nfs_exports": [],
        "samba_shares": []
    },
    "collectors": {
        "system": {"status": "SUCCESS", "duration_seconds": 0.02},
        "hardware": {"status": "SUCCESS", "duration_seconds": 0.04},
        "cpu": {"status": "SUCCESS", "duration_seconds": 0.01},
        "memory": {"status": "SUCCESS", "duration_seconds": 0.01},
        "storage": {"status": "SUCCESS", "duration_seconds": 0.05},
        "smart": {"status": "SUCCESS", "duration_seconds": 0.12},
        "network": {"status": "SUCCESS", "duration_seconds": 0.03},
        "ports": {"status": "SUCCESS", "duration_seconds": 0.02},
        "ssh": {"status": "SUCCESS", "duration_seconds": 0.02},
        "users": {"status": "SUCCESS", "duration_seconds": 0.03},
        "security": {"status": "SUCCESS", "duration_seconds": 0.04},
        "docker": {"status": "SUCCESS", "duration_seconds": 0.08},
        "caddy": {"status": "SUCCESS", "duration_seconds": 0.03},
        "applications": {"status": "SUCCESS", "duration_seconds": 0.05},
        "scheduled": {"status": "SUCCESS", "duration_seconds": 0.02},
        "backups": {"status": "SUCCESS", "duration_seconds": 0.02},
        "logs": {"status": "SUCCESS", "duration_seconds": 0.03},
        "thermal": {"status": "SUCCESS", "duration_seconds": 0.01},
        "power": {"status": "SUCCESS", "duration_seconds": 0.01},
        "boot": {"status": "SUCCESS", "duration_seconds": 0.01},
        "sharing": {"status": "SUCCESS", "duration_seconds": 0.01}
    },
    "analysis": {
        "health": [
            {"component": "SSH Security", "status": "OK", "message": "Password authentication is disabled and root login requires SSH keys."},
            {"component": "Storage Health", "status": "OK", "message": "All RAID arrays (md0, md1) are healthy and NVMe/SATA SMART diagnostics report 0 defects."},
            {"component": "Firewall", "status": "OK", "message": "UFW active with default inbound DROP policy."}
        ],
        "exposure": [
            {"port": 22, "protocol": "tcp", "bound_address": "0.0.0.0", "exposure_type": "Public (All Interfaces)", "process": "sshd", "is_behind_caddy": False},
            {"port": 80, "protocol": "tcp", "bound_address": "0.0.0.0", "exposure_type": "Public (All Interfaces)", "process": "caddy", "is_behind_caddy": False},
            {"port": 443, "protocol": "tcp", "bound_address": "0.0.0.0", "exposure_type": "Public (All Interfaces)", "process": "caddy", "is_behind_caddy": False},
            {"port": 8096, "protocol": "tcp", "bound_address": "10.0.10.15", "exposure_type": "Internal LAN Only", "process": "jellyfin", "is_behind_caddy": True},
            {"port": 5432, "protocol": "tcp", "bound_address": "127.0.0.1", "exposure_type": "Localhost Only", "process": "postgres", "is_behind_caddy": False},
            {"port": 6379, "protocol": "tcp", "bound_address": "127.0.0.1", "exposure_type": "Localhost Only", "process": "redis-server", "is_behind_caddy": False}
        ],
        "conflicts": []
    }
}

os.makedirs("examples", exist_ok=True)

# Write audit.json
with open("examples/audit.json", "w", encoding="utf-8") as f:
    json.dump(sample_audit_data, f, indent=2)

# Write audit.md
md_content = MarkdownRenderer.render(sample_audit_data)
with open("examples/audit.md", "w", encoding="utf-8") as f:
    f.write(md_content)

print("Generated examples/audit.json and examples/audit.md successfully!")
