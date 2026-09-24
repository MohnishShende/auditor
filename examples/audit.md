# Linux Server Audit: `srv-prod-node01.infra.internal`

> **Observational System State Snapshot & Infrastructure Documentation**

---

### 🏷️ Server Identity & Audit Metadata

- **Server Hostname:** `srv-prod-node01.infra.internal`
- **Operating System:** Ubuntu 24.04.1 LTS (Noble Numbat)
- **Linux Kernel:** `6.8.0-45-generic` (`x86_64`)
- **Audit Timestamp:** `2026-09-24T05:30:00Z`
- **Audit Profile:** `PUBLIC`
- **Execution Duration:** `3.84s`
- **Privilege Status:** `Sudo / Root Active`

---

## 📑 Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Findings & Health Assessment](#2-findings--health-assessment)
3. [System Identity & Operating System](#3-system-identity--operating-system)
4. [Hardware, Motherboard & Firmware](#4-hardware-motherboard--firmware)
5. [Processor & Memory Topology](#5-processor--memory-topology)
6. [Storage Subsystems & Physical Health](#6-storage-subsystems--physical-health)
7. [Network Interfaces, Addressing & Exposure](#7-network-interfaces-addressing--exposure)
8. [Security Controls, SSH & User Accounts](#8-security-controls-ssh--user-accounts)
9. [Docker Containers & Container Security](#9-docker-containers--container-security)
10. [Caddy Reverse Proxy & Web Services](#10-caddy-reverse-proxy--web-services)
11. [Discovered Applications](#11-discovered-applications)
12. [Infrastructure & Storage Topology](#12-infrastructure--storage-topology)
13. [Scheduled Tasks, Backups & System Logs](#13-scheduled-tasks-backups--system-logs)
14. [Audit Provenance & Collector Limitations](#14-audit-provenance--collector-limitations)

---

## 1. Executive Summary

| Component | Status / Overview | Details |
|---|---|---|
| **System & OS** | 🟢 Active | Ubuntu 24.04.1 LTS (Noble Numbat) (Uptime: 42 days, 14 hrs, 23 mins) |
| **Hardware Platform** | ℹ️ Detected | Supermicro SYS-5019P-MT |
| **CPU & Cores** | 🟢 Normal | Intel(R) Xeon(R) E-2288G CPU @ 3.50GHz (8C / 16T) |
| **Memory (RAM)** | 🟢 Available | 62.79 GB (42.18% used) |
| **Physical Storage** | 🟢 Passed | 4 disks, SMART: 🟢 Passed |
| **Networking** | 🟢 Connected | 2 interfaces, Default Gateway: `None` |
| **Firewall** | ℹ️ Configured | Active: `None / Open` |
| **SSH Security** | 🔒 Configured | Port 22 (Root: `prohibit-password`, Pass: `no`) |
| **Docker Engine** | 🟢 Running | 5 running / 5 total containers |
| **Reverse Proxy** | 🟢 Configured | 2 Caddy sites configured |
| **Applications** | ℹ️ Discovered | 5 self-hosted applications discovered |

## 2. Findings & Health Assessment

| Severity | Subsystem | Finding | Details |
|---|---|---|---|
| ℹ️ **NOTICE** | None | **None** | None |
| ℹ️ **NOTICE** | None | **None** | None |
| ℹ️ **NOTICE** | None | **None** | None |

## 3. System Identity & Operating System

- **Distribution:** Ubuntu 24.04.1 LTS (Noble Numbat)
- **Release Codename:** `N/A`
- **Kernel Build:** `6.8.0-45-generic` (`x86_64`)
- **System Uptime:** 42 days, 14 hrs, 23 mins
- **Boot Mode:** `Unknown`
- **Virtualization Layer:** `none (bare-metal)` (Container Host: `False`)
- **Configured Timezone:** `UTC`
- **Kernel Command Line:** `N/A`

## 4. Hardware, Motherboard & Firmware

### Platform & Motherboard
- **System Manufacturer:** Supermicro
- **Product Model:** SYS-5019P-MT
- **Motherboard Model:** Supermicro X11SPM-TPF
- **Chassis Type:** Unknown

### Firmware & Security Chip
- **BIOS Vendor & Version:** Unknown `Unknown` (N/A)
- **Secure Boot State:** `Unknown`
- **TPM Module:** Not Detected

## 5. Processor & Memory Topology

### CPU Specifications
- **Model:** Intel(R) Xeon(R) E-2288G CPU @ 3.50GHz
- **Cores & Sockets:** 8 Physical Cores / 16 Logical Threads (1 Sockets)
- **Scaling Governor:** `N/A` (Driver: `N/A`)
- **Cache Hierarchy:** L1d: `N/A`, L2: `N/A`, L3: `N/A`

### Memory (RAM & Swap)
- **Total RAM:** 62.79 GB (42.18% utilized)
- **Used RAM:** 26.48 GB (Available: N/A)
- **Swap Space:** 16.00 GB (Used: 0 B)
- **DIMM Slots:** 0 populated / N/A total physical slots

## 6. Storage Subsystems & Physical Health

### Physical Disks & SMART Health
| Device Path | Media Type | Model | Capacity | SMART Status | Temp | Reallocated |
|---|---|---|---|---|---|---|
| `/dev/nvme0n1` | NVME | Samsung SSD 980 PRO 2TB | 1.90 TB | `N/A` | 36°C | 0 |
| `/dev/nvme1n1` | NVME | Samsung SSD 980 PRO 2TB | 1.90 TB | `N/A` | 37°C | 0 |
| `/dev/sda` | HDD | WDC WD181KFGX-68AFPN0 | 18.20 TB | `N/A` | 32°C | 0 |
| `/dev/sdb` | HDD | WDC WD181KFGX-68AFPN0 | 18.20 TB | `N/A` | 33°C | 0 |

### Mounted Filesystems
## 7. Network Interfaces, Addressing & Exposure

### Network Interfaces
| Interface | Link State | Type | MAC Address | Assigned IPv4 Addresses |
|---|---|---|---|---|
| `eno1` | `UP` | Physical | `[REDACTED_MAC]` | `10.0.10.15/24` |
| `wg0` | `UP` | Virtual | `N/A` | `10.8.0.1/24` |

### Listening Ports & Service Exposure
| Port / Proto | Bound Address | Exposure Tier | Owning Process | Reverse Proxied |
|---|---|---|---|---|
| `22/tcp` | `0.0.0.0` | `Public (All Interfaces)` | `sshd` | Direct |
| `80/tcp` | `0.0.0.0` | `Public (All Interfaces)` | `caddy` | Direct |
| `443/tcp` | `0.0.0.0` | `Public (All Interfaces)` | `caddy` | Direct |
| `8096/tcp` | `10.0.10.15` | `Internal LAN Only` | `jellyfin` | 🟢 Caddy (TLS) |
| `5432/tcp` | `127.0.0.1` | `Localhost Only` | `postgres` | Direct |
| `6379/tcp` | `127.0.0.1` | `Localhost Only` | `redis-server` | Direct |

## 8. Security Controls, SSH & User Accounts

### OpenSSH Server Hardening
- **SSH Version:** OpenSSH_9.6p1 Ubuntu-3ubuntu13.4
- **Listening Port:** `22`
- **PermitRootLogin:** `prohibit-password`
- **PasswordAuthentication:** `no`
- **PubkeyAuthentication:** `yes`

### Linux Security Modules & Controls
- **AppArmor:** `Active (68 enforce profiles)`
- **SELinux Mode:** `disabled`
- **ASLR State:** `Full Randomization (2)`
- **Kernel Lockdown:** `none`
- **Privileged Accounts (Sudo):** root, admin

## 9. Docker Containers & Container Security

- **Docker Server:** `27.2.0` (Driver: `overlay2`, Cgroup: `systemd`)
- **Containers:** 5 Running / 5 Total

### Container Inventory
| Container Name | Image Repository | State | Published Ports | Compose Project | Privileged |
|---|---|---|---|---|---|
| `jellyfin` | `jellyfin/jellyfin:latest` | `running` | 8096->8096 | media | `False` |
| `paperless-ngx` | `ghcr.io/paperless-ngx/paperless-ngx:latest` | `running` | 8000->8000 | docs | `False` |
| `pihole` | `pihole/pihole:latest` | `running` | 53->53 | dns | `False` |
| `searxng` | `searxng/searxng:latest` | `running` | 8080->8080 | search | `False` |
| `redis` | `redis:7-alpine` | `running` | 6379->6379 | docs | `False` |

## 10. Caddy Reverse Proxy & Web Services

| Public Hostname | Backend Upstream | TLS Policy |
|---|---|---|
| `media.example.com` | `http://127.0.0.1:8096` | `Automated Let's Encrypt` |
| `docs.example.com` | `http://127.0.0.1:8000` | `Automated Let's Encrypt` |

## 11. Discovered Applications

| Application | Category | Deployment | Container / Service | Port(s) |
|---|---|---|---|---|
| **Jellyfin** | Media Server | `Docker` | `jellyfin` | `8096` |
| **Paperless-ngx** | Document Management | `Docker` | `paperless-ngx` | `8000` |
| **Pi-hole** | DNS & Ad Blocking | `Docker` | `pihole` | `53` |
| **PostgreSQL** | Database | `Native Systemd` | `native` | `5432` |
| **Redis** | In-Memory Cache | `Docker` | `redis` | `6379` |

## 12. Infrastructure & Storage Topology

### Reconstructed End-to-End Chains
```text
/dev/nvme0n1 -> /dev/nvme0n1p2 -> LVM(vg_system/lv_root) -> / -> Container(None) -> App(OS Root)
/dev/sda -> /dev/sda1 -> LUKS(cryptdata) -> LVM(vg_data/lv_media) -> /mnt/media -> Container(jellyfin) -> App(Jellyfin Media Library)
```

## 13. Scheduled Tasks, Backups & System Logs

### Backup Software Detection
- **restic:** `0.16.4` (`/usr/bin/restic`)
- **rsync:** `3.2.7` (`/usr/bin/rsync`)

### System Logs Summary
- **Boot Errors Recorded:** `0`
- **Journal Disk Space:** `1.2 GB`

## 14. Audit Provenance & Collector Limitations

- **Audit Tool Version:** `serveraudit v0.1.0`
- **Operating User:** `audit-operator`
- **Outbound Network Access:** `Disabled (Strictly Local)`
- **System Modification:** `Zero (Guaranteed Observational)`

### Collector Execution Statuses
| Collector Module | Status | Execution Duration | Status Notes |
|---|---|---|---|
| `system` | 🟢 `SUCCESS` | `0.02s` | Completed |
| `hardware` | 🟢 `SUCCESS` | `0.04s` | Completed |
| `cpu` | 🟢 `SUCCESS` | `0.01s` | Completed |
| `memory` | 🟢 `SUCCESS` | `0.01s` | Completed |
| `storage` | 🟢 `SUCCESS` | `0.05s` | Completed |
| `smart` | 🟢 `SUCCESS` | `0.12s` | Completed |
| `network` | 🟢 `SUCCESS` | `0.03s` | Completed |
| `ports` | 🟢 `SUCCESS` | `0.02s` | Completed |
| `ssh` | 🟢 `SUCCESS` | `0.02s` | Completed |
| `users` | 🟢 `SUCCESS` | `0.03s` | Completed |
| `security` | 🟢 `SUCCESS` | `0.04s` | Completed |
| `docker` | 🟢 `SUCCESS` | `0.08s` | Completed |
| `caddy` | 🟢 `SUCCESS` | `0.03s` | Completed |
| `applications` | 🟢 `SUCCESS` | `0.05s` | Completed |
| `scheduled` | 🟢 `SUCCESS` | `0.02s` | Completed |
| `backups` | 🟢 `SUCCESS` | `0.02s` | Completed |
| `logs` | 🟢 `SUCCESS` | `0.03s` | Completed |
| `thermal` | 🟢 `SUCCESS` | `0.01s` | Completed |
| `power` | 🟢 `SUCCESS` | `0.01s` | Completed |
| `boot` | 🟢 `SUCCESS` | `0.01s` | Completed |
| `sharing` | 🟢 `SUCCESS` | `0.01s` | Completed |
