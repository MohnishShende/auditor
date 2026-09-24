# Collector Reference

Linux Server Audit implements a comprehensive suite of observational collectors. Each collector declares its behavior via a `CollectorManifest`.

## Manifest Fields

- `name`: Unique identifier
- `category`: Subsystem grouping (system, hardware, storage, network, security, runtime, services, containers, applications)
- `requires_root`: Boolean indicating whether elevated privilege (`sudo`) is required
- `network_access`: Must be `False` for core offline collectors
- `writes_system_state`: Must be `False`
- `collects_secrets`: Must be `False`
- `commands`: List of system commands queried
- `outputs`: List of exported structured fields

## Implemented Collectors

| Collector | Category | Root Required | Inspected Subsystems |
|---|---|---|---|
| `system` | System | No | Distribution, kernel release, uptime, virtualization, boot mode (UEFI/BIOS) |
| `hardware` | Hardware | No (optional DMI) | Motherboard, platform manufacturer, chassis, DMI metadata |
| `firmware` | Firmware | No | BIOS vendor, version, release date, UEFI runtime, Secure Boot state, TPM version |
| `cpu` | Hardware | No | Cores, logical CPUs, thread topology, governor, frequencies, cache, kernel mitigations |
| `memory` | Hardware | No (optional DMI) | RAM metrics, swap utilization, DIMM slots/speeds, HugePages, PSI memory pressure |
| `pci` | Hardware | No | PCI devices, GPUs, NICs, storage controllers, kernel drivers, IOMMU |
| `usb` | Hardware | No | USB controllers, buses, topology, connected devices, security tokens |
| `storage` | Storage | No | Block devices, partitions, rotational vs SSD/NVMe, sizes, UUIDs |
| `smart` | Storage | Yes | SMART & NVMe health, temperatures, endurance, reallocated sectors, error counters |
| `filesystems` | Storage | No | Mounted filesystems, mount points, used/free bytes, inode utilization, NFS/CIFS |
| `fstab` | Storage | No | Static `/etc/fstab` entries, mount options, dump/pass, stale target warnings |
| `lvm` | Storage | Yes | Physical Volumes, Volume Groups, Logical Volumes, extents, mappings |
| `raid` | Storage | No | Software RAID (`/proc/mdstat`), active members, degraded array detection |
| `zfs` | Storage | No | ZFS pools, datasets, compression, health status |
| `btrfs` | Storage | No | Btrfs filesystems, devices, subvolumes |
| `encryption` | Storage | Yes | LUKS / dm-crypt active mappings, cipher, key sizes, crypttab configuration |
| `network` | Network | No | Physical/virtual interfaces, MAC addresses, link states, MTU, IPv4/IPv6 addresses |
| `routes` | Network | No | IPv4/IPv6 routing tables, default gateway, policy routing rules |
| `dns` | Network | No | `/etc/resolv.conf`, systemd-resolved status, search domains, `/etc/hosts` |
| `ports` | Network | Yes | Listening TCP/UDP ports, bound addresses, owning process PID/name |
| `active_net` | Network | No | TCP connection state counts, interface rx/tx drop and error counters |
| `firewall` | Network | Yes | UFW status/rules, iptables default policies, nftables tables, firewalld |
| `fail2ban` | Security | Yes | Fail2ban active jails, CrowdSec status |
| `ssh` | Security | Yes | SSH client/server version, effective `sshd -T` config, host key fingerprints |
| `users` | Security | Yes | Local users, human accounts, sudoers memberships, UID 0 accounts, password status |
| `security` | Security | Yes | AppArmor, SELinux, Seccomp, ASLR, Kernel Lockdown, sysctl hardening |
| `permissions` | Security | No | Targeted checks on `/etc/shadow`, `/etc/sudoers`, `/root`, Docker socket, SUID |
| `systemd` | Runtime | No | Active/failed units, enabled services, systemd timers, boot duration |
| `processes` | Runtime | No | Process count, zombie processes, top CPU and memory consumers |
| `runtime_health`| Runtime | No | Load averages, CPU/Memory/IO PSI metrics, dmesg OOM killer logs |
| `packages` | System | No | Installed packages (dpkg/apt), manual vs auto, pending security updates, Snap, Flatpak |
| `docker` | Containers | Yes | Docker engine, containers, images, volumes, networks, compose, container security |
| `caddy` | Services | No | Caddy version, Caddyfile sites, reverse proxy upstreams, TLS mode |
| `tls` | Security | Yes | X.509 TLS certificates, SANs, issuers, expiration dates, days remaining |
| `applications` | Applications | No | Self-hosted applications discovery (Jellyfin, Paperless, Pi-hole, *arr stack, DBs) |
| `scheduled` | System | Yes | Cron jobs, `/etc/cron.*`, user crontabs |
| `backups` | System | No | Backup software detection (Restic, Borg, Duplicati, Rclone) |
| `logs` | Runtime | Yes | Journalctl boot error summaries, dmesg kernel alerts, log storage usage |
| `thermal` | Hardware | No | Thermal zone readings, CPU temperatures, fan speeds, max temperatures |
| `power` | Hardware | No | ACPI power supplies, battery status, UPS monitoring via NUT |
| `boot` | System | No | UEFI/BIOS, GRUB default parameters, installed kernel images |
| `time` | System | No | System clock, timezone, NTP synchronization state, time daemon |
| `sharing` | Services | Yes | Samba shares (`/etc/samba/smb.conf`), NFS exports (`/etc/exports`) |
