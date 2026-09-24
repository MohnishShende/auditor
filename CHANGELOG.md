# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-09-24

### Fixed
- **CLI Wrapper Symlink Resolution (Bug 1)**: Resolved symlink traversal in `install.sh`, `audit.sh`, and `bin/serveraudit` so invocation via `~/.local/bin/serveraudit` or any external symlink correctly resolves the project root and virtual environment without `ModuleNotFoundError`.
- **CPU Collector Parsing Resilience (Bug 2)**: Fixed `KeyError: 'model_name'` caused by key mismatch when parsing `/proc/cpuinfo`. Added cross-architecture fallbacks (ARM, x86, RISC-V), `lscpu -J` integration, and tolerant error handling returning `PARTIAL` rather than crashing on missing optional metadata.
- **Docker Detection & Error Differentiation (Bug 3)**: Resolved Docker false-negative where operational daemons were marked `SKIPPED`. Added multi-tier detection supporting contemporary Docker Engine 29.x / API 1.56, unprivileged execution with automatic privilege elevation retry, and explicit status differentiation between missing CLI, stopped daemon, permission denied, and active engine.
- **Runpy CLI Module Import Warning (Bug 4)**: Resolved `RuntimeWarning: 'serveraudit.cli.main' found in sys.modules` by implementing lazy attribute loading in `serveraudit.cli.__init__`.

## [0.1.0] - 2026-09-24

### Added
- Core modular auditing framework with single-sudo authentication and least-privilege executor.
- Comprehensive collectors:
  - System identity, distribution, kernel, uptime, virtualization
  - Hardware, motherboard, DMI, platform, firmware, TPM, ACPI
  - CPU specifications, topology, frequencies, vulnerabilities & mitigations
  - Memory, DIMMs, swap, HugePages, ECC, PSI
  - PCI and USB inventory, kernel drivers, IOMMU groups
  - Storage block devices, partitions, filesystem utilization, inode usage
  - SMART & NVMe disk health, temperatures, endurance, error logs
  - LVM (PV/VG/LV), Software RAID, ZFS pools, Btrfs subvolumes, LUKS encryption
  - Filesystems, `/etc/fstab` consistency analysis, NFS/CIFS mounts
  - Network hardware, MACs, link speeds, IPv4/IPv6 addresses, routes, DNS, hosts
  - Listening TCP/UDP ports with process attribution, UFW, nftables, iptables
  - SSH configuration, effective `sshd -T`, host key fingerprints, hardening
  - Users, groups, sudoers, UID 0 accounts, locked accounts
  - Linux security controls (AppArmor, SELinux, Seccomp, Kernel Lockdown, ASLR, sysctl)
  - systemd units, failed services, timers, sockets, boot performance
  - Process tree, top resource consumers, command line sanitization
  - Package inventory (dpkg/apt), manual vs automatic, pending security updates
  - Docker engine, containers, images, volumes, networks, Docker Compose projects
  - Container security posture (privileged, socket mounts, capabilities, user)
  - Caddy web server, reverse proxy upstreams, TLS certificates & PKI structure
  - Application discovery plugins (Jellyfin, Paperless, Pi-hole, qBittorrent, *arr stack, Kavita, SearXNG, Databases)
  - Scheduled jobs (cron, systemd timers), backup software detection, logs summary
  - Thermal sensors, power management, UPS monitoring, boot chain, time synchronization
  - Targeted security permissions on sensitive files
- Secret-aware typed sanitization engine supporting `private` and `public` (shareable) profiles.
- Topology reconstruction engine mapping physical disks to partitions, LUKS, LVM, filesystems, mounts, docker containers, applications, reverse proxies, and hostnames.
- Deterministic analysis engine for system health, service exposure classification, configuration conflicts, and drift detection.
- Multi-format renderers: Markdown (`audit.md`), Canonical JSON (`audit.json`), HTML (`audit.html`), and optional PDF.
- Cryptographic provenance: `manifest.json` and `checksums.sha256`.
- Snapshot comparison & configuration drift CLI (`serveraudit diff`).
- Self-hosted web interface with live progress, report browser, comparison tool, and artifact downloads.
- Full test suite with unit tests, schema validation, fake secret leak prevention tests, and fixture snapshots.
