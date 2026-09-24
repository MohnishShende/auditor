# Auditor v0.1.0 — Initial Release

We are thrilled to announce the initial release of **Auditor (serveraudit)**, a comprehensive, open-source Linux server auditing, inventory, documentation, topology-mapping, and historical-baselining system.

Auditor is engineered for system administrators, DevOps engineers, and homelab architects who need an authoritative, beautiful, and verifiable representation of their Linux servers.

---

### 🌟 Key Highlights

- **⚡ Target Experience**: `git clone https://github.com/MohnishShende/auditor.git && cd auditor && ./install.sh && serveraudit audit`
- **🔒 Single Sudo Authentication**: Validates credentials once via `sudo -v` at launch; privileged collectors execute via `sudo -n` with zero repetitive password prompts.
- **🛡️ Strict Observational Safety**: Zero intentional system-state modifications. Strict forbidden command denylist prevents any mutation, restarts, or writes.
- **🌐 Offline-First & Private**: Zero cloud dependencies, zero telemetry, zero analytics, zero AI dependencies, zero default outbound network calls.
- **🧩 43 Deep Domain Collectors**: Complete coverage across CPU, memory, platform, PCI, USB, storage, SMART diagnostics, RAID, LVM, ZFS, Btrfs, LUKS, network interfaces, firewall (UFW/nftables/iptables), SSH hardening, systemd, processes, Docker, Caddy, self-hosted applications, cron/timers, backups, and logs.
- **🗺️ End-to-End Topology Mapping**: Automatic reconstruction of multi-tier storage stacks (`Disk → Partition → LUKS → LVM → Filesystem → Mount → Container → App`) and network-to-process exposure.
- **🧹 Secret-Aware Typed Sanitization**: Scrub passwords, hashes (`$6$`, argon2), private keys, authorization headers, database connection URLs, and tokens across `private` and shareable `public` profiles.
- **📊 Multi-Format Renderers**: Beautiful GitHub Flavored Markdown (`audit.md`), Canonical JSON Schema (`audit.json`), standalone responsive HTML dashboard (`audit.html`), and optional PDF.
- **📈 Historical Baselining & Drift**: Instant comparison of two historical snapshots using `serveraudit diff <old> <new>` to detect configuration drift.
- **🖥️ Zero-Dependency Web Interface**: Embedded stdlib HTTP server for inspecting server identity, triggering audits, viewing reports, and comparing baselines.
- **🔐 Cryptographic Provenance**: Every audit snapshot is bundled with `manifest.json` and cryptographic `checksums.sha256`.

---

### 📦 Installation & Getting Started

```bash
git clone https://github.com/MohnishShende/auditor.git
cd auditor
./install.sh

# Run audit
serveraudit audit
```

Full documentation and architecture diagrams are available in the [README](https://github.com/MohnishShende/auditor#readme).
