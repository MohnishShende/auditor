# Linux Server Audit

## Comprehensive Open-Source Linux Server Auditing, Documentation, Topology and Baselining Platform

**Status:** Project specification / initial architecture  
**Primary platform:** Linux, initially Ubuntu and Debian  
**Distribution:** Open-source GitHub repository  
**Primary interface:** CLI + optional self-hosted web interface  
**Primary artifact:** Markdown  
**Structured artifact:** JSON  
**Optional artifacts:** HTML and PDF  
**AI dependency:** None  
**Cloud dependency:** None  
**Default outbound network access:** None  
**Privilege model:** Single sudo authentication with least-privilege collection  
**System modification:** No intentional system-state modification  

---

# 1. Project Vision

Linux Server Audit is a comprehensive, open-source Linux server auditing, inventory, documentation, health-inspection, topology-mapping and historical-baselining system.

The central idea is deliberately simple:

> Clone the repository, run one command, authenticate with sudo once, and receive an exceptionally detailed, structured representation of the current state of the Linux server.

The project should be capable of answering:

> What exactly is this server?

> What hardware does it contain?

> What Linux distribution and kernel are installed?

> How is storage organized?

> What is the health of every physical disk?

> What filesystems, LVM volumes, RAID arrays and encrypted devices exist?

> How is networking configured?

> What services are listening and where?

> How is SSH configured?

> What security controls are active?

> What packages are installed?

> What systemd services exist?

> What Docker containers, images, volumes and networks exist?

> What Docker Compose projects exist?

> What applications are running?

> How is Caddy configured?

> What certificates and TLS infrastructure exist?

> How do disks, filesystems, containers, applications and reverse proxies relate to one another?

> What changed since the previous audit?

The final result should be a reproducible snapshot of the machine at a particular point in time.

---

# 2. Intended Users

The project is intended for:

- Homelab operators
- Self-hosters
- Linux administrators
- Developers
- Researchers
- Cybersecurity professionals
- Digital-forensics practitioners
- Small organizations
- Infrastructure maintainers
- People migrating or rebuilding servers
- People documenting personal servers
- People troubleshooting complex Linux installations
- People who want historical configuration baselines

The project should remain useful for a single Raspberry Pi, a home media server, a workstation, a Docker host, or a considerably more complicated Linux server.

---

# 3. What the Project Is

The project is fundamentally a:

**Server State Recorder**

It combines aspects of:

- Hardware inventory
- Software inventory
- Configuration auditing
- Security auditing
- Storage auditing
- SMART health reporting
- Network auditing
- Service discovery
- Container auditing
- Application discovery
- TLS/PKI inspection
- System-health reporting
- Infrastructure documentation
- Topology reconstruction
- Historical baselining
- Configuration-drift detection

Traditional infrastructure tools answer different questions:

```text
Monitoring
    → What is happening right now?

Asset Inventory
    → What assets exist?

Backup
    → Can the data be restored?

Configuration Management
    → What configuration should exist?

Vulnerability Scanner
    → What known vulnerabilities might exist?

Linux Server Audit
    → What exactly exists on this machine,
      how is it configured,
      how is everything connected,
      what is its current state,
      and what did it look like at this point in time?
```

---

# 4. What the Project Is Not

The project is not primarily:

- A monitoring dashboard
- A SIEM
- An EDR
- A configuration-management platform
- A package manager
- A backup program
- A vulnerability exploitation tool
- An automatic remediation framework
- An AI assistant
- A cloud service

The project observes and documents.

It does not automatically modify the server to make the server conform to recommendations.

---

# 5. Fundamental Design Principles

The project SHALL be:

1. Comprehensive
2. Open source
3. Locally executable
4. Read-oriented
5. Deterministic wherever practical
6. Reproducible
7. Human-readable
8. Machine-readable
9. Secret-aware
10. Privacy-preserving
11. Modular
12. Extensible
13. Auditable
14. Suitable for historical comparison
15. Safe for normal servers
16. Independent of AI
17. Independent of cloud services
18. Useful through both CLI and web interfaces
19. Capable of operating without Internet connectivity
20. Explicit about collection failures and blind spots

The fundamental pipeline is:

```text
OBSERVE
   ↓
COLLECT
   ↓
NORMALIZE
   ↓
SANITIZE
   ↓
ANALYZE
   ↓
CORRELATE
   ↓
RENDER
   ↓
PRESERVE
```

Not:

```text
OBSERVE
   ↓
CHANGE THE SERVER
```

---

# 6. Safety Contract

The auditor may require elevated privileges because comprehensive Linux auditing requires information unavailable to ordinary users.

Elevated privilege does not grant permission to modify the machine.

The project performs no intentional system-configuration changes.

The intended persistent writes are limited to:

- Generated audit artifacts
- Audit history
- Temporary working data
- Project-owned metadata

The project SHALL NOT automatically:

- Install packages
- Remove packages
- Upgrade packages
- Modify repositories
- Restart services
- Start services
- Stop services
- Enable services
- Disable services
- Restart the machine
- Modify users
- Modify groups
- Change passwords
- Modify sudoers
- Modify SSH configuration
- Modify firewall rules
- Modify routes
- Modify DNS
- Modify Docker configuration
- Start containers
- Stop containers
- Restart containers
- Modify Caddy
- Change file ownership
- Change file permissions
- Mount filesystems
- Unmount filesystems
- Open encrypted volumes
- Close encrypted volumes
- Modify encryption configuration
- Initiate destructive disk operations
- Write kernel parameters
- Write to `/etc`
- Write to `/proc/sys`
- Write to `/sys`
- Automatically remediate detected problems

The core rule is:

> **Observe and report. Never remediate.**

---

# 7. Precise Meaning of Read-Only

The project should not make the technically inaccurate claim that execution causes literally zero state changes.

Observation itself can produce incidental effects.

Examples include:

- sudo authentication generating log entries
- shell/process accounting recording execution
- filesystem access-time changes where applicable
- hardware queries communicating with devices
- API queries appearing in service logs
- temporary files being created
- CPU, RAM and I/O being consumed

Therefore the project's formal guarantee should be:

> **Linux Server Audit performs no intentional system-state modification beyond creating its own explicitly requested audit artifacts and temporary working data.**

---

# 8. Open-Source Trust Model

The project should not claim:

> "It is open source, therefore it is automatically trustworthy."

Instead:

> **It is open source, therefore its behavior can be independently inspected and verified.**

Users should be able to determine:

- Which commands execute
- Which commands require root
- Which files are inspected
- Which APIs are queried
- Which information is collected
- Which information is redacted
- Which information is written
- Whether any network connections are attempted

The repository should make privileged operations especially easy to audit.

---

# 9. Default Network Policy

The default audit SHALL require no outbound network access.

```text
LOCAL MACHINE
     │
     ▼
COLLECTION
     │
     ▼
LOCAL PROCESSING
     │
     ▼
LOCAL REPORT
```

No telemetry.

No analytics.

No cloud processing.

No AI API.

No automatic report upload.

No external server dependency.

Optional future functionality requiring external information, such as current CVE intelligence, should be separately enabled and clearly identified as network-dependent.

---

# 10. Privilege Model

## 10.1 One sudo Authentication

The intended workflow is:

```bash
git clone <repository>
cd <repository>
./audit.sh
```

The launcher validates elevated privileges once:

```bash
sudo -v
```

Example:

```text
Linux Server Audit
────────────────────────────────────────

A comprehensive server audit is about to begin.

Elevated privileges are required to inspect protected
hardware, storage, security and service information.

No intentional system configuration changes will occur.

[sudo] password for user:

✓ Privilege validated
✓ Audit started
```

The user should not repeatedly enter the sudo password.

---

# 11. Least-Privilege Execution

The entire program should not unnecessarily execute permanently as root.

Preferred architecture:

```text
./audit.sh
     │
     ├── sudo -v
     │
     ├── Unprivileged collectors
     │
     ├── Privileged collectors
     │       ├── dmidecode
     │       ├── SMART
     │       ├── storage metadata
     │       ├── encryption metadata
     │       ├── protected configuration
     │       └── security state
     │
     ├── normalization
     ├── sanitization
     ├── topology
     ├── analysis
     └── rendering
```

Only operations requiring elevated access should use it.

The existing sudo timestamp should normally allow subsequent privileged collectors to execute without requesting the password again.

Long audits should be designed so the user is not repeatedly interrupted for authentication.

---

# 12. Repository Structure

The repository should initially resemble:

```text
linux-server-audit/
│
├── README.md
├── LICENSE
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── pyproject.toml
├── audit.sh
│
├── config/
│   ├── default.yaml
│   ├── public.yaml
│   └── private.yaml
│
├── src/
│   └── serveraudit/
│       │
│       ├── cli/
│       │   ├── main.py
│       │   ├── audit.py
│       │   ├── diff.py
│       │   └── render.py
│       │
│       ├── core/
│       │   ├── collector.py
│       │   ├── executor.py
│       │   ├── privileges.py
│       │   ├── normalizer.py
│       │   ├── sanitizer.py
│       │   ├── manifest.py
│       │   └── snapshot.py
│       │
│       ├── collectors/
│       │   ├── system/
│       │   ├── hardware/
│       │   ├── cpu/
│       │   ├── memory/
│       │   ├── firmware/
│       │   ├── usb/
│       │   ├── pci/
│       │   ├── storage/
│       │   ├── smart/
│       │   ├── filesystems/
│       │   ├── lvm/
│       │   ├── raid/
│       │   ├── encryption/
│       │   ├── network/
│       │   ├── dns/
│       │   ├── firewall/
│       │   ├── ssh/
│       │   ├── users/
│       │   ├── security/
│       │   ├── systemd/
│       │   ├── processes/
│       │   ├── packages/
│       │   ├── docker/
│       │   ├── compose/
│       │   ├── caddy/
│       │   ├── tls/
│       │   ├── services/
│       │   ├── scheduled/
│       │   ├── backups/
│       │   ├── logs/
│       │   ├── thermal/
│       │   ├── power/
│       │   ├── boot/
│       │   ├── time/
│       │   ├── sharing/
│       │   └── permissions/
│       │
│       ├── applications/
│       │   ├── jellyfin/
│       │   ├── paperless/
│       │   ├── pihole/
│       │   ├── qbittorrent/
│       │   ├── sonarr/
│       │   ├── radarr/
│       │   ├── prowlarr/
│       │   ├── bazarr/
│       │   ├── kavita/
│       │   └── searxng/
│       │
│       ├── topology/
│       │   ├── storage.py
│       │   ├── network.py
│       │   ├── containers.py
│       │   ├── services.py
│       │   └── graph.py
│       │
│       ├── analysis/
│       │   ├── health.py
│       │   ├── exposure.py
│       │   ├── conflicts.py
│       │   └── drift.py
│       │
│       ├── renderers/
│       │   ├── markdown.py
│       │   ├── json.py
│       │   ├── html.py
│       │   └── pdf.py
│       │
│       └── web/
│           ├── app.py
│           ├── api/
│           ├── templates/
│           └── static/
│
├── schemas/
│   ├── audit.schema.json
│   ├── collector.schema.json
│   └── manifest.schema.json
│
├── templates/
│   ├── audit.md.j2
│   ├── section.md.j2
│   └── pdf/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   ├── sanitization/
│   └── snapshots/
│
├── docs/
│   ├── architecture.md
│   ├── collectors.md
│   ├── security-model.md
│   ├── privacy.md
│   ├── report-format.md
│   ├── adding-collectors.md
│   └── web-interface.md
│
└── audits/
    └── .gitkeep
```

---

# 13. Major Project Components

```text
config/
    Audit policies and profiles

src/
    Main application

collectors/
    Linux information acquisition

applications/
    Application-specific inspection

topology/
    Relationship reconstruction

analysis/
    Deterministic interpretation

renderers/
    Markdown / JSON / HTML / PDF

schemas/
    Canonical data definitions

tests/
    Correctness, safety and sanitization testing

docs/
    Developer and user documentation

audits/
    Generated snapshots
```

---

# 14. Architectural Pipeline

Collectors should NOT directly construct Markdown.

The architecture should be:

```text
              COLLECTORS
                  │
                  ▼
           RAW OBSERVATIONS
                  │
                  ▼
              NORMALIZER
                  │
                  ▼
         CANONICAL AUDIT MODEL
            │        │        │
            ▼        ▼        ▼
       SANITIZER  TOPOLOGY  ANALYSIS
            │        │        │
            └────────┴────────┘
                     │
                     ▼
                 RENDERERS
             ┌───────┼────────┐
             ▼       ▼        ▼
             MD     JSON     HTML
                              │
                              ▼
                             PDF
```

This separation is fundamental.

---

# 15. Structured Intermediate Representation

For example, the SMART collector should not generate:

```markdown
## Disk

Samsung 980 PRO is healthy.
```

Instead it should produce structured information similar to:

```json
{
  "device": "/dev/nvme0n1",
  "model": "Samsung SSD 980 PRO",
  "type": "nvme",
  "capacity_bytes": 1000204886016,
  "smart": {
    "available": true,
    "health": "passed",
    "temperature_c": 41,
    "percentage_used": 3,
    "critical_warning": 0
  }
}
```

The renderer determines presentation.

This allows the same observation to generate:

- Markdown
- JSON
- HTML
- PDF
- Web UI
- Historical comparisons
- Machine-readable APIs

without recollecting the information.

---

# 16. Audit Profiles

The project should initially provide two major profiles.

## 16.1 Private Audit

Designed for the server owner.

May preserve:

- Internal hostnames
- Internal IP addresses
- Device identifiers
- Filesystem UUIDs
- Hardware serial numbers
- Internal topology
- Detailed paths
- Detailed configuration metadata

Even private mode should never unnecessarily dump actual secrets.

---

## 16.2 Sanitized / Shareable Audit

Designed for:

- GitHub issues
- Technical support
- Public sharing
- Forums
- Documentation
- External analysis

It should automatically remove or transform sensitive material.

Examples:

- Passwords
- Password hashes
- API keys
- Tokens
- Cookies
- Session credentials
- Authorization headers
- SSH private keys
- TLS private keys
- Database passwords
- Wi-Fi credentials
- `.env` secret values
- Secret environment variables
- Authentication material
- Selected internal addresses
- Personally identifying hardware identifiers
- Sensitive paths where configured

The sanitized report should retain maximum diagnostic usefulness without exposing credentials.

---

# 17. Possible Future Raw / Forensic Mode

An advanced mode could preserve minimally transformed observations for expert troubleshooting.

Example:

```bash
serveraudit --raw
```

This mode should:

- Require explicit selection
- Clearly warn about disclosure risk
- Never be the default
- Remain observational
- Preserve provenance

It is not disk forensics.

It is an expert-level raw observation bundle.

---

# 18. Secret Sanitization Architecture

Sanitization must be a first-class component.

It must NOT be an afterthought implemented only as a final regular-expression pass over Markdown.

The pipeline should understand data types.

Example:

```text
Caddy Collector
      │
      ▼
Certificate Object
      │
      ├── Subject          → allowed
      ├── Issuer           → allowed
      ├── SAN              → policy dependent
      ├── Expiration       → allowed
      ├── Public Key Info  → allowed
      └── Private Key      → NEVER OUTPUT
```

Environment example:

```text
PAPERLESS_URL=https://...
PAPERLESS_DBHOST=db
PAPERLESS_DBUSER=paperless
PAPERLESS_DBPASS=[REDACTED]
API_TOKEN=[REDACTED]
```

---

# 19. Collector Manifest

Every collector should declare its behavior.

Example:

```yaml
collector: smart

description: Collect physical disk SMART/NVMe health information

requires_root: true

network_access: false

writes_system_state: false

collects_secrets: false

commands:
  - smartctl --all
  - nvme smart-log

outputs:
  - disk_health
  - temperature
  - endurance
  - error_counters
```

This allows someone auditing the auditor to inspect privileged behavior quickly.

---

# 20. Primary CLI

The canonical interface should remain CLI-first.

Examples:

```bash
sudo nodeaudit
```

or:

```bash
./audit.sh
```

Additional commands could include:

```bash
nodeaudit audit
nodeaudit audit --public
nodeaudit audit --private
nodeaudit diff <snapshot-a> <snapshot-b>
nodeaudit render <snapshot> --format markdown
nodeaudit render <snapshot> --format html
nodeaudit render <snapshot> --format pdf
nodeaudit list
nodeaudit verify <snapshot>
```

The web application must use the same underlying engine.

There should not be separate web-audit logic and CLI-audit logic.

---

# 21. Generated Audit Directory

A completed audit might produce:

```text
audits/
└── nodezero-2026-09-24T101700+0530/
    │
    ├── audit.md
    ├── audit.json
    ├── manifest.json
    ├── checksums.sha256
    │
    ├── topology/
    │   ├── system.md
    │   ├── storage.md
    │   ├── network.md
    │   └── services.md
    │
    └── optional/
        ├── audit.html
        └── audit.pdf
```

---

# 22. Canonical Artifact

`audit.md` should remain the primary human-readable artifact.

The Markdown report should be useful independently of the application.

A user should be able to:

- Open it in any text editor
- Store it in Git
- Archive it
- Search it
- Send it to another administrator
- Feed it into another program
- Convert it to HTML
- Convert it to PDF
- Process it using scripts
- Analyze it with AI if they independently choose to
- Preserve it for years

The project itself requires no AI.

---

# 23. JSON Artifact

`audit.json` should contain the canonical structured representation.

This is essential for:

- Historical comparison
- Automated analysis
- Web rendering
- API access
- Future integrations
- Testing
- Schema validation
- Topology generation

Markdown should not have to be reparsed to perform comparisons.

---

# 24. Optional PDF

PDF generation should be optional.

The Markdown artifact remains canonical.

Pipeline:

```text
Canonical Model
      │
      ├── Markdown
      ├── JSON
      ├── HTML
      └── PDF
```

PDF exists primarily for:

- Archival
- Sharing
- Printing
- Formal documentation

---

# 25. Self-Hosted Web Interface

The project should optionally run continuously as a local server application.

Example:

```text
serveraudit.service
       │
       ▼
localhost:<port>
       │
       ▼
Caddy
       │
       ▼
audit.<local-domain>
```

The web interface should not require cloud services.

---

# 26. Web Interface Concept

A simple initial interface could resemble:

```text
┌─────────────────────────────────────────────────────────────┐
│                      SERVER AUDIT                           │
│                                                             │
│  NODEZERO                                                   │
│  Ubuntu 26.04.1 LTS                         ● Online        │
│                                                             │
│  Last Audit                                                 │
│  24 September 2026 · 10:17                                 │
│                                                             │
│                  [ RUN NEW AUDIT ]                          │
│                                                             │
│  System          ✓        Hardware        ✓                 │
│  Storage         ✓        SMART           ✓                 │
│  Network         ✓        Security        ✓                 │
│  Docker          ✓        Caddy           ✓                 │
│  Services        ✓        Packages        ✓                 │
│                                                             │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│  Recent Audits                                              │
│                                                             │
│  24 Sep 2026 10:17    [View] [MD] [JSON] [PDF]             │
│  23 Sep 2026 22:41    [View] [MD] [JSON] [PDF]             │
│  20 Sep 2026 05:29    [View] [MD] [JSON] [PDF]             │
│                                                             │
│                  [ Compare Audits ]                         │
└─────────────────────────────────────────────────────────────┘
```

The frontend should emphasize:

- Current server identity
- Last audit
- Audit health
- Run Audit
- Historical audits
- View report
- Download Markdown
- Download JSON
- Optional PDF
- Compare snapshots

---

# 27. Web Privilege Boundary

The web process should NOT permanently run unrestricted as root.

Preferred design:

```text
Web UI
  │
  ▼
Unprivileged ServerAudit service
  │
  ▼
Controlled audit execution mechanism
  │
  ▼
Privileged collectors only where required
```

The web-facing application should have the smallest privilege surface practical.

---

# 28. Audit Progress

The frontend and CLI should expose collector progress.

Example:

```text
Audit started...

[✓] System identity
[✓] Hardware
[✓] CPU
[✓] Memory
[✓] Firmware
[✓] Storage
[✓] SMART
[✓] LVM
[✓] Encryption
[✓] Network
[✓] DNS
[✓] SSH
[✓] Security
[✓] Docker
[✓] Caddy
[ ] Packages
[ ] Services
[ ] Topology
[ ] Report generation

87% complete
```

A failure in one collector should not necessarily abort the entire audit.

---

# 29. Collector Failure Handling

Each collector should report:

```text
SUCCESS
PARTIAL
SKIPPED
UNSUPPORTED
PERMISSION_DENIED
DEPENDENCY_MISSING
FAILED
```

Example:

```text
SMART
Status: PARTIAL

/dev/nvme0n1    SUCCESS
/dev/sda        SUCCESS
/dev/sdb        PERMISSION_DENIED
```

The final report must never silently omit failed collection.

---

# 30. Comprehensive Audit Scope

The following represents the intended comprehensive audit surface.

---

# 31. System Identity and Operating System

Collect:

- Hostname
- Pretty hostname
- Distribution
- Distribution version
- Distribution codename
- Architecture
- Kernel version
- Kernel build
- Kernel command line
- Operating-system installation information where available
- Machine identity, subject to sanitization
- Boot ID, subject to sanitization
- Uptime
- Last boot
- Timezone
- Locale
- System clock
- Virtualization detection
- Containerized-host detection
- BIOS vs UEFI boot
- Secure Boot state
- Installed kernels
- Running kernel
- Pending reboot state
- OS support lifecycle where locally determinable

---

# 32. Motherboard, Platform and Firmware

Collect:

- System manufacturer
- System product/model
- Chassis type
- Motherboard manufacturer
- Motherboard model
- Motherboard revision
- BIOS vendor
- BIOS version
- BIOS release date
- UEFI information
- Firmware inventory
- `fwupd` support
- Locally available firmware metadata
- TPM presence
- TPM version
- TPM state
- Secure Boot state
- ACPI information
- Sanitized hardware identifiers

---

# 33. CPU

Collect:

- Exact processor model
- Architecture
- Socket count
- Physical core count
- Logical CPU count
- Thread topology
- NUMA topology
- CPU flags
- Instruction-set capabilities
- Current frequency
- Minimum frequency
- Maximum frequency
- Frequency scaling
- CPU governor
- Cache hierarchy
- Microcode version
- Virtualization extensions
- Current CPU utilization
- Load averages
- CPU temperatures
- Linux-reported CPU vulnerabilities
- Active kernel mitigations

---

# 34. Memory

Collect:

- Installed RAM
- Available RAM
- Used RAM
- Cached RAM
- Buffers
- DIMM inventory
- DIMM capacity
- DIMM manufacturer
- DIMM model/part number where available
- DIMM speed
- Configured speed
- Memory slots
- Empty slots
- ECC capability
- ECC status where available
- Swap devices
- Swap files
- Swap size
- Swap utilization
- HugePages
- Memory pressure
- OOM history
- Memory errors where locally exposed

---

# 35. PCI and Internal Hardware

Collect:

- PCI inventory
- PCI IDs
- GPUs
- NICs
- SATA controllers
- NVMe controllers
- USB controllers
- Audio hardware
- Wi-Fi adapters
- Bluetooth adapters
- PCIe link width
- PCIe negotiated speed
- Kernel driver
- Kernel modules
- IOMMU groups
- Hardware without drivers
- Hardware/driver errors

---

# 36. USB

Collect:

- USB controllers
- USB buses
- USB topology
- Connected USB devices
- Vendor IDs
- Product IDs
- Manufacturer
- Product description
- USB generation
- Negotiated speed
- Storage devices
- Security tokens
- YubiKeys where identifiable
- Device drivers
- Power information where available

Sensitive identifiers should be configurable for sanitization.

---

# 37. Storage Inventory

Collect every block device.

For each device:

- Device path
- Device type
- HDD/SSD/NVMe
- Manufacturer
- Model
- Capacity
- Logical sector size
- Physical sector size
- Rotation state
- Serial number
- WWN where available
- Partition table
- Partitions
- Filesystems
- Filesystem labels
- UUIDs
- Mount points
- Mount options
- Used space
- Free space
- Percentage utilization
- Inode utilization
- Removable status
- Device-mapper relationships
- Loop devices
- Multipath configuration where applicable

Sensitive identifiers should be redacted in public mode.

---

# 38. SMART and Physical Disk Health

For SATA/SAS disks where supported:

- SMART support
- SMART enabled state
- Overall health
- Power-on hours
- Power-cycle count
- Temperature
- Reallocated sectors
- Pending sectors
- Offline uncorrectable sectors
- Interface CRC errors
- Command errors
- Read/write errors
- Spin-up information
- SMART attributes
- SMART error log
- SMART self-test history

For SSDs:

- Wear indicators
- Remaining lifetime where available
- Total bytes written
- Total bytes read
- Endurance information

For NVMe:

- Critical warning
- Temperature
- Available spare
- Available spare threshold
- Percentage used
- Data units read
- Data units written
- Host read commands
- Host write commands
- Controller busy time
- Power cycles
- Power-on hours
- Unsafe shutdowns
- Media/data-integrity errors
- Error-log entries
- NVMe health state

The audit itself should not initiate destructive or long-running disk operations.

---

# 39. LVM

Collect:

- Physical volumes
- Physical-volume sizes
- Volume groups
- Volume-group sizes
- Free extents
- Logical volumes
- Logical-volume sizes
- Logical-volume attributes
- Thin pools
- Thin volumes
- Snapshots
- Device relationships

Reconstruct:

```text
Disk
 ↓
Partition
 ↓
Physical Volume
 ↓
Volume Group
 ↓
Logical Volume
 ↓
Filesystem
 ↓
Mount
```

---

# 40. RAID

Detect and document:

- Linux software RAID
- RAID arrays
- RAID level
- Member devices
- Array state
- Degraded arrays
- Failed members
- Rebuild state
- Synchronization state
- Relevant metadata

Where supported, hardware RAID information may be collected through optional plugins.

---

# 41. ZFS

If installed:

- Pools
- Pool health
- VDEVs
- Datasets
- Capacity
- Compression
- Snapshots
- Mount points
- Relevant health state

---

# 42. Btrfs

If present:

- Filesystems
- Devices
- Subvolumes
- Profiles
- RAID configuration
- Snapshots
- Usage
- Mount options
- Relevant health information

---

# 43. Encryption

Detect and document:

- LUKS volumes
- LUKS version
- Cipher
- Cipher mode
- Key size
- PBKDF
- Active mappings
- Encrypted swap
- Filesystem-level encryption
- TPM-bound encryption where detectable
- `/etc/crypttab` structure

Never output:

- Encryption keys
- Recovery keys
- Passphrases
- Keyfile contents

---

# 44. Filesystems

Collect:

- Filesystem types
- Labels
- UUIDs according to privacy profile
- Mount points
- Mount options
- Capacity
- Used space
- Free space
- Inode usage
- Read-only state
- Network filesystems
- SMB mounts
- NFS mounts
- Automounts
- Quotas
- Reserved space
- Filesystem features
- Relevant filesystem health indicators

---

# 45. `/etc/fstab`

Parse and document:

- Device/source
- Mount point
- Filesystem
- Mount options
- Dump
- fsck pass
- Missing targets
- Potential stale entries

Sensitive information must be sanitized.

---

# 46. Network Hardware

Collect:

- Physical interfaces
- Virtual interfaces
- Interface names
- Interface type
- MAC addresses
- Link state
- Link speed
- Duplex
- MTU
- Driver
- Firmware
- PCI/USB association

MAC addresses may be redacted in public mode.

---

# 47. Network Addressing

Collect:

- IPv4 addresses
- IPv6 addresses
- Prefixes
- Default gateway
- Routing tables
- Policy routing
- ARP/neighbour state
- Network namespaces
- Bridges
- Bonds
- VLANs
- Tunnels
- Virtual interfaces
- Docker bridges

Public mode should support IP sanitization.

---

# 48. Network Configuration

Detect:

- NetworkManager
- systemd-networkd
- Netplan
- ifupdown
- Other supported network managers

Document relevant configuration without exposing credentials.

---

# 49. DNS

Collect:

- Configured DNS resolvers
- `/etc/resolv.conf`
- Ownership/source of resolver configuration
- systemd-resolved state
- Search domains
- Local DNS services
- DNSSEC configuration
- DNSSEC state where determinable
- Hosts file
- Split DNS
- Docker DNS
- Pi-hole presence
- Local resolver topology

Optional safe resolution tests may be performed.

---

# 50. Listening Services and Ports

Collect:

- Listening TCP ports
- Listening UDP ports
- Bound addresses
- Owning process
- Owning user
- IPv4 listeners
- IPv6 listeners
- Loopback-only services
- LAN-facing services
- Externally bound services
- Container-published ports

Correlate:

```text
Port
 ↓
Process
 ↓
Service
 ↓
Container/Application
```

---

# 51. Active Network State

Summarize:

- Established connections
- Listening connections
- Connection counts
- Interface traffic counters
- Errors
- Dropped packets
- Retransmission indicators where available

Avoid unnecessarily recording remote endpoint information in public reports.

---

# 52. Firewall

Detect and inspect:

- UFW
- nftables
- iptables compatibility rules
- firewalld where applicable
- Default policies
- Allowed ports
- Denied ports
- NAT
- Forwarding
- Docker-generated rules
- IP forwarding
- Relevant network-security configuration

The auditor never modifies firewall state.

---

# 53. Fail2ban / CrowdSec

If installed:

- Version
- Service state
- Enabled jails/scenarios
- Current status
- Relevant configuration metadata

Do not expose sensitive credentials.

---

# 54. SSH

Collect:

- OpenSSH client version
- OpenSSH server version
- sshd service state
- Listening addresses
- Listening ports
- Effective `sshd -T` configuration
- Configuration file locations
- Included configuration fragments
- Authentication methods
- PasswordAuthentication
- PubkeyAuthentication
- KbdInteractiveAuthentication
- AuthenticationMethods
- PermitRootLogin
- PermitEmptyPasswords
- AllowUsers
- DenyUsers
- AllowGroups
- DenyGroups
- MaxAuthTries
- LoginGraceTime
- Ciphers
- MACs
- KEX algorithms
- Host-key algorithms
- Host-key fingerprints
- Authorized-key inventory/fingerprints where appropriate
- Recent authentication-success summary
- Recent authentication-failure summary

Never output private SSH keys.

The system should detect contradictory SSH configuration fragments and distinguish:

```text
Configured values
vs.
Effective sshd configuration
```

---

# 55. Users and Groups

Collect:

- Local users
- UID
- Primary GID
- Group memberships
- Login shell
- Home directory
- Human vs system account
- sudo membership
- UID 0 accounts
- Locked accounts
- Account expiration
- Password status without hashes
- Last login
- Sudoers structure
- Privileged groups

Never output password hashes.

---

# 56. Linux Security Controls

Inspect:

- AppArmor
- SELinux where applicable
- Seccomp availability
- Kernel lockdown
- Secure Boot
- TPM
- ASLR
- ptrace restrictions
- Core-dump policy
- Relevant `/proc` restrictions
- PAM configuration
- Audit subsystem
- Relevant sysctl hardening
- Kernel security mitigations

---

# 57. systemd

Collect:

- systemd version
- Running units
- Enabled units
- Disabled units
- Failed units
- Masked units
- Timers
- Socket units
- Mount units
- Custom services
- Service dependencies
- Restart policies
- Boot targets
- Services running as root
- Service security information where supported
- `systemd-analyze security` information where appropriate
- Boot performance

---

# 58. Processes

Collect:

- Process count
- Process tree
- Highest CPU consumers
- Highest memory consumers
- Long-running processes
- Zombie processes
- Process owners
- Relevant process capabilities
- Cgroup association
- Resource limits

Avoid dumping sensitive command-line secrets.

Command-line sanitization must occur before reporting.

---

# 59. Runtime Health

Collect:

- Load averages
- CPU utilization
- Memory utilization
- Swap utilization
- CPU pressure
- Memory pressure
- I/O pressure
- OOM events
- Resource exhaustion indicators
- Failed services
- Kernel warnings
- Disk errors

---

# 60. Package Inventory

For Debian/Ubuntu initially:

- dpkg package inventory
- Package versions
- APT package state
- Manually installed packages
- Automatically installed packages
- Held packages
- Residual packages
- Pending updates
- Pending security updates
- Repository configuration
- Repository signing configuration
- Ubuntu Pro/ESM state where applicable

Also detect:

- Snap
- Flatpak
- pip
- npm global packages
- Go tooling
- Rust tooling

where appropriate.

---

# 61. Docker Engine

Collect:

- Docker client version
- Docker server version
- API version
- Storage driver
- Logging driver
- Cgroup driver
- Cgroup version
- Docker root directory
- Docker daemon configuration
- Registry configuration with sanitization
- Live-restore configuration
- Docker disk usage
- Engine health

---

# 62. Docker Containers

For every container:

- Name
- ID
- Image
- Image ID
- Image digest where available
- Creation time
- Start time
- Current state
- Health state
- Restart count
- Restart policy
- Published ports
- Exposed ports
- Networks
- IP addresses according to profile
- Mounts
- Bind mounts
- Named volumes
- Running user
- Privileged state
- Capabilities
- Devices
- Resource limits
- CPU limits
- Memory limits
- Health check
- Dependencies
- Labels
- Environment variable names

Secret environment values must never be exposed in sanitized mode.

---

# 63. Docker Images

Collect:

- Repository
- Tag
- Image ID
- Digest
- Creation time
- Size
- Usage
- Dangling state
- Containers using image

Potentially identify:

- `latest` tags
- Unused images
- Old images

without automatically deleting anything.

---

# 64. Docker Volumes

Collect:

- Volume names
- Drivers
- Mount points
- Usage
- Containers using volumes
- Orphaned/unused status where safely determinable

---

# 65. Docker Networks

Collect:

- Network name
- Driver
- Scope
- Subnet
- Gateway
- Connected containers
- Internal state
- IPv6 configuration
- Relevant options

---

# 66. Docker Compose

Discover Compose projects.

Collect:

- Project name
- Compose file locations
- Services
- Profiles
- Networks
- Volumes
- Bind mounts
- Port mappings
- Restart policies
- Health checks
- Dependencies
- Environment-file presence
- Configuration relationships

Never dump `.env` secrets.

---

# 67. Container Security

Identify:

- Privileged containers
- Host networking
- Docker socket mounts
- Sensitive host mounts
- Writable host mounts
- Root-running containers
- Added Linux capabilities
- Dropped capabilities
- `no-new-privileges`
- Seccomp profiles
- AppArmor profiles
- Read-only root filesystems
- Published ports
- Unpinned image tags
- Health failures

These are observations, not automatic vulnerability verdicts.

---

# 68. Caddy

Collect:

- Caddy version
- Installation method
- Service/container state
- Caddyfile location
- Configuration locations
- Site inventory
- Hostnames
- Reverse-proxy destinations
- Upstreams
- HTTP/HTTPS configuration
- TLS mode
- Local CA usage
- Logging configuration
- Caddy storage paths
- Certificate storage structure
- PKI structure

Private keys may be detected as present but their contents must never be emitted.

---

# 69. TLS and PKI

For certificates discovered in configured service locations:

- Subject
- Issuer
- SANs
- Serial according to privacy policy
- Public-key algorithm
- Public-key size
- Signature algorithm
- Valid-from
- Valid-until
- Remaining validity
- Self-signed state
- Chain information
- Local CA relationship
- Expiration warnings

Detect:

- Root CA
- Intermediate CA
- Leaf certificates
- Expired certificates
- Near-expiry certificates
- Broken chains where determinable

Private key presence:

```text
Present: yes
Contents: NEVER EXPORTED
```

---

# 70. Application Discovery

The project should support application-aware plugins.

Initial candidates:

- Jellyfin
- Paperless-ngx
- Pi-hole
- qBittorrent
- Sonarr
- Radarr
- Prowlarr
- Bazarr
- Kavita
- SearXNG
- Redis
- Valkey
- PostgreSQL
- MariaDB/MySQL
- SQLite-backed applications
- Samba
- NFS
- Generic web applications

Application plugins should report:

- Version
- State
- Ports
- Bind addresses
- Container/service relationship
- Persistent storage
- Dependencies
- Configuration locations
- Reverse proxy
- Health state

Credentials must never be dumped.

---

# 71. Scheduled Work

Inspect:

- system cron
- User crontabs
- `/etc/cron.*`
- systemd timers
- `at` jobs
- Maintenance tasks
- Backup schedules
- Update schedules
- Certificate-renewal mechanisms
- Application scheduling where safely discoverable

---

# 72. Backups and Recoverability

Detect:

- Backup software
- Backup services
- Backup destinations
- Snapshot mechanisms
- Last successful backup where determinable
- Backup schedule
- Retention configuration
- Filesystems included/excluded
- Configuration backup presence
- Restore metadata availability

The auditor should never copy backup contents into the report.

---

# 73. Logs and System Health

Collect summarized information from:

- systemd journal
- Kernel log
- Relevant system logs

Report:

- Current boot errors
- Kernel errors
- Filesystem errors
- Disk errors
- OOM events
- Machine-check events
- Hardware errors
- Repeated service crashes
- Unexpected shutdowns
- Failed units
- Log storage usage
- Log rotation configuration

Avoid dumping massive raw logs into the primary Markdown report.

---

# 74. Thermal State

Collect:

- CPU temperature
- Motherboard sensors
- NVMe temperature
- HDD/SSD temperature
- GPU temperature where available
- Thermal zones
- Fan speeds
- Throttling indicators
- Critical temperature events where available

---

# 75. Power

Collect where available:

- Power-management configuration
- ACPI information
- CPU power policy
- Power state
- UPS detection
- UPS state
- Battery information for applicable systems
- Unexpected shutdown history

---

# 76. Boot Chain

Collect:

- BIOS/UEFI
- Bootloader
- GRUB metadata
- Kernel command line
- EFI system partitions
- Secure Boot
- initramfs information
- Installed kernels
- Running kernel
- Failed boot units
- Boot duration
- Boot-critical services

---

# 77. Time Synchronization

Collect:

- Current system time
- Timezone
- RTC state
- NTP implementation
- NTP synchronization state
- Configured time sources
- Clock synchronization
- Container timezone consistency where relevant

---

# 78. File Sharing

Inspect:

- Samba
- NFS

For Samba:

- Shares
- Paths
- Read/write state
- Guest access
- Relevant permissions

For NFS:

- Exports
- Paths
- Export options
- Relevant access policy

Never output credentials.

---

# 79. File Permissions and Sensitive Paths

Inspect selected security-relevant locations for:

- Ownership
- Permissions
- ACLs
- World-writable state
- SUID
- SGID
- Linux capabilities
- SSH directory permissions
- Docker socket permissions
- Configuration permissions
- Private-key permissions

This should be targeted rather than recursively crawling the entire filesystem by default.

---

# 80. Security and Update Posture

Report:

- Pending security updates
- Distribution security state
- Ubuntu Pro/ESM state where applicable
- Automatic-update configuration
- Reboot-required state
- Unsupported repositories
- End-of-life information where locally determinable
- Kernel security information
- Package update state

Current CVE correlation should be an optional network-enabled module rather than part of the offline core.

---

# 81. Hardware-to-Service Topology

One of the project's major capabilities should be relationship reconstruction.

Example:

```text
Physical Disk
      ↓
Partition
      ↓
LUKS
      ↓
LVM Physical Volume
      ↓
Volume Group
      ↓
Logical Volume
      ↓
ext4
      ↓
/srv/appdata
      ↓
Docker Bind Mount
      ↓
Container
      ↓
Application
      ↓
Caddy Reverse Proxy
      ↓
HTTPS Hostname
```

This transforms an inventory into an infrastructure model.

---

# 82. Network Topology

Example:

```text
Physical NIC
    │
    ▼
eno1
    │
    ▼
192.168.x.x
    │
    ├──────────── Host Services
    │
    └──────────── Docker
                       │
                       ├── bridge A
                       │     ├── Caddy
                       │     └── Application
                       │
                       └── bridge B
                             ├── Database
                             └── Application
```

---

# 83. Service Topology

Example:

```text
Browser
   │
 HTTPS
   │
   ▼
Caddy
   │
   ▼
paperless-webserver
   │
   ├── PostgreSQL
   ├── Redis
   └── Persistent Storage
          │
          ▼
      /srv/appdata
          │
          ▼
      Logical Volume
          │
          ▼
      Physical Disk
```

---

# 84. Topology Representation

Topology should be represented internally as structured nodes and relationships.

Example:

```text
NODE:
    disk:nvme0n1

EDGE:
    contains

NODE:
    partition:nvme0n1p3
```

This makes future graph rendering possible.

Potential outputs:

- Markdown trees
- Mermaid
- Graphviz
- D2
- Interactive web graph

Graph generation should remain optional.

---

# 85. Historical Snapshots

Every audit should be independently preserved.

Example:

```text
2026-09-20
2026-09-23
2026-09-24
2026-10-01
```

Each snapshot represents server state at a specific point in time.

---

# 86. Configuration Drift

The project should compare structured snapshots.

Example:

```diff
SYSTEM

- Kernel 7.0.0-31
+ Kernel 7.0.0-34


DOCKER

+ paperless-webserver
+ paperless-db
+ paperless-redis


SSH

- PubkeyAuthentication yes
+ PubkeyAuthentication no


STORAGE

- /srv/appdata used: 31 GB
+ /srv/appdata used: 46 GB


CADDY

+ paperless.nodezero
```

---

# 87. Drift Categories

Track changes in:

- Hardware
- RAM
- USB devices
- PCI devices
- Storage devices
- SMART health
- Partitions
- LVM
- Filesystems
- Encryption
- Mounts
- Network interfaces
- Addresses
- Routes
- DNS
- Firewall
- Listening ports
- SSH
- Users
- Groups
- Security controls
- Packages
- Kernel
- systemd
- Docker
- Containers
- Images
- Volumes
- Networks
- Compose
- Caddy
- TLS certificates
- Applications
- Scheduled tasks
- Backup state

---

# 88. Health Analysis

The analysis engine may deterministically identify states such as:

```text
OK
INFO
NOTICE
WARNING
CRITICAL
UNKNOWN
```

However, health analysis must remain evidence-based.

Example:

```text
Disk /dev/sda

SMART overall health: PASSED
Temperature: 39°C
Reallocated sectors: 0
Pending sectors: 0

Assessment: OK
```

Analysis rules should be documented and testable.

---

# 89. Exposure Analysis

The project should distinguish:

```text
127.0.0.1:8080
    → Loopback only

192.168.x.x:8096
    → LAN-bound

0.0.0.0:22
    → All IPv4 interfaces

:::
    → All IPv6 interfaces
```

It should correlate exposure with:

- Processes
- systemd services
- Docker containers
- Caddy
- Firewall state

---

# 90. Configuration Conflict Detection

Where meaningful, the auditor should detect situations where configuration files disagree.

Example:

```text
SSH Configuration

/etc/ssh/sshd_config:
    PasswordAuthentication no

/etc/ssh/sshd_config.d/50-cloud-init.conf:
    PasswordAuthentication yes

/etc/ssh/sshd_config.d/00-password.conf:
    PasswordAuthentication yes

Effective sshd configuration:
    PasswordAuthentication yes
```

The effective state must be distinguished from source configuration.

---

# 91. Audit Provenance

Every audit should record:

- Audit tool name
- Tool version
- Git commit where available
- Audit schema version
- Timestamp
- Hostname
- Audit duration
- Audit profile
- Privileges available
- Operating user
- Collectors requested
- Collectors executed
- Collectors skipped
- Collector failures
- Dependencies missing
- Sanitization mode
- Network-access policy
- Renderer versions

---

# 92. Integrity

Every snapshot should optionally include:

```text
checksums.sha256
```

Example:

```text
SHA256(audit.md)
SHA256(audit.json)
SHA256(manifest.json)
```

This allows later verification that archived audit artifacts have not changed.

---

# 93. Manifest

Example:

```json
{
  "tool": "serveraudit",
  "version": "0.1.0",
  "schema": "1.0",
  "profile": "private",
  "timestamp": "2026-09-24T10:17:00+05:30",
  "collectors": {
    "system": "success",
    "hardware": "success",
    "smart": "success",
    "docker": "success",
    "caddy": "success"
  },
  "network_access": false,
  "intentional_system_modification": false
}
```

---

# 94. Report Structure

The generated Markdown should itself be carefully organized.

Example:

```text
# Server Audit

## Executive Summary

## Audit Metadata

## System Identity

## Operating System

## Hardware

### Motherboard
### Firmware
### CPU
### Memory
### PCI
### USB

## Storage

### Physical Disks
### SMART Health
### Partitions
### LVM
### RAID
### Encryption
### Filesystems
### Mounts

## Network

### Interfaces
### Addresses
### Routes
### DNS
### Listening Ports
### Firewall

## Security

### SSH
### Users
### Groups
### sudo
### AppArmor / SELinux
### Kernel Security
### Secure Boot
### TPM
### Permissions

## Runtime

### systemd
### Processes
### Resource Usage
### Logs
### Thermal
### Power

## Packages

## Docker

### Engine
### Containers
### Images
### Volumes
### Networks
### Compose
### Container Security

## Caddy

### Sites
### Reverse Proxies
### TLS
### PKI

## Applications

## Scheduled Tasks

## Backups

## Topology

### Storage Topology
### Network Topology
### Service Topology

## Findings

## Collection Limitations

## Audit Provenance
```

---

# 95. Markdown Quality

The generated Markdown must be:

- Clean
- Predictable
- Consistently formatted
- Searchable
- Git-friendly
- Diff-friendly
- Human-readable
- Machine-processable where practical

Avoid enormous unstructured command dumps.

Prefer tables and structured sections.

---

# 96. Example Summary

```markdown
# Server Audit

**Hostname:** nodezero  
**OS:** Ubuntu 26.04.1 LTS  
**Kernel:** 7.0.0-34-generic  
**Architecture:** x86_64  
**Audit:** 2026-09-24 10:17 +05:30  

## Summary

| Component | Status |
|---|---|
| System | OK |
| Hardware | OK |
| Memory | OK |
| Storage | OK |
| SMART | OK |
| Network | OK |
| SSH | OK |
| Docker | OK |
| Caddy | OK |
| Services | OK |

## Collection

Collectors successful: 37  
Collectors partial: 1  
Collectors skipped: 2  
Collectors failed: 0
```

---

# 97. Application Plugin Architecture

Applications should not be hard-coded into the core.

Example:

```text
applications/
├── jellyfin/
│   ├── collector.py
│   └── manifest.yaml
├── paperless/
│   ├── collector.py
│   └── manifest.yaml
└── pihole/
    ├── collector.py
    └── manifest.yaml
```

Third-party developers should eventually be able to add application support without modifying the core engine.

---

# 98. Collector Extensibility

Adding a new collector should require:

```text
1. Collector implementation
2. Collector manifest
3. Output schema
4. Sanitization policy
5. Tests
6. Documentation
```

Example future collector:

```text
collectors/
└── gpu/
    ├── collector.py
    ├── manifest.yaml
    ├── schema.json
    └── tests/
```

---

# 99. Testing Strategy

Testing is critical because the project executes privileged observations.

Tests should include:

- Unit tests
- Integration tests
- Snapshot tests
- Schema tests
- Sanitization tests
- Secret-leak tests
- Collector failure tests
- Missing-dependency tests
- Permission tests
- Distribution compatibility tests
- Renderer tests
- Diff tests

---

# 100. Sanitization Tests

The test suite should deliberately contain fake secrets:

```text
password=SuperSecret123
API_KEY=fake-secret-key
Authorization: Bearer fake-token
DATABASE_URL=postgres://user:password@db/database
```

The sanitized report must prove that these values never appear.

Secret leakage should be treated as a test failure.

---

# 101. Safety Testing

The project should make it possible to inspect the commands collectors may execute.

Potential CI checks should detect or require review for commands associated with state modification.

Examples requiring explicit scrutiny:

```text
rm
mv
cp into system paths
chmod
chown
apt install
apt remove
systemctl start
systemctl stop
systemctl restart
docker stop
docker rm
mount
umount
cryptsetup open
nft add
iptables -A
```

The purpose is defense in depth, not blind string matching as the only safety mechanism.

---

# 102. Dependency Philosophy

Dependencies should be minimized.

The auditor should:

1. Use standard Linux interfaces where possible.
2. Detect optional tools.
3. Use richer collectors when tools are available.
4. Report missing capabilities rather than automatically installing software.

Example:

```text
SMART collector

smartctl found:
    Full SMART collection available.

smartctl missing:
    SMART collector skipped.
    Reason: smartmontools not installed.
```

The audit should not silently install `smartmontools`.

---

# 103. Performance

The audit should be comprehensive without being wasteful.

Collectors should:

- Avoid repeated command execution
- Cache shared observations
- Avoid repeatedly parsing the same file
- Avoid unnecessary filesystem traversal
- Avoid expensive recursive operations by default
- Parallelize independent safe collectors where beneficial
- Place timeouts around potentially hanging commands

---

# 104. Determinism

Two audits performed against materially identical server state should produce materially equivalent structured results.

Volatile values should be clearly identified.

Examples:

```text
Stable:
    CPU model
    disk model
    filesystem
    package version

Semi-stable:
    IP address
    service state
    Docker image

Volatile:
    CPU utilization
    RAM utilization
    connection counts
    temperature
```

Historical diffing should distinguish configuration drift from ordinary runtime fluctuation.

---

# 105. Privacy

The project should have an explicit privacy model.

Possible sensitivity classifications:

```text
PUBLIC
INTERNAL
SENSITIVE
SECRET
NEVER_COLLECT
```

Example:

```text
OS version                 PUBLIC
CPU model                  PUBLIC
Internal hostname          INTERNAL
Private IP                 INTERNAL
Disk serial                SENSITIVE
API token                  SECRET
Private key contents       NEVER_COLLECT
Password                   NEVER_COLLECT
```

---

# 106. Public Report Guarantee

The public profile should prioritize:

> Maximum diagnostic information with minimum unnecessary disclosure.

A public report should preserve architecture while removing credentials and sensitive identifiers.

---

# 107. No AI Requirement

AI must not be required anywhere in the trusted collection pipeline.

```text
Linux
  ↓
Deterministic collectors
  ↓
Structured model
  ↓
Deterministic sanitizer
  ↓
Deterministic renderer
  ↓
Markdown
```

A user may later choose to analyze `audit.md` with an AI system, but that is outside the core project's requirements.

---

# 108. No Cloud Requirement

Everything necessary for normal auditing should operate locally.

The server owner retains:

- Raw observations
- Structured data
- Markdown
- Historical snapshots
- Topology
- Reports

No third-party account should be required.

---

# 109. Front Page / README Concept

The GitHub front page should immediately communicate:

```text
LINUX SERVER AUDIT
==================

One command.
One sudo authentication.
No intentional system modification.
No cloud.
No AI.
No telemetry.
No outbound network access by default.

Comprehensive Linux server documentation:

✓ Operating System
✓ Hardware
✓ CPU
✓ RAM
✓ Firmware
✓ PCI
✓ USB
✓ Storage
✓ SMART
✓ LVM
✓ RAID
✓ Encryption
✓ Filesystems
✓ Network
✓ DNS
✓ Firewall
✓ SSH
✓ Users
✓ Security
✓ systemd
✓ Processes
✓ Packages
✓ Docker
✓ Compose
✓ Caddy
✓ TLS / PKI
✓ Applications
✓ Scheduled Tasks
✓ Backups
✓ Logs
✓ Thermals
✓ Power
✓ Boot
✓ File Sharing
✓ Permissions
✓ Topology
✓ Historical Baselines
✓ Configuration Drift

Outputs:

✓ Markdown
✓ JSON
✓ Optional HTML
✓ Optional PDF
✓ Self-hosted Web UI
```

---

# 110. Example User Experience

Installation:

```bash
git clone <repository>
cd linux-server-audit
```

Audit:

```bash
./audit.sh
```

Interaction:

```text
Linux Server Audit v0.1

Hostname: nodezero

Audit profile:
    Private

Network access:
    Disabled

System modification:
    None intended

Elevated privileges are required for comprehensive collection.

[sudo] password for user:

✓ sudo authenticated

Collecting...

✓ System
✓ Hardware
✓ Firmware
✓ CPU
✓ Memory
✓ PCI
✓ USB
✓ Storage
✓ SMART
✓ LVM
✓ Encryption
✓ Filesystems
✓ Network
✓ DNS
✓ Firewall
✓ SSH
✓ Users
✓ Security
✓ systemd
✓ Processes
✓ Packages
✓ Docker
✓ Compose
✓ Caddy
✓ TLS
✓ Applications
✓ Scheduled Tasks
✓ Backups
✓ Logs
✓ Thermals
✓ Boot

Building topology...

✓ Storage topology
✓ Network topology
✓ Service topology

Sanitizing...

✓ Complete

Rendering...

✓ Markdown
✓ JSON

Audit complete.

Output:
audits/nodezero-2026-09-24T101700+0530/

Primary report:
audit.md
```

---

# 111. Historical Comparison User Experience

```bash
nodeaudit diff \
    nodezero-2026-09-23T220000+0530 \
    nodezero-2026-09-24T101700+0530
```

Output:

```text
SERVER DRIFT REPORT

Hardware
    No changes

Kernel
    7.0.0-31 → 7.0.0-34

SSH
    PubkeyAuthentication:
        yes → no

Docker
    Added:
        paperless-webserver
        paperless-db

Storage
    /srv/appdata:
        31 GB → 46 GB used

Caddy
    Added route:
        paperless.nodezero

Packages
    Added: 4
    Removed: 0
    Updated: 17
```

---

# 112. Potential Future Features

Once the core auditor is mature, possible extensions include:

- Additional Linux distributions
- Remote SSH auditing
- Multiple-server dashboards
- Fleet comparison
- Interactive topology graphs
- Prometheus integration
- Optional CVE correlation
- Signed audit artifacts
- Cryptographic snapshot chains
- Git-backed audit history
- Automated scheduled audits
- Notifications when significant drift occurs
- Plugin marketplace/repository
- REST API
- Export to documentation systems
- Optional anonymized support bundles

These should not compromise the simplicity or safety of the core auditor.

---

# 113. Development Roadmap

## Version 0.1

Focus on the auditing engine.

Support:

- Ubuntu/Debian
- CLI
- Single sudo authentication
- System
- Hardware
- CPU
- Memory
- Storage
- SMART
- LVM
- Filesystems
- Network
- SSH
- systemd
- Packages
- Docker
- Compose
- Caddy
- Markdown
- JSON
- Sanitization
- Audit manifest

No web frontend is required for the first functional engine.

---

## Version 0.2

Add:

- Encryption
- RAID
- Security controls
- TLS/PKI
- Logs
- Thermal state
- Application plugins
- Improved topology
- Historical snapshot comparison

---

## Version 0.3

Add:

- Self-hosted web interface
- Audit history
- Run Audit button
- Report browser
- Snapshot comparison
- Download interface
- Optional HTML/PDF rendering

---

## Version 1.0

Target:

- Stable audit schema
- Mature sanitization
- Comprehensive Linux audit
- Stable plugin API
- Strong automated testing
- Documented security model
- Reproducible reports
- Reliable historical comparison
- Self-hosted frontend
- Production-quality documentation

---

# 114. Core Project Invariants

The following should remain true throughout development:

```text
ONE USER-INITIATED AUDIT
          │
          ▼
ONE SUDO AUTHENTICATION
          │
          ▼
OBSERVATIONAL COLLECTION
          │
          ▼
NO INTENTIONAL SYSTEM CONFIGURATION CHANGES
          │
          ▼
NO OUTBOUND NETWORK ACCESS BY DEFAULT
          │
          ▼
STRUCTURED LOCAL DATA
          │
          ▼
SECRET-AWARE SANITIZATION
          │
          ▼
TOPOLOGY + ANALYSIS
          │
          ▼
DETERMINISTIC REPORTING
          │
          ▼
MARKDOWN + JSON
          │
          ├──── Optional HTML
          │
          └──── Optional PDF
```

---

# 115. Project Identity

The project's distinguishing characteristics are not any individual Linux command.

Its identity comes from combining:

- Extremely broad server inspection
- One-command operation
- Minimal sudo interaction
- Observational safety
- Open-source inspectability
- No telemetry
- Offline-first operation
- Aggressive secret protection
- Structured canonical data
- High-quality Markdown
- Hardware-to-application topology
- Docker and Caddy awareness
- Historical server baselines
- Configuration-drift detection
- Self-hosted audit management
- Optional PDF/HTML
- No AI dependency

The objective is not to produce another collection of shell-command output.

The objective is to produce a coherent, reproducible description of an entire Linux server.

---

# 116. Final Concept

At its most complete, Linux Server Audit should be capable of describing the complete observable stack:

```text
PHYSICAL MACHINE
       │
       ├── Motherboard / Firmware
       ├── CPU
       ├── RAM
       ├── PCI
       ├── USB
       │
       ▼
PHYSICAL STORAGE
       │
       ├── SMART / NVMe Health
       ├── Partitions
       ├── RAID
       ├── Encryption
       ├── LVM
       └── Filesystems
       │
       ▼
LINUX
       │
       ├── Distribution
       ├── Kernel
       ├── Boot
       ├── Security
       ├── Users
       ├── Permissions
       ├── Packages
       ├── systemd
       └── Processes
       │
       ▼
NETWORK
       │
       ├── Interfaces
       ├── Addresses
       ├── Routes
       ├── DNS
       ├── Firewall
       ├── SSH
       └── Listening Services
       │
       ▼
CONTAINER PLATFORM
       │
       ├── Docker Engine
       ├── Images
       ├── Containers
       ├── Volumes
       ├── Networks
       └── Compose
       │
       ▼
APPLICATIONS
       │
       ├── Jellyfin
       ├── Paperless
       ├── Pi-hole
       ├── qBittorrent
       ├── Sonarr
       ├── Radarr
       ├── Prowlarr
       ├── Bazarr
       ├── Kavita
       ├── SearXNG
       └── Other detected applications
       │
       ▼
REVERSE PROXY / PKI
       │
       ├── Caddy
       ├── Routes
       ├── TLS
       ├── Certificates
       └── Local PKI
       │
       ▼
SERVICE EXPOSURE
       │
       └── Hostnames / Ports / Interfaces
       │
       ▼
CURRENT HEALTH
       │
       ├── Resources
       ├── Disk Health
       ├── Services
       ├── Logs
       ├── Thermals
       └── Security State
       │
       ▼
HISTORICAL BASELINE
       │
       └── Configuration Drift
```

The resulting audit should allow a technically competent person who has never seen the machine before to understand, as far as safely and locally observable:

> **What the server is, what it contains, how it is configured, what it is running, how its components relate to one another, what its current health and security-relevant state are, and what has changed over time.**

That is the project.