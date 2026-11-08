<div align="center">

# Auditor

### A tool that saves your tooling.

**A deep, read-only audit of a Linux server, written down as a clean report you can read, diff, archive, and paste into any AI assistant.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/MohnishShende/auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/MohnishShende/auditor/actions/workflows/ci.yml)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-informational.svg)](#-requirements)
[![No Cloud](https://img.shields.io/badge/Cloud-None-success.svg)](#-security--privacy-model)
[![No AI](https://img.shields.io/badge/AI-None-success.svg)](#-using-reports-with-ai-assistants)
[![Zero Telemetry](https://img.shields.io/badge/Telemetry-None-success.svg)](#-security--privacy-model)
[![Read Only](https://img.shields.io/badge/System%20changes-None-success.svg)](#-security--privacy-model)

</div>

---

## 📖 Table of contents

- [What is Auditor?](#-what-is-auditor)
- [Requirements](#-requirements)
- [Install](#-install)
- [Quick start](#-quick-start)
- [Audit modes: `user` vs `sudo`](#-audit-modes-user-vs-sudo)
- [Profiles: `private` vs `public`](#-profiles-private-vs-public)
- [Command reference](#-command-reference)
- [What you get: the output bundle](#-what-you-get-the-output-bundle)
- [How to read a report](#-how-to-read-a-report)
- [How it works](#-how-it-works)
- [What gets audited (43 modules)](#-what-gets-audited-43-modules)
- [Drift detection and baselines](#-drift-detection-and-baselines)
- [Web dashboard](#-web-dashboard)
- [Using reports with AI assistants](#-using-reports-with-ai-assistants)
- [Security & privacy model](#-security--privacy-model)
- [Platform support and known limitations](#-platform-support-and-known-limitations)
- [Troubleshooting](#-troubleshooting)
- [Development](#-development)
- [Author & license](#-author--license)

---

## 🎯 What is Auditor?

Auditor inspects a Linux server end to end, hardware, storage, network, security, containers, services and applications, and writes the result into a timestamped folder:

| You get | What it is |
|---|---|
| `audit.md` | A human-readable Markdown report. Read it, commit it, or paste it into an AI assistant. |
| `audit.json` | The canonical structured data. The report, the HTML and every comparison are built from this. |
| `audit.html` | A standalone single-file HTML report. |
| `manifest.json` + `checksums.sha256` | What ran, how long it took, and SHA-256 hashes so you can prove a report was not altered. |

It is built around four promises:

- **Read-only.** It only observes. It never installs, restarts, mounts, formats, or edits anything. A command denylist enforces this in code.
- **Local.** No cloud, no telemetry, no outbound network, and **no AI in the tool**. The report is generated deterministically, so the same server gives the same report.
- **Honest.** When it could not read something (no root, tool not installed), the report says *not collected*. It never presents a gap as a healthy value.
- **Safe to share (with care).** Secrets are redacted in every report, and a `public` profile also masks the hostname, IPs, MACs and serial numbers. See [what `public` does not mask](#-profiles-private-vs-public) before posting a report anywhere public.

```mermaid
flowchart LR
    A["Your Linux server"] -->|"43 read-only collectors"| B["Auditor"]
    B --> C["audit.md<br/>read it / paste it"]
    B --> D["audit.json<br/>diff it / script it"]
    B --> E["audit.html<br/>open it"]
    B --> F["manifest.json + checksums.sha256<br/>prove it is untouched"]
```

---

## ✅ Requirements

| Need | Details |
|---|---|
| **OS** | **Linux.** Developed and verified on Ubuntu 26.04 LTS. Best on Debian/Ubuntu-family systems (package inventory uses `dpkg`, `apt`, `snap`, `flatpak`). Other distributions work, but the package section will be empty. |
| **Python** | 3.10 or newer, with the `venv` module (`python3-venv` on Debian/Ubuntu). |
| **Python packages** | `PyYAML` and `Jinja2`. Installed for you. |
| **Privileges** | None for `--mode user`. `sudo` (passwordless or with a password) for `--mode sudo`. Never run Auditor as root in user mode. |
| **Host tools (optional)** | Each module uses ordinary system tools such as `lscpu`, `lsblk`, `ip`, `ss`, `smartctl`, `dmidecode`, `docker`. A missing tool turns *that one module* into `DEPENDENCY_MISSING` or `SKIPPED`. The rest of the audit continues. See the [module table](#-what-gets-audited-43-modules) for the tool each one needs. |
| **PDF (optional)** | [WeasyPrint](https://weasyprint.org/) via `pip install -e ".[pdf]"`. |

> **macOS and Windows are not supported yet.** On macOS the tool runs but collects almost nothing, so it prints a warning and the report is flagged *Unsupported*. Windows is not supported. See [Platform support](#-platform-support-and-known-limitations).

---

## 📦 Install

```bash
git clone https://github.com/MohnishShende/auditor.git
cd auditor
./install.sh
```

`install.sh` is safe to re-run. It will:

1. Find a Python 3.10+ interpreter and check that `venv` works (with a distro-specific hint if not).
2. Create a project-local virtual environment in `./.venv`.
3. Install Auditor and its two dependencies into it (`pip install -e .`).
4. Write the launcher `./bin/serveraudit` (also available as `./bin/nodeaudit`).
5. Link both into `~/.local/bin` **if that folder exists and is on your `PATH`**.
6. Verify the install by running `serveraudit --version`.

If `~/.local/bin` is not on your `PATH`, run the tool as `./bin/serveraudit`, or add the folder to your `PATH`.

<details>
<summary><b>Manual install (no script)</b></summary>

```bash
git clone https://github.com/MohnishShende/auditor.git
cd auditor
python3 -m venv .venv
.venv/bin/pip install -e .          # core
.venv/bin/pip install -e ".[pdf]"   # optional: PDF output
.venv/bin/serveraudit --version
```

</details>

<details>
<summary><b>Uninstall</b></summary>

Nothing is installed outside the project folder, apart from two optional links:

```bash
rm -f ~/.local/bin/serveraudit ~/.local/bin/nodeaudit
rm -rf /path/to/auditor
```

Audit folders (`audits/`) live wherever you ran the tool, in the current directory by default.

</details>

---

## 🚀 Quick start

**Audit this server without any privileges:**

```bash
serveraudit audit --mode user
```

**Audit it fully (needs sudo):**

```bash
serveraudit audit --mode sudo
```

Either command takes seconds and writes a folder like `audits/myserver-2026-11-08T041819.7302850000/`. Open `audit.md` first.

**Make a version you can share:**

```bash
serveraudit audit --mode sudo --profile public
```

**See what you have, check it, and compare it:**

```bash
serveraudit list
serveraudit verify audits/<snapshot>
serveraudit diff audits/<older-snapshot> audits/<newer-snapshot>
```

> **If you leave out `--mode`:** in a terminal Auditor asks you to choose `user` or `sudo`. With no terminal (cron, CI, a pipe) it defaults to `user`. Be explicit in scripts.

> **`./audit.sh`** is a convenience launcher: it checks sudo once, keeps the sudo timestamp alive during the run, then calls `serveraudit audit` with your arguments. Pass the mode yourself, for example `./audit.sh --mode sudo`.

---

## 🔐 Audit modes: `user` vs `sudo`

| | `--mode user` | `--mode sudo` |
|---|---|---|
| Needs sudo | No | Yes |
| `sudo` processes spawned | **Zero, guaranteed** (enforced in code and covered by tests) | Only for modules that need root, one `sudo -n` per command |
| Depth | Shallower. Root-only modules are skipped or partial. | Full. |
| Use it for | Quick look, least-privilege environments, the web dashboard | The real audit |

### What `user` mode cannot see

13 modules need root: **`firewall`, `ports`, `ssh` (`sshd -T`), `users` (password status), `security`, `tls`, `fail2ban`, `smart`, `lvm`, `encryption`, `logs`, `sharing`, `scheduled`**. A few more (for example DMI hardware detail) add information when elevated.

The report does not hide this. A user-mode report says so in its header and in the affected rows:

```text
- Coverage: Reduced (user mode). 3 module(s) not fully collected; `unknown` / `not collected` values
  mean "could not be read without root", not "unset". Re-run with `--mode sudo` for full coverage.
  - `firewall` (SKIPPED): Skipped in user mode (requires elevated privilege)
  - `smart`    (SKIPPED): Skipped in user mode (requires elevated privilege)
  - `ssh`      (PARTIAL): SSH effective config not collected: sshd -T requires --mode sudo
```

### How sudo is validated

```mermaid
flowchart TD
    S["serveraudit audit --mode sudo"] --> R{"Running as root?"}
    R -- yes --> OK["Elevated: collectors run directly"]
    R -- no --> H{"sudo installed?"}
    H -- no --> NO["Unprivileged run + warning"]
    H -- yes --> P{"sudo -n true succeeds?<br/>(passwordless sudo)"}
    P -- yes --> EL["Elevated: each root command runs as sudo -n"]
    P -- no --> T{"Is a terminal attached?"}
    T -- yes --> V["Ask for your password once: sudo -v"]
    V -- ok --> EL
    V -- cancelled or wrong --> NO
    T -- no --> NO
```

- **Passwordless sudo works out of the box**, including on Ubuntu's newer `sudo-rs`, where `sudo -v` would otherwise demand a password even with `NOPASSWD`.
- **With a password:** you are asked once at the start. After that every elevated command uses `sudo -n`, so there are **no prompts in the middle of an audit**.
- **No terminal and no passwordless sudo:** Auditor never tries to prompt. It continues without elevation, prints a warning, and the report carries the *Coverage* block, so the result is never mistaken for a full audit.

---

## 🛡️ Profiles: `private` vs `public`

Every report is redacted for secrets. The profile decides how much *identifying detail* stays in.

| | `private` (default) | `public` |
|---|---|---|
| Passwords, tokens, API keys, private keys, password hashes, secret environment values | **Redacted** | **Redacted** |
| IPv4 addresses | Kept | Masked (`192.168.x.x`, `10.x.x.x`, `172.17.x.x`; public IPv4 → `xxx.xxx.xxx.xxx`) |
| MAC addresses | Kept | Last three bytes masked (`aa:bb:cc:xx:xx:xx`) |
| Disk serials, machine IDs, device UUIDs | Kept | Redacted (`[REDACTED_SERIAL]`, `[REDACTED_ID]`) |
| IPv6 addresses | Kept | Masked (`fe80:x:x:x:x:x:x:x`; `::1` is left alone) |
| Hostname | Kept | Replaced by `[REDACTED_HOST]` everywhere, including `manifest.json`; the folder is named `host-<timestamp>` |
| Intended for | You, your team, your private notes | Forums, issue trackers, support tickets, AI assistants |

> ⚠️ **Read a `public` report once before you post it.** It still contains **usernames, Docker container and application names, installed-package names, domain names and the names of other machines** (for example Caddy sites or DNS servers). If your username or a container name is identifying, edit it out. `public` removes secrets and the most identifying host, hardware and network details. It does not make a report anonymous.

### What redaction catches

Redaction works by **key name** and by **value shape**:

- **By key name** (words, not substrings): `db_password`, `api_key`, `secret_key_base`, `client_secret`, `access_token`, `authorization`, `private_key`, `api_keys`, `certificate_key`, `password_hash`, `PGPASSWORD`, and similar, wherever they appear as dictionary keys or as `NAME=value` in text. Settings that merely *talk about* secrets stay readable: `password_authentication`, `max_auth_tries`, `passno`, `password_status`.
- **By value shape:** password hashes (`$1$`, `$2b$`, `$5$`, `$6$`, `$y$` yescrypt, `$gy$`, argon2), PEM private key blocks, `Authorization:` header values, `Bearer` and `Basic` tokens, and credentials inside URLs (`postgres://user:pass@host`).
- **Never collected at all:** private keys and password hashes. The users module reads only whether an account is locked, never the hash.

---

## 🧰 Command reference

All commands are `serveraudit <command>`. `nodeaudit` is an alias. `serveraudit --version` prints the version.

### `audit`: run an audit

```bash
serveraudit audit [--mode {user,sudo}] [--profile {private,public}]
                  [--output-dir DIR] [--format LIST] [--config FILE] [-q]
```

| Option | Default | Meaning |
|---|---|---|
| `--mode` | asks in a terminal, else `user` | `user` (no sudo) or `sudo` (elevated). See [modes](#-audit-modes-user-vs-sudo). |
| `--profile` | `private` | `private` or `public`. See [profiles](#-profiles-private-vs-public). |
| `--output-dir` | `audits` | Where snapshot folders are created (relative to the current directory). |
| `--format` | `markdown,json,html` | Comma-separated: `markdown`, `json`, `html`, `pdf`. Markdown and JSON are always written. `pdf` needs WeasyPrint. |
| `--config` | none | Accepted, but **not applied in this version** (see [limitations](#-platform-support-and-known-limitations)). |
| `-q`, `--quiet` | off | Minimal terminal output. Warnings still print. |

### `list`: show saved snapshots

```bash
serveraudit list [--output-dir DIR]
```

### `verify`: prove a snapshot is untouched

```bash
serveraudit verify audits/<snapshot>
```

Recomputes the SHA-256 of every file against `checksums.sha256`. Prints `✓ ... integrity VERIFIED` or lists what changed.

### `diff`: compare two snapshots

```bash
serveraudit diff <snapshot-a> <snapshot-b> [--base-dir DIR]
```

Each argument can be a path or a folder name under `--base-dir` (default `audits`). See [drift detection](#-drift-detection-and-baselines).

### `render`: re-render an existing `audit.json`

```bash
serveraudit render audits/<snapshot>/audit.json --format {markdown,html,pdf} [-o FILE]
```

Markdown and HTML print to the terminal unless you pass `-o`. PDF needs `-o` and WeasyPrint. Useful after a renderer update, or to produce a different format from an old snapshot.

### `web`: start the dashboard

```bash
serveraudit web [--host 127.0.0.1] [--port 8080] [--output-dir DIR] [--allowed-host NAME ...]
```

See [web dashboard](#-web-dashboard).

---

## 📂 What you get: the output bundle

```text
audits/
└── <hostname>-<timestamp>/      # public profile: host-<timestamp>
    ├── audit.md           # human-readable report (always)
    ├── audit.json         # canonical structured data (always)
    ├── audit.html         # standalone HTML report (default; drop it with --format)
    ├── audit.pdf          # only with --format ...,pdf and WeasyPrint installed
    ├── manifest.json      # what ran, status and duration of every module
    └── checksums.sha256   # SHA-256 of every file above
```

- `audit.json` follows [`schemas/audit.schema.json`](schemas/audit.schema.json). It is the single source of truth, so you can script against it.
- A complete synthetic example is in [`examples/audit.md`](examples/audit.md) and [`examples/audit.json`](examples/audit.json).
- Snapshots never overwrite each other. Each run is a new folder.

> **PDF note:** if you ask for `pdf` and WeasyPrint is not installed, the PDF is skipped and the audit still succeeds. `serveraudit render --format pdf` tells you plainly when WeasyPrint is missing.

---

## 📑 How to read a report

`audit.md` has a fixed structure, so you always know where to look:

| # | Section | What is in it |
|---|---|---|
| 1 | **Executive Summary** | One table: system, hardware, CPU, memory, storage health, network, firewall, SSH, Docker, reverse proxy, applications. |
| 2 | **Findings & Health** | Rule-based problems, plus configuration conflicts. Empty is good: `All Health Checks Passed`. |
| 3 | System Identity & OS | Distribution, kernel, uptime, virtualization, boot mode. |
| 4 | Hardware, Motherboard & Firmware | DMI, BIOS/UEFI, Secure Boot, TPM. |
| 5 | Processor & Memory | CPU model and topology, RAM, swap. |
| 6 | Storage & Physical Health | Disks, SMART, filesystems, LVM, RAID. |
| 7 | Network, Addressing & Exposure | Interfaces, routes, DNS, **listening ports and what exposes them**. |
| 8 | Security, SSH & Accounts | `sshd -T` hardening, AppArmor/SELinux, sudo users. |
| 9 | Docker & Container Security | Engine, containers, privileged containers, socket mounts. |
| 10 | Caddy & Web Services | Sites, reverse-proxy upstreams, TLS certificates. |
| 11 | Discovered Applications | Known self-hosted apps mapped to their containers and ports. |
| 12 | Infrastructure & Storage Topology | Disk → … → application chains. |
| 13 | Scheduled Tasks, Backups & Logs | Cron, timers, backup tools, recent errors. |
| 14 | **Audit Provenance & Collector Limitations** | Status of every module and why anything was skipped. **Read this when something looks missing.** |

### Findings severities

| Severity | Examples of what raises it |
|---|---|
| 🔴 **CRITICAL** | Disk SMART failure, NVMe critical warning, filesystem ≥ 95 % full, degraded RAID array, **expired** TLS certificate |
| 🟠 **WARNING** | Reallocated sectors, filesystem ≥ 85 % full, failed systemd units, OOM-killer events, TLS certificate expiring soon, `fstab` problems |
| 🔵 **NOTICE** | Reboot required, several SSH config fragments, excessive nameservers |

Kernel pseudo-filesystems such as `efivarfs` are ignored for disk-space checks (they are always nearly full and mean nothing). `tmpfs` and container layers are still checked.

### Module statuses

Every module ends with one status, listed in section 14 and in `manifest.json`:

| Status | Meaning |
|---|---|
| `SUCCESS` | Collected normally. |
| `PARTIAL` | Collected some of it. The message says what is missing (for example SSH without `sshd -T`). |
| `SKIPPED` | Not applicable (for example ZFS not installed) or needs root and you ran `--mode user`. |
| `PERMISSION_DENIED` | The command needed a privilege it did not have. |
| `DEPENDENCY_MISSING` | A required tool (for example `lspci`) is not installed. |
| `UNSUPPORTED` | Not available on this system. |
| `FAILED` | The tool ran and failed. The error is recorded. |

A `SKIPPED` module for software you do not run is normal.

---

## ⚙️ How it works

Auditor is a pipeline. Collectors observe, everything after that works on structured data.

```mermaid
flowchart TD
    subgraph OBSERVE["1 · Observe (read-only)"]
        C["43 collectors<br/>hardware · storage · network<br/>security · docker · services"]
        X["Command executor<br/>denylist + sudo -n only"]
        C --> X
    end
    X --> N["2 · Normalize<br/>sizes · frequencies · timestamps"]
    N --> M["Canonical audit model"]
    M --> S["3 · Sanitize<br/>private or public profile"]
    M --> T["4 · Topology<br/>disk → app chains"]
    M --> A["5 · Analyze<br/>health · exposure · conflicts"]
    S --> R
    T --> R
    A --> R
    R["6 · Render"] --> MD["audit.md"]
    R --> J["audit.json"]
    R --> H["audit.html"]
    R --> P["audit.pdf (optional)"]
    MD --> I["7 · Persist<br/>manifest.json + checksums.sha256"]
    J --> I
    H --> I
    P --> I
```

### What happens during `serveraudit audit`

```mermaid
sequenceDiagram
    actor U as You
    participant CLI as serveraudit
    participant PM as Privilege manager
    participant EX as Executor
    participant CO as Collectors
    participant SA as Sanitizer
    participant RE as Renderers
    participant FS as audits/ folder

    U->>CLI: audit --mode sudo --profile public
    CLI->>PM: validate sudo once
    PM-->>CLI: elevated / unprivileged
    loop each of the 43 collectors
        CLI->>CO: run
        CO->>EX: read-only command
        EX->>EX: denylist check
        EX-->>CO: output (sudo -n only if needed)
        CO-->>CLI: status + data
    end
    CLI->>SA: redact secrets, apply profile
    SA-->>CLI: sanitized data
    CLI->>RE: render md, json, html
    RE-->>CLI: files
    CLI->>FS: write bundle + manifest + checksums
    CLI-->>U: snapshot folder path
```

### Topology: how the pieces connect

The topology stage reconstructs how a byte on disk becomes a running service:

```mermaid
flowchart LR
    D["Disk"] --> P["Partition"] --> L["LUKS"] --> V["LVM"] --> F["Filesystem"] --> M["Mount"]
    M --> B["Docker bind mount"] --> C["Container"] --> A["Application"] --> W["Caddy route"] --> H["Hostname"]
    N["Network interface"] --> FW["Firewall rule"] --> PT["Listening port"] --> PR["Owning process"]
```

Section 12 of the report shows these chains for your server. Links that do not exist on your machine (no LUKS, no LVM, no Caddy) are simply left out.

---

## 📋 What gets audited (43 modules)

`root` means the module needs `--mode sudo` for full data. Everything else works in user mode if the tool is installed.

| Category | Module | root | Uses |
|---|---|:-:|---|
| **System** | `system` | | `hostnamectl`, `uname`, `uptime`, `systemd-detect-virt` |
| | `time` | | `timedatectl`, `chronyc` |
| | `boot` | | `efibootmgr` |
| | `packages` | | `dpkg-query`, `apt-mark`, `snap`, `flatpak` *(Debian-family)* |
| | `backups` | | `restic`, `borg`, `rclone` (detection) |
| | `scheduled` | ✅ | `crontab`, `/etc/cron*` |
| **Hardware** | `hardware` | | `dmidecode` (more detail with root) |
| | `cpu` | | `lscpu` |
| | `memory` | | `free`, `dmidecode` |
| | `pci` | | `lspci` |
| | `usb` | | `lsusb` |
| | `thermal` | | `sensors` |
| | `power` | | `upsc`, `powerprofilesctl` |
| | `firmware` | | `mokutil`, `fwupdmgr` |
| **Storage** | `storage` | | `lsblk` |
| | `smart` | ✅ | `smartctl`, `nvme` |
| | `filesystems` | | `df`, `findmnt` |
| | `fstab` | | `/etc/fstab` |
| | `lvm` | ✅ | `pvs`, `vgs`, `lvs` |
| | `raid` | | `/proc/mdstat`, `mdadm` |
| | `zfs` | | `zpool`, `zfs` |
| | `btrfs` | | `btrfs` |
| | `encryption` | ✅ | `cryptsetup`, `dmsetup` |
| **Network** | `network` | | `ip` |
| | `routes` | | `ip` |
| | `dns` | | `resolvectl` |
| | `active_net` | | `ss -s` |
| | `ports` | ✅ | `ss -tulpn` |
| | `firewall` | ✅ | `ufw`, `iptables-save`, `nft` |
| **Security** | `ssh` | ✅ | `sshd -T`, `ssh-keygen` |
| | `users` | ✅ | `passwd -S` (status only, never hashes) |
| | `security` | ✅ | `aa-status`, `sestatus` |
| | `tls` | ✅ | `openssl` |
| | `fail2ban` | ✅ | `fail2ban-client`, `cscli` |
| | `permissions` | | `stat` on sensitive files |
| **Runtime** | `systemd` | | `systemctl`, `systemd-analyze` |
| | `processes` | | `ps` |
| | `runtime_health` | | `dmesg` (OOM, errors) |
| | `logs` | ✅ | `journalctl` |
| **Services** | `docker` | | `docker` (engine, containers, images, volumes, networks, compose, security posture) |
| | `caddy` | | `caddy` |
| | `sharing` | ✅ | `exportfs`, `testparm` |
| | `applications` | | Matches known apps (Jellyfin, Paperless, Pi-hole, qBittorrent, Sonarr, Radarr, Prowlarr, Bazarr, Kavita, SearXNG, databases) to containers and ports |

Install what you want covered, for example on Debian/Ubuntu:

```bash
sudo apt install -y pciutils usbutils iproute2 util-linux smartmontools dmidecode lm-sensors
```

---

## 🔁 Drift detection and baselines

Keep an audit as a **baseline**, audit again later, and see exactly what changed:

```bash
serveraudit audit --mode sudo            # today
# ... time passes, something changes ...
serveraudit audit --mode sudo            # later
serveraudit list
serveraudit diff <older> <newer>
```

`diff` compares these areas: **kernel and OS, Docker containers (added, removed, image changed), SSH settings, listening ports, Caddy routes, users and sudo users, installed-package count.** Volatile counters (bytes transferred, uptime) are ignored on purpose.

### Comparing across modes

A `user`-mode snapshot cannot read SSH settings, ports or users, so comparing it against a `sudo`-mode one would report false changes. Auditor skips those categories and tells you:

```text
NOT COMPARED (collected without elevation in at least one snapshot):
  ! SSH Configuration: snapshot A could not collect 'ssh' without elevation; run both audits with --mode sudo to compare it
----------------------------------------------------------------------
No drift detected in the categories that could be compared (see above).
```

For meaningful drift, **always audit in the same mode**, ideally `sudo`.

---

## 🌐 Web dashboard

An optional, dependency-free dashboard built on Python's standard library:

```bash
serveraudit web                              # http://127.0.0.1:8080
serveraudit web --port 9000 --output-dir /srv/audits
```

It shows the server identity, lists snapshots, opens HTML reports, downloads Markdown and JSON, compares two snapshots, and has a **Run New Audit** button. **Audits started from the dashboard run in `user` mode** (the web process never uses sudo).

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Dashboard |
| `/api/status` | GET | Is an audit running |
| `/api/snapshots` | GET | List snapshots |
| `/api/snapshot/<name>` (`/md`, `/html`) | GET | A snapshot as JSON, Markdown or HTML |
| `/api/diff?a=<name>&b=<name>` | GET | Drift between two snapshots |
| `/api/audit/run` | POST | Start an audit |

### Security of the dashboard

> **There is no login.** The dashboard is protected against web-page tricks, not against people who can reach the port. **Keep the default `127.0.0.1` bind**, or put it behind something that authenticates.

```mermaid
flowchart TD
    Q["Incoming request"] --> H{"Host header is loopback<br/>or in --allowed-host?"}
    H -- no --> X1["403 Host not allowed<br/>(blocks DNS rebinding)"]
    H -- yes --> K{"POST?"}
    K -- no --> G["GET: snapshot name checked,<br/>cannot leave the audits folder"]
    K -- yes --> O{"Sec-Fetch-Site / Origin<br/>same-origin?"}
    O -- no --> X2["403 cross-site request rejected"]
    O -- yes --> RUN["Start audit (user mode)"]
```

- Snapshot names are validated and resolved inside the audits folder: `../`, encoded `%2e%2e`, absolute paths and symlinks out of the folder are all rejected (`400`).
- Forwarding headers (`X-Forwarded-*`, `Forwarded`) are **never trusted**, because a page can set them itself after a DNS rebind.

### Behind a reverse proxy

Pass the public name with `--allowed-host`. The proxy must forward the original `Host` header (Caddy does by default):

```bash
serveraudit web --allowed-host audit.example.com
```

```caddyfile
audit.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Add your own authentication in front (for example Caddy `basicauth`), since Auditor has none.

---

## 🤖 Using reports with AI assistants

Auditor has no AI inside it, on purpose: the audit data is sensitive, and a deterministic report is reproducible and diffable. But the Markdown is designed to be **copied into an AI assistant** of your choice:

```text
Here is an audit of my Linux server. Summarize the risks, list what to fix first,
and ask me about anything marked "not collected".

<paste audit.md>
```

To do that safely:

1. **Use `--profile public`.** A `private` report contains your real IPs, MACs and serials.
2. **Run `--mode sudo`** if you want advice on SSH, firewall, users or SMART. In user mode those sections say *not collected*, and a good assistant will tell you so.
3. **Skim the report first.** `public` still contains usernames, container and application names, domain names and other machines' names. See [what `public` does not mask](#-profiles-private-vs-public).
4. **Check the header.** It states the mode, the profile and any coverage gaps, so the assistant (and you) know what the report does not include.

---

## 🔒 Security & privacy model

| Guarantee | How it is enforced |
|---|---|
| **Read-only** | A command denylist rejects state-changing commands (package installs, `systemctl start/stop/restart`, firewall edits, `mount`, `mkfs`, `fdisk`, `dd`, writes to `/etc`, `/sys`, `/proc`). Collectors declare `writes_system_state = False`. |
| **Least privilege** | One `sudo` validation up front, then `sudo -n` per command and only for modules that need it. In user mode **no sudo process is ever started**. The web process is unprivileged. |
| **No network** | The core pipeline makes no outbound connections, has no telemetry, and has no cloud or AI dependency. |
| **Secrets** | Private keys and password hashes are never collected. Passwords, tokens, API keys, `Authorization` headers, database URLs and secret environment values are redacted in every profile. |
| **Integrity** | Each snapshot has `manifest.json` and `checksums.sha256`. `serveraudit verify` checks them. |

Found a leak or a vulnerability? Please follow [`SECURITY.md`](SECURITY.md) and do not post real server output in a public issue.

---

## ⚠️ Platform support and known limitations

Honest status, so nothing surprises you:

| Area | Status |
|---|---|
| **Linux** | Supported. Full audits verified on Ubuntu 26.04 LTS in `user` and `sudo` mode. |
| **macOS** | **Not supported.** It runs, but there is no `/proc` and no `ip`, `lsblk`, `lspci`, `systemctl`, so most modules report nothing. Auditor prints a warning and the report header says `Platform Support: Unsupported`. Unit tests run on macOS in CI. Real audits do not. |
| **Windows** | Not supported. CI does not run on Windows. |
| **Other Linux distributions** | The audit runs. The package inventory is Debian-family only. |
| `--config FILE` and the files in `config/` | **Accepted but not applied** in this version. Use `--profile`, `--format` and `--output-dir`. The YAML files are reference templates for planned work. |
| **Public profile** | Masks secrets, the hostname, IPs, MACs and serials, but not usernames, container or application names, domain names or other machines' names. See [profiles](#-profiles-private-vs-public). |
| **PDF output** | Needs WeasyPrint. Requested via `audit --format ...pdf` without it, the PDF is skipped silently. |
| **Restricted sudo rules** | Sudo rules that allow only specific commands (instead of `ALL`) are not recognized by the passwordless check. In a terminal you are asked for a password. Without one, the audit runs unprivileged and says so. |
| **Very long audits** | With password sudo, the credential timestamp can expire during a very long run. Audits normally take seconds. |

---

## 🩺 Troubleshooting

<details>
<summary><b>"Warning: Sudo validation failed or was cancelled"</b></summary>

You asked for `--mode sudo` but sudo could not be used. The audit still ran, unprivileged, and the report says so. Run it again from a terminal and enter your password, or set up passwordless sudo, then re-run.

</details>

<details>
<summary><b>The report says "not collected" or shows <code>unknown</code></b></summary>

That means *could not be read*, not *unset*. Re-run with `--mode sudo`. See the Coverage block at the top of the report and section 14.

</details>

<details>
<summary><b>A module is <code>DEPENDENCY_MISSING</code> (for example <code>lspci</code> or <code>ip</code>)</b></summary>

Install the tool (see the [module table](#-what-gets-audited-43-modules)) and re-run. Only that module was affected.

</details>

<details>
<summary><b>A module is <code>SKIPPED</code></b></summary>

Read the message in section 14. Usually the software is not installed (ZFS, Btrfs, Caddy) or it needs `--mode sudo`. Both are normal.

</details>

<details>
<summary><b>"AuditMode.USER cannot be run as root"</b></summary>

User mode refuses to run as root, on purpose. As root, use `--mode sudo`.

</details>

<details>
<summary><b><code>./install.sh</code> says Python 3.10+ or venv is missing</b></summary>

It prints the exact command for your distribution. On Debian/Ubuntu: `sudo apt install -y python3 python3-venv python3-pip`.

</details>

<details>
<summary><b>The dashboard returns "403 Host not allowed"</b></summary>

You reached it by a name that is not `localhost` or `127.0.0.1`. Add the name with `--allowed-host`, and make your reverse proxy forward the original `Host` header.

</details>

<details>
<summary><b>"serveraudit: command not found"</b></summary>

`~/.local/bin` was not on your `PATH` at install time. Run `./bin/serveraudit`, or add `~/.local/bin` to your `PATH` and re-run `./install.sh`.

</details>

---

## 🛠️ Development

```bash
git clone https://github.com/MohnishShende/auditor.git
cd auditor
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest tests/
```

The suite (about 200 tests, about 40 seconds) covers collectors, the sanitizer, renderers, the JSON schemas, drift, privilege handling and the web server. CI runs it on Ubuntu and macOS with Python 3.10, 3.11 and 3.12.

```text
src/serveraudit/
├── cli/          # audit, diff, render, list, verify, web entry points
├── core/         # executor (denylist), privileges, sanitizer, snapshot, normalizer
├── collectors/   # the 43 read-only collectors
├── topology/     # disk → application chain reconstruction
├── analysis/     # health, exposure, conflicts, drift
├── renderers/    # markdown, json, html, pdf
├── applications/ # known-application detection
└── web/          # self-hosted dashboard
schemas/          # JSON schemas for audit.json, manifest.json, collectors
config/           # reference profile templates (not yet applied, see limitations)
docs/             # architecture, security model, collectors, web interface
examples/         # a full synthetic report
tests/            # unit and sanitization tests
```

**Adding a collector:** see [`docs/adding-collectors.md`](docs/adding-collectors.md) and [`CONTRIBUTING.md`](CONTRIBUTING.md). Collectors must be read-only, return structured data (not pre-rendered text), handle missing tools and missing root, and never export secrets.

More documentation: [Architecture](docs/architecture.md) · [Security model](docs/security-model.md) · [Privacy](docs/privacy.md) · [Collectors](docs/collectors.md) · [Report format](docs/report-format.md) · [Web interface](docs/web-interface.md) · [Specification](docs/SPECIFICATION.md) · [Changelog](CHANGELOG.md)

---

## 👤 Author & license

**Mohnish Shende** · GitHub: [@MohnishShende](https://github.com/MohnishShende)

Released under the [MIT License](LICENSE).
