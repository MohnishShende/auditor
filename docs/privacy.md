# Privacy Model & Sanitization Profiles

Linux Server Audit distinguishes between internal documentation (intended exclusively for the server owner) and public/shareable documentation (intended for GitHub issues, technical forums, or vendor support).

## Classification Tiers

| Classification | Examples | Private Profile | Public / Shareable Profile |
|---|---|---|---|
| **PUBLIC** | OS version, CPU model, RAM size, package versions | Preserved | Preserved |
| **INTERNAL** | Internal LAN IPs, hostnames, interface names | Preserved | **Masked** (`192.168.x.x`) |
| **SENSITIVE** | Disk serial numbers, MAC addresses, machine IDs | Preserved | **Redacted** (`[REDACTED_SERIAL]`) |
| **SECRET** | API tokens, Bearer headers, database passwords | **Redacted** | **Redacted** |
| **NEVER_COLLECT** | Private keys (SSH/TLS), password hashes | **Never Emitted** | **Never Emitted** |

## Profiles

### 1. `private` Profile (Default)
- Retains internal topology, LAN IP addresses, MAC addresses, hardware serial numbers, and device UUIDs.
- Automatically redacts passwords, private keys, authorization headers, and secret environment variables.

### 2. `public` Profile
- In addition to standard secret scrubbing, masks all internal/external IP addresses, MAC addresses, hardware serial numbers, machine IDs, and hostnames.
- Safely shareable on public issue trackers.
