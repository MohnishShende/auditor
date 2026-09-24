# Security Model

Linux Server Audit is an observational, read-only system state recorder. The security model is built on strict design invariants to guarantee that executing an audit will never compromise server stability or expose authentication secrets.

## Invariant 1: Zero Intentional Modification

The system enforces a strict command denylist and never executes state-altering commands:
- No package installs or removals (`apt-get install`, `dpkg -i`, `snap install`).
- No service manipulations (`systemctl start/stop/restart/enable`).
- No firewall rule modifications (`ufw enable`, `iptables -A`, `nft add`).
- No filesystem mounts/unmounts or block-device formatting (`mount`, `mkfs`, `fdisk`, `dd`).
- No writes to `/etc`, `/sys`, or `/proc`.

## Invariant 2: Least Privilege & Single Sudo Validation

- The audit launcher (`./audit.sh`) validates sudo credentials once via `sudo -v`.
- Individual collectors only execute via `sudo -n` if elevated privileges are strictly required.
- The web-facing application runs as an unprivileged process.

## Invariant 3: Zero Outbound Network Access

- The default audit pipeline requires no Internet connectivity.
- No telemetry, analytics, cloud processing, or external API dependencies exist in the core engine.

## Invariant 4: Aggressive Secret Redaction

- **Private Keys**: SSH, TLS, and GPG private keys are **never** exported.
- **Passwords**: `/etc/shadow` password hashes and cleartext database passwords are redacted.
- **Tokens**: API keys, Bearer tokens, and authorization headers are scrubbed.
- **Environment Variables**: Only environment key names are preserved; values matching credential patterns are redacted to `[REDACTED]`.
