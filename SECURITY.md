# Security Policy

## Safety Contract & Guarantees

Linux Server Audit is an observational server state recorder. The project adheres to strict security and safety policies:

1. **Zero Intentional Modification**: The audit tool never modifies server configuration, packages, filesystems, users, firewall rules, services, or containers.
2. **Least Privilege**: Only collectors that strictly require elevated privileges execute via `sudo`. The application itself avoids running as unrestricted root.
3. **Secret Redaction**:
   - Private keys (SSH, TLS, GPG) are **never** read or exported.
   - Passwords and password hashes (`/etc/shadow`) are never exported.
   - Authentication tokens, API keys, bearer tokens, database connection passwords, and `.env` credentials are automatically sanitized.
4. **No Telemetry or Exfiltration**: The core audit pipeline performs no outbound network requests. All data stays local to the audited server.

## Reporting Security Vulnerabilities

If you discover a security vulnerability or unintended credential leakage within Linux Server Audit:
- Please report it confidentially via GitHub Security Advisories or by contacting the project maintainers.
- Do not open a public issue containing real server secrets or vulnerable outputs.

We take secret handling and observational safety with the highest priority and will review reports promptly.
