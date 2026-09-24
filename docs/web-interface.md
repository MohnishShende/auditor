# Self-Hosted Web Interface

Linux Server Audit includes an optional, unprivileged, self-hosted web interface.

## Launching the Web Server

```bash
serveraudit web --host 127.0.0.1 --port 8080
```

Or reverse-proxy behind Caddy:

```caddyfile
audit.local {
    reverse_proxy 127.0.0.1:8080
}
```

## Security & Privilege Boundary

The web service operates unprivileged. When the "Run New Audit" button is clicked, an asynchronous background thread invokes the standard `AuditOrchestrator` engine using least-privilege collectors. The web process itself never runs permanently as unrestricted root.

## Features

- Real-time server identity, kernel, and online status.
- One-click "Run New Audit" trigger with status polling.
- Historical audit snapshot table.
- Direct links to View HTML reports, download Markdown, and inspect canonical JSON.
- Built-in snapshot diff and configuration drift comparison.
