# Architecture Overview

Linux Server Audit is engineered as a multi-stage observational data pipeline separating data acquisition, normalization, sanitization, topology reconstruction, analysis, rendering, and historical persistence.

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

## Pipeline Stages

1. **Observational Collection**:
   - Collectors execute isolated, non-modifying system queries.
   - Privileged commands use `sudo -n` without interactive blocking.
   - Failures report explicit statuses (`SUCCESS`, `PARTIAL`, `SKIPPED`, `UNSUPPORTED`, `PERMISSION_DENIED`, `DEPENDENCY_MISSING`, `FAILED`).
2. **Data Normalization**:
   - Standardizes byte sizes, clock frequencies, temperatures, and timestamps into canonical types.
3. **Typed Sanitization**:
   - Operates on typed Python objects.
   - Redacts secrets, private keys, authentication tokens, database passwords, and environment variables.
   - Supports `private` and `public` (shareable) profiles.
4. **Topology Reconstruction**:
   - Generates nodes and edges linking physical disks -> partitions -> LUKS -> LVM PVs -> VGs -> LVs -> filesystems -> mounts -> Docker bind mounts -> containers -> applications -> Caddy routes -> hostnames.
5. **Deterministic Analysis**:
   - Performs rule-based evaluations for hardware health, port exposure classifications, and configuration conflicts.
6. **Multi-Format Rendering**:
   - Generates canonical structured `audit.json`, human-readable `audit.md`, standalone `audit.html`, and optional `audit.pdf`.
7. **Integrity & Preservation**:
   - Generates timestamped audit directories with `manifest.json` and `checksums.sha256`.
