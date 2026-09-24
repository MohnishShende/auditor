# Report Formats & Artifact Structure

Every completed audit generates an isolated timestamped directory within the configured `audits/` base directory.

## Bundle Layout

```text
audits/
└── <hostname>-<YYYY-MM-DDTHHMMSS>/
    ├── audit.md          # Primary human-readable Markdown report
    ├── audit.json        # Canonical structured JSON representation
    ├── manifest.json     # Collector execution log, duration, and provenance
    ├── checksums.sha256  # SHA256 integrity checksums for all files
    └── optional/
        ├── audit.html    # Standalone interactive single-file HTML report
        └── audit.pdf     # Document for archival / print (via WeasyPrint)
```

## JSON Schema Compatibility

The `audit.json` artifact strictly adheres to the JSON schema defined at `schemas/audit.schema.json`. It acts as the single source of truth for all downstream tools, diff comparisons, and web renderings.
