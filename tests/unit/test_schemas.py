"""
JSON schema validation tests for Linux Server Audit canonical data models.
"""

import json
from pathlib import Path
import jsonschema
import pytest
from serveraudit.cli.audit import AuditOrchestrator
from serveraudit.core.collector import CollectorResult, CollectorStatus
from serveraudit.core.manifest import ManifestGenerator


def test_audit_json_schema_validation(tmp_path):
    """Verify that generated audit.json strictly conforms to schemas/audit.schema.json."""
    schema_path = Path("schemas/audit.schema.json")
    assert schema_path.exists()

    with open(schema_path, "r", encoding="utf-8") as f:
        audit_schema = json.load(f)

    orchestrator = AuditOrchestrator(output_dir=str(tmp_path), quiet=True)
    snap_dir = orchestrator.run_audit()

    json_file = snap_dir / "audit.json"
    assert json_file.exists()

    with open(json_file, "r", encoding="utf-8") as f:
        audit_data = json.load(f)

    # Validate against JSON schema
    jsonschema.validate(instance=audit_data, schema=audit_schema)


def test_manifest_schema_validation(tmp_path):
    """Verify that generated manifest.json strictly conforms to schemas/manifest.schema.json."""
    schema_path = Path("schemas/manifest.schema.json")
    assert schema_path.exists()

    with open(schema_path, "r", encoding="utf-8") as f:
        manifest_schema = json.load(f)

    mock_results = {
        "system": CollectorResult("system", CollectorStatus.SUCCESS, duration_seconds=0.05),
        "smart": CollectorResult("smart", CollectorStatus.PARTIAL, message="Single disk failed"),
    }

    manifest = ManifestGenerator.generate(
        hostname="nodezero",
        profile="private",
        duration_seconds=1.23,
        results=mock_results,
        privileges_available=True,
    )

    # Validate against JSON schema
    jsonschema.validate(instance=manifest, schema=manifest_schema)
