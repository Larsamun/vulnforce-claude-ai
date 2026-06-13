"""Write the normalized, machine-readable findings.json."""
from __future__ import annotations

import json
from pathlib import Path

from ..config import AppDescription, ScanConfig
from ..context import RunContext
from ..models import Finding, severity_counts


def write_findings_json(ctx: RunContext, findings: list[Finding]) -> Path:
    payload = {
        "schema": "vulnforge.findings/v1",
        "application": ctx.description.application_name,
        "environment": ctx.description.environment,
        "scan_mode": ctx.config.scan_mode.value,
        "detected_stack": ctx.detected_stack,
        "summary": severity_counts(findings),
        "stages": [s.__dict__ for s in ctx.stages],
        "findings": [f.to_dict() for f in findings],
    }
    out = ctx.out_dir / "findings.json"
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out
