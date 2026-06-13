"""Gitleaks adapter - secret detection. Raw secret values are masked before storage."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..base import Scanner, ScannerOutcome
from ...models import Finding, Engine, Severity, Confidence, mask_secret
from ...tooling import ToolRunner, Availability

DOCKER_IMAGE = "zricethezav/gitleaks:latest"
CONTAINER_SRC = "/repo"
# Gitleaks logs to stderr and its /dev/stdout report path is unreliable on Docker
# Desktop (Windows). We make it write the JSON report to a file in the workspace and
# read that file back from the host - robust across platforms.
REPORT_NAME = ".vulnforge-gitleaks.json"


class GitleaksScanner(Scanner):
    name = "gitleaks"
    engine = Engine.SAST
    native_binary = "gitleaks"
    docker_image = DOCKER_IMAGE

    def scan(self, target_dir: str, runner: ToolRunner, raw_out) -> ScannerOutcome:
        avail = self.availability(runner)
        if avail == Availability.UNAVAILABLE:
            return ScannerOutcome(self.name, "skipped", detail="gitleaks not available (no binary, no docker)")

        host_report = Path(target_dir) / REPORT_NAME
        # `detect --no-git` scans the working tree (not git history). `--exit-code 0`
        # so finding leaks is not treated as a process failure.
        common = ["detect", "--no-git", "--report-format", "json", "--exit-code", "0", "--no-banner"]
        if avail == Availability.DOCKER:
            res = runner.run_docker(
                self.docker_image,
                common + ["--source", CONTAINER_SRC, "--report-path", f"{CONTAINER_SRC}/{REPORT_NAME}"],
                mounts={target_dir: CONTAINER_SRC},
            )
        else:
            res = runner.run_native(
                ["gitleaks"] + common + ["--source", target_dir, "--report-path", str(host_report)]
            )

        report_text = ""
        if host_report.exists():
            try:
                report_text = host_report.read_text(encoding="utf-8")
            finally:
                host_report.unlink(missing_ok=True)  # don't leave artifacts in the workspace

        try:
            data = json.loads(report_text) if report_text.strip() else []
        except json.JSONDecodeError:
            raw_file = raw_out("gitleaks.json", res.stderr or res.stdout)
            if res.timed_out:
                return ScannerOutcome(self.name, "error", detail="gitleaks timed out", raw_file=str(raw_file))
            return ScannerOutcome(
                self.name, "error",
                detail=f"could not parse gitleaks report (rc={res.returncode}): {res.stderr[:200]}",
                raw_file=str(raw_file),
            )

        # Redact cleartext secrets from the raw evidence we persist to disk.
        redacted = [
            {**{k: v for k, v in item.items() if k not in ("Secret", "Match", "Line")},
             "Secret": mask_secret(item.get("Secret"))}
            for item in (data or [])
        ]
        raw_file = raw_out("gitleaks.json", json.dumps(redacted, indent=2))

        findings = self.parse(data)
        return ScannerOutcome(self.name, "ran", findings=findings, raw_file=str(raw_file),
                              detail=f"{len(findings)} secret(s)")

    @classmethod
    def parse(cls, data: Any) -> list[Finding]:
        findings: list[Finding] = []
        for item in data or []:
            rule = item.get("RuleID") or item.get("Description") or "secret"
            secret = item.get("Secret")
            redacted = mask_secret(secret)
            line = item.get("StartLine")
            findings.append(
                Finding(
                    source="gitleaks",
                    engine=Engine.SAST,
                    category="secret",
                    severity=Severity.HIGH,
                    title=f"Hardcoded secret: {item.get('Description', rule)}"[:160],
                    description=(
                        f"Potential secret matching rule '{rule}' found in source. "
                        f"Verify whether it is live and rotate if so."
                    ),
                    file=item.get("File"),
                    line=line if isinstance(line, int) else None,
                    evidence=redacted,
                    rule_id=str(rule),
                    cwe=["CWE-798"],
                    owasp="A07:2021 - Identification and Authentication Failures",
                    remediation="Remove the secret from source, rotate it, and load it from a secret manager.",
                    confidence=Confidence.LIKELY,
                    # Never persist raw secret material: both `Secret` and `Match`
                    # (and the surrounding `Line`) can contain the cleartext value.
                    raw={k: v for k, v in item.items() if k not in ("Secret", "Match", "Line")},
                )
            )
        return findings
