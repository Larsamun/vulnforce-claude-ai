"""Trivy adapter - filesystem scan for vulnerable dependencies, secrets, and IaC
misconfigurations. We enable vuln + misconfig scanners (secrets handled by gitleaks
to avoid double-reporting, but kept here as a fallback category mapping)."""
from __future__ import annotations

import json
from typing import Any

from ..base import Scanner, ScannerOutcome
from ...models import Finding, Engine, Severity, Confidence
from ...tooling import ToolRunner, Availability

DOCKER_IMAGE = "aquasec/trivy:latest"
CONTAINER_SRC = "/src"


class TrivyScanner(Scanner):
    name = "trivy"
    engine = Engine.SAST
    native_binary = "trivy"
    docker_image = DOCKER_IMAGE

    def scan(self, target_dir: str, runner: ToolRunner, raw_out) -> ScannerOutcome:
        avail = self.availability(runner)
        if avail == Availability.UNAVAILABLE:
            return ScannerOutcome(self.name, "skipped", detail="trivy not available (no binary, no docker)")

        args = ["fs", "--format", "json", "--scanners", "vuln,misconfig", "--quiet"]
        if avail == Availability.DOCKER:
            res = runner.run_docker(
                self.docker_image,
                args + [CONTAINER_SRC],
                mounts={target_dir: CONTAINER_SRC},
                read_only_mounts=True,
            )
        else:
            res = runner.run_native(["trivy"] + args + [target_dir])

        raw_file = raw_out("trivy.json", res.stdout or res.stderr)

        try:
            data = json.loads(res.stdout) if res.stdout.strip() else {}
        except json.JSONDecodeError:
            if res.timed_out:
                return ScannerOutcome(self.name, "error", detail="trivy timed out", raw_file=str(raw_file))
            return ScannerOutcome(
                self.name, "error",
                detail=f"could not parse trivy output (rc={res.returncode}): {res.stderr[:200]}",
                raw_file=str(raw_file),
            )

        findings = self.parse(data)
        return ScannerOutcome(self.name, "ran", findings=findings, raw_file=str(raw_file),
                              detail=f"{len(findings)} finding(s)")

    @classmethod
    def parse(cls, data: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for result in data.get("Results", []) or []:
            target = result.get("Target", "")

            # Vulnerable dependencies
            for v in result.get("Vulnerabilities", []) or []:
                refs = v.get("References", []) or []
                findings.append(
                    Finding(
                        source="trivy",
                        engine=Engine.SAST,
                        category="dependency",
                        severity=Severity.parse(v.get("Severity")),
                        title=f"{v.get('VulnerabilityID', 'VULN')} in {v.get('PkgName', '')} "
                              f"{v.get('InstalledVersion', '')}".strip()[:160],
                        description=str(v.get("Title") or v.get("Description", "")).strip()[:1000],
                        file=target,
                        evidence=(
                            f"{v.get('PkgName')} {v.get('InstalledVersion')} "
                            f"(fixed in {v.get('FixedVersion', 'n/a')})"
                        ),
                        rule_id=v.get("VulnerabilityID"),
                        cwe=[str(c) for c in (v.get("CweIDs") or [])],
                        remediation=(
                            f"Upgrade {v.get('PkgName')} to {v.get('FixedVersion')}."
                            if v.get("FixedVersion") else "No fixed version published yet; assess exposure."
                        ),
                        references=[str(x) for x in refs[:5]],
                        confidence=Confidence.LIKELY,
                        raw=v,
                    )
                )

            # IaC / config misconfigurations
            for m in result.get("Misconfigurations", []) or []:
                findings.append(
                    Finding(
                        source="trivy",
                        engine=Engine.SAST,
                        category="misconfig",
                        severity=Severity.parse(m.get("Severity")),
                        title=f"{m.get('ID', 'MISCONFIG')}: {m.get('Title', '')}".strip()[:160],
                        description=str(m.get("Description", "")).strip()[:1000],
                        file=target,
                        line=(m.get("CauseMetadata", {}) or {}).get("StartLine"),
                        evidence=str(m.get("Message", "")).strip()[:500] or None,
                        rule_id=m.get("ID"),
                        remediation=str(m.get("Resolution", "")).strip() or None,
                        references=[str(x) for x in (m.get("References") or [])[:5]],
                        confidence=Confidence.POSSIBLE,
                        raw=m,
                    )
                )
        return findings
