"""Semgrep adapter - code pattern static analysis (injection, XSS, crypto, authz...)."""
from __future__ import annotations

import json
from typing import Any

from ..base import Scanner, ScannerOutcome
from ...models import Finding, Engine, Severity, Confidence
from ...tooling import ToolRunner, Availability

DOCKER_IMAGE = "semgrep/semgrep:latest"
CONTAINER_SRC = "/src"

# Categories where a SAST hit naturally suggests a follow-up dynamic test.
_DAST_HINTS = {
    "security": "Probe the corresponding endpoint with category-appropriate payloads.",
    "injection": "Send injection payloads to the endpoint that reaches this sink and diff responses/timing.",
    "xss": "Reflect a benign marker through this output path and check it renders unescaped.",
    "ssrf": "Attempt to make the server fetch an attacker-controlled URL via this code path.",
    "path-traversal": "Try traversal sequences against the parameter feeding this file operation.",
}


class SemgrepScanner(Scanner):
    name = "semgrep"
    engine = Engine.SAST
    native_binary = "semgrep"
    docker_image = DOCKER_IMAGE

    def scan(self, target_dir: str, runner: ToolRunner, raw_out) -> ScannerOutcome:
        avail = self.availability(runner)
        if avail == Availability.UNAVAILABLE:
            return ScannerOutcome(self.name, "skipped", detail="semgrep not available (no binary, no docker)")

        args = ["semgrep", "scan", "--config", "auto", "--json", "--quiet", "--disable-version-check"]
        if avail == Availability.DOCKER:
            res = runner.run_docker(
                self.docker_image,
                args + [CONTAINER_SRC],
                mounts={target_dir: CONTAINER_SRC},
                read_only_mounts=True,
            )
        else:
            res = runner.run_native(args + [target_dir])

        raw_file = raw_out("semgrep.json", res.stdout or res.stderr)

        # Semgrep exits 0 with results in stdout; non-zero may still carry JSON.
        try:
            data = json.loads(res.stdout) if res.stdout.strip() else {}
        except json.JSONDecodeError:
            if res.timed_out:
                return ScannerOutcome(self.name, "error", detail="semgrep timed out", raw_file=str(raw_file))
            return ScannerOutcome(
                self.name, "error",
                detail=f"could not parse semgrep output (rc={res.returncode}): {res.stderr[:200]}",
                raw_file=str(raw_file),
            )

        findings = self.parse(data)
        return ScannerOutcome(self.name, "ran", findings=findings, raw_file=str(raw_file),
                              detail=f"{len(findings)} finding(s)")

    @classmethod
    def parse(cls, data: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for r in data.get("results", []) or []:
            extra = r.get("extra", {}) or {}
            meta = extra.get("metadata", {}) or {}
            category = str(meta.get("category", "code")).lower()
            check_id = r.get("check_id", "")
            severity = Severity.parse(extra.get("severity") or meta.get("impact") or "warning")

            cwe = meta.get("cwe", [])
            if isinstance(cwe, str):
                cwe = [cwe]
            owasp = meta.get("owasp")
            if isinstance(owasp, list):
                owasp = ", ".join(str(o) for o in owasp)

            references = meta.get("references", []) or []
            if isinstance(references, str):
                references = [references]

            hint = next((v for k, v in _DAST_HINTS.items() if k in category or k in check_id.lower()), None)

            findings.append(
                Finding(
                    source="semgrep",
                    engine=Engine.SAST,
                    category=category or "code",
                    severity=severity,
                    title=str(meta.get("shortDescription") or extra.get("message") or check_id)[:160],
                    description=str(extra.get("message", "")).strip(),
                    file=r.get("path"),
                    line=(r.get("start") or {}).get("line"),
                    evidence=(extra.get("lines") or "").strip()[:500] or None,
                    rule_id=check_id,
                    cwe=[str(c) for c in cwe],
                    owasp=str(owasp) if owasp else None,
                    remediation=str(meta.get("fix") or extra.get("fix") or "").strip() or None,
                    references=[str(x) for x in references],
                    confidence=Confidence.POSSIBLE,
                    suggested_dast_tests=[hint] if hint else [],
                    raw=r,
                )
            )
        return findings
