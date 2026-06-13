"""Nuclei adapter - template-based dynamic checks. Runs via Docker. In `safe` mode
we restrict to passive/low-impact template tags and exclude intrusive/DoS tags so
the scan stays production-safe."""
from __future__ import annotations

import json
from typing import Any

from ..base import Scanner, ScannerOutcome
from ...models import Finding, Engine, Severity, Confidence
from ...tooling import ToolRunner, Availability

DOCKER_IMAGE = "projectdiscovery/nuclei:latest"

# Tags considered safe for production (passive / low-impact detection).
_SAFE_TAGS = "misconfig,exposure,tech,ssl,cors,headers,cve,default-login"
_EXCLUDE_TAGS = "dos,intrusive,fuzz,brute-force"


class NucleiScanner(Scanner):
    name = "nuclei"
    engine = Engine.DAST
    native_binary = "nuclei"
    docker_image = DOCKER_IMAGE

    def __init__(self, safe_mode: bool = True):
        self.safe_mode = safe_mode

    def scan(self, target: str, runner: ToolRunner, raw_out) -> ScannerOutcome:
        if not target:
            return ScannerOutcome(self.name, "skipped", detail="no target URL")
        avail = self.availability(runner)
        if avail == Availability.UNAVAILABLE:
            return ScannerOutcome(self.name, "skipped", detail="nuclei not available (no binary, no docker)")

        args = ["-u", target, "-jsonl", "-silent", "-no-color", "-disable-update-check"]
        if self.safe_mode:
            args += ["-tags", _SAFE_TAGS, "-exclude-tags", _EXCLUDE_TAGS, "-rate-limit", "20"]

        if avail == Availability.DOCKER:
            res = runner.run_docker(self.docker_image, args, network="host")
        else:
            res = runner.run_native(["nuclei"] + args)

        raw_file = raw_out("dast_nuclei.jsonl", res.stdout or res.stderr)
        if not res.stdout.strip():
            if res.timed_out:
                return ScannerOutcome(self.name, "error", detail="nuclei timed out", raw_file=str(raw_file))
            return ScannerOutcome(self.name, "ran", detail="0 finding(s)", raw_file=str(raw_file))

        findings = self.parse(res.stdout)
        return ScannerOutcome(self.name, "ran", findings=findings, raw_file=str(raw_file),
                              detail=f"{len(findings)} finding(s)")

    @classmethod
    def parse(cls, jsonl: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in jsonl.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = item.get("info", {}) or {}
            classification = info.get("classification", {}) or {}
            cwe = classification.get("cwe-id") or []
            if isinstance(cwe, str):
                cwe = [cwe]
            findings.append(Finding(
                source="nuclei", engine=Engine.DAST,
                category=_category(info.get("tags")),
                severity=Severity.parse(info.get("severity")),
                title=str(info.get("name") or item.get("template-id", "nuclei finding"))[:160],
                description=str(info.get("description", "")).strip()[:1000],
                endpoint=item.get("matched-at") or item.get("host"),
                method=item.get("type", "http").upper() if item.get("type") else None,
                evidence=str(item.get("extracted-results") or item.get("matcher-name") or "")[:300] or None,
                rule_id=item.get("template-id"),
                cwe=[str(c).upper() for c in cwe],
                references=[str(x) for x in (info.get("reference") or [])[:5]],
                remediation=str(info.get("remediation", "")).strip() or None,
                confidence=Confidence.LIKELY,
                raw=item,
            ))
        return findings


def _category(tags: Any) -> str:
    tags = tags or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    tagset = {str(t).lower() for t in tags}
    for cat in ("cors", "headers", "exposure", "misconfig", "cve", "ssl", "xss", "sqli"):
        if cat in tagset:
            return "misconfig" if cat in ("headers", "ssl") else cat
    return "dynamic"
