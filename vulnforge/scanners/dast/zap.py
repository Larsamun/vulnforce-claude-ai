"""OWASP ZAP baseline adapter - a passive spider + passive scan of the target,
safe for production. Runs via Docker (the official zaproxy image), writes a JSON
report to a mounted working dir, and normalizes ZAP alerts into Findings."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from ..base import Scanner, ScannerOutcome
from ...models import Finding, Engine, Severity, Confidence
from ...tooling import ToolRunner, Availability

DOCKER_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
CONTAINER_WRK = "/zap/wrk"
REPORT_NAME = "vulnforge-zap.json"

# ZAP riskcode -> severity
_RISK = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}


class ZapBaselineScanner(Scanner):
    name = "zap"
    engine = Engine.DAST
    docker_image = DOCKER_IMAGE  # native ZAP install is uncommon; docker-only here

    def scan(self, target: str, runner: ToolRunner, raw_out) -> ScannerOutcome:
        if not target:
            return ScannerOutcome(self.name, "skipped", detail="no target URL")
        # ZAP baseline is effectively docker-only for us.
        if not (self.docker_image and runner.resolve(None, self.docker_image) == Availability.DOCKER):
            return ScannerOutcome(self.name, "skipped", detail="zap requires Docker (not available)")

        with tempfile.TemporaryDirectory(prefix="vulnforge-zap-") as wrk:
            args = ["zap-baseline.py", "-t", target, "-J", REPORT_NAME, "-I"]
            res = runner.run_docker(
                self.docker_image, args,
                mounts={wrk: CONTAINER_WRK}, workdir=CONTAINER_WRK, network="host",
            )
            report_path = Path(wrk) / REPORT_NAME
            report_text = report_path.read_text(encoding="utf-8") if report_path.exists() else ""

        raw_file = raw_out("dast_zap.json", report_text or res.stderr or res.stdout)
        if not report_text.strip():
            if res.timed_out:
                return ScannerOutcome(self.name, "error", detail="zap timed out", raw_file=str(raw_file))
            return ScannerOutcome(
                self.name, "error",
                detail=f"zap produced no report (rc={res.returncode}): {res.stderr[:200]}",
                raw_file=str(raw_file),
            )

        try:
            data = json.loads(report_text)
        except json.JSONDecodeError:
            return ScannerOutcome(self.name, "error", detail="could not parse zap report",
                                  raw_file=str(raw_file))

        findings = self.parse(data)
        return ScannerOutcome(self.name, "ran", findings=findings, raw_file=str(raw_file),
                              detail=f"{len(findings)} alert(s)")

    @classmethod
    def parse(cls, data: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for site in data.get("site", []) or []:
            for alert in site.get("alerts", []) or []:
                instances = alert.get("instances", []) or []
                first = instances[0] if instances else {}
                cwe = alert.get("cweid")
                findings.append(Finding(
                    source="zap", engine=Engine.DAST,
                    category="dynamic",
                    severity=_RISK.get(str(alert.get("riskcode", "0")), Severity.INFO),
                    title=str(alert.get("alert") or alert.get("name", "ZAP alert"))[:160],
                    description=_strip_html(alert.get("desc", ""))[:1000],
                    endpoint=first.get("uri") or site.get("@name"),
                    method=first.get("method"),
                    evidence=str(first.get("evidence") or "")[:300] or None,
                    rule_id=str(alert.get("pluginid") or alert.get("alertRef") or ""),
                    cwe=[f"CWE-{cwe}"] if cwe and str(cwe) != "-1" else [],
                    references=[r for r in _strip_html(alert.get("reference", "")).split("\n") if r][:5],
                    remediation=_strip_html(alert.get("solution", "")).strip()[:600] or None,
                    confidence=_confidence(alert.get("confidence")),
                    raw=alert,
                ))
        return findings


def _strip_html(text: str) -> str:
    import re
    return re.sub(r"<[^>]+>", "", text or "").replace("&lt;", "<").replace("&gt;", ">").strip()


def _confidence(value: Any) -> Confidence:
    # ZAP confidence: 0 false-positive, 1 low, 2 medium, 3 high, 4 confirmed
    return {
        "4": Confidence.CONFIRMED, "3": Confidence.LIKELY, "2": Confidence.POSSIBLE,
        "1": Confidence.POSSIBLE, "0": Confidence.FALSE_POSITIVE,
    }.get(str(value), Confidence.POSSIBLE)
