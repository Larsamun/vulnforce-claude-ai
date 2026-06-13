import json
from pathlib import Path

from vulnforge.models import Severity, Engine
from vulnforge.scanners.sast.semgrep import SemgrepScanner
from vulnforge.scanners.sast.gitleaks import GitleaksScanner
from vulnforge.scanners.sast.trivy import TrivyScanner

FIX = Path(__file__).parent / "fixtures"


def _load(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def test_semgrep_parse():
    findings = SemgrepScanner.parse(_load("semgrep_sample.json"))
    assert len(findings) == 2
    sqli = findings[0]
    assert sqli.engine is Engine.SAST
    assert sqli.severity is Severity.HIGH        # ERROR -> HIGH
    assert sqli.file == "src/api/orders.py" and sqli.line == 87
    assert "CWE-89: SQL Injection" in sqli.cwe
    # injection category yields a DAST follow-up hint
    assert sqli.suggested_dast_tests


def test_gitleaks_parse_masks_secret():
    findings = GitleaksScanner.parse(_load("gitleaks_sample.json"))
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "secret"
    assert f.severity is Severity.HIGH
    # the raw secret must never survive into the finding
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(f.to_dict())
    assert "CWE-798" in f.cwe


def test_trivy_parse_vuln_and_misconfig():
    findings = TrivyScanner.parse(_load("trivy_sample.json"))
    cats = {f.category for f in findings}
    assert "dependency" in cats and "misconfig" in cats
    dep = next(f for f in findings if f.category == "dependency")
    assert dep.rule_id == "CVE-2019-1010083"
    assert "Upgrade flask to 1.0" in (dep.remediation or "")
