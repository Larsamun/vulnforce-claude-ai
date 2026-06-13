import json
from pathlib import Path

from vulnforge.models import Severity, Engine, Confidence
from vulnforge.scanners.dast.headers import HeadersScanner
from vulnforge.scanners.dast.nuclei import NucleiScanner
from vulnforge.scanners.dast.zap import ZapBaselineScanner

FIX = Path(__file__).parent / "fixtures"


def test_headers_parse_missing_and_cors_and_cookies():
    raw = {
        "url": "https://app.example.com/",
        "status": 200,
        "headers": {"Server": "nginx", "Content-Type": "text/html"},  # no security headers
        "set_cookie": ["session=abc; Path=/"],                          # missing all flags
        "cors_probe": {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
            "reflected_origin": False,
        },
    }
    findings = HeadersScanner.parse(raw)
    cats = {f.category for f in findings}
    assert "header" in cats and "cors" in cats and "cookie" in cats and "info-leak" in cats
    # all generated header findings are confirmed (deterministic checks)
    assert all(f.engine is Engine.DAST for f in findings)
    cors = next(f for f in findings if f.category == "cors")
    assert cors.severity is Severity.HIGH
    cookie = next(f for f in findings if f.category == "cookie")
    assert "SameSite" in cookie.title and "Secure" in cookie.title


def test_headers_no_findings_when_well_configured():
    raw = {
        "url": "https://app.example.com/",
        "status": 200,
        "headers": {
            "strict-transport-security": "max-age=63072000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        },
        "set_cookie": ["session=abc; Secure; HttpOnly; SameSite=Strict"],
        "cors_probe": {},
    }
    findings = HeadersScanner.parse(raw)
    assert findings == []


def test_nuclei_parse_jsonl():
    findings = NucleiScanner.parse((FIX / "nuclei_sample.jsonl").read_text(encoding="utf-8"))
    assert len(findings) == 2
    high = next(f for f in findings if f.severity is Severity.HIGH)
    assert high.rule_id == "CVE-2021-12345"
    assert "CWE-78" in high.cwe
    assert high.endpoint == "https://app.example.com/api/run"


def test_zap_parse_alerts():
    data = json.loads((FIX / "zap_sample.json").read_text(encoding="utf-8"))
    findings = ZapBaselineScanner.parse(data)
    assert len(findings) == 2
    xss = next(f for f in findings if "Scripting" in f.title)
    assert xss.severity is Severity.HIGH
    assert xss.endpoint == "https://app.example.com/search?q=x"
    assert "CWE-79" in xss.cwe
    # HTML stripped from description
    assert "<p>" not in xss.description
