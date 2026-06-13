"""Built-in passive DAST check: security response headers, CSP weaknesses, CORS
misconfiguration, and cookie flags. Pure Python (stdlib only), so it is always
available and 100% safe (GET + one OPTIONS preflight, no payloads) - the right
first DAST adapter for `safe` mode."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any, Optional

from ..base import Scanner, ScannerOutcome
from ...models import Finding, Engine, Severity, Confidence

_UA = "VulnForge-AI/0.1 (+safe-scan)"
_TIMEOUT = 20

# header -> (severity, why it matters)
_SECURITY_HEADERS = {
    "strict-transport-security": (Severity.MEDIUM, "Enforces HTTPS; its absence allows protocol downgrade/MITM."),
    "content-security-policy": (Severity.MEDIUM, "Mitigates XSS and data injection; absent means no CSP defense."),
    "x-content-type-options": (Severity.LOW, "Prevents MIME sniffing (should be 'nosniff')."),
    "x-frame-options": (Severity.LOW, "Defends against clickjacking (or use CSP frame-ancestors)."),
    "referrer-policy": (Severity.LOW, "Controls referrer leakage of sensitive URLs."),
    "permissions-policy": (Severity.LOW, "Restricts powerful browser features."),
}


class HeadersScanner(Scanner):
    name = "headers"
    engine = Engine.DAST
    builtin = True

    def scan(self, target: str, runner, raw_out) -> ScannerOutcome:
        if not target:
            return ScannerOutcome(self.name, "skipped", detail="no target URL")
        try:
            resp, headers, cookies, final_url = _fetch(target)
        except Exception as exc:  # noqa: BLE001
            return ScannerOutcome(self.name, "error", detail=f"could not reach {target}: {exc}")

        cors = _probe_cors(target)
        raw = {
            "url": final_url,
            "status": resp,
            "headers": headers,
            "set_cookie": cookies,
            "cors_probe": cors,
        }
        raw_file = raw_out("dast_headers.json", json.dumps(raw, indent=2))
        findings = self.parse(raw)
        return ScannerOutcome(self.name, "ran", findings=findings, raw_file=str(raw_file),
                              detail=f"{len(findings)} finding(s)")

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        url = raw.get("url", "")
        headers = {k.lower(): v for k, v in (raw.get("headers") or {}).items()}

        # 1. Missing security headers
        for name, (sev, why) in _SECURITY_HEADERS.items():
            if name not in headers:
                findings.append(Finding(
                    source="headers", engine=Engine.DAST, category="header",
                    severity=sev, title=f"Missing security header: {name}",
                    description=why, endpoint=url, method="GET",
                    rule_id=f"missing-{name}", owasp="A05:2021 - Security Misconfiguration",
                    remediation=f"Set the '{name}' response header.",
                    confidence=Confidence.CONFIRMED,
                ))

        # 2. CSP weaknesses (if present)
        csp = headers.get("content-security-policy", "")
        if csp:
            weak = []
            if "unsafe-inline" in csp:
                weak.append("'unsafe-inline'")
            if "unsafe-eval" in csp:
                weak.append("'unsafe-eval'")
            if "default-src *" in csp or " * " in f" {csp} ":
                weak.append("wildcard source (*)")
            if weak:
                findings.append(Finding(
                    source="headers", engine=Engine.DAST, category="header",
                    severity=Severity.MEDIUM, title="Weak Content-Security-Policy",
                    description=f"CSP contains weakening directives: {', '.join(weak)}.",
                    endpoint=url, method="GET", evidence=csp[:300],
                    rule_id="weak-csp", owasp="A05:2021 - Security Misconfiguration",
                    remediation="Remove unsafe-inline/unsafe-eval and wildcard sources; use nonces/hashes.",
                    confidence=Confidence.CONFIRMED,
                ))

        # 3. Info disclosure
        for h in ("server", "x-powered-by", "x-aspnet-version"):
            if h in headers and headers[h]:
                findings.append(Finding(
                    source="headers", engine=Engine.DAST, category="info-leak",
                    severity=Severity.INFO, title=f"Technology disclosure via '{h}' header",
                    description=f"Response advertises '{h}: {headers[h]}', aiding attacker fingerprinting.",
                    endpoint=url, method="GET", evidence=f"{h}: {headers[h]}",
                    rule_id=f"disclosure-{h}",
                    remediation=f"Suppress or genericize the '{h}' header.",
                    confidence=Confidence.CONFIRMED,
                ))

        # 4. CORS misconfiguration
        cors = raw.get("cors_probe") or {}
        acao = cors.get("access-control-allow-origin")
        acac = str(cors.get("access-control-allow-credentials", "")).lower()
        if acao == "*" and acac == "true":
            findings.append(Finding(
                source="headers", engine=Engine.DAST, category="cors",
                severity=Severity.HIGH, title="Insecure CORS: wildcard origin with credentials",
                description="ACAO '*' combined with credentials true lets any site read authenticated responses.",
                endpoint=url, method="OPTIONS", evidence=str(cors),
                rule_id="cors-wildcard-credentials", owasp="A05:2021 - Security Misconfiguration",
                remediation="Reflect only explicitly allow-listed origins; never pair '*' with credentials.",
                confidence=Confidence.CONFIRMED,
            ))
        elif cors.get("reflected_origin") and acac == "true":
            findings.append(Finding(
                source="headers", engine=Engine.DAST, category="cors",
                severity=Severity.HIGH, title="Insecure CORS: origin reflection with credentials",
                description="The server reflects an arbitrary Origin and allows credentials, enabling cross-site data theft.",
                endpoint=url, method="OPTIONS", evidence=str(cors),
                rule_id="cors-reflection-credentials", owasp="A05:2021 - Security Misconfiguration",
                remediation="Validate Origin against an allow-list before echoing it.",
                confidence=Confidence.CONFIRMED,
            ))

        # 5. Cookie flags
        for raw_cookie in raw.get("set_cookie") or []:
            lc = raw_cookie.lower()
            name = raw_cookie.split("=", 1)[0].strip()
            missing = [flag for flag, tok in (("Secure", "secure"), ("HttpOnly", "httponly")) if tok not in lc]
            if "samesite" not in lc:
                missing.append("SameSite")
            if missing:
                findings.append(Finding(
                    source="headers", engine=Engine.DAST, category="cookie",
                    severity=Severity.MEDIUM if "HttpOnly" in missing or "Secure" in missing else Severity.LOW,
                    title=f"Cookie '{name}' missing flags: {', '.join(missing)}",
                    description="Session cookies should set Secure, HttpOnly and SameSite to resist theft/CSRF.",
                    endpoint=url, method="GET", evidence=raw_cookie.split(";", 1)[0] + "; ...",
                    rule_id="cookie-flags",
                    remediation=f"Add the {', '.join(missing)} attribute(s) to cookie '{name}'.",
                    confidence=Confidence.CONFIRMED,
                ))
        return findings


def _opener() -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context()
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


def _fetch(url: str) -> tuple[int, dict[str, str], list[str], str]:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": _UA})
    opener = _opener()
    try:
        with opener.open(req, timeout=_TIMEOUT) as r:
            status = r.status
            headers = dict(r.headers.items())
            cookies = r.headers.get_all("Set-Cookie") or []
            final_url = r.geturl()
    except urllib.error.HTTPError as e:
        # An HTTP error response still carries headers worth inspecting.
        status = e.code
        headers = dict(e.headers.items()) if e.headers else {}
        cookies = e.headers.get_all("Set-Cookie") if e.headers else []
        final_url = url
    return status, headers, list(cookies or []), final_url


def _probe_cors(url: str) -> dict[str, Optional[str]]:
    """Send a benign cross-origin preflight to detect reflective/over-permissive CORS."""
    evil = "https://vulnforge-cors-probe.example"
    req = urllib.request.Request(
        url, method="OPTIONS",
        headers={
            "User-Agent": _UA,
            "Origin": evil,
            "Access-Control-Request-Method": "GET",
        },
    )
    try:
        with _opener().open(req, timeout=_TIMEOUT) as r:
            h = {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        h = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
    except Exception:
        return {}
    acao = h.get("access-control-allow-origin")
    return {
        "access-control-allow-origin": acao,
        "access-control-allow-credentials": h.get("access-control-allow-credentials"),
        "reflected_origin": (acao == evil),
    }
