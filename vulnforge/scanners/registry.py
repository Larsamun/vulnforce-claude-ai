"""Registry of available scanner adapters, keyed by name."""
from __future__ import annotations

from typing import Optional

from .base import Scanner
from .sast.semgrep import SemgrepScanner
from .sast.gitleaks import GitleaksScanner
from .sast.trivy import TrivyScanner
from .dast.headers import HeadersScanner
from .dast.nuclei import NucleiScanner
from .dast.zap import ZapBaselineScanner

_SAST: dict[str, type[Scanner]] = {
    "semgrep": SemgrepScanner,
    "gitleaks": GitleaksScanner,
    "trivy": TrivyScanner,
}

_DAST: dict[str, type[Scanner]] = {
    "headers": HeadersScanner,
    "nuclei": NucleiScanner,
    "zap": ZapBaselineScanner,
}


def get_sast_scanner(name: str) -> Optional[Scanner]:
    cls = _SAST.get(name.lower())
    return cls() if cls else None


def get_dast_scanner(name: str) -> Optional[Scanner]:
    cls = _DAST.get(name.lower())
    return cls() if cls else None


def known_sast() -> list[str]:
    return list(_SAST)


def known_dast() -> list[str]:
    return list(_DAST)
