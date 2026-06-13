"""Registry of available scanner adapters, keyed by name."""
from __future__ import annotations

from typing import Optional

from .base import Scanner
from .sast.semgrep import SemgrepScanner
from .sast.gitleaks import GitleaksScanner
from .sast.trivy import TrivyScanner

_SAST: dict[str, type[Scanner]] = {
    "semgrep": SemgrepScanner,
    "gitleaks": GitleaksScanner,
    "trivy": TrivyScanner,
}

# DAST adapters are registered here as they are implemented (phase 3+).
_DAST: dict[str, type[Scanner]] = {}


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
