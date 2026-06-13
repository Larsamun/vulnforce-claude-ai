"""Dynamic analysis scanner adapters (Phase 3+ - scaffold).

Planned adapters (registered in ../registry.py as implemented):
  - headers : custom security-headers / CSP / CORS / cookie-flags check (no deps)
  - httpx   : fast HTTP probe
  - katana  : crawler for route discovery
  - zap     : OWASP ZAP baseline (passive) scan
  - nuclei  : template-based active checks

All will implement the same `Scanner` contract as the SAST adapters, run via
Docker-or-native with graceful skip, and honor the scan mode's safety envelope.
"""
