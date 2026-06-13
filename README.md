# VulnForge AI

**Code-aware DAST. Runtime-aware SAST. AI-guided offensive testing.**

VulnForge AI is a combined **SAST + DAST** security scanning *orchestrator*. It does
not reinvent scanners — it runs best-in-class open-source tools, normalizes their
output into one schema, uses SAST findings to guide DAST, correlates static and
dynamic evidence into confirmed findings, and produces developer-, security-, and
executive-grade reports with architecture, data-flow, and attack-path diagrams.

> The differentiator is **SAST-guided DAST**: code analysis tells VulnForge *where*
> the app looks weak; dynamic testing *proves* whether it is exploitable; the
> correlation layer turns the two into a single, high-confidence finding.

## Status

This is an **MVP**, built CLI-first, one target at a time. See
[docs/MVP_SCOPE.md](docs/MVP_SCOPE.md) for exactly what is and isn't implemented.

| Phase | Capability | State |
|-------|-----------|-------|
| 1 | Project context + CLI + normalized findings + HTML report | ✅ working |
| 2 | SAST pipeline (Semgrep, Gitleaks, Trivy) | ✅ working |
| 3 | DAST pipeline (ZAP baseline, Nuclei, headers/CSP) | 🚧 scaffolded |
| 4 | Authenticated scanning (Playwright session replay) | 🚧 scaffolded |
| 5 | AI test planner | 🚧 scaffolded |
| 6 | Correlation engine + Mermaid diagrams | 🚧 scaffolded |

## Quick start

```powershell
# 1. Install (editable)
python -m pip install -e .

# 2. Create a project description to give the scan business context
vulnforge init my-app.yaml

# 3. Run a SAST scan against a repo (URL, local path, or .zip) and build a report
vulnforge scan --repo https://github.com/OWASP/NodeGoat --description my-app.yaml --out runs/nodegoat

# 4. Open the report
runs/nodegoat/report.html
```

VulnForge prefers **Docker** to run scanners (no local installs needed) and falls
back to native binaries on `PATH`. Any tool that is unavailable is **skipped
gracefully** and noted in the report — the scan never hard-fails because one
scanner is missing.

## Design principles

- **AI orchestrates scanners; it does not replace them.** Deterministic tools find
  facts; the AI layer interprets, prioritizes, and explains.
- **Simple and robust over clever.** One target at a time, a clean adapter per
  tool, graceful degradation everywhere.
- **Show progression, fail gracefully.** Every stage reports progress and survives
  individual tool failures.
- **Safe by default.** `safe` scan mode does no destructive/brute-force/DoS testing.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).
