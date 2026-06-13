# VulnForge AI — Product Spec

## One-liner

VulnForge AI is a context-aware offensive-security platform that connects to code,
logs in to applications, runs AI-guided SAST and DAST, maps application
architecture and data flows, validates attack paths, and produces visual,
business-aware security reports developers and leaders can act on.

## Problem

Most tools run SAST and DAST **separately**, producing two piles of noisy,
low-confidence findings. SAST says "possible SQL injection" with no proof; DAST
fuzzes blindly with no knowledge of the code. Neither understands what the
application *does* or which data *matters*, so prioritization is guesswork.

## Approach

1. **Context first.** The user describes the app (purpose, users, data
   criticality, critical flows, testing goals, out-of-scope) — this becomes the
   "business brain" of the scan and drives prioritization.
2. **SAST finds suspicious code paths** (sources → sinks, missing auth checks,
   secrets, vulnerable deps, IaC misconfig).
3. **AI turns code knowledge into a targeted DAST test plan** instead of blind
   fuzzing.
4. **DAST validates against the running app** (authenticated, multi-identity).
5. **The correlation engine** fuses static + dynamic evidence into a single
   finding with a confidence state (Confirmed / Likely / Possible / False
   positive).
6. **Reports** explain *how the app works*, *where data flows*, and *how each
   finding maps to a realistic attack path* — with diagrams.

## The differentiator: SAST-guided DAST

```
SAST finds:                      DAST then tests:
- /api/customer/{id}             - user A requests /api/customer/B
- missing ownership check        - compares response
- customerId from request path   - checks whether cross-user data is exposed
- DB returns customer profile    => confirmed IDOR / broken access control
```

## Inputs

- GitHub repo URL, private repo (token), or `.zip` / local folder upload
- Target URL (live app)
- OpenAPI/Swagger spec (optional)
- Description YAML (business + security context) — see `examples/app-description.yaml`
- Optional Playwright auth session (`storageState`) for authenticated DAST

## Scanners orchestrated (MVP set)

| Engine | Tools |
|--------|-------|
| SAST | Semgrep (code patterns), Gitleaks (secrets), Trivy (deps/secrets/IaC misconfig) |
| DAST | OWASP ZAP baseline, Nuclei, custom security-headers/CSP/CORS check |

**Other orchestration candidates worth adding** (answering "suggest others"):
osv-scanner, Bandit (Python), pip-audit / npm audit, Checkov (IaC), CodeQL where
available, `httpx` + `katana` (probing/crawl), `ffuf`/`feroxbuster` (content
discovery), Nikto, `nikto`, `dalfox` (XSS), `sqlmap` (gated, deep mode only),
`nuclei` fuzzing templates, `retire.js`. Keep all of these behind the same
"detect & skip" adapter contract.

## Outputs

- **HTML report** (3 audiences: developer / security / executive)
- **Mermaid diagrams** (architecture, data flow, trust boundary, attack path) +
  raw Mermaid source stored per finding
- **Normalized `findings.json`** (machine-readable, stable schema)
- Later: Jira / GitHub / Azure DevOps tickets, PDF, retest tracking

## Scan modes

| Mode | Use | Behavior |
|------|-----|----------|
| `safe` | production | read-only, no destructive payloads, no brute force, no DoS, rate-limited |
| `deep` | staging / authorized | heavier fuzzing, role testing, business-logic checks, controlled validation |
| `release` | CI/CD | fast checks, blocks confirmed critical/high, comments on PRs, stores evidence |

Default is `safe`.

## Naming

Chosen: **VulnForge AI**. Alternatives considered: Helix (two intertwined strands =
SAST+DAST), Chimera (two-headed hybrid), ForgeSight, Aegisweave, Continuum (CTEM),
Sentriforge, Reforge, Vantage.
