# VulnForge AI — MVP Scope

Anchored to the final target in the brief: *successfully scan one target (SAST +
DAST), a manual step during the process is OK, CLI is OK, one target at a time.*

## In scope (MVP)

- **CLI**, one target per run, no multi-project/multi-tenant.
- **Inputs:** GitHub repo URL · local folder · `.zip` upload · target URL ·
  description YAML · optional Playwright `storageState` for auth.
- **SAST:** Semgrep, Gitleaks, Trivy — normalized into one schema.
- **DAST:** ZAP baseline, Nuclei, custom security-headers/CSP/CORS check.
- **AI (optional):** summarize app, generate DAST test priorities, explain
  findings, generate attack-path diagram. Degrades cleanly with no API key.
- **Correlation:** map SAST sinks ↔ DAST endpoints into combined findings.
- **Output:** HTML report (dev/security/exec views), Mermaid diagrams, normalized
  `findings.json`.

## Explicitly NOT in the MVP

(Deferred per the brief — "the first version should not do these things".)

- Full exploit automation, autonomous brute-forcing, heavy fuzzing by default
- Multi-tenant SaaS, web UI, enterprise SSO
- Complex Kubernetes deployment, billing
- Automatic GitHub App installation flow (token / local path is fine for the lab)
- Custom SAST or DAST engines written from scratch (orchestrate existing tools)

## Implemented in this build

- ✅ Phase 1 — Project context, CLI shell, normalized `Finding` schema, run
  directory, HTML report, `findings.json`, tool `doctor` command.
- ✅ Phase 2 — SAST pipeline: Semgrep + Gitleaks + Trivy adapters (Docker-first,
  native fallback, graceful skip), repo ingestion (clone / zip / local).
- ✅ Phase 3 — DAST pipeline: built-in headers/CSP/CORS/cookie check (no deps),
  Nuclei (safe-tagged) and ZAP baseline adapters; authorization + safe-mode
  enforcement; DAST findings merged through the correlation engine.
- 🚧 Phases 4–6 — authenticated scanning (Playwright), LLM-backed AI planner,
  full SAST↔DAST correlation/diagrams: contracts and stubs in place, implemented next.

## Build order (remaining)

1. DAST orchestrator: `httpx` probe → `katana` crawl → ZAP baseline → Nuclei →
   headers/CSP/CORS check. First milestone: given a URL, crawl + report runtime
   findings.
2. Authenticated scanning: Playwright login recorder → reuse `storageState`.
3. AI planner: description + SAST findings + crawl → prioritized DAST test plan.
4. Correlation + Mermaid: code evidence + runtime evidence + attack-path diagram
   per finding.

## Acceptance for "MVP done"

A single command takes a repo + URL + description and produces an HTML report
containing: detected stack, normalized SAST findings, runtime DAST findings, at
least one **correlated** finding with both code and runtime evidence, an attack-path
diagram, and a machine-readable `findings.json`.
