"""Generate Mermaid diagram sources. We store Mermaid text (not just rendered
images) so developers can paste it into GitHub / Azure DevOps / Confluence. The
HTML report renders it client-side via mermaid.js."""
from __future__ import annotations

import re

from ..config import AppDescription
from ..models import Finding, Severity


def _node_id(text: str) -> str:
    """Safe Mermaid node id."""
    return "n_" + re.sub(r"[^a-zA-Z0-9]", "_", text)[:40]


def _esc(text: str) -> str:
    return (text or "").replace('"', "'").replace("\n", " ")[:80]


def architecture_diagram(desc: AppDescription, stack: list[str]) -> str:
    """High-level architecture from description + detected stack. Best-effort; the
    full code-graph version comes in a later phase."""
    frontend = next((s for s in stack if s in ("Next.js", "React", "Angular", "Vue")), "Web Frontend")
    backend = next((s for s in stack if s in ("Express", "NestJS", "FastAPI", "Django", "Flask", "Java (Maven)")), "Backend / API")
    users = desc.primary_users or ["User"]

    lines = ["flowchart TD"]
    for u in users[:3]:
        lines.append(f'  {_node_id(u)}["{_esc(u)}"]:::actor')
    lines.append(f'  FE["{_esc(frontend)}"]:::app')
    lines.append(f'  BE["{_esc(backend)}"]:::api')
    lines.append('  DB[("Data Store")]:::data')
    for u in users[:3]:
        lines.append(f"  {_node_id(u)} --> FE")
    lines.append("  FE --> BE")
    lines.append("  BE --> DB")
    if desc.sensitive_data:
        lines.append(f'  DB -. "{_esc(", ".join(desc.sensitive_data[:3]))}" .-> BE')
    lines += [
        "  classDef actor fill:#eef,stroke:#88a;",
        "  classDef app fill:#efe,stroke:#8a8;",
        "  classDef api fill:#ffe,stroke:#aa8;",
        "  classDef data fill:#fee,stroke:#a88;",
    ]
    return "\n".join(lines)


def trust_boundary_diagram(desc: AppDescription) -> str:
    return "\n".join([
        "flowchart TD",
        '  I["Internet User"]:::untrusted',
        '  W["Public Web App"]:::semi',
        '  A["Backend API"]:::trusted',
        '  D[("Sensitive Data Store")]:::data',
        '  I -- "untrusted input" --> W',
        '  W -- "authenticated call" --> A',
        '  A -- "privileged query" --> D',
        "  classDef untrusted fill:#fde,stroke:#c69;",
        "  classDef semi fill:#ffe,stroke:#aa6;",
        "  classDef trusted fill:#efe,stroke:#6a6;",
        "  classDef data fill:#eef,stroke:#66a;",
    ])


def attack_path_diagram(f: Finding) -> str:
    """A generic-but-specific attack path for a high/critical finding."""
    where = f.endpoint or (f"{f.file}:{f.line}" if f.file else "the affected component")
    cat = f.category.lower()

    if "secret" in cat:
        steps = [
            "Attacker obtains source or build artifact",
            f"Locates exposed secret in {_esc(where)}",
            "Uses credential against the live service",
            "Gains unauthorized access / lateral movement",
        ]
    elif cat in ("injection",) or "sql" in f.title.lower():
        steps = [
            "Attacker authenticates as a normal user",
            f"Sends crafted input to {_esc(where)}",
            "Input reaches a sink without parameterization",
            "Database query is manipulated",
            "Data exfiltration or auth bypass",
        ]
    elif "idor" in f.title.lower() or "access" in cat or "authz" in cat:
        steps = [
            "Attacker logs in as customer A",
            f"Requests own object via {_esc(where)}",
            "Swaps the object id to customer B's",
            "Server does not verify ownership",
            "Attacker receives another user's data",
        ]
    else:
        steps = [
            "Attacker reaches the affected surface",
            f"Targets {_esc(where)}",
            f"Exploits the {_esc(f.category)} weakness",
            "Security impact realized",
        ]

    lines = ["flowchart TD"]
    ids = [f"s{i}" for i in range(len(steps))]
    for i, (sid, step) in enumerate(zip(ids, steps)):
        lines.append(f'  {sid}["{_esc(step)}"]')
        if i:
            lines.append(f"  {ids[i-1]} --> {sid}")
    return "\n".join(lines)


def dataflow_diagram(f: Finding) -> str:
    src = f.endpoint or (f.file or "request input")
    lines = [
        "flowchart TD",
        f'  a["{_esc(src)}"]',
        '  b["Application handler"]',
        '  c["Data access / sink"]',
        '  d["Response returned"]',
        "  a --> b --> c --> d",
    ]
    if "access" in f.category or "idor" in f.title.lower():
        lines.append('  c -.->|"missing ownership/authorization check"| d')
    return "\n".join(lines)
