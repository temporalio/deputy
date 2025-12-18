# Deputy Documentation 🛡️

Deputy helps teams **understand, enforce, and improve** their software supply chain:

- **Inventory** dependencies across ecosystems
- **Scan** for known vulnerabilities (OSV) and produce actionable reports
- **Generate SBOMs** (CycloneDX / SPDX) for audit and compliance
- **Create remediation plans** and optionally apply them
- **Enforce policies** (CEL) in CI and at download-time via a package proxy

## Why Deputy

| Problem | Deputy's Approach |
| --- | --- |
| Scattered tools for scanning, SBOMs, remediation | Single CLI with composable commands |
| Policies repeated across repos and tools | Write once, enforce everywhere (scan, diff, proxy) |
| Reactive scanning finds issues too late | Proxy blocks risky packages at download time |
| Manual vulnerability triage | AI-assisted prioritization and remediation |
| Hard to audit "what changed" | Git-aware diff with time-travel queries |

## Who Uses Deputy

| Role | Primary Commands |
| --- | --- |
| **Developers** | `scan`, `diff`, `fix --apply` |
| **Security Teams** | `policy`, `scan --policy`, `proxy` |
| **Platform/CI** | `scan --format json`, `sbom`, policy gates |
| **Compliance** | `sbom --licenses`, historical scans |

## Quick Start

```console
# 1) Scan the current repo at HEAD
$ deputy scan

# 2) Generate a remediation plan (text)
$ deputy fix

# 3) Apply runnable fixes (local repos only)
$ deputy fix --apply

# 4) Produce an SBOM (CycloneDX JSON by default)
$ deputy sbom --output sbom.cdx.json
```

## How Deputy fits together

```mermaid
flowchart LR
  Repo[(Repo / Dir / Remote)] -->|inventory| Inv[Package inventory]
  Inv --> Scan[deputy scan]
  Inv --> SBOM[deputy sbom]
  Scan --> Findings[Vulnerability findings]
  Findings --> Fix[deputy fix]
  Fix --> Plan[Remediation plan]
  Plan --> Apply([--apply / agent / manual])

  subgraph Control["Control plane"]
    Policy[CEL policies] --> Scan
    Policy --> SBOM
    Policy --> Fix
    Policy --> Proxy[deputy proxy]
  end

  style Repo fill:#e1f5fe,stroke:#01579b
  style Inv fill:#fff3e0,stroke:#e65100
  style Scan fill:#e3f2fd,stroke:#1565c0
  style SBOM fill:#e3f2fd,stroke:#1565c0
  style Findings fill:#ffebee,stroke:#c62828
  style Fix fill:#e3f2fd,stroke:#1565c0
  style Plan fill:#e8f5e9,stroke:#2e7d32
  style Apply fill:#c8e6c9,stroke:#2e7d32
  style Policy fill:#fff3e0,stroke:#e65100,stroke-width:2px
  style Proxy fill:#e3f2fd,stroke:#1565c0
  style Control fill:#fffde7,stroke:#f57f17
```

## Documentation map

| Section | Description |
| --- | --- |
| [Getting Started](getting-started.md) | Install and first commands |
| [Cheat Sheet](cheatsheet.md) | Quick reference for common patterns |
| [FAQ](faq.md) | Frequently asked questions |
| [Glossary](glossary.md) | Key terms and definitions |
| [Concepts](concepts/README.md) | Mental models: targets, refs, policies |
| [Commands](commands/README.md) | Full command reference |
| [Guides](guides/README.md) | CI, workflows, policy cookbook |
| [Examples](examples/README.md) | Realistic output and transcripts |
| [Reference](reference/README.md) | Configuration, logging, environment |
| [Development](development/README.md) | Contributing, architecture |

> **For LLMs:** See [`LLMS.txt`](../LLMS.txt) for structured project context.

## Where to look in code

- CLI wiring + subcommands: [`internal/cli`](../internal/cli) and [`internal/cli/cmd`](../internal/cli/cmd)
- Inventory + PURL normalization: [`internal/inventory`](../internal/inventory), [`internal/purlx`](../internal/purlx)
- Vulnerability analysis + remediation planning: [`internal/analysis`](../internal/analysis), [`internal/remediation`](../internal/remediation)
- SBOM generation: [`internal/sbom`](../internal/sbom)
- Policy engine + entrypoints: [`internal/policy`](../internal/policy)
- Proxy runtime: [`internal/proxy`](../internal/proxy)
