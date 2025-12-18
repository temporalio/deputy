# Concepts

Understanding these core ideas makes Deputy's CLI output and flags feel predictable.

## Core Mental Models

| Concept | What it answers | Doc |
| --- | --- | --- |
| **Targets & Refs** | "What can Deputy analyze? How do I specify versions?" | [`targets-and-refs.md`](targets-and-refs.md) |
| **Inventory & SBOMs** | "How does Deputy discover packages? What's a PURL?" | [`inventory-and-sboms.md`](inventory-and-sboms.md) |
| **Vulnerabilities & Remediation** | "How does scanning work? What's a fix plan?" | [`vulnerabilities-and-remediation.md`](vulnerabilities-and-remediation.md) |
| **Policies (CEL)** | "How do I encode rules? What are entrypoints?" | [`policies.md`](policies.md) |

## Quick Orientation

```
┌─────────────────────────────────────────────────────────────────┐
│                         TARGET                                  │
│  (repo, directory, SBOM file, remote URL)                       │
│                            │                                    │
│                            ▼                                    │
│                      ┌──────────┐                               │
│                      │ Inventory│ ◄── Package discovery         │
│                      └────┬─────┘                               │
│                           │                                     │
│          ┌────────────────┼────────────────┐                    │
│          ▼                ▼                ▼                    │
│    ┌──────────┐    ┌──────────┐    ┌──────────┐                │
│    │   scan   │    │   sbom   │    │   diff   │                │
│    └────┬─────┘    └──────────┘    └──────────┘                │
│         │                                                       │
│         ▼                                                       │
│    ┌──────────┐                                                │
│    │   fix    │ ◄── Remediation plan                           │
│    └──────────┘                                                │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  POLICIES (CEL)                                         │   │
│  │  Applied to: scan, diff, sbom, fix, triage, proxy       │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Key Terms

- **PURL**: Package URL — a standard way to identify packages across ecosystems (`pkg:golang/github.com/gin-gonic/gin@v1.9.0`)
- **OSV**: Open Source Vulnerabilities database — Deputy's vulnerability data source
- **CEL**: Common Expression Language — the language used for Deputy policies
- **Entrypoint**: A specific point where policies are evaluated (e.g., `scan_vulnerability`, `go_artifact_request`)
- **SBOM**: Software Bill of Materials — a machine-readable inventory of components

## See Also

- Commands reference: [`docs/commands/README.md`](../commands/README.md)
- Practical guides: [`docs/guides/README.md`](../guides/README.md)
