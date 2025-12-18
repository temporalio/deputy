# Workflows

Use this page to pick the “right” Deputy command for the job.

## Choose a command

```mermaid
flowchart TD
  Start([What are you trying to do?]) --> A{Need an inventory artifact?}
  A -->|Yes| SBOM(["✅ deputy sbom"])
  A -->|No| B{Need vulnerability findings?}
  B -->|Yes| Scan(["✅ deputy scan"])
  B -->|No| C{Need a dependency change view?}
  C -->|Yes| Diff(["✅ deputy diff"])
  C -->|No| D{Need upgrade commands?}
  D -->|Yes| Fix(["✅ deputy fix"])
  D -->|No| E{Need prioritization?}
  E -->|Yes| Triage(["✅ deputy triage"])
  E -->|No| F{Need enforcement at download-time?}
  F -->|Yes| Proxy(["✅ deputy proxy"])
  F -->|No| Policy(["✅ deputy policy"])

  style Start fill:#e3f2fd,stroke:#1565c0
  style A fill:#fff8e1,stroke:#ff8f00
  style B fill:#fff8e1,stroke:#ff8f00
  style C fill:#fff8e1,stroke:#ff8f00
  style D fill:#fff8e1,stroke:#ff8f00
  style E fill:#fff8e1,stroke:#ff8f00
  style F fill:#fff8e1,stroke:#ff8f00
  style SBOM fill:#c8e6c9,stroke:#2e7d32
  style Scan fill:#c8e6c9,stroke:#2e7d32
  style Diff fill:#c8e6c9,stroke:#2e7d32
  style Fix fill:#c8e6c9,stroke:#2e7d32
  style Triage fill:#c8e6c9,stroke:#2e7d32
  style Proxy fill:#c8e6c9,stroke:#2e7d32
  style Policy fill:#c8e6c9,stroke:#2e7d32
```

## Typical team setup

- Local: `deputy diff` and `deputy scan` for rapid feedback.
- CI: `deputy scan --format json` and `deputy sbom` to produce artifacts.
- Org controls: policies in `policy/`, enforced in CI and/or proxy.

