# Architecture

Deputy is a Go CLI that composes a few core subsystems: inventory, analysis, remediation, policy, and proxy.

## Package map (high level)

```mermaid
flowchart TB
  subgraph Entry["Entry Point"]
    CLI[internal/cli]
  end

  subgraph Commands["Command Layer"]
    CMD[internal/cli/cmd]
  end

  subgraph Core["Core Packages"]
    Repo[internal/repository]
    Inv[internal/inventory]
    Analysis[internal/analysis]
    Remed[internal/remediation]
    SBOM[internal/sbom]
    Policy[internal/policy]
    Proxy[internal/proxy]
  end

  subgraph Support["Support Packages"]
    Git[internal/gitutil]
    PURL[internal/purlx]
    Out[internal/output]
  end

  CLI --> CMD
  CMD --> Repo & Inv & Analysis & Remed & SBOM & Policy & Proxy
  Repo --> Git
  Inv --> PURL
  Analysis --> Out

  style CLI fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
  style CMD fill:#fff3e0,stroke:#e65100
  style Entry fill:#e3f2fd,stroke:#1565c0
  style Commands fill:#fff3e0,stroke:#e65100
  style Core fill:#e8f5e9,stroke:#2e7d32
  style Support fill:#f3e5f5,stroke:#7b1fa2
```

## Design principles

- **One inventory model** reused across commands.
- **Non-destructive Git operations** (snapshots vs mutating working trees).
- **Policy as a reusable control plane**, not a one-off filter per command.
- **Pipeline-friendly I/O** (stdout/stderr, JSON formats, `--output` flags).

## Code pointers

- Root command wiring: [`internal/cli/cli.go`](../../internal/cli/cli.go)
- Subcommands: [`internal/cli/cmd`](../../internal/cli/cmd)
- Policy engine: [`internal/policy`](../../internal/policy)
- Proxy adapters + servers: [`internal/proxy`](../../internal/proxy)
