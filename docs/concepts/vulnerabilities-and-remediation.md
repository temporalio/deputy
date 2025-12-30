# Vulnerabilities & remediation

Deputy is optimized for answering:

1) **What's vulnerable right now?** (`scan`)
2) **What changed?** (`diff`)
3) **What should we do next?** (`fix`, `triage`)

## Vulnerability Lifecycle

```mermaid
flowchart LR
    subgraph Discovery["Discovery"]
        Scan["deputy scan"]
        Diff["deputy diff"]
    end

    subgraph Analysis["Analysis"]
        Enrich["Enrich from OSV"]
        Severity["Classify severity"]
        Reachability["Check reachability"]
    end

    subgraph Action["Action"]
        Triage["deputy triage"]
        Fix["deputy fix"]
        Apply["--apply"]
    end

    subgraph Verify["Verify"]
        Rescan["Rescan"]
        Policy["Policy check"]
    end

    Scan --> Enrich
    Diff --> Enrich
    Enrich --> Severity
    Severity --> Reachability
    Reachability --> Triage
    Reachability --> Fix
    Triage --> Fix
    Fix --> Apply
    Apply --> Rescan
    Rescan --> Policy

    classDef source fill:#e3f2fd,stroke:#1565c0
    classDef process fill:#e8f5e9,stroke:#2e7d32
    classDef action fill:#fff3e0,stroke:#e65100
    classDef verify fill:#f3e5f5,stroke:#7b1fa2

    class Scan,Diff source
    class Enrich,Severity,Reachability process
    class Triage,Fix,Apply action
    class Rescan,Policy verify
```

## Vulnerability lookups

Deputy queries the OSV database using the normalized inventory.

Key flags (shared across `scan`, `diff`, `fix`, `triage`):

- `--ignore-unfixed`: filter out vulnerabilities without a known fixed version.
- `--published-after` / `--published-before`: time-window views (publication date).
- `--as-of`: “what was known up to and including this date?”

## Severity Handling

Deputy maps OSV severity scores to actionable tiers:

```mermaid
block-beta
    columns 4

    block:critical:1
        C["CRITICAL"]
    end
    block:high:1
        H["HIGH"]
    end
    block:medium:1
        M["MEDIUM"]
    end
    block:low:1
        L["LOW"]
    end

    block:critdesc:1
        CD["Immediate action<br/>Block releases"]
    end
    block:highdesc:1
        HD["Prioritize fix<br/>Track in sprint"]
    end
    block:meddesc:1
        MD["Schedule fix<br/>Monitor"]
    end
    block:lowdesc:1
        LD["Backlog<br/>Accept risk"]
    end

    C --> CD
    H --> HD
    M --> MD
    L --> LD

    classDef critical fill:#ffcdd2,stroke:#c62828
    classDef high fill:#ffe0b2,stroke:#e65100
    classDef medium fill:#fff9c4,stroke:#f9a825
    classDef low fill:#c8e6c9,stroke:#2e7d32

    class C,CD critical
    class H,HD high
    class M,MD medium
    class L,LD low
```

## Remediation plans

`deputy fix` turns findings into a **plan**:

- Runnable steps (e.g., `go get`, `npm install`) when Deputy can express a safe command
- Manual steps when human edits are required
- Optional application with `--apply` (local targets only)

Plans can be exported as JSON (`--format json`) for review/approval workflows.

## Triage

`deputy triage` produces a prioritized summary and can optionally delegate “what matters most?” analysis
to an agent (without necessarily granting repository write access).

## Code pointers

- Finding consolidation + severity logic: [`internal/analysis`](../../internal/analysis)
- Upgrade hints + plan materialization: [`internal/remediation`](../../internal/remediation)
- Report output formatters: [`internal/output`](../../internal/output)
