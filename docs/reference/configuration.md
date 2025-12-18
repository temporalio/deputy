# Configuration

Deputy can be configured via flags, environment variables, and an optional YAML config file.

## Precedence

Highest wins:

1. Command-line flags
2. Environment variables (`DEPUTY_*`)
3. Configuration file
4. Built-in defaults

## Config file locations

Deputy searches (in order):

- `.deputy.yaml` (current directory)
- `deputy.yaml` (current directory)
- `~/.deputy.yaml` (home directory)

Or set `DEPUTY_CONFIG=/path/to/config.yaml`.

```mermaid
flowchart TD
  Flags["1️⃣ CLI flags"] --> Merge[Effective config]
  Env["2️⃣ DEPUTY_* env vars"] --> Merge
  File["3️⃣ Config file"] --> Merge
  Defaults["4️⃣ Built-in defaults"] --> Merge

  style Flags fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
  style Env fill:#dcedc8,stroke:#558b2f
  style File fill:#f0f4c3,stroke:#9e9d24
  style Defaults fill:#fff9c4,stroke:#f9a825
  style Merge fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
```

## Starter config

This repo includes an annotated example:

- [`.deputy.yaml.example`](../../.deputy.yaml.example)

Copy it to `.deputy.yaml` and adjust as needed.

## What belongs in config

- Logging defaults (level/format/color)
- Scan defaults (ecosystems, caching)
- Proxy defaults (listen address, policy paths)
- Policy defaults (paths, mode)

For command-specific one-offs, prefer flags so CI jobs remain explicit.

