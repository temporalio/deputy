# Vulnerabilities & remediation

Deputy is optimized for answering:

1) **What’s vulnerable right now?** (`scan`)  
2) **What changed?** (`diff`)  
3) **What should we do next?** (`fix`, `triage`)

## Vulnerability lookups

Deputy queries the OSV database using the normalized inventory.

Key flags (shared across `scan`, `diff`, `fix`, `triage`):

- `--ignore-unfixed`: filter out vulnerabilities without a known fixed version.
- `--published-after` / `--published-before`: time-window views (publication date).
- `--as-of`: “what was known up to and including this date?”

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
