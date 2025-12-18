# `deputy triage`

Summarize and prioritize vulnerability findings so you know where to start.

## When to use it

- A repo has many findings and you need the “top risks” view.
- You want a structured summary (`--format json`) for dashboards or audits.
- You want optional AI analysis (text-only or repo-aware, depending on agent).

## Common patterns

```console
# Triage current repo
$ deputy triage

# Triage remote repo at a ref
$ deputy triage github.com/hashicorp/vagrant --ref main

# Reduce noise
$ deputy triage --ignore-unfixed

# JSON output
$ deputy triage --format json > triage.json

# Triage an existing scan report
$ deputy triage --report scan.json --format json
```

## Notes

- Triaging without `--report` performs a fresh scan (same inventory engine as `deputy scan`).
- `--format json` emits a structured summary suitable for archiving and diffing over time.

## Code pointers

- CLI command: [`internal/cli/cmd/triage.go`](../../internal/cli/cmd/triage.go)
- Analysis + clustering: [`internal/analysis`](../../internal/analysis)
