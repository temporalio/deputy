# `deputy fix`

Generate a remediation plan from a scan report (or a fresh scan) and optionally apply runnable steps.

## When to use it

- You want **upgrade commands** for fixable findings.
- You want a JSON plan for review/approval or automation.
- You want to delegate implementation to an agent (carefully).

## Common patterns

```console
# Plan from a fresh scan
$ deputy fix

# Export a plan you can review
$ deputy fix --format json > plan.json

# Reuse an existing scan report (JSON) from CI
$ deputy scan --format json --output scan.json
$ deputy fix --report scan.json

# Pipe a report directly
$ deputy scan --format json --output - | deputy fix --report -

# Apply runnable steps (local repos only)
$ deputy fix --apply .

# Apply a previously saved plan
$ deputy fix --plan plan.json --apply .
```

## Notes

- `--ref`, `--ecosystems`, and published-date filters mirror `deputy scan`.
- `--apply` executes only steps marked runnable (for example `go get`, `npm install`) and runs them from the manifest directory.
- Use `--format json` to produce a reviewable plan artifact for approval workflows.

## Example output

- End-to-end transcript (scan → fix → diff → sbom): [`docs/examples/pipeline.md`](../examples/pipeline.md)

## Agent delegation

Deputy can pass the plan to an agent for assistance:

```console
$ deputy fix --agent codex --agent-sandbox workspace-write
```

See [`docs/guides/agents.md`](../guides/agents.md) for safe operating patterns.

## Code pointers

- CLI command: [`internal/cli/cmd/fix.go`](../../internal/cli/cmd/fix.go)
- Planning logic: [`internal/remediation`](../../internal/remediation)
