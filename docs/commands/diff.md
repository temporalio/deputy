# `deputy diff`

Compare dependency changes between Git references and (optionally) scan the resulting dependency set.

## When to use it

- In PR review (“what dependencies did this change introduce?”).
- For release comparisons between tags.
- To evaluate the impact of a lockfile update.

## Common patterns

```console
# Default: default branch → HEAD (or WORKING when manifests changed)
$ deputy diff

# Compare two explicit refs
$ deputy diff v1.27.0 v1.28.0

# Compare default branch → a feature branch
$ deputy diff feature/user-auth

# Time-based refs (quote `@{...}`)
$ deputy diff "HEAD@{yesterday}" HEAD
$ deputy diff "main@{1.week.ago}" main

# Speed: skip vulnerability scanning
$ deputy diff --skip-vuln-scan main feature/user-auth

# Include license info for changed dependencies
$ deputy diff --licenses --license-source depsdev main feature/user-auth
```

## Vulnerability output controls

The diff view can scan the target dependency set and present a focused report:

- Changed dependencies first.
- Unchanged dependencies are hidden by default unless they exceed a severity threshold.

Useful flags:

```console
# Always show vulnerabilities from unchanged dependencies
$ deputy diff v1.27.0 v1.28.0 --show-unchanged

# Hide vulnerabilities without a known fix (mirrors scan)
$ deputy diff v1.27.0 v1.28.0 --ignore-unfixed

# Control the auto-show threshold for unchanged vulnerabilities
# Options: none | low | med | high | critical | any (default: critical)
$ deputy diff v1.27.0 v1.28.0 --unchanged-threshold high
```

## Tips

- Quote time-based refs: `deputy diff "HEAD@{yesterday}" HEAD`
- Use `--show-unchanged` and `--unchanged-threshold` to tune how vulnerability output is summarized.
- For a deeper “time travel” guide (WORKING, `@{...}`, and examples), see [`docs/examples/time-travel.md`](../examples/time-travel.md).

## Code pointers

- CLI command: [`internal/cli/cmd/diff.go`](../../internal/cli/cmd/diff.go)
- Repo snapshots + ref parsing: [`internal/gitutil`](../../internal/gitutil), [`internal/repository`](../../internal/repository)
- Comparison engine: [`internal/compare`](../../internal/compare)
