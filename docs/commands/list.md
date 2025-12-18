# `deputy list`

Emit a flat dependency inventory (PURLs) for quick auditing and scripting.

## When to use it

- You want a lightweight inventory (vs a full SBOM).
- You want to grep/jq a normalized list of package identifiers.
- You want to verify what Deputy is detecting.

## Common patterns

```console
# Default output
$ deputy list

# JSON for jq
$ deputy list --format json | jq '.items[] | {purl: .purl, direct: .isDirect}'

# TSV for pipelines: purl<TAB>direct
$ deputy list --format tsv --no-header | cut -f1

# Only direct deps
$ deputy list --only-direct

# Show sources (which manifest/lockfile)
$ deputy list --show-sources
```

## Output formats

- `text`: aligned, colored columns `PURL` and `DIRECT` (indirect is dimmed)
- `tsv`: `purl\tdirect` (use `--no-header` to omit header)
- `json`: structured output including `ecosystem`, `name`, `version`, `module`, `isDirect`, `purl`

Notes:
- No dedup: every discovered package is emitted (similar to SBOM output).
- Sorting: results are sorted by PURL for stable output.

## Code pointers

- CLI command: [`internal/cli/cmd/list.go`](../../internal/cli/cmd/list.go)
- Inventory extraction: [`internal/inventory`](../../internal/inventory)
