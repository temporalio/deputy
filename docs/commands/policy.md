# `deputy policy`

Develop, test, and evaluate Deputy CEL policies.

See also:
- Framework overview: [`POLICY.md`](../../POLICY.md)
- Policy spec: [`POLICY_SPEC.md`](../../POLICY_SPEC.md)
- LSP wiring: [`docs/policy-lsp.md`](../policy-lsp.md)

## Common patterns

```console
# Lint policies
$ deputy policy lint policy/examples/*.yaml

# Bundle policies for fast reuse
$ deputy policy bundle --out corp.bundle.json policy/examples/*.yaml

# Evaluate policies against JSON from any deputy command
$ deputy scan --format json > scan.json
$ deputy policy eval --policy policy/examples/severity-guardrail.yaml --input scan.json
```

## Code pointers

- CLI command: [`internal/cli/cmd/policy.go`](../../internal/cli/cmd/policy.go)
- Policy runtime: [`internal/policy`](../../internal/policy)
