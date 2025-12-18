# CI: gating and artifacts

Deputy can power two common CI patterns:

1) **Gate merges/releases** (fail on unacceptable risk)  
2) **Produce artifacts** (JSON reports + SBOMs for audit and diffing)

## Minimal GitHub Actions example

```yaml
name: deputy
on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "stable"
      - run: go install github.com/picatz/deputy@latest

      # Produce JSON artifacts you can archive or diff over time
      - run: deputy scan --format json --ignore-unfixed --output scan.json
      - run: deputy sbom --format spdx-json --output sbom.spdx.json

      - uses: actions/upload-artifact@v4
        with:
          name: deputy
          path: |
            scan.json
            sbom.spdx.json
```

## Enforcing policy in CI

Policies are the most maintainable way to encode org-specific rules.

```console
$ deputy scan --policy policy/examples/severity-guardrail.yaml
```

See:
- [`docs/concepts/policies.md`](../concepts/policies.md)
- [`POLICY.md`](../../POLICY.md)
