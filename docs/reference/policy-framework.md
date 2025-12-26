# Policy Framework

Deputy policies capture a decision once and enforce it everywhere: scan, diff, sbom, fix, triage, and the artifact proxy. Policies are structured YAML bundles compiled to CEL and evaluated against a consistent input map, so rules stay readable, testable, and auditable.

## Quick start

1. Write a policy bundle in YAML.
2. Lint and test it.
3. Bundle it for distribution.
4. Attach it to any command with `--policy`.

Example policy (`policy/block-critical.yaml`):

```yaml
policies:
  - name: block-critical
    entrypoints: ["scan_vulnerability"]
    rules:
      - action: deny
        when: vulnerability.?severity.orValue("") == "CRITICAL"
        reason: "critical vulnerability found"
```

Typical workflow:

```bash
deputy policy lint policy/block-critical.yaml
deputy policy test policy/
deputy policy bundle --out policy/corp.bundle.json policy/*.yaml
deputy scan --policy policy/corp.bundle.json
```

## Bundle structure

Policies are structured bundles with a top-level `policies` list. Each policy supports:

- `name`, `description`
- `entrypoints`, `commands`, `ecosystems` (optional filters)
- `mode` (`enforce` default, or `advisory`)
- `vars` (reusable values for rule logic)
- `rules` (each rule has `action`, `when`, and optional metadata)

Example license policy (from `policy/examples/license-allowlist.yaml`):

```yaml
policies:
  - name: allow-sans-copyleft
    description: Block packages carrying copyleft licenses
    vars:
      forbidden:
        - SSPL-1.0
        - AGPL-3.0-only
        - AGPL-3.0
        - GPL-3.0
        - GPL-3.0-only
    rules:
      - action: deny
        when: pkg.?licenses.orValue([]).exists(l, l in forbidden)
        reason: package carries a forbidden license
      - action: warn
        when: size(pkg.?licenses.orValue([])) == 0
        reason: package missing license metadata
```

Note on `vars`: string values are CEL expressions; non-string values are treated as literal data (lists, maps, numbers). Structured YAML is the supported authoring format; `deputy policy eval` expects raw CEL and is best used for ad hoc evaluation.

## Actions and enforcement

Policies return a list of action objects:

| Action | Effect | Common use |
| --- | --- | --- |
| `allow` | Explicitly allow | Add metadata, optional override |
| `warn` | Non-blocking | Notify, audit, or soft gates |
| `deny` | Blocking | Enforce policy, fail the command |

Use `mode: advisory` to downgrade `deny` actions from that policy into `warn` actions for canary rollouts.

## Inputs and entrypoints

See the [policy inputs](policy-inputs.md) for the full entrypoint list, standard variables, proxy version fields, and example payloads.

## CEL helpers and extensions

Deputy enables CEL optional types and registers a small helper library:

- `now()` and `age()` for time-based checks
- `levenshtein()` and `levenshteinWithin()` for string distance checks

Enabled CEL extensions:

- `ext.Strings` (matches, split, join, trim, replace, upperAscii, lowerAscii)
- `ext.Lists`, `ext.Sets`, `ext.Regex`
- `ext.Bindings` (cel.bind)
- `ext.Encoders` (base64.encode/decode)
- `ext.Math`

## Tooling commands

| Command | Use case | Notes |
| --- | --- | --- |
| `deputy policy eval` | Evaluate raw CEL against JSON | Expects CEL source, not YAML bundles |
| `deputy policy lint` | Validate syntax and types | Accepts YAML bundles or bundles compiled to JSON |
| `deputy policy test` | Run JSON fixtures | Uses `.policytest.json` files |
| `deputy policy bundle` | Build a JSON bundle | Output is portable and fast to load |
| `deputy policy inspect` | Inspect a bundle | Prints schema and policy names |
| `deputy policy simulate` | Replay policies against inputs | Useful for canarying changes |
| `deputy policy repl` | Interactive CEL playground | Good for quick experiments |
| `deputy policy lsp` | Editor integrations | See the [policy LSP setup](../policy-lsp.md) |

### Policy tests

Policy tests live in `.policytest.json` files alongside your policies:

```json
{
  "name": "blocks critical vulnerabilities",
  "policy": "./policy/block-critical.yaml",
  "input": "./testdata/critical.json",
  "want": [
    {"action": "deny", "reason": "critical vulnerability found"}
  ]
}
```

You can also use `policies` (array) or inline `input_json` to avoid separate files.

## Bundles and distribution

`deputy policy bundle` produces a JSON bundle with schema `policy.deputy.sh/v1alpha1`. Bundles can be loaded by any Deputy command via `--policy` or by the proxy server for runtime enforcement.

## See also

- [Policy concepts](../concepts/policies.md)
- [Policy command reference](../commands/policy.md)
- [Policy inputs](policy-inputs.md)
- [Policy spec](policy-spec.md)
- [Policy examples](../../policy/examples/)
- [Policy LSP setup](../policy-lsp.md)
