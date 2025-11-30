# Deputy Policy Bundle Specification

This document defines the structured bundle format used by Deputy for CEL policies.

## Schema

```yaml
metadata:          # optional map
  title: "... "
policies:          # required, non-empty list
  - name:          # required, unique within bundle
    description:   # optional
    ecosystems:    # optional list of ecosystem strings
    vars:          # optional ordered map (preserves author order)
      <name>: <cel-expression-string>
    rules:         # required list
      - action: <string>   # e.g., deny | warn | allow
        when:   <cel-expression-string>   # required
        reason: <string>                  # optional
        status: <int>                     # optional
        headers: <map<string,string>>     # optional
        remediation: <string>             # optional
        details: <any>                    # optional
```

### Variable ordering
- Variables are evaluated in the **author-specified order**. Later vars can reference earlier ones. Duplicate or empty names are rejected.
- JSON bundles fall back to lexical order for determinism (JSON objects are unordered).

### Expansion semantics
- Each var is expanded as `([expr]).map(name, BODY)[0]` from last to first, so each name is in scope for subsequent vars and rules.
- CEL environment includes optional types, plus string helpers from `ext.Strings()` (e.g., `join`, `upper`, `upperAscii`, `lowerAscii`).

### Entrypoint inputs
- Standard top-level identifiers: `request`, `vulnerabilities`, `sbom`, `config`, `env`, `dependency`, `plan`, `step`, `repo`, `cluster`, `component`, `findings`.
- `env.command` and `env.entrypoint` indicate the invoking command/entrypoint.

### Validation
- Empty `policies` or missing `rules` is invalid.
- Vars must be strings; rules must include `action` and `when`.

## Examples

License allowlist (composed):
policies:
  - name: license-allowlist-composed
    description: Copyleft block with layered vars and scope guard
    vars:
      componentLicenses: 'component.?licenses.orValue([])'
      requestLicenses: 'request.?licenses.orValue([])'
      licenses_union: 'componentLicenses + requestLicenses'
      normalized: 'licenses_union.map(l, l.upper())'
      forbidden: '["SSPL-1.0","AGPL-3.0-ONLY","AGPL-3.0","GPL-3.0","GPL-3.0-ONLY"]'
      in_scope: 'env.command in ["proxy","sbom","diff"]'
    rules:
      - action: deny
        when: in_scope && normalized.exists(l, l in forbidden)
        reason: "forbidden license(s): " + normalized.join(", ")
      - action: warn
        when: in_scope && size(normalized) == 0
        reason: "package missing license metadata"
```

High-severity proxy blocker:
policies:
  - name: proxy-high-sev
    vars:
      high: '["CRITICAL","HIGH"]'
    rules:
      - action: deny
        when: env.command == "proxy" && vulnerabilities.exists(v, v.Severity in high)
        reason: "proxy block: high severity vuln"
```

## Tooling and tests
- `deputy policy lint` (via `policy.LoadSources`) rejects malformed bundles or CEL.
- `go test ./internal/policy` compiles all examples and runs entrypoint evaluations.
- `ext.Strings()` is enabled by default; add more CEL extensions in `internal/policy/evaluator.go` if required.

## Compatibility notes
- Raw `.cel` files are not supported. Author structured bundles and load them directly.
