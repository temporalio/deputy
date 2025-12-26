# Policy Cookbook

Real-world CEL policy patterns for common security and compliance scenarios.

> All examples are available in the [policy examples](../../policy/examples/).

## Quick Reference

| Category | Policy | Use Case |
| --- | --- | --- |
| **Severity** | [`severity-guardrail.yaml`](#block-critical-and-high-severity) | Block critical/high vulnerabilities |
| **Licenses** | [`license-allowlist.yaml`](#license-allowlist) | Block copyleft licenses |
| **Packages** | [`block-package.yaml`](#blocklist-specific-packages) | Ban compromised packages |
| **Typosquats** | [`typosquat-levenshtein-guard.yaml`](#typosquat-detection) | Detect name confusion attacks |
| **Ecosystems** | [`npm-scope-allowlist.yaml`](#npm-scope-allowlist) | Restrict to approved scopes |
| **Versions** | [`prerelease-guard.yaml`](#block-prerelease-versions) | Block alpha/beta/rc versions |
| **Proxy** | [`proxy-critical-advisory.yaml`](#proxy-time-enforcement) | Enforce at download time |

---

## Vulnerability Policies

### Block Critical and High Severity

```yaml
# severity-guardrail.yaml
policies:
  - name: deny-critical-and-high
    description: Deny artifacts with CRITICAL/HIGH vulnerabilities
    vars:
      blockedSeverities:
        - CRITICAL
        - HIGH
    rules:
      - action: deny
        when: vulnerabilities.exists(v, blockedSeverities.exists(s, s == v.severity))
        reason: dependency has unresolved high-severity vulnerabilities
        remediation: Apply the vendor patch or upgrade to a remediated release
```

**When to use:** CI gates, release pipelines, proxy enforcement

### Block Only If Fix Available

```yaml
# direct-high-fix-block.yaml
policies:
  - name: direct-high-fix-block
    description: Block direct dependencies with HIGH/CRITICAL vulns when a fix exists
    vars:
      highSeverities:
        - CRITICAL
        - HIGH
      severity: 'vulnerability.?severity.orValue("").upperAscii()'
      isDirect: 'vulnerability.?isDirect.orValue(false)'
      hasFix: 'size(vulnerability.?fixedVersions.orValue([])) > 0'
      inScope: 'env.entrypoint in ["scan_vulnerability", "diff_vulnerability"]'
    rules:
      - action: deny
        when: inScope && isDirect && hasFix && severity in highSeverities
        reason: Direct dependency has a HIGH/CRITICAL vulnerability with an available fix
        remediation: Upgrade this dependency to a fixed version
```

**When to use:** Allow unfixed vulns to pass while enforcing upgrades when fixes exist

### Exploit Available Blocker

```yaml
# exploit-available-blocker.yaml
policies:
  - name: exploit-available-critical
    rules:
      - action: deny
        when: |
          vulnerabilities.exists(v, 
            v.severity == "CRITICAL" && 
            v.?hasExploit.orValue(false)
          )
        reason: critical vulnerability with known exploit
        remediation: Immediate patching required
```

**When to use:** Prioritize actively exploited vulnerabilities

---

## License Policies

### License Allowlist

```yaml
# license-allowlist.yaml
policies:
  - name: allow-sans-copyleft
    description: Block copyleft licenses
    vars:
      forbidden:
        - SSPL-1.0
        - AGPL-3.0-only
        - GPL-3.0
    rules:
      - action: deny
        when: pkg.?licenses.orValue([]).exists(l, l in forbidden)
        reason: package carries a forbidden license
      - action: warn
        when: size(pkg.?licenses.orValue([])) == 0
        reason: package missing license metadata
```

### Composed License Policy

```yaml
# license-allowlist-composed.yaml
policies:
  - name: approved-licenses-only
    vars:
      approved:
        - MIT
        - Apache-2.0
        - BSD-2-Clause
        - BSD-3-Clause
        - ISC
        - 0BSD
    rules:
      - action: deny
        when: |
          size(pkg.?licenses.orValue([])) > 0 &&
          !pkg.licenses.all(l, l in approved)
        reason: package uses non-approved license
        remediation: Request license exception or find alternative
```

**When to use:** Strict compliance environments, legal requirements

---

## Package Policies

### Blocklist Specific Packages

```yaml
# block-package.yaml
policies:
  - name: block-known-bad-packages
    vars:
      blockedPkgs:
        - left-pad
        - event-stream
        - ua-parser-js
        - ctx
    rules:
      - action: deny
        when: pkg.name in blockedPkgs
        reason: package is blocklisted due to previous compromises
        remediation: Use reviewed internal alternatives
```

### Log4Shell Specific Block

```yaml
# log4shell.yaml
policies:
  - name: log4shell-cve-2021-44228
    rules:
      - action: deny
        when: |
          vulnerabilities.exists(v, 
            v.id == "CVE-2021-44228" || 
            v.?aliases.orValue([]).exists(a, a == "CVE-2021-44228")
          )
        reason: Log4Shell vulnerability detected
        remediation: Upgrade log4j to 2.17.0+ or remove dependency
```

### XZ Backdoor Detection

```yaml
# xz-backdoor.yaml
policies:
  - name: xz-backdoor-cve-2024-3094
    rules:
      - action: deny
        when: |
          pkg.name.matches("(?i)^xz(-utils)?$") &&
          pkg.version.matches("^5\\.6\\.[01]$")
        reason: xz-utils versions 5.6.0/5.6.1 contain backdoor
        remediation: Downgrade to 5.4.x or upgrade to 5.6.2+
```

---

## Ecosystem-Specific Policies

### npm Scope Allowlist

```yaml
# npm-scope-allowlist.yaml
policies:
  - name: npm-scope-allowlist
    vars:
      allowedScopes:
        - "@mycompany"
        - "@types"
        - "@babel"
        - "@testing-library"
    rules:
      - action: deny
        when: |
          pkg.?ecosystem.orValue("") == "npm" &&
          pkg.name.startsWith("@") &&
          !allowedScopes.exists(s, pkg.name.startsWith(s + "/"))
        reason: npm scope not in allowlist
        remediation: Request scope approval or use unscoped package
```

### Go Module Registry Allowlist

```yaml
# gomod-registry-allowlist.yaml
policies:
  - name: go-registry-allowlist
    vars:
      allowedPrefixes:
        - "github.com/"
        - "golang.org/"
        - "google.golang.org/"
        - "k8s.io/"
    rules:
      - action: deny
        when: |
          pkg.?ecosystem.orValue("") == "go" &&
          !allowedPrefixes.exists(p, pkg.name.startsWith(p))
        reason: Go module not from approved registry
```

### PyPI Prefix Allowlist

```yaml
# pypi-prefix-allowlist.yaml
policies:
  - name: pypi-org-packages
    vars:
      allowedPrefixes:
        - "mycompany-"
        - "django-"
        - "flask-"
    rules:
      - action: warn
        when: |
          pkg.?ecosystem.orValue("") == "pypi" &&
          !allowedPrefixes.exists(p, pkg.name.startsWith(p))
        reason: PyPI package not from approved namespace
```

---

## Version Policies

### Block Prerelease Versions

```yaml
# prerelease-guard.yaml
policies:
  - name: no-prerelease
    rules:
      - action: deny
        when: pkg.version.matches("(?i)-(alpha|beta|rc|dev|pre)")
        reason: prerelease versions not allowed in production
        remediation: Use stable release version
```

### Go Pseudo-Version Deny

```yaml
# go-pseudo-version-deny.yaml
policies:
  - name: no-pseudo-versions
    rules:
      - action: deny
        when: |
          pkg.?ecosystem.orValue("") == "go" &&
          pkg.version.matches("v\\d+\\.\\d+\\.\\d+-\\d{14}-[a-f0-9]{12}")
        reason: Go pseudo-versions indicate unreleased code
        remediation: Pin to a tagged release
```

### Minimum Version Enforcement

```yaml
# min-version.yaml
policies:
  - name: minimum-go-version
    rules:
      - action: warn
        when: |
          pkg.name == "stdlib" &&
          semver(pkg.version) < semver("1.21.0")
        reason: Go version below minimum supported
        remediation: Upgrade to Go 1.21+
```

---

## Typosquat & Supply Chain

### Typosquat Detection

```yaml
# typosquat-levenshtein-guard.yaml
policies:
  - name: typosquat-levenshtein-guard
    vars:
      popular: ["react","lodash","express","typescript","axios"]
      allowScopes: ["@acme", "@types"]
      name: 'pkg.?name.orValue("").lowerAscii()'
      isScoped: 'name.startsWith("@")'
      limit: '(size(name) <= 5 ? 1 : (size(name) <= 8 ? 2 : 3))'
      nearPopular: 'popular.exists(p, levenshteinWithin(name, p, limit))'
    rules:
      - action: deny
        when: env.command == "proxy" && !isScoped && nearPopular
        reason: package name suspiciously similar to popular package
        remediation: Verify the intended package name
```

### Domain-Branded Package Guard

```yaml
# domain-branded-package-guard.yaml
policies:
  - name: domain-brand-guard
    vars:
      protectedDomains: ["google", "microsoft", "amazon", "apple"]
    rules:
      - action: warn
        when: |
          protectedDomains.exists(d, 
            pkg.name.contains(d) && 
            !pkg.name.startsWith("@" + d)
          )
        reason: package name contains protected brand
```

---

## Proxy Policies

### Proxy-Time Enforcement

```yaml
# proxy-critical-advisory.yaml
policies:
  - name: proxy-block-critical
    rules:
      - action: deny
        when: |
          env.command == "proxy" &&
          vulnerabilities.exists(v, v.severity == "CRITICAL")
        reason: critical vulnerability blocked at download
        remediation: Check OSV for remediation guidance
```

### New Dependency Review

```yaml
# new-dependency-review.yaml
policies:
  - name: new-dep-requires-review
    rules:
      - action: warn
        when: |
          env.command == "proxy" &&
          !pkg.?existsInLockfile.orValue(false)
        reason: new dependency requires security review
        details:
          requiresApproval: true
```

---

## Combining Policies

Bundle multiple policies for comprehensive coverage:

```console
# Lint all policies
$ deputy policy lint policy/examples/*.yaml

# Bundle for deployment
$ deputy policy bundle \
    --out production-bundle.json \
    policy/examples/severity-guardrail.yaml \
    policy/examples/license-allowlist.yaml \
    policy/examples/block-package.yaml

# Use in CI
$ deputy scan --policy production-bundle.json
```

---

## Writing Custom Policies

### Available Variables

| Variable | Type | Description |
| --- | --- | --- |
| `pkg` | object | Current package being evaluated |
| `pkg.name` | string | Package name |
| `pkg.version` | string | Package version |
| `pkg.ecosystem` | string | `go`, `npm`, `pypi`, `rubygems` |
| `pkg.licenses` | []string | SPDX license identifiers (when available) |
| `vulnerability` | object | Single vulnerability (in `scan_vulnerability` entrypoint) |
| `vulnerability.severity` | string | Severity level (CRITICAL/HIGH/MEDIUM/LOW) |
| `vulnerability.isDirect` | bool | Whether the affected package is a direct dependency |
| `vulnerability.fixedVersions` | []string | Available fix versions |
| `vulnerabilities` | []object | List of vulnerabilities (in `scan_report` entrypoint) |
| `env.command` | string | `scan`, `diff`, `proxy`, etc. |
| `env.entrypoint` | string | Current entrypoint (e.g., `scan_vulnerability`) |

### CEL Functions

| Function | Description |
| --- | --- |
| `semver(s)` | Parse semantic version for comparison |
| `levenshteinWithin(a, b, n)` | Check edit distance ≤ n |
| `matches(pattern)` | Regex match |
| `startsWith(prefix)` | String prefix check |
| `contains(substr)` | Substring check |

### Testing Your Policy

```console
# 1. Write policy
$ cat > my-policy.yaml << 'EOF'
policies:
  - name: my-custom-rule
    rules:
      - action: deny
        when: pkg.name == "bad-package"
        reason: blocked by policy
EOF

# 2. Lint
$ deputy policy lint my-policy.yaml

# 3. Test interactively
$ deputy policy repl
> :set name=bad-package
> pkg.name == "bad-package"
Result: true

# 4. Test against real scan
$ deputy scan --policy my-policy.yaml
```

## See Also

- [Policy command reference](../commands/policy.md)
- [Policy spec](../reference/policy-spec.md)
- [Policy examples](../../policy/examples/)
