# Pipeline example: scan → fix → diff → sbom

Deputy’s commands are designed to compose in pipelines. This workflow is a common “tight loop” before committing dependency updates:

1. `scan` for vulnerabilities
2. `fix` to generate (and optionally apply) remediation steps
3. `diff` to verify dependency changes and re-check vulnerabilities
4. `sbom` to produce an inventory artifact (and validate with downstream tools like `jq`)

```console
$ deputy scan

Scanned /Users/yournamehere/Documents/GitHub/deputy @ WORKING (4b2eb48)
  Origin: https://github.com/picatz/deputy.git

∴ Vulnerabilities Found:

github.com/containerd/containerd v1.7.28 [indirect]:
  • CVE-2024-25621 [HIGH] (↑ v1.7.29)
    containerd affected by a local privilege escalation via wide permissions on CRI directory
    Aliases: GHSA-pwhc-rpq9-4c8w
    Published: 2025-11-06
  • CVE-2025-64329 [MED] (↑ v1.7.29)
    containerd CRI server: Host memory exhaustion through Attach goroutine leak
    Aliases: GHSA-m6hq-p25p-ffr2
    Published: 2025-11-06
    Context:
      Sources:
        • go.mod

github.com/opencontainers/selinux v1.12.0 [indirect]:
  • CVE-2025-52881 [HIGH] (↑ v1.13.0)
    runc container escape and denial of service due to arbitrary write gadgets and procfs write redirects
    Aliases: GHSA-cgrx-mc8f-2prm
    Published: 2025-11-05
    Context:
      Sources:
        • go.mod

stdlib v1.24.6 [direct]:
  • CVE-2025-58187 [HIGH] (↑ v1.24.9)
    Quadratic complexity when checking name constraints in crypto/x509
    Aliases: GO-2025-4007, (+1 more)
    Published: 2025-10-29
  • CVE-2025-58188 [HIGH] (↑ v1.24.8)
    Panic when validating certificates with DSA public keys in crypto/x509
    Aliases: GO-2025-4013, (+1 more)
    Published: 2025-10-29
  • CVE-2025-61723 [HIGH] (↑ v1.24.8)
    Quadratic complexity when parsing some invalid inputs in encoding/pem
    Aliases: GO-2025-4009, (+1 more)
    Published: 2025-10-29
  • CVE-2025-61725 [HIGH] (↑ v1.24.8)
    Excessive CPU consumption in ParseAddress in net/mail
    Aliases: GO-2025-4006, (+1 more)
    Published: 2025-10-29
  • CVE-2025-47912 [MED] (↑ v1.24.8)
    Insufficient validation of bracketed IPv6 hostnames in net/url
    Aliases: GO-2025-4010, (+1 more)
    Published: 2025-10-29

Vulnerability Summary:
  ! 6 require immediate attention (critical/high severity)
  ↑ 13 can be fixed by upgrading

Recommended Actions:
  1. Upgrade Go toolchain to v1.24.9 (update 'go' directive in go.mod)
  2. Upgrade critical/high modules first
       go.mod:
         › go get github.com/containerd/containerd@v1.7.29
         › go get github.com/opencontainers/selinux@v1.13.0
         › go get go@1.24.9  # updates go directive
         ↻ go mod tidy

$ deputy fix --apply
Remediation Plan:
  Target: /Users/yournamehere/Documents/GitHub/deputy
  Commit: 4b2eb485b2d18f37dd9a42c19aa52178c0fa1631
  • Upgrade Go toolchain to v1.24.9 (update 'go' directive in go.mod)
  • Apply dependency upgrades (4 total, 4 runnable)
       go.mod:
         › go get github.com/containerd/containerd@v1.7.29
         › go get github.com/opencontainers/selinux@v1.13.0
         › go get go@1.24.9  # updates go directive
         ↻ go mod tidy
  ↻ go get github.com/containerd/containerd@v1.7.29 (in .)
    go: upgraded github.com/containerd/containerd v1.7.28 => v1.7.29
  ↻ go get github.com/opencontainers/selinux@v1.13.0 (in .)
    go: upgraded github.com/cyphar/filepath-securejoin v0.4.1 => v0.6.0
    go: upgraded github.com/opencontainers/selinux v1.12.0 => v1.13.0
  ↻ go get go@1.24.9 (in .)
    go: upgraded go 1.24.6 => 1.24.9
  ↻ go mod tidy (in .)

$ deputy diff
Comparing dependencies: main → WORKING
Scanning packages in working tree...
Scanning packages in base reference 4b2eb48...

Dependency Changes:
  ↑ github.com/containerd/containerd @ 1.7.28 → 1.7.29 (indirect)
  ↑ stdlib @ 1.24.6 → 1.24.9 (direct)
  ↑ github.com/cyphar/filepath-securejoin @ 0.4.1 → 0.6.0 (indirect)
  ↑ github.com/opencontainers/selinux @ 1.12.0 → 1.13.0 (indirect)
  - github.com/prometheus/procfs @ 0.17.0 (indirect)
  + cyphar.com/go-pathrs @ 0.2.1 (indirect)

Summary:
  + 1 package added
  - 1 package removed
  ↑ 4 packages upgraded

Scanning dependencies for vulnerabilities...

∴ Vulnerabilities

✓ No vulnerabilities found

$ deputy sbom | jq -r '.components[].purl' | grep \"github.com/containerd/containerd@\"
pkg:golang/github.com/containerd/containerd@1.7.29
```

Notes:
- Output is illustrative; exact findings depend on your target, ref, and the state of vulnerability databases.
- For “exact commit” artifacts (vs working tree), use `--ref=$(git rev-parse HEAD)` for `scan`, `sbom`, and other ref-aware commands.

See also:
- `docs/commands/scan.md`
- `docs/commands/fix.md`
- `docs/commands/diff.md`
- `docs/commands/sbom.md`

