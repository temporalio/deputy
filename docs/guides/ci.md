# CI Integration

Deputy integrates into CI/CD pipelines for two main purposes:

1. **Gate merges/releases** — fail builds on unacceptable risk
2. **Produce artifacts** — JSON reports + SBOMs for audit, compliance, and trending

## CI Pipeline Overview

```mermaid
flowchart LR
    subgraph PR["Pull Request"]
        direction TB
        Diff["deputy diff"]
        ScanPR["deputy scan"]
    end

    subgraph Main["Main Branch"]
        direction TB
        ScanMain["deputy scan"]
        SBOM["deputy sbom"]
    end

    subgraph Release["Release"]
        direction TB
        Policy["Policy gate"]
        SBOMRelease["deputy sbom --licenses"]
        Attest["Sign + attest"]
    end

    subgraph Artifacts["Artifacts"]
        direction TB
        Reports["scan.json"]
        SBOMs["sbom.json"]
        Sigs["signatures"]
    end

    PR --> Main
    Main --> Release
    Diff --> Reports
    ScanPR --> Reports
    ScanMain --> Reports
    SBOM --> SBOMs
    Policy --> Release
    SBOMRelease --> SBOMs
    Attest --> Sigs

    classDef source fill:#e3f2fd,stroke:#1565c0
    classDef process fill:#e8f5e9,stroke:#2e7d32
    classDef control fill:#fff3e0,stroke:#e65100
    classDef output fill:#f3e5f5,stroke:#7b1fa2

    class Diff,ScanPR,ScanMain,SBOM,SBOMRelease process
    class Policy,Attest control
    class Reports,SBOMs,Sigs output
```

## GitHub Actions

### Basic scan + SBOM

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

      # Scan for vulnerabilities
      - run: deputy scan --format json --output scan.json

      # Generate SBOM
      - run: deputy sbom --format spdx-json --output sbom.spdx.json

      # Upload artifacts for audit trail
      - uses: actions/upload-artifact@v4
        with:
          name: deputy-reports
          path: |
            scan.json
            sbom.spdx.json
```

### With policy enforcement

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "stable"
      - run: go install github.com/picatz/deputy@latest

      # Fail if policy violations found
      - run: deputy scan --policy policy/severity-guardrail.yaml

      # Or use a bundled policy
      - run: |
          deputy policy bundle --out corp.bundle.json policy/*.yaml
          deputy scan --policy corp.bundle.json
```

### PR diff analysis

```yaml
jobs:
  diff:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Need full history for diff
      - uses: actions/setup-go@v5
        with:
          go-version: "stable"
      - run: go install github.com/picatz/deputy@latest

      # Compare PR branch against base
      - run: deputy diff ${{ github.event.pull_request.base.sha }} ${{ github.sha }}
```

## GitLab CI

```yaml
stages:
  - security

deputy-scan:
  stage: security
  image: golang:latest
  before_script:
    - go install github.com/picatz/deputy@latest
  script:
    - deputy scan --format json --output scan.json
    - deputy sbom --format cyclonedx-json --output sbom.cdx.json
  artifacts:
    paths:
      - scan.json
      - sbom.cdx.json
    reports:
      # GitLab can parse SARIF for security dashboard
      sast: scan.json
```

## Azure DevOps

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: GoTool@0
    inputs:
      version: '1.22'

  - script: go install github.com/picatz/deputy@latest
    displayName: 'Install Deputy'

  - script: |
      deputy scan --format json --output $(Build.ArtifactStagingDirectory)/scan.json
      deputy sbom --format spdx-json --output $(Build.ArtifactStagingDirectory)/sbom.spdx.json
    displayName: 'Run Deputy'

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: '$(Build.ArtifactStagingDirectory)'
      artifactName: 'deputy-reports'
```

## CircleCI

```yaml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/go:1.22
    steps:
      - checkout
      - run:
          name: Install Deputy
          command: go install github.com/picatz/deputy@latest
      - run:
          name: Scan
          command: |
            deputy scan --format json --output scan.json
            deputy sbom --format spdx-json --output sbom.spdx.json
      - store_artifacts:
          path: scan.json
      - store_artifacts:
          path: sbom.spdx.json

workflows:
  security:
    jobs:
      - security-scan
```

## CI Stage Matrix

The following diagram shows which Deputy commands to run at each CI stage:

```mermaid
block-beta
    columns 4

    block:header:4
        H["CI Stage Matrix"]
    end

    block:stages:4
        columns 4
        S1["PR Check"]
        S2["Build"]
        S3["Gate"]
        S4["Release"]
    end

    block:commands:4
        columns 4
        C1["diff<br/>scan"]
        C2["sbom"]
        C3["scan --policy"]
        C4["sbom --licenses"]
    end

    block:artifacts:4
        columns 4
        A1["(optional)"]
        A2["sbom.json"]
        A3["scan.json"]
        A4["sbom-full.json"]
    end

    block:exit:4
        columns 4
        E1["0 = pass"]
        E2["0 = pass"]
        E3["1 = block"]
        E4["0 = ship"]
    end

    classDef header fill:#e3f2fd,stroke:#1565c0
    classDef stage fill:#fff3e0,stroke:#e65100
    classDef command fill:#e8f5e9,stroke:#2e7d32
    classDef artifact fill:#f3e5f5,stroke:#7b1fa2
    classDef exit fill:#fff9c4,stroke:#f9a825

    class H header
    class S1,S2,S3,S4 stage
    class C1,C2,C3,C4 command
    class A1,A2,A3,A4 artifact
    class E1,E2,E3,E4 exit
```

## Best Practices

### 1. Use policies for maintainable rules

Instead of parsing JSON output in scripts, encode rules in policies:

```yaml
# policy/ci-guardrails.yaml
policies:
  - name: ci-vulnerability-gate
    rules:
      - action: deny
        when: vulnerabilities.exists(v, v.severity in ["CRITICAL", "HIGH"])
        reason: "Critical/high severity vulnerabilities must be addressed before merge"
```

```console
$ deputy scan --policy policy/ci-guardrails.yaml
```

### 2. Archive artifacts for compliance

Store scan results and SBOMs with your release artifacts:
- Enables retroactive analysis ("what did we ship?")
- Satisfies audit requirements
- Allows trending over time

### 3. Use `--ignore-unfixed` thoughtfully

`--ignore-unfixed` hides vulnerabilities without known fixes. Use it to reduce noise, but be aware it hides real issues.

### 4. Pin Deputy versions for reproducibility

```console
$ go install github.com/picatz/deputy@v1.2.3
```

### 5. Set exit codes appropriately

Deputy exits with:
- `0` — success (no policy violations)
- `1` — policy violations or scan failures
- Use this for gating merges

## Related

- [Policy concepts](../concepts/policies.md)
- [Policy framework](../reference/policy-framework.md)
- [Troubleshooting](troubleshooting.md)
