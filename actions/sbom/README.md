# Deputy SBOM Action

Generate Software Bill of Materials (SBOM) in CycloneDX or SPDX format.

## Usage

```yaml
- uses: picatz/deputy/actions/setup@main
- uses: picatz/deputy/actions/sbom@main
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `target` | Path to analyze | `.` |
| `ref` | Git reference | `HEAD` |
| `format` | SBOM format (`cyclonedx-json`, `spdx-json`, `protobom-json`) | `cyclonedx-json` |
| `output` | Output file path | `sbom.json` |
| `name` | SBOM document name | `''` |
| `enrich-licenses` | Add license information | `true` |
| `license-source` | License source (`depsdev`, `scan`, `both`) | `depsdev` |
| `policy` | Policy file(s) for validation | `''` |
| `upload-artifact` | Upload as GitHub artifact | `true` |
| `artifact-name` | Artifact name | `sbom` |
| `retention-days` | Artifact retention | `90` |
| `github-token` | Token for API access | `${{ github.token }}` |

## Outputs

| Output | Description |
|--------|-------------|
| `sbom-path` | Path to generated SBOM file |
| `filename` | SBOM filename (basename only) |
| `format` | SBOM format used |
| `component-count` | Number of components |
| `artifact-name` | Name of uploaded artifact (for downloading in other jobs) |

## Examples

### Basic SBOM

```yaml
- uses: picatz/deputy/actions/setup@main
- uses: picatz/deputy/actions/sbom@main
```

### CycloneDX with Licenses

```yaml
- uses: picatz/deputy/actions/sbom@main
  with:
    format: cyclonedx-json
    enrich-licenses: true
    output: sbom.cdx.json
```

### SPDX Format

```yaml
- uses: picatz/deputy/actions/sbom@main
  with:
    format: spdx-json
    output: sbom.spdx.json
```

### Release Artifact

```yaml
name: Release SBOM
on:
  release:
    types: [published]

jobs:
  sbom:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - uses: picatz/deputy/actions/setup@main
      - uses: picatz/deputy/actions/sbom@main
        id: sbom
        with:
          format: cyclonedx-json
          output: sbom.cdx.json
          upload-artifact: false
      - name: Upload to release
        env:
          GH_TOKEN: ${{ github.token }}
          TAG: ${{ github.ref_name }}
        run: gh release upload "$TAG" "${{ steps.sbom.outputs.sbom-path }}"
```

### Using Outputs Across Jobs

```yaml
jobs:
  generate:
    runs-on: ubuntu-latest
    outputs:
      sbom-path: ${{ steps.sbom.outputs.sbom-path }}
      artifact-name: ${{ steps.sbom.outputs.artifact-name }}
    steps:
      - uses: actions/checkout@v4
      - uses: picatz/deputy/actions/setup@main
      - uses: picatz/deputy/actions/sbom@main
        id: sbom
        with:
          artifact-name: my-project-sbom

  analyze:
    needs: generate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: ${{ needs.generate.outputs.artifact-name }}
      - run: echo "SBOM downloaded from ${{ needs.generate.outputs.artifact-name }}"
```

## See Also

- [Setup Action](../setup/README.md) - Install Deputy
- [Scan Action](../scan/README.md) - Vulnerability scanning
- [Diff Action](../diff/README.md) - Dependency diff
