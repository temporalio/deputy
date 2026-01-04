# Dockerfile Scanning

Deputy can analyze Dockerfiles to enforce security best practices and configuration standards without pulling images. This static analysis approach is fast, works offline, and helps catch issues early in the development process.

## Quick Start

```bash
# Scan a Dockerfile
deputy scan Dockerfile

# Scan with policies
deputy scan Dockerfile --policy policy/examples/dockerfile-security.yaml

# Explicit source type
deputy scan --source dockerfile /path/to/my.containerfile

# JSON output
deputy scan Dockerfile --format json
```

## What Gets Analyzed

Deputy parses Dockerfiles using the official BuildKit parser and extracts:

- **Build stages**: Multi-stage builds, stage names (AS aliases), builder detection
- **Base images**: Registry, repository, tag, digest resolution
- **Configuration**: USER, WORKDIR, EXPOSE, HEALTHCHECK, ENTRYPOINT, CMD
- **Environment**: ENV and ARG declarations with sensitive variable detection
- **Instructions**: RUN, COPY, ADD with security-relevant details
- **Labels**: OCI annotations and custom metadata

### ARG Substitution

Deputy substitutes ARG defaults in base image references:

```dockerfile
ARG GO_VERSION=1.22
FROM golang:${GO_VERSION}  # Resolves to golang:1.22
```

If an ARG has no default and isn't provided, the reference remains unresolved, which policies can detect.

## Output Formats

### Text Output (Default)

```
Dockerfile: /path/to/Dockerfile
Stages: 2

Stage 0 (builder)
  Base: golang:1.22
  Type: builder stage
  User: root (default)

Stage 1
  Base: alpine:3.19
  User: nobody
  Ports: 8080
  Healthcheck: configured

Multi-stage build detected

Policy Findings:
  [!] require-digest-for-production: Final stage base image not pinned by digest
      Remediation: Use digest reference: image@sha256:...
```

### JSON Output

```bash
deputy scan Dockerfile --format json
```

```json
{
  "path": "/path/to/Dockerfile",
  "stage_count": 2,
  "stages": [
    {
      "index": 0,
      "name": "builder",
      "base_image": "golang:1.22",
      "is_scratch": false,
      "is_builder": true,
      "is_root": true,
      "has_healthcheck": false
    }
  ],
  "analysis": {
    "has_multi_stage": true,
    "final_stage_is_root": false,
    "final_stage_is_scratch": false,
    "sensitive_env_vars": [],
    "has_add_url": false
  },
  "policy_findings": []
}
```

## Policy Evaluation

Dockerfile policies use CEL expressions with two entrypoints:

### dockerfile_report

Evaluates once per Dockerfile for whole-file analysis:

```yaml
policies:
  - name: require-non-root-user
    entrypoints: ["dockerfile_report"]
    rules:
      - action: deny
        when: |
          has(dockerfile.final_stage) &&
          !dockerfile.final_stage.is_scratch &&
          dockerfile.final_stage.is_root
        reason: "Container runs as root user"
```

### dockerfile_stage

Evaluates for each stage, enabling per-stage policies:

```yaml
policies:
  - name: no-secrets-in-builder
    entrypoints: ["dockerfile_stage"]
    rules:
      - action: deny
        when: |
          stage.is_builder_stage &&
          size(stage.sensitive_env) > 0
        reason: "Builder stage contains sensitive environment variables"
```

## Available Policy Variables

### dockerfile Object

| Field | Type | Description |
|-------|------|-------------|
| `dockerfile.path` | string | Path to the Dockerfile |
| `dockerfile.stages` | list | All build stages |
| `dockerfile.args` | map | ARG instructions with defaults |
| `dockerfile.final_stage` | object | The last stage (what gets built) |

### dockerfile_analysis Object

| Field | Type | Description |
|-------|------|-------------|
| `dockerfile_analysis.stage_count` | int | Number of stages |
| `dockerfile_analysis.has_multi_stage` | bool | True if multi-stage build |
| `dockerfile_analysis.builder_stage_count` | int | Stages used only as COPY sources |
| `dockerfile_analysis.final_stage_is_root` | bool | Final stage runs as root |
| `dockerfile_analysis.final_stage_is_scratch` | bool | Final stage uses FROM scratch |
| `dockerfile_analysis.sensitive_env_vars` | list | ENV vars matching secret patterns |
| `dockerfile_analysis.has_add_url` | bool | Any ADD instruction uses URLs |

### stage Object (in dockerfile_stage entrypoint)

| Field | Type | Description |
|-------|------|-------------|
| `stage.index` | int | 0-based stage position |
| `stage.name` | string | AS alias (empty if unnamed) |
| `stage.base_image` | string | FROM image reference as written |
| `stage.base_image_resolved` | object | Parsed image reference |
| `stage.platform` | string | --platform flag value |
| `stage.is_scratch` | bool | True if FROM scratch |
| `stage.is_builder_stage` | bool | True if only used as COPY source |
| `stage.user` | string | Final USER directive value |
| `stage.is_root` | bool | True if running as root |
| `stage.workdir` | string | WORKDIR value |
| `stage.env_vars` | map | ENV declarations |
| `stage.sensitive_env` | list | Env vars matching secret patterns |
| `stage.exposed_ports` | list | EXPOSE ports |
| `stage.labels` | map | LABEL key-value pairs |
| `stage.healthcheck` | object | HEALTHCHECK config (or null) |
| `stage.run_commands` | list | RUN instructions |
| `stage.copy_commands` | list | COPY instructions |
| `stage.add_commands` | list | ADD instructions |
| `stage.copy_from_stages` | list | COPY --from references |
| `stage.entrypoint` | list | ENTRYPOINT command |
| `stage.cmd` | list | CMD arguments |

### base_image_resolved Object

| Field | Type | Description |
|-------|------|-------------|
| `base_image_resolved.registry` | string | Registry (e.g., "index.docker.io") |
| `base_image_resolved.repository` | string | Repository (e.g., "library/nginx") |
| `base_image_resolved.tag` | string | Tag (e.g., "latest") |
| `base_image_resolved.digest` | string | Digest if specified |
| `base_image_resolved.full` | string | Original reference |

## Example Policies

### Block Root User

```yaml
- name: no-root
  entrypoints: ["dockerfile_report"]
  rules:
    - action: deny
      when: dockerfile.final_stage.is_root && !dockerfile.final_stage.is_scratch
      reason: "Final image runs as root"
      remediation: "Add USER directive with non-root user"
```

### Require Pinned Base Images

```yaml
- name: pin-base-images
  entrypoints: ["dockerfile_report"]
  rules:
    - action: deny
      when: |
        dockerfile.stages.exists(s,
          !s.is_scratch &&
          s.base_image_resolved.tag == "latest")
      reason: "Base image uses mutable :latest tag"
      remediation: "Pin to a specific version or digest"
```

### Approved Registries Only

```yaml
- name: approved-registries
  entrypoints: ["dockerfile_report"]
  vars:
    # Note: Docker Hub resolves to "index.docker.io"
    allowed: ["index.docker.io", "gcr.io", "ghcr.io"]
  rules:
    - action: deny
      when: |
        dockerfile.stages.exists(s,
          !s.is_scratch &&
          s.base_image_resolved.registry != "" &&
          !(s.base_image_resolved.registry in allowed))
      reason: "Base image from unapproved registry"
```

### No Secrets in ENV

```yaml
- name: no-secrets
  entrypoints: ["dockerfile_report"]
  rules:
    - action: deny
      when: size(dockerfile_analysis.sensitive_env_vars) > 0
      reason: "Dockerfile contains ENV variables that may contain secrets"
      remediation: "Use --mount=type=secret or runtime environment variables"
```

### Require HEALTHCHECK

```yaml
- name: require-healthcheck
  entrypoints: ["dockerfile_report"]
  rules:
    - action: warn
      when: |
        has(dockerfile.final_stage) &&
        !dockerfile.final_stage.is_scratch &&
        dockerfile.final_stage.healthcheck == null
      reason: "No HEALTHCHECK defined"
      remediation: "Add HEALTHCHECK for container orchestration"
```

### Clean apt Cache

```yaml
- name: apt-cleanup
  entrypoints: ["dockerfile_stage"]
  rules:
    - action: warn
      when: |
        stage.run_commands.exists(r,
          r.command.contains("apt-get install") &&
          !r.command.contains("rm -rf /var/lib/apt/lists"))
      reason: "apt-get install without cleaning cache"
      remediation: "Add 'rm -rf /var/lib/apt/lists/*' in same RUN"
```

## Sensitive Environment Detection

Deputy detects environment variables that may contain secrets based on patterns:

- `*_KEY`, `*_SECRET`, `*_TOKEN`, `*_PASSWORD`
- `*_PRIVATE_*`, `*_CREDENTIAL*`
- `API_KEY`, `AWS_*`, `DATABASE_*`

These are flagged in `dockerfile_analysis.sensitive_env_vars` and available in policies.

## File Detection

Deputy automatically detects Dockerfiles by filename:

- `Dockerfile`, `Containerfile` (exact match)
- `Dockerfile.*`, `Containerfile.*` (e.g., `Dockerfile.prod`)
- `*.dockerfile`, `*.containerfile` (e.g., `app.dockerfile`)
- `*Dockerfile`, `*Containerfile` (e.g., `test-Dockerfile`)

## Limitations

### Static Analysis Only

Dockerfile scanning performs static analysis without pulling images. This means:

- Base image vulnerabilities are not scanned (use `deputy scan <image>` separately)
- Runtime ARG values cannot be tested (only defaults are used)
- Layer contents are not inspected

### No SBOM Generation

Dockerfiles describe how to build images, not package contents. To generate SBOMs:

1. Build the image: `docker build -t myapp .`
2. Scan the image: `deputy sbom docker://myapp`

### ARG Limitations

- Only ARG defaults from the Dockerfile are used
- `--build-arg` overrides are not supported yet
- Missing ARGs result in empty substitution

## Integration with Image Scanning

For comprehensive container security, combine Dockerfile and image scanning:

```bash
# 1. Check Dockerfile configuration
deputy scan Dockerfile --policy policy/examples/dockerfile-security.yaml

# 2. Build the image
docker build -t myapp:v1 .

# 3. Scan for vulnerabilities
deputy scan docker://myapp:v1

# 4. Generate SBOM
deputy sbom docker://myapp:v1 --format cyclonedx-json
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Scan Dockerfile
  run: |
    deputy scan Dockerfile \
      --policy policy/dockerfile-security.yaml \
      --format json \
      --output dockerfile-report.json
```

### GitLab CI

```yaml
dockerfile-scan:
  script:
    - deputy scan Dockerfile --policy policy/dockerfile-security.yaml
  allow_failure: false
```

## See Also

- [Policy Framework Reference](../reference/policy-framework.md)
- [Container Image Scanning](./container-images.md)
- [Example Policies](../../policy/examples/)
