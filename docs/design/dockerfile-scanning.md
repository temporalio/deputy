# Dockerfile Scanning Design

This document outlines the architecture for adding Dockerfile scanning to Deputy, enabling vulnerability and policy analysis for Dockerfiles found in repositories.

## Problem Statement

Deputy currently scans:
1. **Built container images** (`oci://`, `docker-daemon://`, `tarball://`) - extracts packages from image layers
2. **Repository lockfiles** (go.mod, package-lock.json, etc.) - extracts declared dependencies

**Missing capability**: Scanning Dockerfiles to:
- Resolve base images and their vulnerabilities
- Detect insecure configurations (root user, secrets in ENV)
- Enforce organizational standards (approved registries, required labels)
- Track image lineage in multi-stage builds

## Research Findings

### OSV-SCALIBR Capability

**SCALIBR v0.3.2 has NO Dockerfile support.** Its extractors work on:
- Filesystem lockfiles (go.mod, package.json, requirements.txt, etc.)
- Container image layers (via `scalibrimage.Image` interface)

There is no `Dockerfile` extractor, and the extraction model (filesystem-based) doesn't fit Dockerfile parsing which requires:
1. Parsing Dockerfile syntax
2. Resolving remote image references
3. Optionally pulling and scanning referenced images

### moby/buildkit Parser

The official Dockerfile parser from BuildKit provides comprehensive parsing:

```go
import (
    "github.com/moby/buildkit/frontend/dockerfile/parser"
    "github.com/moby/buildkit/frontend/dockerfile/instructions"
)

// Parse Dockerfile into AST
result, err := parser.Parse(reader)

// Convert AST to typed instructions
stages, metaArgs, err := instructions.Parse(result.AST, nil)
```

**Key types available:**

| Type | Description | Policy-Relevant Fields |
|------|-------------|------------------------|
| `instructions.Stage` | A build stage (FROM) | `BaseName`, `Platform`, `Name`, `Commands` |
| `instructions.RunCommand` | RUN instruction | `CmdLine`, `FlagsUsed`, `Mounts`, `NetworkMode` |
| `instructions.CopyCommand` | COPY instruction | `From`, `SourcesAndDest` |
| `instructions.AddCommand` | ADD instruction | `SourcesAndDest`, `Chown` |
| `instructions.EnvCommand` | ENV instruction | `Env` (key-value pairs) |
| `instructions.UserCommand` | USER instruction | `User` |
| `instructions.ExposeCommand` | EXPOSE instruction | `Ports` |
| `instructions.LabelCommand` | LABEL instruction | `Labels` |
| `instructions.HealthCheckCommand` | HEALTHCHECK | `Health` config |
| `instructions.ArgCommand` | ARG instruction | `Args` with defaults |

## Architecture Design

### Option A: Dockerfile as Analysis Target (Recommended)

Add Dockerfile as a first-class target type alongside container images and repositories.

```
┌─────────────────────────────────────────────────────────────────┐
│                        deputy scan                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │   Repository │  │  Container   │  │     Dockerfile       │   │
│  │    Target    │  │    Image     │  │       Target         │   │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘   │
│         │                  │                     │               │
│         ▼                  ▼                     ▼               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │   SCALIBR    │  │   SCALIBR    │  │   buildkit/parser    │   │
│  │  Filesystem  │  │    Image     │  │   + go-container     │   │
│  │  Extractors  │  │  Extractors  │  │     -registry        │   │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘   │
│         │                  │                     │               │
│         ▼                  ▼                     ▼               │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                  Unified Scan Result                     │    │
│  │  - Packages/Inventory                                    │    │
│  │  - Vulnerabilities                                       │    │
│  │  - ImageInfo (config, metadata, history)                 │    │
│  │  - DockerfileInfo (stages, base images, instructions)    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    Policy Engine (CEL)                   │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Proposed Target Types

```go
// New target kind
const KindDockerfile targets.Kind = "dockerfile"

// Detection: files named "Dockerfile" or "*.dockerfile" or "Containerfile"
func (dockerfileProvider) Detect(ctx context.Context, target string) bool {
    // Match:
    // - Dockerfile
    // - Dockerfile.prod
    // - app.dockerfile
    // - Containerfile
    base := filepath.Base(target)
    if base == "Dockerfile" || base == "Containerfile" {
        return true
    }
    if strings.HasPrefix(base, "Dockerfile.") {
        return true
    }
    if strings.HasSuffix(strings.ToLower(base), ".dockerfile") {
        return true
    }
    return false
}
```

### New Data Structures

```go
// DockerfileInfo contains parsed Dockerfile data for policy evaluation.
type DockerfileInfo struct {
    // Path is the Dockerfile location.
    Path string `json:"path"`

    // Stages contains all build stages.
    Stages []DockerfileStage `json:"stages"`

    // Args are ARG instructions with their default values.
    Args map[string]string `json:"args,omitempty"`

    // FinalStage points to the last stage (what gets built by default).
    FinalStage *DockerfileStage `json:"final_stage,omitempty"`
}

// DockerfileStage represents a FROM ... AS stage.
type DockerfileStage struct {
    // Index is the 0-based stage position.
    Index int `json:"index"`

    // Name is the AS alias (empty if unnamed).
    Name string `json:"name,omitempty"`

    // BaseImage is the FROM image reference.
    BaseImage string `json:"base_image"`

    // BaseImageResolved is the parsed image reference.
    BaseImageResolved *ImageRef `json:"base_image_resolved,omitempty"`

    // Platform from --platform flag.
    Platform string `json:"platform,omitempty"`

    // IsScratch is true if FROM scratch.
    IsScratch bool `json:"is_scratch"`

    // IsBuilderStage is true if this stage is only used as a COPY source.
    IsBuilderStage bool `json:"is_builder_stage"`

    // User is the final USER directive value (empty = root).
    User string `json:"user,omitempty"`

    // EnvVars are ENV declarations.
    EnvVars map[string]string `json:"env_vars,omitempty"`

    // ExposedPorts from EXPOSE instructions.
    ExposedPorts []string `json:"exposed_ports,omitempty"`

    // Labels from LABEL instructions.
    Labels map[string]string `json:"labels,omitempty"`

    // Healthcheck configuration.
    Healthcheck *HealthcheckConfig `json:"healthcheck,omitempty"`

    // RunCommands are RUN instructions in order.
    RunCommands []RunCommand `json:"run_commands,omitempty"`

    // CopyFromStages tracks COPY --from references.
    CopyFromStages []string `json:"copy_from_stages,omitempty"`

    // AddCommands for ADD instructions (security concern: remote URLs).
    AddCommands []AddCommand `json:"add_commands,omitempty"`
}

// RunCommand represents a RUN instruction.
type RunCommand struct {
    Command     string   `json:"command"`
    Shell       bool     `json:"shell"`       // true if shell form, false if exec form
    Mounts      []string `json:"mounts,omitempty"` // --mount flags
    NetworkMode string   `json:"network,omitempty"` // --network flag
}

// AddCommand represents an ADD instruction.
type AddCommand struct {
    Sources     []string `json:"sources"`
    Destination string   `json:"destination"`
    FromURL     bool     `json:"from_url"` // true if source is a URL (security concern)
    Chown       string   `json:"chown,omitempty"`
}

// ImageRef is a parsed image reference.
type ImageRef struct {
    Registry   string `json:"registry"`
    Repository string `json:"repository"`
    Tag        string `json:"tag,omitempty"`
    Digest     string `json:"digest,omitempty"`
}
```

### Scan Modes

#### 1. Static Analysis (Default, Fast)

Parse Dockerfile without pulling images. Useful for:
- Policy enforcement (approved registries, required labels)
- Configuration checks (no root user, no secrets in ENV)
- Multi-stage build analysis

```bash
deputy scan Dockerfile                    # Static analysis only
deputy scan --dockerfile-mode=static .    # Scan repo + Dockerfiles statically
```

#### 2. Deep Analysis (With Image Resolution)

Optionally resolve and scan base images:

```bash
deputy scan --dockerfile-mode=deep Dockerfile  # Resolve + scan base images
```

Deep analysis:
1. Parses Dockerfile
2. Resolves base image references (handles ARG substitution)
3. Pulls and scans base images
4. Reports vulnerabilities by stage/layer origin

### Handling Special Cases

#### scratch Base Image

`FROM scratch` is the empty image - no filesystem, no packages.

```go
func (s *DockerfileStage) IsScratch() bool {
    return s.BaseImage == "scratch"
}
```

Policy example:
```yaml
policies:
  - name: prefer-scratch-for-go
    entrypoints: ["dockerfile_report"]
    rules:
      - action: warn
        when: |
          dockerfile.final_stage.base_image.contains("golang") &&
          !dockerfile.stages.exists(s, s.is_scratch && !s.is_builder_stage)
        reason: "Go binaries should use scratch or distroless final stage"
```

#### ARG Substitution in FROM

```dockerfile
ARG GO_VERSION=1.22
FROM golang:${GO_VERSION}
```

The parser needs to:
1. Collect ARG defaults
2. Allow override via `--build-arg`
3. Substitute in base image references

```go
func resolveBaseImage(baseImage string, args map[string]string) string {
    // Handle ${VAR} and $VAR syntax
    return os.Expand(baseImage, func(key string) string {
        if val, ok := args[key]; ok {
            return val
        }
        return ""
    })
}
```

#### Multi-Stage Builds

Track which stages are "builder" stages vs the final stage:

```dockerfile
FROM golang:1.22 AS builder  # Builder stage
RUN go build -o /app

FROM scratch                  # Final stage
COPY --from=builder /app /app
```

```go
func identifyBuilderStages(stages []DockerfileStage) {
    // A stage is a builder if:
    // 1. It has a name (AS alias)
    // 2. That name is referenced in COPY --from
    // 3. It's not the final stage

    copyFromRefs := collectCopyFromReferences(stages)
    for i := range stages {
        if i < len(stages)-1 { // Not final stage
            if stages[i].Name != "" && copyFromRefs[stages[i].Name] {
                stages[i].IsBuilderStage = true
            }
        }
    }
}
```

### Policy Integration

#### New Entrypoint

```go
const EntrypointDockerfileReport = "dockerfile_report"
```

#### CEL Variables

```yaml
# Available in dockerfile_report entrypoint
dockerfile:
  path: "Dockerfile"
  stages: [...]
  args: {...}
  final_stage: {...}

# Per-stage iteration
dockerfile.stages.exists(s, ...)
dockerfile.final_stage.user == ""
```

#### Example Policies

```yaml
policies:
  # Require non-root user in final stage
  - name: require-non-root
    entrypoints: ["dockerfile_report"]
    rules:
      - action: deny
        when: |
          !dockerfile.final_stage.is_scratch &&
          (dockerfile.final_stage.user == "" ||
           dockerfile.final_stage.user == "root" ||
           dockerfile.final_stage.user == "0")
        reason: "Final stage must specify a non-root USER"
        remediation: "Add 'USER nobody' or create a dedicated user"

  # Block :latest tag
  - name: no-latest-tag
    entrypoints: ["dockerfile_report"]
    rules:
      - action: deny
        when: |
          dockerfile.stages.exists(s,
            !s.is_scratch &&
            s.base_image_resolved.tag == "latest")
        reason: "Do not use :latest tag - it's mutable"
        remediation: "Pin to a specific version or digest"

  # Require approved registries
  - name: approved-registries
    entrypoints: ["dockerfile_report"]
    vars:
      allowed: ["docker.io", "gcr.io", "ghcr.io"]
    rules:
      - action: deny
        when: |
          dockerfile.stages.exists(s,
            !s.is_scratch &&
            !(s.base_image_resolved.registry in allowed))
        reason: "Base image must be from approved registry"

  # Block ADD with URLs
  - name: no-add-url
    entrypoints: ["dockerfile_report"]
    rules:
      - action: deny
        when: |
          dockerfile.stages.exists(s,
            s.add_commands.exists(a, a.from_url))
        reason: "ADD with URLs is insecure - use COPY + curl"

  # Require HEALTHCHECK
  - name: require-healthcheck
    entrypoints: ["dockerfile_report"]
    rules:
      - action: warn
        when: |
          !dockerfile.final_stage.is_scratch &&
          dockerfile.final_stage.healthcheck == null
        reason: "Consider adding HEALTHCHECK for container orchestration"

  # Detect secrets in ENV
  - name: no-secrets-in-env
    entrypoints: ["dockerfile_report"]
    vars:
      sensitive_patterns: ["PASSWORD", "SECRET", "KEY", "TOKEN", "CREDENTIAL"]
    rules:
      - action: deny
        when: |
          dockerfile.stages.exists(s,
            s.env_vars.keys().exists(k,
              sensitive_patterns.exists(p, k.upperAscii().contains(p))))
        reason: "Potential secret in ENV instruction"
        remediation: "Use --mount=type=secret or runtime environment variables"

  # Require OCI labels
  - name: require-oci-labels
    entrypoints: ["dockerfile_report"]
    vars:
      required: ["org.opencontainers.image.source", "org.opencontainers.image.version"]
    rules:
      - action: warn
        when: |
          required.exists(label,
            !label in dockerfile.final_stage.labels)
        reason: "Missing OCI standard labels for image provenance"
```

### Repository Integration

When scanning a repository, optionally discover and scan Dockerfiles:

```bash
# Scan repo dependencies + all Dockerfiles
deputy scan --include-dockerfiles .

# Scan only Dockerfiles in a repo
deputy scan --dockerfiles-only .
```

```go
func (s *Service) ScanRepository(ctx context.Context, ...) {
    // Existing lockfile scanning...

    if opts.IncludeDockerfiles {
        dockerfiles := findDockerfiles(mat.FS)
        for _, df := range dockerfiles {
            dfResult, err := s.ScanDockerfile(ctx, df, opts)
            // Merge results...
        }
    }
}

func findDockerfiles(fs fs.FS) []string {
    var results []string
    fs.WalkDir(fs, ".", func(path string, d fs.DirEntry, err error) error {
        if isDockerfile(path) {
            results = append(results, path)
        }
        return nil
    })
    return results
}
```

### Deep Analysis: Base Image Scanning

When `--dockerfile-mode=deep`:

```go
func (s *Service) scanDockerfileDeep(ctx context.Context, info *DockerfileInfo, opts Options) error {
    for i := range info.Stages {
        stage := &info.Stages[i]
        if stage.IsScratch {
            continue
        }

        // Resolve ARG substitution
        baseImage := resolveBaseImage(stage.BaseImage, info.Args)

        // Parse image reference
        ref, err := parseImageRef(baseImage)
        if err != nil {
            return fmt.Errorf("stage %d: invalid base image %q: %w", i, baseImage, err)
        }
        stage.BaseImageResolved = ref

        // Scan the base image
        imageTarget := fmt.Sprintf("oci://%s", baseImage)
        exec, err := s.ScanContainerImage(ctx, imageTarget, nil, opts)
        if err != nil {
            // Log warning but continue - image might not exist yet
            stage.BaseImageScanError = err.Error()
            continue
        }
        defer exec.Close()

        stage.BaseImageVulnerabilities = exec.Result.Findings
        stage.BaseImageInfo = exec.Result.ImageInfo
    }
    return nil
}
```

## Implementation Plan

### Phase 1: Static Dockerfile Parsing

1. Add `github.com/moby/buildkit` dependency
2. Create `internal/dockerfile/` package:
   - `parser.go` - wraps buildkit parser
   - `types.go` - DockerfileInfo, DockerfileStage types
   - `analyze.go` - static analysis (detect secrets, identify builders)
3. Add `dockerfileProvider` to `internal/targets/providers/`
4. Add `ScanDockerfile` to `internal/scan/service.go`
5. Add CEL variables for `dockerfile.*`
6. Add `dockerfile_report` entrypoint

### Phase 2: Policy Examples

1. Create `policy/examples/dockerfile-security.yaml`
2. Update AGENTS.md with Dockerfile policy variables
3. Add to policy cookbook

### Phase 3: Deep Analysis (Optional)

1. Add `--dockerfile-mode` flag
2. Implement base image resolution with ARG substitution
3. Add image scanning integration
4. Handle multi-arch base images (--platform)

### Phase 4: Repository Integration

1. Add `--include-dockerfiles` flag to `deputy scan`
2. Implement Dockerfile discovery in repositories
3. Merge Dockerfile findings with repository results

## Alternatives Considered

### A: SCALIBR Plugin

Create a SCALIBR extractor for Dockerfiles.

**Rejected because:**
- SCALIBR extractors are filesystem-based, returning packages
- Dockerfiles don't contain packages - they reference images
- Would require significant SCALIBR architecture changes

### B: External Tool Integration

Shell out to `hadolint` or similar.

**Rejected because:**
- Adds external dependency
- Limited integration with Deputy's policy engine
- Can't leverage existing image scanning infrastructure

### C: Dockerfile-Only Tool

Create a separate `deputy lint-dockerfile` command.

**Partially accepted:** The implementation allows standalone Dockerfile scanning, but also integrates with repository scanning for a unified experience.

## Dependencies

```go
require (
    github.com/moby/buildkit v0.13.0  // Dockerfile parser
    // Already have: go-containerregistry for image resolution
)
```

## Testing Strategy

1. **Unit tests**: Parser edge cases (ARGs, multi-stage, scratch)
2. **Policy tests**: Each example policy with fixtures
3. **Integration tests**: Real Dockerfiles from popular projects
4. **Snapshot tests**: Full scan output for regression

## Security Considerations

1. **Image pulling in deep mode**: Only pull when explicitly requested
2. **ARG values**: Don't log resolved ARGs (may contain secrets from CI)
3. **ADD URLs**: Flag as security risk in static analysis
4. **Network access**: Static mode should work fully offline
