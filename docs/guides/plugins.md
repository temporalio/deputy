# Building Deputy Extractor Plugins

This guide covers how to build custom extractor plugins for Deputy. Plugins enable custom package detection for file formats not supported by the built-in extractors.

## Overview

Deputy supports three types of inventory extractors:

| Type | Location | Language | Discovery |
|------|----------|----------|-----------|
| **OSV-SCALIBR** | Built-in | Go | Automatic |
| **Deputy Built-in** | `internal/inventory/plugins/` | Go | Automatic |
| **Plugins** | External executables | Any | PATH or config |

Plugins are standalone executables that communicate with Deputy via [pluginrpc](https://github.com/pluginrpc/pluginrpc), a subprocess-based RPC protocol using Protocol Buffers.

## Architecture

```mermaid
flowchart TB
    subgraph Deputy["Deputy Process"]
        direction TB
        scan["scan command"]
        inventory["inventory extraction"]
        client["plugin.Client"]

        scan --> inventory
        inventory --> client
    end

    subgraph Protocol["pluginrpc Protocol"]
        direction LR
        spawn["subprocess spawn"]
        stdin["stdin (protobuf)"]
        stdout["stdout (protobuf)"]
    end

    subgraph Plugin["Plugin Process"]
        direction TB
        server["pluginrpc.Server"]
        handler["ExtractorService"]
        impl["Your Extractor"]
        sdk["sdk/plugin helpers"]

        server --> handler
        handler --> impl
        impl --> sdk
    end

    client --> spawn --> server
    client --> stdin --> server
    server --> stdout --> client

    classDef deputy fill:#e3f2fd,stroke:#1565c0
    classDef protocol fill:#fff3e0,stroke:#e65100
    classDef plugin fill:#e8f5e9,stroke:#2e7d32

    class Deputy,scan,inventory,client deputy
    class Protocol,spawn,stdin,stdout protocol
    class Plugin,server,handler,impl,sdk plugin
```

## Quick Start (Go)

Create a plugin in a single `main.go` file:

```go
package main

import (
    "strings"
    "github.com/temporalio/deputy/sdk/plugin"
)

func main() {
    plugin.Main(&myExtractor{})
}

type myExtractor struct{}

func (e *myExtractor) Name() string           { return "custom/myformat" }
func (e *myExtractor) DisplayName() string    { return "My Custom Format" }
func (e *myExtractor) Ecosystem() string      { return "custom" }
func (e *myExtractor) Version() int           { return 1 }
func (e *myExtractor) Description() string    { return "Extracts packages from .myformat files" }
func (e *myExtractor) FilePatterns() []string { return []string{"*.myformat"} }

func (e *myExtractor) FileRequired(path string, isDir bool, mode uint32, size int64) bool {
    return strings.HasSuffix(path, ".myformat")
}

func (e *myExtractor) Extract(path string, contents []byte, root string) ([]*plugin.Package, error) {
    // Parse contents and return packages
    return []*plugin.Package{
        plugin.NewPackage("example-pkg", "1.0.0", "custom"),
    }, nil
}
```

Build and install:

```bash
go build -o deputy-extractor-myformat .
mv deputy-extractor-myformat /usr/local/bin/
```

## Plugin Lifecycle

```mermaid
sequenceDiagram
    participant D as Deputy
    participant P as Plugin Process

    Note over D,P: Discovery Phase
    D->>D: Find plugins in PATH or config

    Note over D,P: Initialization
    D->>P: spawn process
    D->>P: Info() RPC
    P->>D: ExtractorInfo (name, ecosystem, patterns)

    Note over D,P: File Scanning
    loop For each file in scan target
        D->>P: FileRequired(path, isDir, mode, size)
        P->>D: required: true/false

        alt File is required
            D->>D: Read file contents
            D->>P: Extract(path, contents, root)
            P->>D: packages[]
        end
    end

    Note over D,P: Cleanup
    D->>P: process exit
```

## The Extractor Interface

Implement the `Extractor` interface from `github.com/temporalio/deputy/sdk/plugin`:

```go
type Extractor interface {
    // Metadata - called once at startup
    Name() string           // Unique identifier (e.g., "ruby/gemspec")
    DisplayName() string    // Human-readable name
    Ecosystem() string      // Package ecosystem (go, npm, pypi, etc.)
    Version() int           // Increment on behavior changes
    Description() string    // What does this extractor do?
    FilePatterns() []string // Glob patterns for matched files

    // File filtering - called for every file (keep fast!)
    FileRequired(path string, isDir bool, mode uint32, size int64) bool

    // Package extraction - called only for required files
    Extract(path string, contents []byte, root string) ([]*Package, error)
}
```

### Metadata Methods

| Method | Purpose | Example |
|--------|---------|---------|
| `Name()` | Unique identifier for the extractor | `"ruby/gemspec"` |
| `DisplayName()` | Human-readable name for logs/UI | `"Ruby Gemspec"` |
| `Ecosystem()` | Package ecosystem for grouping | `"rubygems"` |
| `Version()` | Version number (increment on changes) | `1` |
| `Description()` | What this extractor does | `"Extracts gem dependencies from .gemspec files"` |
| `FilePatterns()` | Glob patterns for discovery | `["*.gemspec", "Gemfile.lock"]` |

### FileRequired

Called for every file during scanning. Return `true` if the file should be extracted.

```go
func (e *myExtractor) FileRequired(path string, isDir bool, mode uint32, size int64) bool {
    // Skip directories
    if isDir {
        return false
    }

    // Match by extension
    if strings.HasSuffix(path, ".myformat") {
        return true
    }

    // Match by filename
    base := filepath.Base(path)
    if base == "myformat.lock" {
        return true
    }

    return false
}
```

**Performance tip:** This method is called for every file. Keep it fast - use string matching, not file I/O.

### Extract

Called for files where `FileRequired` returned `true`. Parse the file contents and return packages.

```go
func (e *myExtractor) Extract(path string, contents []byte, root string) ([]*plugin.Package, error) {
    var packages []*plugin.Package

    // Parse your custom format
    for _, dep := range parseMyFormat(contents) {
        pkg := plugin.NewPackageBuilder(dep.Name, dep.Version, "custom").
            WithPURL(fmt.Sprintf("pkg:custom/%s@%s", dep.Name, dep.Version)).
            WithLicenses(dep.License).
            WithDirect(dep.IsDirect).
            WithLocations(path).
            Build()

        packages = append(packages, pkg)
    }

    return packages, nil
}
```

## Creating Packages

### Simple Constructor

```go
pkg := plugin.NewPackage("lodash", "4.17.21", "npm")
```

### Builder Pattern

For packages with additional metadata:

```go
pkg := plugin.NewPackageBuilder("lodash", "4.17.21", "npm").
    WithPURL("pkg:npm/lodash@4.17.21").
    WithLicenses("MIT").
    WithDirect(true).
    WithLocations("package.json").
    WithManifestRef("package.json", "npm", "dependencies").
    Build()
```

### Package Fields

| Field | Description | Required |
|-------|-------------|----------|
| `Name` | Package name | Yes |
| `Version` | Package version | Yes |
| `Ecosystem` | Package ecosystem | Yes |
| `PURL` | Package URL | No |
| `Licenses` | SPDX license identifiers | No |
| `Direct` | Is direct dependency | No |
| `Locations` | Source file paths | No |

## Plugin Registration

### Via Configuration

Add to `.deputy.yaml`:

```yaml
plugins:
  extractors:
    # Absolute path
    - path: /usr/local/bin/deputy-extractor-myformat

    # Relative path
    - path: ./tools/deputy-extractor-myformat

    # Search PATH by name
    - name: deputy-extractor-gemspec
```

### Via PATH Discovery

Plugins named `deputy-extractor-*` in PATH are auto-discovered:

```bash
# These are auto-discovered
/usr/local/bin/deputy-extractor-gemspec
/usr/local/bin/deputy-extractor-pyproject
~/.local/bin/deputy-extractor-custom
```

## Distributed Tracing

Plugins automatically participate in distributed traces when OpenTelemetry is configured.

```mermaid
flowchart LR
    subgraph Deputy["Deputy Process"]
        span1["scan span"]
        span2["plugin.client.Extract"]
    end

    subgraph Plugin["Plugin Process"]
        span3["plugin.Extract"]
    end

    span1 --> span2
    span2 -->|"TraceContext"| span3

    classDef deputy fill:#e3f2fd,stroke:#1565c0
    classDef plugin fill:#e8f5e9,stroke:#2e7d32

    class Deputy,span1,span2 deputy
    class Plugin,span3 plugin
```

### How It Works

1. Set `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable
2. Deputy injects W3C TraceContext into plugin requests
3. Plugin SDK extracts context and creates child spans
4. Traces flow seamlessly across process boundaries

### Viewing Traces

```bash
# Start Jaeger (or your preferred collector)
docker run -d --name jaeger \
  -p 16686:16686 \
  -p 4317:4317 \
  jaegertracing/all-in-one:latest

# Run Deputy with tracing
DEPUTY_OTEL_ENABLED=true \
OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317 \
deputy scan .

# View traces at http://localhost:16686
```

## Testing Plugins

### Protocol Testing

```bash
# Check protocol version
./deputy-extractor-myformat --protocol
# Output: 1

# Check procedure spec
./deputy-extractor-myformat --spec
# Output: JSON procedure spec

# Get extractor info
./deputy-extractor-myformat info --format json
# Output: {"name":"custom/myformat","display_name":"My Format",...}
```

### Integration Testing

```go
func TestMyExtractor(t *testing.T) {
    // Build the plugin
    pluginPath := buildPlugin(t)
    defer os.Remove(pluginPath)

    // Create client
    ctx := context.Background()
    client, err := invplugin.NewClient(ctx, pluginPath)
    require.NoError(t, err)

    // Test metadata
    info := client.ExtractorInfo()
    assert.Equal(t, "custom/myformat", info.Name)

    // Test file matching
    required, err := client.FileRequired(ctx, "test.myformat", false, 0644, 100)
    require.NoError(t, err)
    assert.True(t, required)

    // Test extraction
    contents := []byte(`name: example\nversion: 1.0.0`)
    packages, err := client.ExtractPackages(ctx, "test.myformat", contents, "/project")
    require.NoError(t, err)
    assert.Len(t, packages, 1)
    assert.Equal(t, "example", packages[0].Name)
}
```

### With Deputy

```bash
# Debug mode shows plugin invocations
DEPUTY_LOG_LEVEL=debug deputy scan .
```

## Writing Plugins in Other Languages

Plugins can be written in any language that supports protobuf. Implement the `ExtractorService` from `api/deputy/plugin/v1/extractor.proto`:

```protobuf
service ExtractorService {
  rpc Info(InfoRequest) returns (InfoResponse);
  rpc FileRequired(FileRequiredRequest) returns (FileRequiredResponse);
  rpc Extract(ExtractRequest) returns (ExtractResponse);
}
```

### Requirements

1. **Protocol flag**: `--protocol` returns `1`
2. **Spec flag**: `--spec` returns the procedure spec (binary protobuf)
3. **Subcommands**: `info`, `file-required`, `extract`
4. **I/O**: Read protobuf from stdin, write protobuf to stdout

### Python Example (Conceptual)

```python
#!/usr/bin/env python3
import sys
from deputy.plugin.v1 import extractor_pb2

def handle_info():
    response = extractor_pb2.InfoResponse()
    response.info.name = "python/custom"
    response.info.display_name = "Python Custom"
    response.info.ecosystem = "pypi"
    response.info.version = 1
    sys.stdout.buffer.write(response.SerializeToString())

def handle_file_required(request):
    response = extractor_pb2.FileRequiredResponse()
    response.required = request.path.endswith(".custom")
    sys.stdout.buffer.write(response.SerializeToString())

def handle_extract(request):
    response = extractor_pb2.ExtractResponse()
    # Parse request.contents and populate response.packages
    sys.stdout.buffer.write(response.SerializeToString())

if __name__ == "__main__":
    if "--protocol" in sys.argv:
        print("1")
    elif "--spec" in sys.argv:
        print('{"procedures":[...]}')
    elif sys.argv[1] == "info":
        handle_info()
    elif sys.argv[1] == "file-required":
        request = extractor_pb2.FileRequiredRequest()
        request.ParseFromString(sys.stdin.buffer.read())
        handle_file_required(request)
    elif sys.argv[1] == "extract":
        request = extractor_pb2.ExtractRequest()
        request.ParseFromString(sys.stdin.buffer.read())
        handle_extract(request)
```

## Best Practices

### Performance

- `FileRequired` is called for every file - keep it fast (string matching only)
- Avoid reading files in `FileRequired` - Deputy provides contents in `Extract`
- Cache compiled regexes if using pattern matching

### Error Handling

```go
func (e *myExtractor) Extract(path string, contents []byte, root string) ([]*plugin.Package, error) {
    packages, err := parseMyFormat(contents)
    if err != nil {
        // Return partial results with error context
        return nil, fmt.Errorf("parse %s: %w", path, err)
    }
    return packages, nil
}
```

### Versioning

Increment `Version()` when:
- Changing what files are matched
- Changing what packages are extracted
- Fixing bugs that affect extraction results

This allows Deputy to invalidate caches appropriately.

### Naming Conventions

| Convention | Example |
|------------|---------|
| Binary name | `deputy-extractor-<format>` |
| Extractor name | `<ecosystem>/<format>` |
| Display name | `<Format> <Ecosystem>` |

## Example: Dotenv Extractor

See [examples/plugins/dotenv-extractor/](../../examples/plugins/dotenv-extractor/) for a complete working example that:

- Discovers `.env` files
- Reports environment variable files as packages
- Demonstrates the full plugin lifecycle

## Troubleshooting

### Plugin Not Found

```bash
# Check if plugin is in PATH
which deputy-extractor-myformat

# Check plugin permissions
ls -la $(which deputy-extractor-myformat)

# Test plugin directly
deputy-extractor-myformat --protocol
```

### Protocol Errors

```bash
# Enable debug logging
DEPUTY_LOG_LEVEL=debug deputy scan .

# Check plugin stderr
deputy-extractor-myformat info 2>&1
```

### Trace Context Not Propagating

```bash
# Verify OTel is enabled
DEPUTY_OTEL_ENABLED=true \
OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317 \
deputy scan .

# Check for trace IDs in debug output
DEPUTY_LOG_LEVEL=debug deputy scan . 2>&1 | grep trace
```

## Advisory Source Plugins

Beyond extractors, Deputy supports **advisory source** plugins: components that,
given a set of packages, return the advisories (vulnerabilities and malware)
affecting them. The built-in OSV source implements the same contract in-process;
plugins let you add threat feeds, vendor databases, or internal allow/deny
intelligence. Deputy aggregates all sources with union-with-provenance
semantics: each finding records which source(s) reported it in `sources`, and
the scan's `coverage` block shows which (ecosystem, artifact) combinations each
source answered for. Advisory records (the shared descriptions keyed by
advisory ID) merge first-source-wins in registration order, with the built-in
OSV source first; a custom source cannot overwrite OSV's record for an ID OSV
already returned, only add findings that reference it.

### Quick Start (Go)

```go
package main

import (
    "context"

    plugin "github.com/temporalio/deputy/sdk/plugin"
)

type mySource struct{}

func (s *mySource) Info() *plugin.AdvisorySourceInfo {
    return &plugin.AdvisorySourceInfo{
        Name:        "my-feed",
        DisplayName: "My Threat Feed",
        Version:     1,
        Capabilities: &plugin.SourceCapabilities{
            Ecosystems:   []string{"npm", "pypi"},
            Artifacts:    []plugin.ArtifactKind{plugin.ArtifactKindPackage},
            FindingKinds: []plugin.FindingKind{plugin.FindingKindMalware},
        },
    }
}

func (s *mySource) Query(ctx context.Context, packages []*plugin.Package) ([]*plugin.Finding, map[string]*plugin.Advisory, error) {
    // Look up packages against your feed and return findings + advisories.
    return nil, nil, nil
}

func main() {
    plugin.MainAdvisorySource(&mySource{})
}
```

Declare accurate capabilities: Deputy routes only packages a source covers, and
a source must ignore anything outside its declared coverage rather than
erroring.

### Registration (explicit opt-in)

Advisory sources are trusted components. A `program:` source runs as a
subprocess with the same operating-system privileges as Deputy itself (there is
no sandbox), it sees every package identity in your scan, and its findings feed
policy and remediation decisions verbatim. Review and version-pin a plugin as
you would any dependency, and prefer the ConnectRPC binding for feeds a team
operates centrally. Because sources can see and shape security findings, Deputy
**never auto-executes** binaries it merely finds on PATH. Name the sources you
trust explicitly, via the environment:

```bash
DEPUTY_ADVISORY_SOURCES=deputy-advisory-source-myfeed deputy scan .
```

or in `.deputy.yaml`:

```yaml
advisory_sources:
  - program: deputy-advisory-source-myfeed   # pluginrpc subprocess plugin
  - url: https://feeds.corp.example          # ConnectRPC service
```

A source that fails to load is skipped with a warning rather than failing the
scan; the scan's `coverage` block shows which sources actually answered.

### Transport Bindings

The `AdvisorySourceService` proto contract has three interchangeable bindings;
pick per source, the aggregation is identical:

| Binding | Config | Cost per query | Right for |
|---------|--------|----------------|-----------|
| In-process | (built-in OSV) | none | core sources |
| pluginrpc | `program:` | subprocess exec | scans, any-language plugins, no daemon |
| ConnectRPC | `url:` | one HTTP call | latency-sensitive callers, shared/remote feeds |

To serve the ConnectRPC binding, implement `AdvisorySourceService` with the
generated `pluginv1connect.NewAdvisorySourceServiceHandler` and run it as a
sidecar or shared service.

See [Example: Static Advisory Source](../../examples/advisory-source-plugins/static/)
for a complete working plugin.

## Reference

- [Plugin SDK (pkg.go.dev)](https://pkg.go.dev/github.com/temporalio/deputy/sdk/plugin)
- [ExtractorService Proto](../../api/deputy/plugin/v1/extractor.proto)
- [AdvisorySourceService Proto](../../api/deputy/plugin/v1/advisory_source.proto)
- [pluginrpc Documentation](https://github.com/pluginrpc/pluginrpc)
- [Example: Dotenv Extractor](../../examples/plugins/dotenv-extractor/)
- [Example: Static Advisory Source](../../examples/advisory-source-plugins/static/)
