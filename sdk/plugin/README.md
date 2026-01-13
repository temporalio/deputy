# Deputy Plugin SDK

Build custom inventory extractors for Deputy in any language.

## Overview

Deputy supports three types of inventory extractors:

1. **OSV-SCALIBR** - Built-in extractors from Google's osv-scalibr project
2. **Deputy Built-in** - Custom Go extractors in `internal/inventory/plugins/`
3. **Plugins** - External executables via pluginrpc (this SDK)

Plugins are standalone executables that Deputy invokes via subprocess using
[pluginrpc](https://github.com/pluginrpc/pluginrpc). This enables:

- **Any language** - Write plugins in Go, Rust, Python, or any language
- **Isolation** - Plugins run in separate processes
- **Distribution** - Ship plugins as standalone binaries
- **Hot reload** - Update plugins without recompiling Deputy

## Quick Start (Go)

```go
package main

import "github.com/picatz/deputy/sdk/plugin"

func main() {
    plugin.Main(&myExtractor{})
}

type myExtractor struct{}

func (e *myExtractor) Name() string        { return "custom/myformat" }
func (e *myExtractor) DisplayName() string { return "My Format Extractor" }
func (e *myExtractor) Ecosystem() string   { return "custom" }
func (e *myExtractor) Version() int        { return 1 }
func (e *myExtractor) Description() string { return "Extracts packages from .myformat files" }
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
```

## Plugin Interface

Implement the `Extractor` interface:

```go
type Extractor interface {
    // Metadata
    Name() string           // Unique identifier (e.g., "ruby/gemspec")
    DisplayName() string    // Human-readable name
    Ecosystem() string      // Package ecosystem (go, npm, pypi, etc.)
    Version() int           // Increment on behavior changes
    Description() string    // What does this extractor do?
    FilePatterns() []string // Glob patterns for matched files

    // File filtering (called for every file - keep fast!)
    FileRequired(path string, isDir bool, mode uint32, size int64) bool

    // Package extraction (called only for required files)
    Extract(path string, contents []byte, root string) ([]*Package, error)
}
```

## Creating Packages

Use the builder pattern for complex packages:

```go
pkg := plugin.NewPackageBuilder("lodash", "4.17.21", "npm").
    WithPURL("pkg:npm/lodash@4.17.21").
    WithLicenses("MIT").
    WithDirect(true).
    WithLocations("package.json").
    WithManifestRef("package.json", "npm", "dependencies").
    Build()
```

Or the simple constructor:

```go
pkg := plugin.NewPackage("lodash", "4.17.21", "npm")
```

## Registration

### Via Configuration

```yaml
# .deputy.yaml
plugins:
  extractors:
    - path: /usr/local/bin/deputy-extractor-myformat
    - name: deputy-extractor-gemspec  # searches PATH
```

### Via PATH Discovery

Plugins named `deputy-extractor-*` in PATH are auto-discovered.

## Protocol

Plugins communicate via [pluginrpc](https://github.com/pluginrpc/pluginrpc):

- Requests are sent via stdin (protobuf or JSON)
- Responses return via stdout
- Errors use gRPC-style status codes
- No network required - just subprocess invocation

### Testing Your Plugin

```bash
# Protocol version
./my-plugin --protocol

# Available procedures
./my-plugin --spec

# Get metadata
./my-plugin info --format json

# Test file matching (binary format)
echo '<protobuf-request>' | ./my-plugin file-required

# Extract packages (binary format)
echo '<protobuf-request>' | ./my-plugin extract
```

## Distributed Tracing

Plugins automatically participate in distributed traces when OpenTelemetry is configured:

1. Set `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable
2. Deputy injects W3C TraceContext into requests
3. Plugin SDK extracts context and creates child spans
4. Traces flow seamlessly across process boundaries

```
Deputy Scan (parent span)
└── plugin.client.FileRequired (child span)
    └── plugin.FileRequired (child span in plugin process)
└── plugin.client.Extract (child span)
    └── plugin.Extract (child span in plugin process)
```

## Writing Plugins in Other Languages

Implement the `ExtractorService` from `api/deputy/plugin/v1/extractor.proto`:

```protobuf
service ExtractorService {
  rpc Info(InfoRequest) returns (InfoResponse);
  rpc FileRequired(FileRequiredRequest) returns (FileRequiredResponse);
  rpc Extract(ExtractRequest) returns (ExtractResponse);
}
```

Your plugin must:

1. Respond to `--protocol` with `1`
2. Respond to `--spec` with the procedure spec
3. Handle `info`, `file-required`, and `extract` subcommands
4. Read protobuf requests from stdin
5. Write protobuf responses to stdout

See [pluginrpc](https://github.com/pluginrpc/pluginrpc) for protocol details.

## Examples

- [dotenv-extractor](../../examples/plugins/dotenv-extractor/) - Discovers .env files

## API Reference

See [pkg.go.dev](https://pkg.go.dev/github.com/picatz/deputy/sdk/plugin) for full documentation.
