# Adding Ecosystem Support

This guide explains how to add support for a new package ecosystem to Deputy.

## Overview

Deputy's ecosystem support is modular. Adding a new ecosystem involves:

1. **Ecosystem constant** - Register the ecosystem identifier
2. **Inventory extraction** - Parse lockfiles to discover dependencies
3. **Proxy handler** (optional) - Intercept package downloads for policy enforcement
4. **Graph resolution** (optional) - Resolve dependency trees for path analysis

## Architecture

```mermaid
flowchart TB
    subgraph Core["Core Registration"]
        Eco["ecosystem.go<br/>Ecosystem constant"]
        Cap["Capabilities()<br/>Feature flags"]
    end

    subgraph Inventory["Inventory Layer"]
        Scalibr["OSV-SCALIBR<br/>Built-in extractors"]
        Custom["Custom extractor<br/>plugins/"]
    end

    subgraph Proxy["Proxy Layer (optional)"]
        Handler["ProxyHandler<br/>proxy/"]
        Policy["Policy entrypoint<br/>_artifact_request"]
    end

    subgraph Graph["Graph Layer (optional)"]
        Resolver["GraphResolver<br/>dependency/graph/"]
    end

    Eco --> Cap
    Cap --> Scalibr & Custom
    Cap --> Handler --> Policy
    Cap --> Resolver

    classDef core fill:#e3f2fd,stroke:#1565c0
    classDef inventory fill:#e8f5e9,stroke:#2e7d32
    classDef proxy fill:#fff3e0,stroke:#e65100
    classDef graph fill:#f3e5f5,stroke:#7b1fa2

    class Eco,Cap core
    class Scalibr,Custom inventory
    class Handler,Policy proxy
    class Resolver graph
```

## Step 1: Register the Ecosystem

Add the ecosystem constant in `internal/ecosystem/ecosystem.go`:

```go
const (
    // ... existing ecosystems
    Swift Ecosystem = "swift"  // Add your ecosystem
)
```

Update these methods:

### Parse() - Alias recognition

```go
func Parse(s string) Ecosystem {
    switch strings.ToLower(strings.TrimSpace(s)) {
    // ... existing cases
    case "swift", "swiftpm", "spm":
        return Swift
    // ...
    }
}
```

### OSVName() - OSV database identifier

```go
func (e Ecosystem) OSVName() string {
    switch e {
    // ... existing cases
    case Swift:
        return "SwiftURL"  // Must match OSV ecosystem name
    // ...
    }
}
```

### DepsDevSystem() - deps.dev API system

```go
func (e Ecosystem) DepsDevSystem() pb.System {
    switch e {
    // ... existing cases
    case Swift:
        return pb.System_SYSTEM_UNSPECIFIED  // If not supported by deps.dev
    // ...
    }
}
```

### ScalibrPrefixes() - SCALIBR plugin filter

```go
func (e Ecosystem) ScalibrPrefixes() []string {
    switch e {
    // ... existing cases
    case Swift:
        return []string{"swift"}  // Matches SCALIBR plugin naming
    // ...
    }
}
```

### Capabilities() - Feature availability

```go
func (e Ecosystem) Capabilities() Capabilities {
    switch e {
    // ... existing cases
    case Swift:
        return Capabilities{
            Scan:            true,   // Vulnerability scanning
            SBOM:            true,   // SBOM generation
            Proxy:           false,  // Download-time enforcement
            License:         false,  // License enrichment
            GraphResolution: false,  // Dependency path resolution
        }
    // ...
    }
}
```

### All() - Include in ecosystem list

```go
func All() []Ecosystem {
    return []Ecosystem{
        Go, NPM, PyPI, Maven, RubyGems, Cargo, NuGet, Hex, Pub, CocoaPods, Packagist,
        Swift,  // Add your ecosystem
    }
}
```

## Step 2: Inventory Extraction

Deputy uses [OSV-SCALIBR](https://github.com/google/osv-scalibr) for lockfile parsing. Check if SCALIBR already supports your ecosystem's lockfiles.

### If SCALIBR supports it

No additional code needed. SCALIBR extractors are auto-discovered based on `ScalibrPrefixes()`.

Verify support:
```bash
# Check SCALIBR plugins
go doc github.com/google/osv-scalibr/extractor/filesystem/list
```

### If custom extraction is needed

Create a custom extractor in `internal/inventory/plugins/`:

```go
// internal/inventory/plugins/swift/packageswift/extractor.go
package packageswift

import (
    "context"
    "io/fs"

    "github.com/google/osv-scalibr/extractor"
    "github.com/google/osv-scalibr/extractor/filesystem"
    "github.com/google/osv-scalibr/purl"
)

// Extractor extracts dependencies from Package.resolved files.
type Extractor struct{}

var _ filesystem.Extractor = (*Extractor)(nil)

func (e *Extractor) Name() string { return "swift/packageresolved" }

func (e *Extractor) Version() int { return 1 }

func (e *Extractor) FileRequired(path string, fi fs.FileInfo) bool {
    return filepath.Base(path) == "Package.resolved"
}

func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
    // Parse the lockfile
    data, err := io.ReadAll(input.Reader)
    if err != nil {
        return nil, err
    }

    var resolved PackageResolved
    if err := json.Unmarshal(data, &resolved); err != nil {
        return nil, err
    }

    var inventory []*extractor.Inventory
    for _, pin := range resolved.Pins {
        inv := &extractor.Inventory{
            Name:      pin.Identity,
            Version:   pin.State.Version,
            Locations: []string{input.Path},
        }
        // Set PURL for vulnerability matching
        inv.SourceCode = &extractor.SourceCodeIdentifier{
            PURL: &purl.PackageURL{
                Type:    "swift",
                Name:    pin.Identity,
                Version: pin.State.Version,
            },
        }
        inventory = append(inventory, inv)
    }

    return inventory, nil
}

// PackageResolved represents Package.resolved structure
type PackageResolved struct {
    Pins []struct {
        Identity string `json:"identity"`
        State    struct {
            Version string `json:"version"`
        } `json:"state"`
    } `json:"pins"`
}
```

Register the extractor in `internal/inventory/inventory.go`:

```go
import "github.com/temporalio/deputy/internal/inventory/plugins/swift/packageswift"

func init() {
    RegisterExtractor(&packageswift.Extractor{})
}
```

## Step 3: Proxy Handler (Optional)

If you want download-time policy enforcement, implement a proxy handler.

### Create the handler

```go
// internal/proxy/swift/handler.go
package swift

import (
    "net/http"
    "net/http/httputil"
    "net/url"

    "github.com/temporalio/deputy/internal/proxy"
)

// Handler proxies Swift Package Manager requests.
type Handler struct {
    upstream *url.URL
    proxy    *httputil.ReverseProxy
    policy   proxy.PolicyEvaluator
}

var _ proxy.Handler = (*Handler)(nil)

func New(upstream string, policy proxy.PolicyEvaluator) (*Handler, error) {
    u, err := url.Parse(upstream)
    if err != nil {
        return nil, err
    }
    return &Handler{
        upstream: u,
        proxy:    httputil.NewSingleHostReverseProxy(u),
        policy:   policy,
    }, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // Parse package request from URL
    pkg, version := parseSwiftRequest(r.URL.Path)
    if pkg == "" {
        h.proxy.ServeHTTP(w, r)
        return
    }

    // Evaluate policy
    ctx := proxy.RequestContext{
        Ecosystem: "swift",
        Package:   pkg,
        Version:   version,
    }

    if err := h.policy.Evaluate(r.Context(), ctx); err != nil {
        proxy.WriteError(w, err)
        return
    }

    h.proxy.ServeHTTP(w, r)
}

func parseSwiftRequest(path string) (pkg, version string) {
    // Parse Swift registry URL format
    // e.g., /scope/package/version
    // ...
    return
}
```

### Register the policy entrypoint

Add to `internal/policy/entrypoints.go`:

```go
const (
    // ... existing entrypoints
    EntrypointSwiftArtifactRequest Entrypoint = "swift_artifact_request"
)
```

## Step 4: Graph Resolution (Optional)

For dependency path analysis (`deputy graph why`), implement a graph resolver.

```go
// internal/dependency/graph/swift.go
package graph

import (
    "context"

    "github.com/temporalio/deputy/internal/dependency"
)

// SwiftResolver resolves Swift package dependencies.
type SwiftResolver struct{}

var _ Resolver = (*SwiftResolver)(nil)

func (r *SwiftResolver) Ecosystem() string { return "swift" }

func (r *SwiftResolver) Resolve(ctx context.Context, root string) (*Graph, error) {
    // Parse Package.resolved to build dependency graph
    // ...
    return nil, nil
}
```

Register in `internal/dependency/graph/registry.go`:

```go
func init() {
    RegisterResolver(&SwiftResolver{})
}
```

## Testing

### Unit tests

```go
// internal/inventory/plugins/swift/packageswift/extractor_test.go
func TestExtractor(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        want     []*extractor.Inventory
        wantErr  bool
    }{
        {
            name: "valid Package.resolved",
            input: `{"pins":[{"identity":"alamofire","state":{"version":"5.6.0"}}]}`,
            want: []*extractor.Inventory{
                {Name: "alamofire", Version: "5.6.0"},
            },
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // ...
        })
    }
}
```

### Integration tests

Add test fixtures in `testdata/`:

```
testdata/
  swift/
    Package.resolved
    expected.json
```

### CLI tests

```bash
# Test scanning
deputy scan testdata/swift/

# Test SBOM generation
deputy sbom testdata/swift/ --format cyclonedx-json
```

## Checklist

Before submitting your PR:

- [ ] Ecosystem constant added to `ecosystem.go`
- [ ] `Parse()` handles common aliases
- [ ] `OSVName()` returns correct OSV ecosystem
- [ ] `ScalibrPrefixes()` returns correct prefixes
- [ ] `Capabilities()` accurately reflects features
- [ ] `All()` includes the new ecosystem
- [ ] Extractor parses all common lockfile variants
- [ ] Unit tests cover edge cases
- [ ] Integration tests with real lockfiles
- [ ] Documentation updated (FAQ, capabilities matrix)

## Example PRs

- [Add RubyGems support](https://github.com/temporalio/deputy/pull/XXX)
- [Add Cargo proxy support](https://github.com/temporalio/deputy/pull/XXX)

## See Also

- [OSV-SCALIBR extractors](https://github.com/google/osv-scalibr/tree/main/extractor/filesystem)
- [PURL specification](https://github.com/package-url/purl-spec)
- [Ecosystem capabilities](../reference/capabilities.md)
