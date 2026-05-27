// Package plugin provides a simple SDK for building Deputy extractor plugins.
//
// Plugins are standalone executables that Deputy invokes via pluginrpc to
// extract package inventory from custom file formats. This SDK provides a
// high-level interface that handles all the pluginrpc boilerplate.
//
// # Architecture
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                     Deputy Process                              │
//	│  ┌───────────┐    ┌──────────────┐    ┌───────────────────┐    │
//	│  │   scan    │───▶│  inventory   │───▶│  plugin.Client    │    │
//	│  │  command  │    │  extraction  │    │  (invokes plugin) │    │
//	│  └───────────┘    └──────────────┘    └─────────┬─────────┘    │
//	│                                                 │              │
//	└─────────────────────────────────────────────────│──────────────┘
//	                                                  │
//	                          ┌────────────────┬──────┴───────┐
//	                          │ stdin (proto)  │  spawn       │
//	                          ▼                ▼              │
//	┌─────────────────────────────────────────────────────────│──────┐
//	│                     Plugin Process                      │      │
//	│  ┌───────────────────┐    ┌───────────────┐    ┌───────┴────┐ │
//	│  │ pluginrpc.Server  │◀───│   Extractor   │◀───│  sdk/plugin│ │
//	│  │ (protocol logic)  │    │ (your impl)   │    │  (helpers) │ │
//	│  └─────────┬─────────┘    └───────────────┘    └────────────┘ │
//	│            │                                                   │
//	│            ▼ stdout (proto)                                    │
//	└────────────│───────────────────────────────────────────────────┘
//	             │
//	             └────▶ back to Deputy
//
// # Quick Start
//
// Create a plugin in a single main.go file:
//
//	package main
//
//	import (
//	    "github.com/temporalio/deputy/sdk/plugin"
//	)
//
//	func main() {
//	    plugin.Main(&myExtractor{})
//	}
//
//	type myExtractor struct{}
//
//	func (e *myExtractor) Name() string        { return "custom/myformat" }
//	func (e *myExtractor) DisplayName() string { return "My Custom Format" }
//	func (e *myExtractor) Ecosystem() string   { return "custom" }
//	func (e *myExtractor) Version() int        { return 1 }
//	func (e *myExtractor) Description() string { return "Extracts packages from .myformat files" }
//	func (e *myExtractor) FilePatterns() []string { return []string{"*.myformat"} }
//
//	func (e *myExtractor) FileRequired(path string, isDir bool, mode uint32, size int64) bool {
//	    return strings.HasSuffix(path, ".myformat")
//	}
//
//	func (e *myExtractor) Extract(path string, contents []byte, root string) ([]*plugin.Package, error) {
//	    // Parse contents and return packages
//	    return []*plugin.Package{
//	        {Name: "example-pkg", Version: "1.0.0", Ecosystem: "custom"},
//	    }, nil
//	}
//
// # Building the Plugin
//
//	go build -o deputy-extractor-myformat ./cmd/myformat-plugin
//
// # Registering with Deputy
//
// Plugins can be registered via configuration or discovered from PATH:
//
//	# .deputy.yaml
//	plugins:
//	  extractors:
//	    - path: /usr/local/bin/deputy-extractor-myformat
//	    - name: deputy-extractor-gemspec  # searches PATH
//
// Or programmatically via the SDK:
//
//	client, _ := sdk.NewClient(ctx)
//	client.RegisterExtractor(ctx, "deputy-extractor-myformat")
//
// # Distributed Tracing
//
// Plugins automatically participate in distributed traces when the
// OTEL_EXPORTER_OTLP_ENDPOINT environment variable is set. The SDK
// extracts trace context from requests and creates child spans.
//
//	Deputy Scan (trace-id: abc123)
//	│
//	├── inventory.Extract
//	│   │
//	│   ├── plugin.client.FileRequired ──────────────────┐
//	│   │   │                                            │ TraceContext
//	│   │   └──[spawn]──▶ plugin.FileRequired (abc123) ◀─┘ in request
//	│   │
//	│   └── plugin.client.Extract ───────────────────────┐
//	│       │                                            │ TraceContext
//	│       └──[spawn]──▶ plugin.Extract (abc123) ◀──────┘ in request
//	│
//	└── vulnerability.Lookup
//
// The TraceContext field in FileRequiredRequest and ExtractRequest carries
// the W3C traceparent header value, enabling end-to-end tracing.
//
// # Plugin Interface
//
// Implement the [Extractor] interface to create a plugin. The SDK handles:
//   - Pluginrpc protocol negotiation (--protocol, --spec flags)
//   - Request/response serialization
//   - OpenTelemetry trace context propagation
//   - Error handling and exit codes
//
// See the [Extractor] interface for detailed documentation.
package plugin
