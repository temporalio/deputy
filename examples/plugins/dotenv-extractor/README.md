# Dotenv Extractor Plugin

Example Deputy extractor plugin that discovers `.env` files.

This demonstrates how to build a custom extractor plugin using the Deputy plugin SDK.

## Architecture

```
Deputy Process                          Plugin Process
+------------------+                    +------------------+
|                  |                    |                  |
|  scan command    |                    |  pluginrpc.Main  |
|       |          |                    |       |          |
|       v          |                    |       v          |
|  inventory       |     subprocess     | ExtractorService |
|  extraction  ----|------ spawn ------>|  handler         |
|       |          |                    |       |          |
|       v          |     stdin/stdout   |       v          |
|  plugin.Client --|---- (protobuf) --->| dotenvExtractor  |
|                  |                    |                  |
+------------------+                    +------------------+
```

## Building

```bash
go build -o deputy-extractor-dotenv .
```

## Usage

### With Deputy Configuration

Add to your `.deputy.yaml`:

```yaml
plugins:
  extractors:
    - path: ./deputy-extractor-dotenv
```

### Testing the Plugin Directly

```bash
# Get plugin protocol version
./deputy-extractor-dotenv --protocol

# Get plugin spec (available procedures)
./deputy-extractor-dotenv --spec

# Get extractor info
./deputy-extractor-dotenv info --format json
```

## Plugin Lifecycle

```
1. Discovery
   Deputy finds plugins via PATH or .deputy.yaml config

2. Initialization
   Deputy spawns plugin process
   Deputy calls Info() RPC
   Plugin returns metadata (name, ecosystem, patterns)

3. File Scanning
   For each file:
     Deputy calls FileRequired(path, isDir, mode, size)
     Plugin returns true/false

     If true:
       Deputy reads file contents
       Deputy calls Extract(path, contents, root)
       Plugin returns packages[]

4. Cleanup
   Plugin process exits
```

## How It Works

1. Deputy calls `Info()` to get extractor metadata
2. For each file in the scan, Deputy calls `FileRequired()`
3. If `FileRequired()` returns true, Deputy calls `Extract()` with the file contents
4. The plugin returns discovered packages

## Creating Your Own Plugin

```go
package main

import "github.com/temporalio/deputy/sdk/plugin"

func main() {
    plugin.Main(&myExtractor{})
}

type myExtractor struct{}

func (e *myExtractor) Name() string        { return "custom/myformat" }
func (e *myExtractor) DisplayName() string { return "My Format" }
func (e *myExtractor) Ecosystem() string   { return "custom" }
func (e *myExtractor) Version() int        { return 1 }
func (e *myExtractor) Description() string { return "Extracts from .myformat files" }
func (e *myExtractor) FilePatterns() []string { return []string{"*.myformat"} }

func (e *myExtractor) FileRequired(path string, isDir bool, mode uint32, size int64) bool {
    return strings.HasSuffix(path, ".myformat")
}

func (e *myExtractor) Extract(path string, contents []byte, root string) ([]*plugin.Package, error) {
    // Parse contents and return packages
    return []*plugin.Package{
        plugin.NewPackage("example", "1.0.0", "custom"),
    }, nil
}
```

## Distributed Tracing

Plugins automatically participate in distributed traces when `OTEL_EXPORTER_OTLP_ENDPOINT` is set.

```
Deputy Scan (trace-id: abc123)
|
+-- inventory.Extract
    |
    +-- plugin.client.FileRequired ----+
    |   |                              | TraceContext
    |   +--[spawn]--> plugin.FileRequired (abc123)
    |
    +-- plugin.client.Extract ---------+
        |                              | TraceContext
        +--[spawn]--> plugin.Extract (abc123)
```

The SDK extracts trace context from requests and creates child spans for `FileRequired()` and `Extract()` operations.

## More Information

- [Plugin Development Guide](../../../docs/guides/plugins.md)
- [Plugin SDK Documentation](../../../sdk/plugin/)
- [ExtractorService Proto](../../../api/deputy/plugin/v1/extractor.proto)
