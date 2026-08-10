# Development

This section is for contributors and maintainers.

## Guides

| Guide | Description |
|-------|-------------|
| [Contributing](contributing.md) | Local setup, development workflow, PR checklist |
| [Architecture](architecture.md) | System design, package structure |
| [Surfaces and the domain](surfaces.md) | How CLI, API, MCP, LSP, DSL, and proxy derive from the protos |
| [Adding ecosystems](adding-ecosystems.md) | How to add support for a new package ecosystem |
| [Docs style](docs-style.md) | Documentation conventions |

## Quick Commands

```bash
# Run all tests
go test ./...

# Build binary
go build -o deputy .

# Test locally
./deputy scan
./deputy --help

# Run specific test
go test -v -run TestName ./internal/pkg/...
```
