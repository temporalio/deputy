# Development

This section is for contributors and maintainers.

## Guides

| Guide | Description |
|-------|-------------|
| [Contributing](contributing.md) | Local setup, development workflow, PR checklist |
| [Architecture](architecture.md) | System design, package structure |
| [Adding ecosystems](adding-ecosystems.md) | How to add support for a new package ecosystem |
| [Docs style](docs-style.md) | Documentation conventions |
| [Surface audit](surface-audit.md) | Measuring the internal API surface with go/types |

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

# Audit the internal API surface
go run ./internal/surface/cmd
```
