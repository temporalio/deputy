# Contributing

## Prerequisites

- Go 1.21+ (uses `toolchain` directive)
- Git
- Make (optional, for convenience targets)

## Local Setup

```bash
# Clone the repository
git clone https://github.com/picatz/deputy.git
cd deputy

# Verify setup - run tests
go test ./...

# Build the binary
go build -o deputy .

# Test locally
./deputy scan
./deputy --help
```

## Development Workflow

### 1. Create a branch

```bash
git checkout -b feature/my-feature
# or
git checkout -b fix/issue-123
```

### 2. Make changes

Follow the code style and patterns established in the codebase:

- Standard Go formatting (`go fmt`, `goimports`)
- Table-driven tests where applicable
- Error wrapping with context: `fmt.Errorf("context: %w", err)`
- Use modern Go packages: `slices`, `maps`, `iter`, `log/slog`

### 3. Run tests

```bash
# All tests
go test ./...

# Specific package
go test ./internal/policy/...

# Specific test
go test -v -run TestEvaluator ./internal/policy/...

# CLI integration tests (blackbox)
go test ./... -run TestBlackbox -count=1

# With race detection
go test -race ./...
```

### 4. Build and test manually

```bash
go build -o deputy .
./deputy scan
./deputy scan --format json | jq .
```

### 5. Submit a PR

- Clear description of what changed and why
- Link to any related issues
- Include test coverage for new functionality

## Code Organization

### Adding a New Command

1. Create `internal/cli/cmd/yourcommand.go`:

```go
package cmd

import (
    "github.com/spf13/cobra"
)

func newYourCommand() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "yourcommand",
        Short: "Brief description",
        Long:  `Longer description with examples.`,
        RunE: func(cmd *cobra.Command, args []string) error {
            // Implementation
            return nil
        },
    }

    // Add flags
    cmd.Flags().StringP("output", "o", "", "Output file")

    return cmd
}
```

2. Register in `internal/cli/cmd/register.go`:

```go
func RegisterCommands(root *cobra.Command) {
    // ... existing commands
    root.AddCommand(newYourCommand())
}
```

3. Add documentation in `docs/commands/yourcommand.md`

4. Update `docs/commands/README.md` with the new command

### Adding a Policy Entrypoint

1. Define the entrypoint in `internal/policy/entrypoints.go`:

```go
const (
    // ... existing entrypoints
    EntrypointYourFeature Entrypoint = "your_feature"
)
```

2. Add input bindings in `internal/policy/evaluator.go`

3. Document in the [policy framework](../reference/policy-framework.md):
   - Entry point name
   - Input shape (available variables)
   - Use cases

4. Add example policy in `policy/examples/`

5. Ensure `deputy policy lint` and `deputy policy test` work

### Adding Ecosystem Support

1. Create inventory extractor in `internal/inventory/`
2. Add proxy adapter in `internal/proxy/` (if applicable)
3. Register PURL type in `internal/purlx/`
4. Add tests with fixtures in `testdata/`
5. Document supported manifest files in FAQ

## Testing Guidelines

### Unit Tests

```go
func TestFeature(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {
            name:  "valid input",
            input: "test",
            want:  "expected",
        },
        {
            name:    "invalid input",
            input:   "",
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := Feature(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("Feature() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if got != tt.want {
                t.Errorf("Feature() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Integration Tests

The `blackbox_test.go` file contains CLI integration tests:

```bash
go test ./... -run TestBlackbox -count=1 -v
```

### Policy Tests

```bash
# Test all policies
deputy policy test ./policy

# Lint policies
deputy policy lint policy/*.yaml
```

## Documentation Guidelines

- Keep pages **short and skimmable**
- Use **Mermaid diagrams** for workflows and architecture
- Link to code where it clarifies implementation
- Prefer examples over long explanations
- Avoid decoration-only emoji
- Update relevant docs when changing behavior

### Documentation Structure

```
docs/
  README.md           # Entry point, overview
  getting-started.md  # Installation, first run
  cheatsheet.md       # Quick reference
  faq.md              # Common questions
  glossary.md         # Term definitions
  commands/           # One file per command
  concepts/           # Mental models
  guides/             # How-to guides
  examples/           # Workflows, transcripts
  reference/          # Config, logging, env vars
  development/        # This section
```

## Pull Request Checklist

- [ ] Tests pass (`go test ./...`)
- [ ] Code formatted (`go fmt ./...`)
- [ ] No new linter warnings
- [ ] Documentation updated (if behavior changed)
- [ ] CHANGELOG entry (if user-facing change)
- [ ] Commit messages are clear and descriptive

## Common Tasks

### Updating dependencies

```bash
go get -u ./...
go mod tidy
go test ./...
```

### Running the full test suite

```bash
# Quick test
go test ./...

# Full suite with race detection
go test -race -count=1 ./...

# Including integration tests
go test -tags=integration ./...
```

### Debugging

```bash
# Verbose logging
DEPUTY_LOG_LEVEL=debug ./deputy scan

# With delve
dlv debug . -- scan
```

## Getting Help

- Check existing issues before opening new ones
- Include reproduction steps for bugs
- For questions, consider opening a discussion first

## See Also

- [Architecture](architecture.md) - System design overview
- [Documentation Style](docs-style.md) - Writing guidelines
