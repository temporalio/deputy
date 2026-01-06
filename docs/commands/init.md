# `deputy init`

Initialize Deputy configuration and policies in a project directory.

## Synopsis

```
deputy init [directory] [flags]
```

## Description

Creates starter files to help you get started with Deputy:

- `.deputy.yaml` — Configuration file with documented options
- `policy/deputy.yaml` — Starter policy with common security rules

The generated files include extensive comments explaining each option, making it easy to customize for your project's needs.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--force`, `-f` | `false` | Overwrite existing files |
| `--config-only` | `false` | Only generate the configuration file |
| `--policy-only` | `false` | Only generate the policy file |

## Examples

```bash
# Initialize in current directory
deputy init

# Initialize in a specific directory
deputy init ./my-project

# Only generate config file (no policy)
deputy init --config-only

# Only generate policy file (no config)
deputy init --policy-only

# Overwrite existing files
deputy init --force
```

## Generated Files

### `.deputy.yaml`

The configuration file controls Deputy's runtime behavior:

```yaml
# Deputy Configuration
logging:
  level: info      # debug, info, warn, error
  format: text     # text, json

scan:
  # ecosystems:    # Limit to specific ecosystems
  #   - go
  #   - npm

policy:
  mode: enforce    # enforce (exit 1) or advisory (warn only)
```

See [Configuration Reference](../reference/configuration.md) for all options.

### `policy/deputy.yaml`

The starter policy includes common security rules:

- **block-critical-high** — Deny critical and high severity vulnerabilities
- **warn-medium** — Warn on medium severity (doesn't fail builds)
- **block-kev** — Block actively exploited vulnerabilities (requires `--enrich`)
- **block-high-epss** — Block high exploitation probability (requires `--enrich`)

The policy file also includes commented examples for:
- License allowlists
- Package blocklists

See [Policy Cookbook](../guides/policy-cookbook.md) for more examples.

## Workflow

After running `deputy init`:

```bash
# 1. Scan for vulnerabilities
deputy scan

# 2. Edit policy to match your requirements
$EDITOR policy/deputy.yaml

# 3. Scan with policy enforcement
deputy scan --policy policy/

# 4. Add to CI/CD
# See: docs/guides/ci.md
```

## Behavior

- **Non-destructive by default** — Existing files are skipped unless `--force` is used
- **Creates directories** — The target directory and `policy/` subdirectory are created if needed
- **Atomic** — Either all files are created successfully, or the command fails

## See Also

- [Configuration Reference](../reference/configuration.md)
- [Policy Framework](../reference/policy-framework.md)
- [CI/CD Integration](../guides/ci.md)
- [`deputy config`](config.md)
