# `deputy config`

Manage Deputy configuration files and settings.

## Synopsis

```
deputy config <subcommand> [flags]
deputy config validate [config-file]
deputy config show [--format yaml|json]
deputy config path
```

## Description

The config command helps you work with Deputy configuration:

- **validate** — Check a config file for syntax and semantic errors
- **show** — Display the effective configuration after merging all sources
- **path** — Show which config file Deputy will use

## Configuration Precedence

Deputy merges configuration from multiple sources in this order (later sources override earlier):

1. Built-in defaults
2. Config file (if found)
3. Environment variables
4. CLI flags

## Config File Locations

Deputy searches for configuration files in this order:

1. `$DEPUTY_CONFIG` environment variable (explicit path)
2. `.deputy.yaml` or `.deputy.yml` in current directory
3. `deputy.yaml` or `deputy.yml` in current directory
4. `.deputy.yaml` in home directory

## Subcommands

### `config validate`

Validate a configuration file for errors.

```bash
# Validate explicit file
deputy config validate .deputy.yaml

# Validate auto-discovered config
deputy config validate
```

**Checks performed:**
- YAML syntax validation
- Field type validation
- Value range validation (e.g., valid log levels)
- Unknown field detection

### `config show`

Display the effective configuration after merging all sources.

```bash
# Show as YAML (default)
deputy config show

# Show as JSON
deputy config show --format json

# Extract specific values with jq
deputy config show --format json | jq '.logging.level'
```

| Flag | Default | Description |
|------|---------|-------------|
| `--format`, `-f` | `yaml` | Output format: `yaml` or `json` |

### `config path`

Show which configuration file Deputy will use.

```bash
deputy config path
```

If no config file is found, shows the locations that were searched.

## Examples

### Debugging Configuration

```bash
# Find which config file is active
deputy config path

# Show effective configuration
deputy config show

# Validate before deploying
deputy config validate .deputy.yaml && echo "Config OK"
```

### CI/CD Validation

```bash
# Validate config in CI pipeline
deputy config validate .deputy.yaml
if [ $? -ne 0 ]; then
  echo "Invalid Deputy configuration"
  exit 1
fi
```

### JSON Processing

```bash
# Check log level
deputy config show --format json | jq -r '.logging.level'

# Check if caching is disabled
deputy config show --format json | jq '.performance.cache.disabled'
```

## See Also

- [Configuration Reference](../reference/configuration.md)
- [`deputy init`](init.md) — Generate starter configuration
