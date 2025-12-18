# `deputy proxy`

Run a policy-enforcing proxy for package managers.

Deputy supports two primary modes:

- **Wrap a single command** (`deputy proxy <ecosystem> -- <tool> ...`)
- **Run a long-lived server** (`deputy proxy serve --config proxy.yaml`)

## When to use it

- You want “secure by default” dependency downloads (block before artifacts land).
- You want consistent enforcement across laptops, CI, and build systems.

## Common patterns

```console
# Wrap go
$ deputy proxy go -- go get github.com/example/pkg@latest

# Wrap npm
$ deputy proxy npm -- npm install

# Start from a template and serve
$ deputy proxy template > proxy.yaml
$ deputy proxy serve --config proxy.yaml
```

## Deep dive

The proxy has its own design document:

- [`PROXY.md`](../../PROXY.md)

## Code pointers

- CLI command: [`internal/cli/cmd/proxy.go`](../../internal/cli/cmd/proxy.go)
- Proxy runtime: [`internal/proxy`](../../internal/proxy)
