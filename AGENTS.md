# AGENTS.md

Deputy is designed to run in a variety of environments, including local developer machines, CI systems, and isolated agent containers. This document provides an overview of the agent architecture, workflows, and key considerations for contributing to or modifying agent-related functionality.

## Start here (docs map)

- Project overview + doc index: [`docs/README.md`](docs/README.md)
- Command reference: [`docs/commands/README.md`](docs/commands/README.md)
- Concepts (targets, policies, remediation): [`docs/concepts/README.md`](docs/concepts/README.md)
- Guides (CI, agents, plugins): [`docs/guides/README.md`](docs/guides/README.md)
- Reference (config, env vars, logging): [`docs/reference/README.md`](docs/reference/README.md)
- Development guides: [`docs/development/README.md`](docs/development/README.md)

## Repo map (high-level)

- Entry points: [`main.go`](main.go) -> [`internal/cli/cli.go`](internal/cli/cli.go) -> [`internal/cli/cmd/root.go`](internal/cli/cmd/root.go)
- CLI commands: [`internal/cli/cmd/`](internal/cli/cmd/)
- Core packages: [`internal/inventory`](internal/inventory), [`internal/analysis`](internal/analysis), [`internal/remediation`](internal/remediation), [`internal/policy`](internal/policy), [`internal/sbom`](internal/sbom), [`internal/proxy`](internal/proxy), [`internal/gitutil`](internal/gitutil)
- Services layer: [`internal/services`](internal/services) (clients/transport), server handlers in [`internal/server`](internal/server)
- Targets: [`internal/targets/detect.go`](internal/targets/detect.go)
- Policies + examples: [`policy/examples`](policy/examples)

## Foundations and extensions

- Inventory/SCA is built on [OSV-SCALIBR](https://github.com/google/osv-scalibr); Deputy extends it with additional extractors, plugins, and policy-aware workflows. Secrets scanning is implemented in Deputy’s own engine under [`internal/secrets`](internal/secrets).
- SBOM generation uses [Protobom](https://github.com/protobom/protobom) with CycloneDX/SPDX output in [`internal/sbom`](internal/sbom).

## Security-critical invariants

- Remote server mode must not access local filesystem or execute code. Use `ValidateRemoteTarget()` for target validation and guard any code execution with `localMode` checks. See [`internal/targets/detect.go`](internal/targets/detect.go) and [`internal/services/services.go`](internal/services/services.go).
- When adding new handlers:
  - Read-only network operations are OK remotely (generally safe, but SSRF risks should be considered).
  - Any filesystem access or code execution must be blocked unless `localMode=true`.
- Target detection is layered: the CLI does richer filesystem-aware detection; shared detection in `internal/targets` is pure pattern matching for RPC routing.

## Deployment + scale

- Deputy is designed to run anywhere: local CLI/in-process, local daemon, or remote shared service/SaaS with authn/authz and policy enforcement. See [`docs/reference/README.md`](docs/reference/README.md) and [`docs/commands/server.md`](docs/commands/server.md).
- Cloud-native + CI/CD use cases (including GitHub Actions) are first-class: [`docs/guides/github-actions.md`](docs/guides/github-actions.md).
- Extensibility is core: extractor plugins and sandbox plugins enable new ecosystems and runtimes without modifying core. See [`docs/guides/plugins.md`](docs/guides/plugins.md).

## Policy/CEL notes

- Policy inputs are proto messages; fields use `snake_case`. Keep variable names aligned with proto definitions. See [`docs/reference/policy-inputs.md`](docs/reference/policy-inputs.md) and [`api/deputy`](api/deputy).
- Use typed entrypoint constants (not string literals): [`internal/policy/entrypoints.go`](internal/policy/entrypoints.go).

## Proto / RPC / Observability

- Protos are the API boundary; generate code with Buf and keep proto changes paired with regenerated Go code. See [`api/deputy`](api/deputy), [`api/buf.gen.yaml`](api/buf.gen.yaml), and [`gen/`](gen/).
- **Proto-first is the project direction**: anything that crosses a surface boundary (CLI JSON output, API, MCP tools, plugin wire, LSP, future TUI) is defined in proto, the ubiquitous domain language, and everything else derives from it. A hand-written Go struct with JSON tags for cross-surface output is a smell; a hand-maintained copy of proto-derivable data (field lists, enums, descriptions) is a bug waiting to drift. Precedents to follow: one proto service with multiple bindings (`AdvisorySourceService`: in-process, pluginrpc, ConnectRPC), tooling derived from descriptors (`policy.VariableFieldCompletions` powers LSP completions), output contracts as proto (`deputy.triage.v1` is what `deputy triage --format json` marshals), and MCP tool contracts as proto (`deputy.mcp.v1`: every tool's input/output schema derives from the descriptors via `internal/mcp/protoschema`, requests are protovalidate-enforced, and the SDK validates outputs; keep new messages within the MCP client constraints, no `oneOf/anyOf/allOf` anywhere, enums enforced client-side). Known consolidation target: docs tables generated from proto comments (the embedded descriptor set in `internal/proto/descriptorset` retains source-info comments for this).
- ConnectRPC is the transport layer; keep handlers and clients consistent with ConnectRPC patterns in [`internal/services`](internal/services) and [`internal/server`](internal/server).
- OpenTelemetry is used for metrics/logs/traces; avoid ad-hoc instrumentation and wire new spans/metrics through the OTel helpers in [`internal/otel`](internal/otel).
- Preferred upstreams/tools: [Protovalidate](https://protovalidate.com/), [CEL](https://cel.dev/), [ConnectRPC](https://connectrpc.com/), [pluginrpc](https://github.com/pluginrpc), and [Buf CLI](https://buf.build/docs/cli/).

## Agent workflows

- Agent command usage and sandboxing: [`docs/guides/agents.md`](docs/guides/agents.md).
- If you change agent behavior, update the guide and CLI help output for the relevant command.

## Build, test, run (common)

```bash
# run all tests
go test ./...

# run a specific test
go test -v -run TestName ./internal/pkg/...

# build binary
go build -o deputy .

# quick local scan
./deputy scan
```

## Style and contribution basics

- Go formatting: `gofmt`/`goimports`.
- Prefer table-driven tests.
- Wrap errors with context: `fmt.Errorf("context: %w", err)`.
- Avoid emojis in CLI output, use strategically in docs/PRs.
- Keep code idiomatic and production-ready: validate inputs, respect `context` timeouts/cancellation, avoid panics, and prefer the standard library or well-established packages.
- Prefer modern Go APIs (`slices`, `maps`, `cmp`, `log/slog`) and avoid deprecated packages.
- Design for coherence and composability: keep features congruent across CLI/API/plugins, favor clear interfaces, and build from first principles with production-grade security and reliability.

## Docs + CLI update checklist

- New or changed CLI flags/output: update [`docs/commands/`](docs/commands/) and command help text.
- New configuration/env vars: update [`docs/reference/configuration.md`](docs/reference/configuration.md) and [`docs/reference/README.md`](docs/reference/README.md).
- New policy entrypoints/inputs: update [`docs/reference/policy-spec.md`](docs/reference/policy-spec.md) and [`docs/reference/policy-inputs.md`](docs/reference/policy-inputs.md).
- New ecosystems or inventory behavior: update [`docs/concepts`](docs/concepts) and [`docs/guides`](docs/guides).
- New agent flows: update [`docs/guides/agents.md`](docs/guides/agents.md).

## When you need more detail

This file is intentionally brief. Use the docs map above for deep dives, or jump to code via the repo map.
