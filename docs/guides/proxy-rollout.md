# Proxy Rollout Guide

A phased approach to introducing `deputy proxy` into your organization.

## Why a phased rollout?

Rolling out a policy-enforcing proxy all at once can disrupt development. A phased approach lets you:
- Discover policy gaps before they block developers
- Build confidence in your rules
- Gather feedback and iterate

## Phase 1: Observe (Advisory Mode)

**Goal**: See what *would* be blocked without actually blocking.

```yaml
# proxy.yaml
listeners:
  - name: go-corp
    bind: ":8080"
    ecosystems: ["go"]
    upstream: https://proxy.golang.org
    policies:
      - bundle: policy/corp.bundle.json
        mode: advisory  # Log warnings, don't block
```

```console
# Generate a starter config
$ deputy proxy template --ecosystem go > proxy.yaml

# Start the proxy
$ deputy proxy serve --config proxy.yaml

# Point Go at it
$ export GOPROXY=http://localhost:8080
$ go build ./...
```

**What to watch for**:
- Review logs for warnings that would have blocked
- Identify false positives (legitimate packages flagged incorrectly)
- Refine policies based on real traffic

**Duration**: 1-2 weeks depending on traffic volume.

## Phase 2: Enforce in CI/Build

**Goal**: Start blocking in controlled environments where failures are recoverable.

```yaml
policies:
  - bundle: policy/corp.bundle.json
    mode: enforce  # Now blocking
```

Update CI configurations to route through the proxy:

```yaml
# GitHub Actions example
env:
  GOPROXY: http://proxy.internal:8080
  npm_config_registry: http://proxy.internal:8081
```

**What to watch for**:
- Build failures due to blocked packages
- Developer feedback on blocked dependencies
- Policy exceptions that need to be added

**Duration**: 2-4 weeks, until builds are stable.

## Phase 3: Enforce on Developer Machines

**Goal**: Extend protection to local development.

Options for rolling out to developers:
1. **Documentation**: Publish setup instructions
2. **Wrapper scripts**: Provide `deputy proxy go -- go build` aliases
3. **Corporate tooling**: Push environment variables via MDM/config management

```console
# Developers can use wrapper mode for easy adoption
$ deputy proxy go -- go get github.com/example/pkg@latest
```

**What to watch for**:
- Developer friction and support requests
- Network/latency issues
- Edge cases not covered by CI testing

## Monitoring and Maintenance

### Metrics to track

- `deputy_proxy_requests_total`: Total requests by ecosystem
- `deputy_proxy_policy_decisions`: Allow/warn/deny counts
- `deputy_proxy_latency_ms`: Request latency (watch for spikes)

### Ongoing tasks

- **Review warnings weekly**: Advisory-mode policies may surface new concerns
- **Update policies with releases**: New CVEs may require policy updates
- **Rotate credentials**: If using authenticated upstreams, rotate regularly

## Rollback plan

If issues arise, you can quickly revert:

1. **Switch to advisory mode**: Change `mode: enforce` → `mode: advisory`
2. **Bypass the proxy**: Remove `GOPROXY`/`npm_config_registry` environment variables
3. **Fall back to direct upstream**: Developers can temporarily use public registries

## Checklist

- [ ] Create initial policy bundle (`deputy policy bundle`)
- [ ] Lint policies (`deputy policy lint`)
- [ ] Test policies (`deputy policy test`)
- [ ] Deploy proxy in advisory mode
- [ ] Monitor for 1-2 weeks
- [ ] Switch to enforce mode in CI
- [ ] Monitor for 2-4 weeks
- [ ] Roll out to developer machines
- [ ] Document escalation/exception process

## Related

- Proxy design: [`PROXY.md`](../../PROXY.md)
- Policy framework: [`POLICY.md`](../../POLICY.md)
- Troubleshooting: [`troubleshooting.md`](troubleshooting.md)
