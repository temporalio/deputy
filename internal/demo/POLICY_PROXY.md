# Using the Shai-Hulud IOC Policy with Deputy

This guide shows how to run Deputy with the Shai-Hulud `npm` IOC policy, both for static scanning and for blocking live installs via the Deputy proxy.

## Prereqs
- Go toolchain installed (for building/running `deputy`).
- Network egress to NPM and GitHub (for proxy upstream).
- Optional: `GITHUB_TOKEN` set if you scan private repos or want higher GitHub API limits.

## Files you need

Policy: `policy/examples/shai-hulud-npm.yaml` (already in the tree).

## A. Block installs via the Deputy proxy (quick, one-shot)

Wrap a single `npm` command with a temporary proxy that enforces the policy.

```bash
deputy proxy npm --policy policy/examples/shai-hulud-npm.yaml -- \
  npm install @actbase/react-absolute@0.8.3
```

> [!WARNING]
> **Don't actually run that exact command**; `0.8.3` is an IOC version. It's just an example to see the blocking in action.

What happens:
- Starts a local npm proxy on a random localhost port.
- Sets `NPM_CONFIG_REGISTRY` (and `YARN_REGISTRY`) for the child process.
- Enforces the Shai-Hulud policy. IOC versions are denied with HTTP 403.

## B. Run a long-lived npm proxy with the policy

1) Create a config (example `proxy-npm.yaml`):
```yaml
listeners:
  - name: npm-proxy
    bind: ":8082"
    ecosystems: ["npm"]
    upstream: "https://registry.npmjs.org"
    policies:
      - policy/examples/shai-hulud-npm.yaml
```

2) Start the proxy:
```bash
deputy proxy serve --config proxy-npm.yaml
```

3) Point npm/yarn at the proxy (shell scoped):
```bash
export NPM_CONFIG_REGISTRY=http://localhost:8082
export YARN_REGISTRY=http://localhost:8082
```

4) Install as usual; IOC matches are blocked with 403 and a clear reason.

To stop the server, press <kbd>Ctrl</kbd>+<kbd>C</kbd>. To stack policies, add multiple paths under `policies:` in your config or pass multiple `--policy` flags to `deputy proxy serve`.

Example (CLI):
```bash
deputy proxy serve --config proxy-npm.yaml --policy policy/a.yaml --policy policy/b.yaml
```

Example (config):
```yaml
policies:
  - policy/a.yaml
  - policy/b.yaml
```

## Notes

- The policy normalizes versions by stripping leading `=` or `v` and compares exact versions only.
- Scope is npm-only (`request.ecosystem == "npm"`).
- Keep the IOC list fresh by regenerating `policy/examples/shai-hulud-npm.yaml` from the Wiz CSV when they update it.
