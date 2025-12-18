# Proxy rollout checklist

Use this when you want to introduce `deputy proxy` into a team or organization.

## Recommended rollout phases

1) **Observe (advisory)**: log warnings but do not block.  
2) **Enforce on CI/build**: start blocking in controlled environments.  
3) **Enforce on dev machines**: expand to laptops once policies are stable.

## Practical steps

- Start from a template: `deputy proxy template > proxy.yaml`
- Keep policies in version control (treat them like code).
- Use `mode: advisory` first, then switch to `enforce`.
- Make policies actionable: include reasons and remediation suggestions.

## Deep dive

- [`PROXY.md`](../../PROXY.md)
- [`POLICY.md`](../../POLICY.md)
