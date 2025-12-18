# Troubleshooting

## “No vulnerabilities found” vs “OSV unreachable”

- Deputy requires network access for OSV queries.
- If OSV lookups fail, Deputy reports warnings and continues where possible (for example, SBOM generation).

Try:

```console
$ deputy scan --log-level debug
```

## Git ref errors

- Quote refs that contain `@{...}` to avoid shell expansion:
  `deputy diff "HEAD@{yesterday}" HEAD`
- Use `--ref WORKING` when you want uncommitted changes included explicitly.

## Rate limits / enrichment failures

If you use license enrichment or GitHub-backed metadata lookups, setting a token can improve reliability:

- `GITHUB_TOKEN`

## Proxy enforcement surprises

Start in advisory mode (log-only) until policies are stable:

- See `docs/guides/proxy-rollout.md`
- Validate policies with `deputy policy lint` / `deputy policy test`

