# Historical vulnerability analysis

Deputy supports “time-window” and “as-of” views so you can ask:

- “What was known at the time?” (avoid retroactive bias)
- “When did a vulnerability become known?”
- “What changed between two releases *given knowledge available then*?”

## `--as-of` (knowledge cutoff)

`--as-of` shows vulnerabilities known up to and including a specific date (it implies `--published-before`).

```console
$ deputy scan --as-of=2024-12-31
$ deputy scan --as-of=2023 --ignore-unfixed
$ deputy diff v1.0.0 v2.0.0 --as-of=2022-12-31
```

## Published date filters (time window)

Filter by when vulnerabilities were published:

```console
$ deputy scan --published-after=2025
$ deputy scan --published-after=2025-02 --published-before=2025-03
$ deputy diff main WORKING --published-after=2025-10-01 --published-before=2025-12-01
```

## Practical uses

- Post-incident reviews (“what did we know when we shipped?”)
- Release auditing (“what changed since v1.2.0?”)
- Trend analysis (“what’s the cadence of newly published issues for our dependency set?”)

See also:
- `docs/commands/scan.md`
- `docs/commands/diff.md`

