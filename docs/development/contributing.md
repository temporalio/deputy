# Contributing

## Local setup

```console
$ git clone https://github.com/picatz/deputy.git
$ cd deputy
$ go test ./...
```

## Adding or changing a command

- CLI wiring lives in [`internal/cli`](../../internal/cli) and [`internal/cli/cmd`](../../internal/cli/cmd).
- Keep command output pipeline-friendly (stable fields in JSON mode, clear exit behavior).
- Prefer adding examples to `docs/commands/*` rather than growing the root `README.md`.

## Adding a new policy entrypoint

- Document it in [`POLICY.md`](../../POLICY.md) (entry point name, input shape, intended use).
- Add a small example in `policy/examples` when possible.
- Ensure `deputy policy lint` and `deputy policy test` continue to work.

## Running targeted tests

```console
$ go test ./internal/...
$ go test ./... -run TestBlackbox -count=1
```
