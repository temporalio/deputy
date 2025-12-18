# Logging

Deputy supports two global logging controls that apply to all commands.

## Flags

- `--log-level {debug,info,warn,error}`
- `--log-format {text,json}`

## Environment variables

- `DEPUTY_LOG_LEVEL`
- `DEPUTY_LOG_FORMAT`

## Examples

```console
$ deputy scan --log-level debug
$ DEPUTY_LOG_FORMAT=json deputy diff --skip-vuln-scan
```

