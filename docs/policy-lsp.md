# Deputy Policy Language Server

The language server helps author Deputy policy bundles (YAML + CEL) with diagnostics, completions, and hovers. It speaks the Language Server Protocol (LSP) so any compatible editor can connect.

See also:
- [Policy concepts](concepts/policies.md)
- [Policy command reference](commands/policy.md)

## Starting the server

```bash
# default: stdio
deputy policy lsp

# TCP (useful for editors that want a socket)
deputy policy lsp --tcp 127.0.0.1:4389

# verbose logs
deputy policy lsp --log-level debug
```

## VS Code setup

Use the built-in “Custom Language Server” (or a minimal `settings.json` entry) to run `deputy policy lsp` on YAML files in `policy/`.

```jsonc
{
  "files.associations": {
    "**/policy/**/*.yaml": "yaml"
  },
  "deputy.policy.lsp.server.command": "deputy",
  "deputy.policy.lsp.server.args": ["policy", "lsp", "--stdio"],
  "yaml.format.enable": true
}
```

Alternatively, configure a VS Code LSP client extension with:

- command: `deputy`
- args: `["policy", "lsp", "--stdio"]`
- document selector: `yaml` (optionally scoped to `policy/**`)

## Neovim (`nvim-lspconfig`)

```lua
local lspconfig = require("lspconfig")
lspconfig.deputy_policy_lsp = {
  default_config = {
    cmd = { "deputy", "policy", "lsp"},
    filetypes = { "yaml" },
    root_dir = function(fname) return vim.fn.getcwd() end,
  },
}
```

This also work, in `~/.config/nvim/init.lua`:

```lua
local function start_deputy()
  -- avoid starting twice in the same buffer
  for _, c in ipairs(vim.lsp.get_clients({ bufnr = 0 })) do
    if c.name == "deputy_policy" then
      return
    end
  end
  vim.lsp.start({
    name = "deputy_policy",
    cmd = { "/usr/local/bin/deputy", "policy", "lsp" }, -- adjust path if needed
    root_dir = vim.fs.root(0, { ".git", "policy" }) or vim.fn.getcwd(),
    filetypes = { "yaml" },
    single_file_support = true,
  })
end

vim.api.nvim_create_autocmd({ "BufReadPost", "BufNewFile" }, {
  pattern = { "*.yaml", "*.yml" },
  callback = start_deputy,
})
```

## Features (current MVP)

- YAML diagnostics: missing `policies`, non-list `rules`, duplicate policy names, invalid `entrypoints`/`commands`.
- CEL diagnostics: type/parse errors on `when` expressions.
- Completions: common keys, `action`/`mode`, CEL identifiers (`request`, `pkg`, `target`, `image`, `env.*`, etc.), helper functions (`levenshtein`, `levenshteinWithin`, `purl`, macros like `exists`, `map`, `filter`, regex/string helpers).
- Hovers: reminders for keys plus CEL helper signatures and variable descriptions.

Future improvements: deeper CEL context-aware completions (e.g., after `vulnerabilities[0].`), richer quick-fixes, formatting.

### CEL helper catalog (shipped today)

| Name | Signature | Note |
| --- | --- | --- |
| `levenshtein` | `levenshtein(string, string) int` | Distance (capped at 128 chars). |
| `levenshteinWithin` | `levenshteinWithin(string, string, int) bool` | True if distance within limit. |
| `now` | `now() timestamp` | Current time (custom helper). |
| `age` | `age(int|timestamp) duration` | Time since Unix seconds or timestamp. |
| `purl` | `purl(string) map` | Parse a Package URL into fields. |
| `timestamp` | `timestamp(int|string) timestamp` | CEL built-in: Unix seconds or RFC 3339. |
| `duration` | `duration(string) duration` | CEL built-in: parse duration strings. |
| `exists` | `list.exists(var, predicate)` | CEL macro: any element matches. |
| `map` | `list.map(var, expr)` | CEL macro: transform list. |
| `filter` | `list.filter(var, predicate)` | CEL macro: filter list. |
| `has` | `has(field)` | CEL macro: field presence check. |
| `matches` | `string.matches(pattern)` | Regex match (ext.Regex). |
| `join` | `list.join(sep)` | Join list elements (ext.Strings). |
| `lowerAscii` | `string.lowerAscii()` | Lowercase ASCII (ext.Strings). |
| `upperAscii` | `string.upperAscii()` | Uppercase ASCII (ext.Strings). |
| `split` | `string.split(sep)` | Split string into list (ext.Strings). |
| `trim` | `string.trim()` | Trim whitespace (ext.Strings). |
| `replace` | `string.replace(old, new)` | Replace occurrences (ext.Strings). |
| `cel.bind` | `cel.bind(var, init, expr)` | Local bindings (ext.Bindings). |
| `base64.encode` | `base64.encode(bytes)` | Base64 encode (ext.Encoders). |
| `base64.decode` | `base64.decode(string)` | Base64 decode (ext.Encoders). |
| `math.abs` | `math.abs(number)` | Absolute value (ext.Math). |
| `math.ceil` | `math.ceil(double)` | Round up (ext.Math). |
| `math.floor` | `math.floor(double)` | Round down (ext.Math). |
| `math.round` | `math.round(double)` | Round to nearest (ext.Math). |
| `math.greatest` | `math.greatest(a, b, ...)` | Maximum value (ext.Math). |
| `math.least` | `math.least(a, b, ...)` | Minimum value (ext.Math). |

This catalog is not exhaustive; it reflects helpers the LSP surfaces today. See the [policy framework CEL reference](reference/policy-framework.md#cel-language-reference) for full CEL language and extension links.

Standard policy identifiers available in `when` expressions: `request`, `pkg`, `target`, `image`, `vulnerabilities`, `vulnerability`, `changes`, `packages`, `sbom`, `config`, `env`, `dependency`, `plan`, `step`, `repo`, `cluster`, `component`, `findings`, `change`.

## Troubleshooting

- Run with `--log-level debug` to see inbound requests.
- If diagnostics do not appear, ensure the editor sends full `textDocument/didOpen` + `didChange` with whole-file text (server expects full sync).
- TCP mode: confirm your editor points to the listening address printed on startup.
