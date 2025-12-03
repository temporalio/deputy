# Deputy Policy Language Server

The language server helps author Deputy policy bundles (YAML + CEL) with diagnostics, completions, and hovers. It speaks the Language Server Protocol (LSP) so any compatible editor can connect.

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
- Completions: common keys, `action`/`mode`, CEL identifiers (`request`, `pkg`, `env.*`, etc.), helper functions (`levenshtein`, `levenshteinWithin`, macros like `exists`, `map`, `filter`, regex/string helpers).
- Hovers: reminders for keys plus CEL helper signatures and variable descriptions.

Future improvements: deeper CEL context-aware completions (e.g., after `vulnerabilities[0].`), richer quick-fixes, formatting.

### CEL helper catalog (shipped today)

| Name | Signature | Note |
| --- | --- | --- |
| `levenshtein` | `levenshtein(string, string) int` | Distance (capped at 128 chars). |
| `levenshteinWithin` | `levenshteinWithin(string, string, int) bool` | True if distance within limit. |
| `exists` | `list.exists(var, predicate)` | CEL macro: any element matches. |
| `map` | `list.map(var, expr)` | CEL macro: transform list. |
| `filter` | `list.filter(var, predicate)` | CEL macro: filter list. |
| `matches` | `string.matches(pattern)` | Regex match (ext.Regex). |
| `join` | `list.join(sep)` | Join list elements (ext.Strings). |
| `lowerAscii` | `string.lowerAscii()` | Lowercase ASCII (ext.Strings). |
| `upperAscii` | `string.upperAscii()` | Uppercase ASCII (ext.Strings). |

Standard policy identifiers available in `when` expressions: `request`, `pkg`, `vulnerabilities`, `vulnerability`, `changes`, `packages`, `sbom`, `config`, `env`, `dependency`, `plan`, `step`, `repo`, `cluster`, `component`, `findings`, `change`.

## Troubleshooting

- Run with `--log-level debug` to see inbound requests.
- If diagnostics do not appear, ensure the editor sends full `textDocument/didOpen` + `didChange` with whole-file text (server expects full sync).
- TCP mode: confirm your editor points to the listening address printed on startup.
