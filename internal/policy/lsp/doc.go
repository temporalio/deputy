// Package lsp implements a lightweight Language Server Protocol (LSP) server
// for Deputy policy bundles. It focuses on YAML+C~E~L authoring ergonomics:
// diagnostics, completions, hovers, and symbols that mirror the policy runtime.
// The server is started via `deputy policy lsp` and speaks stdio or TCP so
// editors like VS Code, Neovim, or Helix can connect without custom plugins.
package lsp
