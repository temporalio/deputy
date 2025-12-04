// Package lsp implements a lightweight, high-performance Language Server Protocol (LSP)
// server tailored for Deputy policy bundles. It provides a rich editing experience
// for YAML+CEL policy authoring, including real-time diagnostics, intelligent
// completions, hover documentation, and symbol navigation.
//
// The server is designed to be editor-agnostic, communicating via standard stdio
// or TCP streams, making it compatible with VS Code, Neovim, Helix, and other
// LSP-capable editors without requiring heavy, custom plugins.
//
// Key features include:
//   - Diagnostics: Instant feedback on policy syntax and logic errors.
//   - Completions: Context-aware suggestions for CEL expressions and YAML fields.
//   - Hovers: Detailed documentation for policy fields and functions.
//   - Symbols: Quick navigation to policy definitions and rules.
package lsp
