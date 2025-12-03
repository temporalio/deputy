package lsp

import "github.com/sourcegraph/go-lsp"

// initializeResultWithServerInfo adds server name/version to the InitializeResult
// using the legacy go-lsp type by embedding in the Result. VSCode/Neovim will
// ignore unknown fields, so we append a minimal ServerInfo struct inline.
type initializeResultWithServerInfo struct {
	lsp.InitializeResult
	ServerInfo serverInfo `json:"serverInfo,omitempty"`
}

type serverInfo struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}
