package lsp

import protocol "github.com/sourcegraph/go-lsp"

// CodeAction is a minimal LSP code action shape with edits. go-lsp does not
// expose CodeAction directly, so we define the subset we need for quick-fixes.
// Keeping this here lets us return structured edits (not just commands) while
// staying compatible with clients that expect standard LSP wire format.
type CodeAction struct {
	Title       string                `json:"title"`
	Kind        string                `json:"kind,omitempty"`
	Edit        *WorkspaceEdit        `json:"edit,omitempty"`
	Command     *protocol.Command     `json:"command,omitempty"`
	IsPreferred bool                  `json:"isPreferred,omitempty"`
	Diagnostics []protocol.Diagnostic `json:"diagnostics,omitempty"`
}

// WorkspaceEdit mirrors the LSP type for text edits.
type WorkspaceEdit struct {
	Changes map[protocol.DocumentURI][]TextEdit `json:"changes,omitempty"`
}

// TextEdit is an insertion/replacement in a document.
type TextEdit struct {
	Range   protocol.Range `json:"range"`
	NewText string         `json:"newText"`
}
