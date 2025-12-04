package lsp

import (
	"strings"

	protocol "github.com/sourcegraph/go-lsp"
)

// buildCodeActions returns quick-fix style actions with inline text edits when possible.
// The server replies with []any so clients can handle either CodeAction or Command.
// docText is used to propose context-aware replacements for undeclared identifiers.
func buildCodeActions(params protocol.CodeActionParams, docText string) []any {
	var out []any
	for _, d := range params.Context.Diagnostics {
		code := d.Code
		switch code {
		case "missing-reason":
			out = append(out, codeActionInsert(params.TextDocument.URI, d.Range.End, " reason: \"\"\n", "quickfix", d))
		case "missing-action":
			out = append(out, codeActionInsert(params.TextDocument.URI, d.Range.Start, "action: allow\n", "quickfix", d))
		case "missing-when":
			out = append(out, codeActionInsert(params.TextDocument.URI, d.Range.Start, "when: true\n", "quickfix", d))
		case "undeclared":
			if sugg := undeclaredReplacement(params.TextDocument.URI, d, docText); sugg != nil {
				out = append(out, *sugg)
			}
		}
	}
	return out
}

// codeActionInsert creates a CodeAction that inserts text at a specific position.
// It packages the edit as a WorkspaceEdit and includes a fallback command.
func codeActionInsert(uri protocol.DocumentURI, pos protocol.Position, text string, kind string, diag protocol.Diagnostic) CodeAction {
	edit := TextEdit{Range: protocol.Range{Start: pos, End: pos}, NewText: text}
	return CodeAction{
		Title:       "Apply quick-fix",
		Kind:        kind,
		IsPreferred: true,
		Diagnostics: []protocol.Diagnostic{diag},
		Edit: &WorkspaceEdit{Changes: map[protocol.DocumentURI][]TextEdit{
			uri: {edit},
		}},
		Command: &protocol.Command{
			Title:   "Insert quick-fix",
			Command: "deputy.policy.applyEdit",
		},
	}
}

// minInt returns the smallest integer from the provided list.
func minInt(a ...int) int {
	if len(a) == 0 {
		return 0
	}
	m := a[0]
	for _, v := range a[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

// undeclaredReplacement proposes a replacement for undeclared identifiers by fuzzy matching
// against known CEL variables. Uses document text for context to include select chains and
// prefers bases that match the chain suffix (e.g., requestx.client -> request.client).
func undeclaredReplacement(uri protocol.DocumentURI, d protocol.Diagnostic, docText string) *CodeAction {
	name := extractUndeclaredName(d.Message)
	if name == "" {
		return nil
	}
	_, token := tokenAtRange(docText, d.Range)
	if token == "" {
		token = name
	}
	base := token
	suffix := ""
	if idx := strings.Index(token, "."); idx >= 0 {
		base = token[:idx]
		suffix = token[idx:]
	}
	best := ""
	bestDist := 3 // allow small Levenshtein distance
	for _, v := range celVariables {
		dist := levenshteinDistance(base, v)
		// prefer matching chain suffix context
		if suffix != "" && strings.HasPrefix(suffix, ".") {
			if strings.HasPrefix(suffix, ".client") && v == "request" {
				dist-- // bias toward request for client chain
			}
		}
		if dist < bestDist {
			bestDist = dist
			best = v
		}
	}
	if best == "" {
		return nil
	}
	replacement := best + suffix
	edit := TextEdit{Range: d.Range, NewText: replacement}
	title := "Replace with " + replacement
	return &CodeAction{
		Title:       title,
		Kind:        "quickfix",
		IsPreferred: true,
		Diagnostics: []protocol.Diagnostic{d},
		Edit: &WorkspaceEdit{Changes: map[protocol.DocumentURI][]TextEdit{
			uri: {edit},
		}},
	}
}

// extractUndeclaredName parses the variable name from a CEL "undeclared reference" error message.
func extractUndeclaredName(msg string) string {
	const needle = "undeclared reference to '"
	idx := strings.Index(msg, needle)
	if idx < 0 {
		return ""
	}
	start := idx + len(needle)
	end := strings.Index(msg[start:], "'")
	if end < 0 {
		return ""
	}
	return msg[start : start+end]
}

// levenshteinDistance is a tiny helper for short strings (policy vars are short).
func levenshteinDistance(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	if la > lb {
		a, b = b, a
		la, lb = lb, la
	}
	prev := make([]int, la+1)
	for i := 0; i <= la; i++ {
		prev[i] = i
	}
	for j := 1; j <= lb; j++ {
		curr := make([]int, la+1)
		curr[0] = j
		for i := 1; i <= la; i++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			curr[i] = minInt(prev[i]+1, curr[i-1]+1, prev[i-1]+cost)
		}
		prev = curr
	}
	return prev[la]
}

// tokenAtRange extracts the token at the diagnostic range from the document text.
func tokenAtRange(doc string, r protocol.Range) (line string, token string) {
	if doc == "" {
		return "", ""
	}
	lines := strings.Split(doc, "\n")
	if int(r.Start.Line) >= len(lines) {
		return "", ""
	}
	line = lines[r.Start.Line]
	if int(r.Start.Character) > len(line) {
		return line, ""
	}
	// Extend backwards to start of token
	start := int(r.Start.Character)
	for start > 0 && isIdentChar(rune(line[start-1])) {
		start--
	}
	end := start
	for end < len(line) && isIdentChar(rune(line[end])) {
		end++
	}
	// Include trailing select chain
	for end < len(line) && line[end] == '.' {
		end++
		for end < len(line) && isIdentChar(rune(line[end])) {
			end++
		}
	}
	if start >= end {
		return line, ""
	}
	return line, line[start:end]
}

// isIdentChar checks if a rune is a valid identifier character (alphanumeric or underscore).
func isIdentChar(r rune) bool {
	return r == '_' || ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9')
}
