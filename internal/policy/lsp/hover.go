package lsp

import (
	"fmt"
	"strings"

	"github.com/picatz/deputy/internal/policy"
)

// hoverForLine returns hover text for YAML keys or CEL tokens on the line.
func hoverForLine(line string) string {
	line = strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(line, "action"):
		return "_action_: allow | warn | deny. Determines whether the operation is blocked."
	case strings.HasPrefix(line, "when"):
		return "_when_: CEL boolean expression. Identifiers: " + strings.Join(policy.DefaultVariableNames(), ", ")
	case strings.HasPrefix(line, "entrypoints"):
		return "Limit policy to Deputy entrypoints (e.g., scan_vulnerability, go_artifact_request)."
	case strings.HasPrefix(line, "commands"):
		return "Limit policy to commands (proxy, scan, diff, sbom, fix, triage)."
	case strings.HasPrefix(line, "mode"):
		return "`mode: advisory` downgrades deny -> warn for safe rollout; `enforce` is default."
	case strings.HasPrefix(line, "vars"):
		return "Ordered variable definitions expanded before rules; later vars can reference earlier ones."
	default:
		// attempt CEL token hover if this looks like a when-line
		if strings.Contains(line, "when:") {
			expr := strings.TrimSpace(strings.TrimPrefix(line, "when:"))
			if h := celHover(expr); h != "" {
				return h
			}
		}
		return ""
	}
}

// celHover returns richer hover info for functions and variables inside CEL expressions.
func celHover(exprLine string) string {
	token := firstToken(exprLine)
	if token == "" {
		return ""
	}
	for _, v := range policy.DefaultVariableNames() {
		if token == v {
			return fmt.Sprintf("`%s` — standard policy variable available in CEL", v)
		}
	}
	for _, fn := range celFunctionCatalog() {
		if token == fn.Name {
			return fmt.Sprintf("%s\n%s", fn.Signature, fn.Doc)
		}
	}
	return ""
}

func firstToken(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	token := strings.TrimLeft(fields[0], "(!")
	// Trim trailing punctuation after identifier (e.g., "levenshtein(")
	for i, r := range token {
		if !(r == '_' || r == '.' || r == '$' || ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z')) {
			return token[:i]
		}
	}
	return token
}
