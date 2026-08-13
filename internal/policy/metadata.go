package policy

import (
	"fmt"
	"strings"
)

// Mode constants are the execution modes a policy may declare.
const (
	// ModeEnforce lets deny actions deny. It is the default when mode is unset.
	ModeEnforce = "enforce"

	// ModeAdvisory downgrades the policy's deny actions to warnings.
	ModeAdvisory = "advisory"
)

// Modes returns the execution modes a policy may declare, in the order used by
// error messages. The slice is freshly allocated so callers cannot mutate the
// vocabulary.
func Modes() []string {
	return []string{ModeAdvisory, ModeEnforce}
}

// NormalizeMode folds an authored mode into its canonical form by trimming and
// lowercasing, matching the case-insensitive comparison the engine does when it
// decides whether to downgrade denials.
func NormalizeMode(mode string) string {
	return strings.ToLower(strings.TrimSpace(mode))
}

// ValidateMode returns the canonical form of an authored mode, or an error
// naming the offending value and the valid vocabulary. An unrecognized mode is
// rejected rather than treated as enforce, because "advsiory" silently
// enforcing is the opposite of what the author asked for.
func ValidateMode(mode string) (string, error) {
	normalized := NormalizeMode(mode)
	switch normalized {
	case ModeAdvisory, ModeEnforce:
		return normalized, nil
	default:
		return "", fmt.Errorf("invalid mode %q (expected %s)", mode, strings.Join(Modes(), "|"))
	}
}

type policyMetadata struct {
	Name        string   // Name is the policy name extracted from metadata.
	Entrypoints []string // Entrypoints lists the entrypoints this policy applies to.
	Commands    []string // Commands lists the commands this policy applies to.
	Ecosystems  []string // Ecosystems lists the ecosystems this policy applies to.
	Mode        string   // Mode is the execution mode the source declares, validated when it is loaded (see declaredMode).
}

// parsePolicyMetadata reads leading `//! key = value` comments from a CEL source body.
func parsePolicyMetadata(body string) policyMetadata {
	var meta policyMetadata
	for line := range strings.SplitSeq(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, "//!") {
			break
		}
		kv := strings.TrimSpace(strings.TrimPrefix(trimmed, "//!"))
		if kv == "" {
			continue
		}
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
		switch key {
		case "policy.name":
			meta.Name = val
		case "policy.entrypoints":
			meta.Entrypoints = splitCSV(val)
		case "policy.commands":
			meta.Commands = splitCSV(val)
		case "policy.ecosystems":
			meta.Ecosystems = splitCSV(val)
		case "policy.mode":
			meta.Mode = strings.ToLower(val)
		}
	}
	return meta
}

// splitCSV splits a comma-separated string into a slice of strings, trimming whitespace and ignoring empty elements.
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
