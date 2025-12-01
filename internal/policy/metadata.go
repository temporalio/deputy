package policy

import "strings"

type policyMetadata struct {
    Name        string
    Entrypoints []string
    Commands    []string
    Ecosystems  []string
    Mode        string
}

// parsePolicyMetadata reads leading `//! key = value` comments from a CEL source body.
func parsePolicyMetadata(body string) policyMetadata {
	var meta policyMetadata
	for _, line := range strings.Split(body, "\n") {
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

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
