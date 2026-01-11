package policy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// REMOVED: StructToMap and normalizeMapKeys
// Proto-first design: pass proto messages directly to CEL evaluation.
// CEL's native proto support provides type-safe field access with
// snake_case naming from proto definitions.

const bundleSchemaVersion = "policy.deputy.sh/v1alpha1"

// Source represents an individual CEL policy ready for evaluation.
type Source struct {
	Name string // Name is the identifier for the policy source.
	Body string // Body is the CEL source code.
}

// Bundle is the on-disk representation produced by `deputy policy bundle`.
type Bundle struct {
	SchemaVersion string         `json:"schemaVersion"`      // SchemaVersion is the bundle format version.
	Generated     string         `json:"generated"`          // Generated is the timestamp when the bundle was built.
	Policies      []BundlePolicy `json:"policies"`           // Policies is the list of compiled policies.
	Metadata      map[string]any `json:"metadata,omitempty"` // Metadata contains arbitrary bundle metadata.
}

// BundlePolicy contains the CEL program for a single entry in a bundle.
type BundlePolicy struct {
	Name   string `json:"name"`   // Name is the policy name.
	Source string `json:"source"` // Source is the compiled CEL source code.
}

// LoadSources reads a list of file paths and returns the flattened list of policy sources.
//
// Supported formats:
//   - Structured YAML bundle (policies: [...]) - recommended for authoring
//   - JSON bundle with schemaVersion field - for compiled/distributed bundles
//
// The function tries to parse each file in order of preference:
//  1. JSON bundle format (compiled bundles from `deputy policy bundle`)
//  2. Structured YAML format (human-authored policy files)
//
// If neither format matches, an error is returned with guidance on valid formats.
func LoadSources(paths []string) ([]Source, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no policy paths provided")
	}
	var sources []Source
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read policy %q: %w", path, err)
		}
		// Try JSON bundle format first (compiled bundles)
		if bundle, ok := tryParseBundle(data); ok {
			for _, p := range bundle.Policies {
				name := p.Name
				if name == "" {
					name = filepath.Base(path)
				}
				sources = append(sources, Source{
					Name: fmt.Sprintf("%s::%s", path, name),
					Body: p.Source,
				})
			}
			continue
		}
		// Try structured YAML format (human-authored policies)
		s, ok, err := tryParseStructuredBundle(data, path)
		if err != nil {
			return nil, err
		}
		if ok {
			sources = append(sources, s...)
			continue
		}
		// Neither format matched - provide helpful error
		return nil, fmt.Errorf("%s: unrecognized policy format; expected YAML with 'policies:' key or JSON bundle with 'schemaVersion' field", path)
	}
	return sources, nil
}

// BuildBundle compiles all provided policy sources and returns a bundle structure.
func BuildBundle(paths []string) (*Bundle, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no policy files supplied")
	}
	sources, err := LoadSources(paths)
	if err != nil {
		return nil, err
	}
	policies := make([]BundlePolicy, 0, len(sources))
	for _, src := range sources {
		if err := Compile(src.Body, nil); err != nil {
			return nil, fmt.Errorf("%s: %w", src.Name, err)
		}
		name := extractPolicyName(src.Body)
		if name == "" {
			name = filepath.Base(src.Name)
		}
		policies = append(policies, BundlePolicy{
			Name:   name,
			Source: src.Body,
		})
	}
	return &Bundle{
		SchemaVersion: bundleSchemaVersion,
		Generated:     time.Now().UTC().Format(time.RFC3339),
		Policies:      policies,
	}, nil
}

func tryParseBundle(data []byte) (*Bundle, bool) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, false
	}
	if b.SchemaVersion == "" || len(b.Policies) == 0 {
		return nil, false
	}
	return &b, true
}

func extractPolicyName(source string) string {
	scanner := bufio.NewScanner(strings.NewReader(source))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "//!") {
			if line == "" {
				continue
			}
			break
		}
		line = strings.TrimPrefix(line, "//!")
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "policy.name") {
			if idx := strings.Index(line, "="); idx >= 0 {
				value := strings.TrimSpace(line[idx+1:])
				value = strings.Trim(value, `"`)
				return value
			}
		}
	}
	return ""
}

// LoadBundle reads a compiled JSON bundle file from disk.
// For structured YAML policies, use LoadSources instead.
func LoadBundle(path string) (*Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	bundle, ok := tryParseBundle(data)
	if !ok {
		return nil, fmt.Errorf("%s: not a valid JSON bundle (expected 'schemaVersion' field and 'policies' array)", path)
	}
	return bundle, nil
}

// ParseBundle attempts to parse the provided bytes as a policy bundle.
func ParseBundle(data []byte) (*Bundle, bool) {
	return tryParseBundle(data)
}
