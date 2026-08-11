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
		s, err := LoadSourcesFromBytes(data, path)
		if err != nil {
			return nil, err
		}
		sources = append(sources, s...)
	}
	return sources, nil
}

// LoadSourcesFromBytes returns the policy sources data holds, trying the
// compiled bundle format first and the authored one second, exactly as
// LoadSources does; it is the implementation LoadSources reads files for.
//
// It exists for a caller that already has the bytes and no file to reread, such
// as lint reading stdin. Sharing it is what keeps a policy supplied on stdin
// loading the same way as the identical file, rather than each caller deciding
// the format for itself.
//
// path names the source in errors and in generated source names; a caller
// without a file may pass any label.
func LoadSourcesFromBytes(data []byte, path string) ([]Source, error) {
	// Try JSON bundle format first (compiled bundles)
	if bundle, ok := tryParseBundle(data); ok {
		sources := make([]Source, 0, len(bundle.Policies))
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
		return sources, nil
	}
	// Try structured YAML format (human-authored policies)
	sources, ok, err := tryParseStructuredBundle(data, path)
	if err != nil {
		return nil, err
	}
	if ok {
		return sources, nil
	}
	// Neither format matched - provide helpful error
	return nil, fmt.Errorf("%s: unrecognized policy format; expected YAML with 'policies:' key or JSON bundle with 'schemaVersion' field", path)
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

// IsCompiledBundle reports whether data is a bundle produced by
// `deputy policy bundle`. JSON is valid YAML, and a compiled bundle also has a
// non-empty "policies" array, so callers that probe for a structured bundle must
// rule this shape out first: its entries carry compiled CEL under "source"
// rather than the rules an authored policy has.
func IsCompiledBundle(data []byte) bool {
	_, ok := tryParseBundle(data)
	return ok
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
			if _, after, ok := strings.Cut(line, "="); ok {
				value := strings.TrimSpace(after)
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
