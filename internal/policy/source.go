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
	Name string
	Body string
}

// Bundle is the on-disk representation produced by `deputy policy bundle`.
type Bundle struct {
	SchemaVersion string         `json:"schemaVersion"`
	Generated     string         `json:"generated"`
	Policies      []BundlePolicy `json:"policies"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

// BundlePolicy contains the CEL program for a single entry in a bundle.
type BundlePolicy struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

// LoadSources reads a list of file paths (either raw CEL files or bundle JSON)
// and returns the flattened list of policy sources.
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
		s, ok, err := tryParseStructuredBundle(data, path)
		if err != nil {
			return nil, err
		}
		if ok {
			sources = append(sources, s...)
			continue
		}
		sources = append(sources, Source{
			Name: path,
			Body: string(data),
		})
	}
	return sources, nil
}

// BuildBundle compiles all provided CEL files and returns a bundle structure.
func BuildBundle(paths []string) (*Bundle, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no policy files supplied")
	}
	policies := make([]BundlePolicy, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read policy %q: %w", path, err)
		}
		if err := Compile(string(data), nil); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		name := extractPolicyName(string(data))
		if name == "" {
			name = filepath.Base(path)
		}
		policies = append(policies, BundlePolicy{
			Name:   name,
			Source: string(data),
		})
	}
	return &Bundle{
		SchemaVersion: bundleSchemaVersion,
		Generated:     time.Now().UTC().Format(time.RFC3339),
		Policies:      policies,
	}, nil
}

// StructToMap marshals any Go struct into a generic map for CEL inputs.
func StructToMap(v any) (map[string]any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
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

// LoadBundle reads a bundle file from disk.
func LoadBundle(path string) (*Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	bundle, ok := tryParseBundle(data)
	if !ok {
		return nil, fmt.Errorf("%s is not a policy bundle", path)
	}
	return bundle, nil
}

// ParseBundle attempts to parse the provided bytes as a policy bundle.
func ParseBundle(data []byte) (*Bundle, bool) {
	return tryParseBundle(data)
}

// ExtractMetadata returns metadata comment key/value pairs from a CEL source.
func ExtractMetadata(source string) map[string]string {
	meta := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(source))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "//!") {
			if line == "" {
				continue
			}
			break
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "//!"))
		if idx := strings.Index(line, "="); idx >= 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.Trim(strings.TrimSpace(line[idx+1:]), `"`)
			meta[key] = val
		}
	}
	return meta
}
