package mise

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// ToolSpec is a single entry from a mise [tools] table (or a .tool-versions
// line). One key may request multiple versions (e.g. python = ["3.11","3.12"]),
// in which case Versions holds each.
type ToolSpec struct {
	// Key is the raw [tools] key as written, e.g. "node" or "npm:prettier".
	Key string
	// Backend is the resolved backend prefix ("npm", "cargo", …) or "" when the
	// key uses the default registry/core backend.
	Backend string
	// Name is the tool name without its backend prefix, e.g. "node", "prettier".
	Name string
	// Versions are the requested version strings, in source order.
	Versions []string
	// Options carries extra inline-table fields (postinstall, os, …) when present.
	Options map[string]any
}

// Settings captures the subset of mise [settings] relevant to supply-chain
// hardening. Booleans are pointers so an explicit false is distinguishable from
// an unset value (mise defaults verification settings to true).
//
// TODO(deputy): expose these hardening facts (lockfile presence, the
// minimum_release_age cooldown, and verification settings — slsa/gpg_verify/
// paranoid/github_attestations/aqua.cosign/aqua.slsa) as CEL policy inputs so
// users can enforce them as policy-as-code (e.g. require a committed mise.lock,
// require minimum_release_age >= "14d", require verification on). Best done as
// part of a broader Deputy policy-inputs capability PR rather than a bespoke
// mise audit command. See docs/reference/policy-inputs.md.
type Settings struct {
	Lockfile           *bool
	MinimumReleaseAge  string
	GithubAttestations *bool
	SLSA               *bool
	GPGVerify          *bool
	Paranoid           *bool
	AquaCosign         *bool
	AquaSLSA           *bool
}

// Config is a parsed mise configuration file.
type Config struct {
	Path     string
	Format   Format
	Tools    []ToolSpec
	Settings Settings
}

// Parse parses mise configuration bytes. The format is inferred from path; an
// unrecognized path is parsed as TOML unless it is named .tool-versions.
func Parse(path string, data []byte) (*Config, error) {
	if isToolVersionsPath(path) {
		return parseToolVersions(path, data), nil
	}
	return parseTOML(path, data)
}

// isToolVersionsPath reports whether path should be parsed as the asdf
// .tool-versions format rather than TOML.
func isToolVersionsPath(path string) bool {
	if format, ok := IsConfigPath(path); ok {
		return format == FormatToolVersions
	}
	return strings.HasSuffix(path, ".tool-versions")
}

// parseTOML parses native mise.toml content.
func parseTOML(path string, data []byte) (*Config, error) {
	var top map[string]any
	if err := toml.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("mise: parsing %s: %w", path, err)
	}
	cfg := &Config{Path: path, Format: FormatTOML}

	if toolsRaw, ok := top["tools"].(map[string]any); ok {
		cfg.Tools = parseToolsTable(toolsRaw)
	}
	if settingsRaw, ok := top["settings"].(map[string]any); ok {
		cfg.Settings = parseSettings(settingsRaw)
	}
	return cfg, nil
}

// parseToolsTable converts a decoded [tools] table into sorted ToolSpecs.
func parseToolsTable(tools map[string]any) []ToolSpec {
	out := make([]ToolSpec, 0, len(tools))
	for key, val := range tools {
		if strings.TrimSpace(key) == "" {
			continue // skip meaningless empty-key entries
		}
		versions, opts := toolVersions(val)
		backend, name := SplitBackend(key)
		out = append(out, ToolSpec{
			Key:      key,
			Backend:  backend,
			Name:     name,
			Versions: versions,
			Options:  mergeKeyOptions(key, opts),
		})
	}
	slices.SortFunc(out, func(a, b ToolSpec) int { return strings.Compare(a.Key, b.Key) })
	return out
}

// mergeKeyOptions folds any inline-key tool options ("ubi:cli/cli[exe=gh]")
// into the inline-table options already parsed from the value. Table options
// take precedence on key collision since they are the more explicit form.
// Returns nil when there are no options of either kind.
func mergeKeyOptions(key string, tableOpts map[string]any) map[string]any {
	keyOpts := ToolOptions(key)
	if len(keyOpts) == 0 {
		return tableOpts
	}
	merged := make(map[string]any, len(keyOpts)+len(tableOpts))
	for k, v := range keyOpts {
		merged[k] = v
	}
	maps.Copy(merged, tableOpts)
	return merged
}

// toolVersions extracts the requested version strings (and any inline options)
// from a single [tools] value, which may be a string, an array of strings, an
// inline table with a version field, or an array of such tables, whether that
// array was written inline or as repeated [[tools.<name>]] headers.
func toolVersions(val any) (versions []string, opts map[string]any) {
	switch t := val.(type) {
	case string:
		return []string{t}, nil
	case int64, float64, bool:
		return []string{coerceScalar(t)}, nil
	case []any:
		for _, e := range t {
			switch ev := e.(type) {
			case string:
				versions = append(versions, ev)
			case map[string]any:
				versions = append(versions, tableVersions(ev)...)
				if opts == nil {
					opts = ev
				}
			default:
				if s := coerceScalar(ev); s != "" {
					versions = append(versions, s)
				}
			}
		}
		return versions, opts
	case []map[string]any:
		// The array-of-tables form, `[[tools.go]]` with its fields below it.
		// The TOML decoder types it as a slice of tables rather than a slice
		// of any, so it reaches none of the cases above, and mise reads it the
		// same as an inline array of tables. Reusing that case keeps one
		// reading of an element instead of a second copy that can drift.
		return toolVersions(anySlice(t))
	case map[string]any:
		return tableVersions(t), t
	default:
		return nil, nil
	}
}

// anySlice widens a slice of TOML tables to a slice of any, so the decoder's
// two spellings of "an array of tables" reach one reader.
func anySlice(tables []map[string]any) []any {
	out := make([]any, len(tables))
	for i, t := range tables {
		out[i] = t
	}
	return out
}

// tableVersions reads the version field from an inline table, supporting both a
// scalar version and an array of versions (e.g. version = ["3.11", "3.12"]).
// All requested versions are returned in source order; empty entries are
// dropped.
func tableVersions(m map[string]any) []string {
	switch v := m["version"].(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case int64, float64, bool:
		if s := coerceScalar(v); s != "" {
			return []string{s}
		}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s := coerceScalar(e); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// coerceScalar renders a non-string scalar TOML value as a string so that
// bare versions like `node = 20` are handled.
func coerceScalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return ""
	}
}

// parseSettings extracts hardening-relevant fields from a decoded [settings]
// table.
func parseSettings(m map[string]any) Settings {
	s := Settings{
		Lockfile:           boolPtr(m["lockfile"]),
		MinimumReleaseAge:  strings.TrimSpace(coerceScalar(m["minimum_release_age"])),
		GithubAttestations: boolPtr(m["github_attestations"]),
		SLSA:               boolPtr(m["slsa"]),
		GPGVerify:          boolPtr(m["gpg_verify"]),
		Paranoid:           boolPtr(m["paranoid"]),
	}
	if aqua, ok := m["aqua"].(map[string]any); ok {
		s.AquaCosign = boolPtr(aqua["cosign"])
		s.AquaSLSA = boolPtr(aqua["slsa"])
	}
	return s
}

// boolPtr returns a pointer to a bool value when v is a bool, else nil.
func boolPtr(v any) *bool {
	if b, ok := v.(bool); ok {
		return &b
	}
	return nil
}

// parseToolVersions parses the legacy asdf .tool-versions format: one tool per
// line, "name version [version...]", with "#" comments.
func parseToolVersions(path string, data []byte) *Config {
	cfg := &Config{Path: path, Format: FormatToolVersions}
	for raw := range strings.SplitSeq(string(data), "\n") {
		line := raw
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := fields[0]
		backend, name := SplitBackend(key)
		cfg.Tools = append(cfg.Tools, ToolSpec{
			Key:      key,
			Backend:  backend,
			Name:     name,
			Versions: fields[1:],
			Options:  mergeKeyOptions(key, nil),
		})
	}
	slices.SortFunc(cfg.Tools, func(a, b ToolSpec) int { return strings.Compare(a.Key, b.Key) })
	return cfg
}
