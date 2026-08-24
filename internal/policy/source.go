package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// bundleSchemaVersion is the compiled bundle format this build writes and the
// only one it reads. It changes whenever a bundle entry's fields change meaning,
// so that a reader can refuse a bundle it would otherwise misread instead of
// applying whichever parts it happens to recognize.
//
// v1alpha2 moved a policy's declared scoping out of `//! policy.*` comments in
// the CEL body and into typed fields on the entry.
const bundleSchemaVersion = "policy.deputy.sh/v1alpha2"

// Source represents an individual CEL policy ready for evaluation.
type Source struct {
	Name     string   // Name identifies where the policy came from, as "path::policy".
	Body     string   // Body is the CEL source code.
	Metadata Metadata // Metadata is what the policy declares about itself; the zero value scopes it to everything.
}

// Bundle is the on-disk representation produced by `deputy policy bundle`.
type Bundle struct {
	SchemaVersion string         `json:"schemaVersion"`      // SchemaVersion is the bundle format version.
	Generated     string         `json:"generated"`          // Generated is the timestamp when the bundle was built.
	Policies      []BundlePolicy `json:"policies"`           // Policies is the list of compiled policies.
	Metadata      map[string]any `json:"metadata,omitempty"` // Metadata contains arbitrary bundle-level metadata, unrelated to a policy's own [Metadata].
}

// BundlePolicy contains the CEL program for a single entry in a bundle, plus
// the metadata the engine needs to scope it. [Metadata] is embedded rather than
// restated field by field, so an entry and a policy share a single field
// definition instead of two that have to be kept in step.
type BundlePolicy struct {
	Metadata // Metadata is the policy's declared identity and scoping, embedded so its fields sit directly on the entry.

	Source string `json:"source"` // Source is the compiled CEL source code.
}

// checkSchemaVersion rejects a bundle written in a format this build does not
// read. Recognizing the shape of a bundle is not the same as understanding it:
// [tryParseBundle] answers the first question so a file can be routed to the
// right parser, and this answers the second, because an entry's fields mean
// whatever the format that wrote them says they mean.
//
// Both directions have to fail. An older bundle kept its policies' scoping in
// CEL comments this build ignores, and a newer one may keep it somewhere this
// build cannot see; either way the policy would load with no scoping at all and
// run for every command and entrypoint, in enforce mode. Refusing the file and
// naming the version to rebuild is the only outcome that cannot silently widen a
// policy.
func (b *Bundle) checkSchemaVersion(path string) error {
	if b.SchemaVersion == bundleSchemaVersion {
		return nil
	}
	return fmt.Errorf("%s: bundle schema version %q is not the version this build reads (%s); rebuild it from its policy sources with `deputy policy bundle`", path, b.SchemaVersion, bundleSchemaVersion)
}

// legacyMetadataMarker is the comment prefix Deputy releases before typed
// bundle metadata used to carry a policy's scoping inside its CEL body.
const legacyMetadataMarker = "//! policy."

// checkLegacyMetadata rejects a bundle entry whose scoping is still encoded in
// its CEL body. Nothing reads those comments any more, so the entry would load
// with no scoping at all and run for every command and entrypoint, in enforce
// mode, silently widening the policy.
//
// [Bundle.checkSchemaVersion] does not cover this: the version is a field in the
// same file, so a hand-edited or merged bundle can claim the current version
// while carrying a body from before it.
func (p BundlePolicy) checkLegacyMetadata(path string) error {
	if !startsWithLegacyMetadata(p.Source) {
		return nil
	}
	return fmt.Errorf("%s: policy %q carries its metadata as %q comments; rebuild it from its policy sources with `deputy policy bundle`", path, p.Name, legacyMetadataMarker)
}

// startsWithLegacyMetadata reports whether body opens with the metadata comment
// older releases prepended to a compiled policy. Only the leading non-empty
// line is considered, because that is where those comments were written and a
// generated body otherwise opens with its rule list; a policy that merely
// mentions the marker inside a string literal is not a stale entry.
func startsWithLegacyMetadata(body string) bool {
	for line := range strings.SplitSeq(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		return strings.HasPrefix(trimmed, legacyMetadataMarker)
	}
	return false
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
			if err := bundle.checkSchemaVersion(path); err != nil {
				return nil, err
			}
			for _, p := range bundle.Policies {
				if err := p.checkLegacyMetadata(path); err != nil {
					return nil, err
				}
				name := p.Name
				if name == "" {
					name = filepath.Base(path)
				}
				sources = append(sources, Source{
					Name:     fmt.Sprintf("%s::%s", path, name),
					Body:     p.Source,
					Metadata: p.Metadata,
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
		meta := src.Metadata
		if meta.Name == "" {
			meta.Name = filepath.Base(src.Name)
		}
		policies = append(policies, BundlePolicy{
			Metadata: meta,
			Source:   src.Body,
		})
	}
	return &Bundle{
		SchemaVersion: bundleSchemaVersion,
		Generated:     time.Now().UTC().Format(time.RFC3339),
		Policies:      policies,
	}, nil
}

// tryParseBundle reports whether data has the shape of a compiled bundle, which
// is what routes a file to this parser rather than the authored YAML one. It
// deliberately does not judge the format's version, so a bundle this build
// cannot read fails with that as its reason instead of "unrecognized format";
// see [Bundle.checkSchemaVersion].
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

// LoadBundle reads a compiled JSON bundle file from disk, failing if it was
// written in a format this build does not read.
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
	if err := bundle.checkSchemaVersion(path); err != nil {
		return nil, err
	}
	return bundle, nil
}

// ParseBundle attempts to parse the provided bytes as a policy bundle. It
// accepts any version, because a caller that only reports what a file contains
// (such as `deputy policy inspect`) is more useful than one that refuses to look
// at a bundle it cannot load. Callers that go on to evaluate the policies must
// use [LoadBundle] or [LoadSources], which check the version.
func ParseBundle(data []byte) (*Bundle, bool) {
	return tryParseBundle(data)
}
