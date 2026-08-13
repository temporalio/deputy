package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestStructuredMetadataReachesSourceIntact pins the property that a policy's
// declared metadata arrives at the engine exactly as authored.
//
// Metadata used to travel as `//! policy.x = "..."` comments prepended to the
// generated CEL body, which cost three things this table covers: the
// description was emitted and never read back, list values were comma joined
// and re-split on commas (so any value containing a comma became two), and
// escaping was one-way (quotes and backslashes came back mangled).
func TestStructuredMetadataReachesSourceIntact(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		policy structuredPolicy
		want   Metadata
	}{
		{
			name: "description survives the loader",
			policy: structuredPolicy{
				Name:        "log4shell",
				Description: "Blocks vulnerable log4j packages",
			},
			want: Metadata{
				Name:        "log4shell",
				Description: "Blocks vulnerable log4j packages",
			},
		},
		{
			name: "multi-line description survives the loader",
			policy: structuredPolicy{
				Name:        "multi-line",
				Description: "first line\nsecond line\r\nthird line",
			},
			want: Metadata{
				Name:        "multi-line",
				Description: "first line\nsecond line\r\nthird line",
			},
		},
		{
			name: "value containing a comma stays one value",
			policy: structuredPolicy{
				Name:       "comma-ecosystem",
				Ecosystems: []string{"weird,name"},
			},
			want: Metadata{
				Name:       "comma-ecosystem",
				Ecosystems: []string{"weird,name"},
			},
		},
		{
			name: "quotes and backslashes survive verbatim",
			policy: structuredPolicy{
				Name:        `he said "hi"`,
				Description: `back\slash and "quote"`,
			},
			want: Metadata{
				Name:        `he said "hi"`,
				Description: `back\slash and "quote"`,
			},
		},
		{
			name: "entrypoints and commands keep their declared order",
			policy: structuredPolicy{
				Name:        "scoped",
				Entrypoints: []string{"scan_report", "scan_vulnerability"},
				Commands:    []string{"scan", "diff"},
			},
			want: Metadata{
				Name:        "scoped",
				Entrypoints: []Entrypoint{EntrypointScanReport, EntrypointScanVulnerability},
				Commands:    []string{"scan", "diff"},
			},
		},
		{
			name: "legacy command aliases normalize and deduplicate",
			policy: structuredPolicy{
				Name:     "sandbox-only",
				Commands: []string{"exec", "sandbox"},
			},
			want: Metadata{
				Name:     "sandbox-only",
				Commands: []string{"sandbox"},
			},
		},
		{
			name: "mode is canonicalized",
			policy: structuredPolicy{
				Name: "advisory-mixed-case",
				Mode: " Advisory ",
			},
			want: Metadata{
				Name: "advisory-mixed-case",
				Mode: ModeAdvisory,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			p := test.policy
			p.Rules = []structuredRule{{Action: "deny", When: "true"}}
			got, err := p.metadata()
			if err != nil {
				t.Fatalf("metadata() error = %v", err)
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("metadata() mismatch (-want +got):\n%s", diff)
			}
			body, err := p.toCELSource()
			if err != nil {
				t.Fatalf("toCELSource() error = %v", err)
			}
			if err := Compile(body, nil); err != nil {
				t.Fatalf("compile generated body: %v", err)
			}
		})
	}
}

// TestStructuredMetadataRejectsUnknownVocabulary keeps the loader's validation
// where policy scoping is decided, so a typo cannot reach the engine as an
// unscoped policy.
func TestStructuredMetadataRejectsUnknownVocabulary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		policy  structuredPolicy
		wantErr string
	}{
		{
			name:    "unknown entrypoint",
			policy:  structuredPolicy{Entrypoints: []string{"malicious_entrypoint"}},
			wantErr: `invalid entrypoint "malicious_entrypoint"`,
		},
		{
			name:    "unknown command",
			policy:  structuredPolicy{Commands: []string{"teleport"}},
			wantErr: `invalid command "teleport"`,
		},
		{
			name:    "unknown mode",
			policy:  structuredPolicy{Mode: "audit"},
			wantErr: `invalid mode "audit" (expected enforce|advisory)`,
		},
		{
			name:    "blank mode",
			policy:  structuredPolicy{Mode: "   "},
			wantErr: `invalid mode "   " (expected enforce|advisory)`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			p := test.policy
			p.Rules = []structuredRule{{Action: "deny", When: "true"}}
			_, err := p.metadata()
			if err == nil {
				t.Fatalf("metadata() error = nil, want %q", test.wantErr)
			}
			if got := err.Error(); got != test.wantErr {
				t.Errorf("metadata() error = %q, want %q", got, test.wantErr)
			}
		})
	}
}

// TestLoadSourcesCarriesYAMLMetadata covers the same property one level up,
// through the file loader every command uses.
func TestLoadSourcesCarriesYAMLMetadata(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	yaml := `policies:
  - name: block-log4shell
    description: Blocks vulnerable log4j packages
    ecosystems: [npm]
    entrypoints: [scan_report]
    commands: [scan]
    mode: advisory
    rules:
      - action: deny
        when: "true"
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	sources, err := LoadSources([]string{path})
	if err != nil {
		t.Fatalf("LoadSources() error = %v", err)
	}
	if len(sources) != 1 {
		t.Fatalf("LoadSources() returned %d sources, want 1", len(sources))
	}
	want := Metadata{
		Name:        "block-log4shell",
		Description: "Blocks vulnerable log4j packages",
		Entrypoints: []Entrypoint{EntrypointScanReport},
		Commands:    []string{"scan"},
		Ecosystems:  []string{"npm"},
		Mode:        ModeAdvisory,
	}
	if diff := cmp.Diff(want, sources[0].Metadata); diff != "" {
		t.Errorf("LoadSources() metadata mismatch (-want +got):\n%s", diff)
	}
}

// TestBundleRoundTripPreservesScoping pins the compiled-bundle hop: a policy's
// entrypoint, command, and mode scoping has to survive `deputy policy bundle`
// and reload, because the engine filters on it. The metadata used to ride along
// inside the CEL body's comments, so this path needs its own coverage now that
// the bundle carries the fields itself.
func TestBundleRoundTripPreservesScoping(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "policy.yaml")
	yaml := `policies:
  - name: scan-only
    description: Only applies to scan reports
    entrypoints: [scan_report]
    commands: [scan]
    mode: advisory
    rules:
      - action: deny
        when: "true"
        reason: nope
`
	if err := os.WriteFile(yamlPath, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	bundle, err := BuildBundle([]string{yamlPath})
	if err != nil {
		t.Fatalf("BuildBundle() error = %v", err)
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, data, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	sources, err := LoadSources([]string{bundlePath})
	if err != nil {
		t.Fatalf("LoadSources() error = %v", err)
	}
	want := Metadata{
		Name:        "scan-only",
		Description: "Only applies to scan reports",
		Entrypoints: []Entrypoint{EntrypointScanReport},
		Commands:    []string{"scan"},
		Mode:        ModeAdvisory,
	}
	if len(sources) != 1 {
		t.Fatalf("LoadSources() returned %d sources, want 1", len(sources))
	}
	if diff := cmp.Diff(want, sources[0].Metadata); diff != "" {
		t.Errorf("reloaded bundle metadata mismatch (-want +got):\n%s", diff)
	}

	eng, err := NewEngine(sources)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	// Declared scoping still filters after the round trip.
	skipped, err := eng.EvaluateAll(t.Context(), nil, "diff", EntrypointDiffReport.String())
	if err != nil {
		t.Fatalf("EvaluateAll() error = %v", err)
	}
	if len(skipped) != 0 {
		t.Errorf("EvaluateAll() on an out-of-scope entrypoint returned %d actions, want 0", len(skipped))
	}
	// And advisory mode still downgrades the deny it produces in scope.
	actions, err := eng.EvaluateAll(t.Context(), nil, "scan", EntrypointScanReport.String())
	if err != nil {
		t.Fatalf("EvaluateAll() error = %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("EvaluateAll() returned %d actions, want 1", len(actions))
	}
	if actions[0].Type != ActionWarn {
		t.Errorf("EvaluateAll() action type = %q, want %q", actions[0].Type, ActionWarn)
	}
}

// TestLoadSourcesRejectsBundleWithCommentMetadata covers the one artifact that
// can still carry metadata in comments: a JSON bundle compiled before the
// fields became typed. Loading it would drop its scoping and run the policy
// everywhere, so the load has to fail instead.
func TestLoadSourcesRejectsBundleWithCommentMetadata(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		policy  BundlePolicy
		wantErr bool
	}{
		{
			// An older bundle named its entries in JSON but kept their scoping
			// in the body, so the name alone must not vouch for the entry.
			name: "stale entry with comment metadata is rejected",
			policy: BundlePolicy{
				Metadata: Metadata{Name: "stale"},
				Source:   "//! policy.name = \"stale\"\n//! policy.entrypoints = \"scan_report\"\n[{\"action\": \"allow\"}]",
			},
			wantErr: true,
		},
		{
			name: "marker inside the program is not a stale entry",
			policy: BundlePolicy{
				Metadata: Metadata{Name: "mentions-marker"},
				Source:   "[{\"action\": \"allow\", \"reason\": \"//! policy.name is not metadata here\"}]",
			},
		},
		{
			name: "rebuilt entry with typed metadata is accepted",
			policy: BundlePolicy{
				Metadata: Metadata{Name: "rebuilt", Entrypoints: []Entrypoint{EntrypointScanReport}},
				Source:   `[{"action": "allow"}]`,
			},
		},
		{
			name:   "entry without metadata of any kind is accepted",
			policy: BundlePolicy{Source: `[{"action": "allow"}]`},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			data, err := json.Marshal(Bundle{
				SchemaVersion: bundleSchemaVersion,
				Policies:      []BundlePolicy{test.policy},
			})
			if err != nil {
				t.Fatalf("marshal bundle: %v", err)
			}
			path := filepath.Join(t.TempDir(), "bundle.json")
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatalf("write bundle: %v", err)
			}
			_, err = LoadSources([]string{path})
			if test.wantErr {
				if err == nil {
					t.Fatal("LoadSources() error = nil, want a rebuild error")
				}
				if !strings.Contains(err.Error(), "rebuild the bundle") {
					t.Errorf("LoadSources() error = %v, want it to ask for a rebuild", err)
				}
				return
			}
			if err != nil {
				t.Errorf("LoadSources() error = %v, want nil", err)
			}
		})
	}
}

// TestBundleScopingIsValidatedAtTheEngine covers the one route into the engine
// that never passes the authoring loader: a compiled bundle is JSON, so its
// typed metadata is whatever the file says, including values no author could
// have written through `deputy policy bundle`.
//
// Both misspellings below fail open if they are trusted. The engine only filters
// on commands it recognizes, so "scna" leaves the policy running for every
// command; and "advisroy" is not advisory, so the deny this policy was meant to
// only warn about is enforced. The load has to fail instead.
func TestBundleScopingIsValidatedAtTheEngine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		entry   string
		wantErr string
	}{
		{
			name:    "misspelled command",
			entry:   `"commands": ["scna"],`,
			wantErr: `invalid command "scna"`,
		},
		{
			name:    "misspelled mode",
			entry:   `"mode": "advisroy",`,
			wantErr: `invalid mode "advisroy"`,
		},
		{
			name:  "canonical scoping loads",
			entry: `"commands": ["scan"], "mode": "advisory",`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			data := fmt.Sprintf(`{
  "schemaVersion": %q,
  "policies": [
    {"name": "hand-written", %s "source": "[{\"action\": \"deny\", \"reason\": \"nope\"}]"}
  ]
}`, bundleSchemaVersion, test.entry)
			path := filepath.Join(t.TempDir(), "bundle.json")
			if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
				t.Fatalf("write bundle: %v", err)
			}
			_, err := NewEngineFromPaths([]string{path})
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("NewEngineFromPaths() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("NewEngineFromPaths() error = nil, want one containing %q", test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("NewEngineFromPaths() error = %v, want it to contain %q", err, test.wantErr)
			}
		})
	}
}

// TestGeneratedBodyCarriesNoMetadataComments keeps the comment channel closed:
// the generated CEL is the policy's logic and nothing else, so no reader is
// tempted to recover metadata by parsing program text.
func TestGeneratedBodyCarriesNoMetadataComments(t *testing.T) {
	t.Parallel()
	p := structuredPolicy{
		Name:        "commentless",
		Description: "no comments, please",
		Entrypoints: []string{"scan_report"},
		Commands:    []string{"scan"},
		Ecosystems:  []string{"npm"},
		Mode:        "advisory",
		Rules:       []structuredRule{{Action: "deny", When: "true"}},
	}
	body, err := p.toCELSource()
	if err != nil {
		t.Fatalf("toCELSource() error = %v", err)
	}
	for _, unwanted := range []string{"//!", "commentless", "no comments, please", "scan_report"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("generated body contains %q:\n%s", unwanted, body)
		}
	}
}
